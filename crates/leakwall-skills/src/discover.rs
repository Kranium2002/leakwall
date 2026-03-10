use crate::{AgentType, SkillLocation, SkillScope};
use std::path::PathBuf;
use tracing::debug;
use walkdir::WalkDir;

/// Skill file extensions we recognize.
const SKILL_EXTENSIONS: &[&str] = &["md", "yaml", "yml", "json", "toml", "txt"];

/// Discover skill files across known agent skill directories.
pub fn discover_skills() -> Vec<SkillLocation> {
    let mut locations = Vec::new();

    // Claude Code global: ~/.claude/skills/
    if let Some(home) = dirs::home_dir() {
        let claude_global = home.join(".claude").join("skills");
        scan_directory(
            &claude_global,
            AgentType::ClaudeCode,
            SkillScope::Global,
            &mut locations,
        );

        // OpenClaw global: ~/.openclaw/skills/
        let openclaw_global = home.join(".openclaw").join("skills");
        scan_directory(
            &openclaw_global,
            AgentType::OpenClaw,
            SkillScope::Global,
            &mut locations,
        );
    }

    // Claude Code project: .claude/skills/ relative to cwd
    if let Ok(cwd) = std::env::current_dir() {
        let claude_project = cwd.join(".claude").join("skills");
        scan_directory(
            &claude_project,
            AgentType::ClaudeCode,
            SkillScope::Project,
            &mut locations,
        );

        // Aider: .aider.conf.yml in cwd
        let aider_conf = cwd.join(".aider.conf.yml");
        if aider_conf.is_file() {
            debug!(path = %aider_conf.display(), "found Aider config");
            locations.push(SkillLocation {
                agent: AgentType::Aider,
                path: aider_conf,
                scope: SkillScope::Project,
            });
        }
    }

    debug!(count = locations.len(), "skill discovery complete");
    locations
}

/// Walk a directory up to depth 3, collecting files with recognized extensions.
fn scan_directory(
    dir: &PathBuf,
    agent: AgentType,
    scope: SkillScope,
    locations: &mut Vec<SkillLocation>,
) {
    if !dir.is_dir() {
        return;
    }

    debug!(path = %dir.display(), agent = %agent, "scanning skill directory");

    for entry in WalkDir::new(dir)
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        let matches = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| SKILL_EXTENSIONS.contains(&ext));

        if matches {
            debug!(path = %path.display(), "found skill file");
            locations.push(SkillLocation {
                agent: agent.clone(),
                path,
                scope: scope.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_scan_directory_finds_skill_files() {
        let tmp = TempDir::new().unwrap();
        let skills_dir = tmp.path().join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(skills_dir.join("deploy.md"), "# Deploy").unwrap();
        std::fs::write(skills_dir.join("config.yaml"), "key: val").unwrap();
        std::fs::write(skills_dir.join("notes.txt"), "notes").unwrap();
        // Non-matching extension
        std::fs::write(skills_dir.join("binary.exe"), "data").unwrap();

        let mut locations = Vec::new();
        scan_directory(
            &skills_dir.to_path_buf(),
            AgentType::ClaudeCode,
            SkillScope::Global,
            &mut locations,
        );

        assert_eq!(locations.len(), 3);
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let mut locations = Vec::new();
        scan_directory(
            &PathBuf::from("/nonexistent/path"),
            AgentType::ClaudeCode,
            SkillScope::Global,
            &mut locations,
        );
        assert!(locations.is_empty());
    }

    #[test]
    fn test_scan_respects_max_depth() {
        // WalkDir max_depth(3) counts root as depth 0.
        // So root/a/b/file.md is depth 3 (found),
        // root/a/b/c/file.md is depth 4 (NOT found).
        let tmp = TempDir::new().unwrap();
        let depth2_dir = tmp.path().join("a").join("b");
        let depth3_dir = depth2_dir.join("c");
        std::fs::create_dir_all(&depth3_dir).unwrap();
        // Depth 3 file (root/a/b/ok.md) — should be found
        std::fs::write(depth2_dir.join("ok.md"), "found").unwrap();
        // Depth 4 file (root/a/b/c/too_deep.md) — should NOT be found
        std::fs::write(depth3_dir.join("too_deep.md"), "hidden").unwrap();

        let mut locations = Vec::new();
        scan_directory(
            &tmp.path().to_path_buf(),
            AgentType::ClaudeCode,
            SkillScope::Project,
            &mut locations,
        );

        let names: Vec<String> = locations
            .iter()
            .map(|l| l.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(names.contains(&"ok.md".to_string()));
        assert!(!names.contains(&"too_deep.md".to_string()));
    }
}
