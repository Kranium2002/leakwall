use crate::SkillsError;
use std::path::Path;
use tracing::debug;

/// Read the full content of a skill file.
pub fn read_skill_content(path: &Path) -> Result<String, SkillsError> {
    debug!(path = %path.display(), "reading skill content");
    std::fs::read_to_string(path).map_err(|source| SkillsError::FileRead {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_skill_content_success() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "# My Skill\nDo stuff").unwrap();
        let content = read_skill_content(file.path()).unwrap();
        assert_eq!(content, "# My Skill\nDo stuff");
    }

    #[test]
    fn test_read_skill_content_missing_file() {
        let result = read_skill_content(Path::new("/nonexistent/skill.md"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("failed to read skill file"));
    }
}
