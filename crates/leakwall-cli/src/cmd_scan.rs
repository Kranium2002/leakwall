use anyhow::{Context, Result};
use chrono::Utc;
use colored::Colorize;
use leakwall_mcp::{
    self, discover, ConfigFinding, ExposureCheck, FindingType, HashChange, HashChangeType,
    McpAuditResult, Severity, Verdict,
};
use leakwall_tui::report::ScanReport;
use std::path::Path;

/// Run the `leakwall scan` command — comprehensive security audit.
pub async fn run_scan(
    lw_dir: &Path,
    refresh: bool,
    json_output: Option<&Path>,
    trust_project: bool,
    no_exec: bool,
) -> Result<()> {
    // Silently sync bundled security data
    sync_security_data(lw_dir, refresh).await;

    println!("{}", "⠿ Scanning MCP servers...".dimmed());

    // 1. Discover MCP configs
    let servers = discover::discover_all_servers().context("MCP discovery failed")?;

    // 2. Check secrets exposure
    let cwd = std::env::current_dir().unwrap_or_default();
    let exposure = leakwall_mcp::check_exposure(&cwd);

    // 3. Audit each MCP server
    let mut audit_results: Vec<McpAuditResult> = Vec::new();
    for server in &servers {
        println!("{}", format!("⠿ Auditing {}...", server.name).dimmed());
        match leakwall_mcp::audit_mcp_server(server, refresh, trust_project, no_exec).await {
            Ok(result) => audit_results.push(result),
            Err(e) => {
                eprintln!(
                    "  {}: Failed to audit {}: {e}",
                    "Warning".yellow(),
                    server.name
                );
            }
        }
    }

    // 4. Calculate score
    let (critical, high, medium, low) = count_findings(&exposure, &audit_results);
    let score = ScanReport::calculate_score(critical, high, medium, low);
    let risk = ScanReport::risk_level(score);

    // 5. Render output
    println!();
    println!("═══════════════════════════════════════════════════");

    let score_display = format!("leakwall security audit — score: {score}/100");
    if score >= 80 {
        println!("           {}", score_display.green().bold());
        println!("                     {} 🟢", risk.green());
    } else if score >= 50 {
        println!("           {}", score_display.yellow().bold());
        println!("                  {} 🟡", risk.yellow());
    } else {
        println!("           {}", score_display.red().bold());
        println!("                     {} 🔴", risk.red());
    }

    println!("═══════════════════════════════════════════════════");
    println!();

    // Secrets exposure section
    print_exposure_section(&exposure);

    // MCP servers section
    if !audit_results.is_empty() || !servers.is_empty() {
        println!(
            "{}",
            format!("MCP SERVERS ({} found)", servers.len()).bold()
        );
        println!();

        for result in &audit_results {
            print_mcp_result(result);
            println!();
        }
    }

    // Agent configuration section (agent config audit)
    let config_findings = audit_agent_configs();
    if !config_findings.is_empty() {
        println!("{}", "AGENT CONFIGURATION".bold());
        for finding in &config_findings {
            let icon = severity_icon(&finding.severity);
            println!(
                "  {icon} {}: {}",
                format!("{}", finding.agent).cyan(),
                finding.recommendation
            );
        }
        println!();
    }

    // Skills analysis section
    let skills = leakwall_skills::discover::discover_skills();
    if !skills.is_empty() {
        println!(
            "{}",
            format!("SKILLS ANALYSIS ({} skills found)", skills.len()).bold()
        );
        println!();

        for skill in &skills {
            match leakwall_skills::analyze::analyze_skill(skill) {
                Ok(analysis) => {
                    print_skill_analysis(&analysis);
                }
                Err(e) => {
                    eprintln!(
                        "  {}: Failed to analyze {}: {e}",
                        "Warning".yellow(),
                        skill.path.display()
                    );
                }
            }
        }
        println!();
    }

    // Hash changes
    let all_hash_changes: Vec<&HashChange> = audit_results
        .iter()
        .flat_map(|r| r.hash_changes.iter())
        .filter(|h| h.change_type == HashChangeType::Modified)
        .collect();

    if !all_hash_changes.is_empty() {
        println!("{}", "TOOL HASH CHANGES (since last scan)".bold());
        for change in &all_hash_changes {
            println!(
                "  ⚠️  {} — definition MODIFIED (possible rug pull)",
                change.tool_name.yellow()
            );
            if let Some(ref prev) = change.previous_hash {
                let display = prev.get(..12).unwrap_or(prev);
                println!("     Previous hash: {}...", display);
            }
            let display = change
                .current_hash
                .get(..12)
                .unwrap_or(&change.current_hash);
            println!("     Current hash:  {}...", display);
        }
        println!();
    }

    // Save report
    let report_dir = lw_dir.join("reports");
    std::fs::create_dir_all(&report_dir)?;
    let report_filename = format!("scan-{}.json", Utc::now().format("%Y-%m-%d-%H%M%S"));
    let report_path = report_dir.join(&report_filename);

    let report = build_json_report(score, risk, &exposure, &audit_results, &config_findings);
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&report_path, &json)?;

    println!("Report saved: {}", report_path.display().to_string().cyan());
    println!();

    // Recommendations
    let recommendations = generate_recommendations(&exposure, &audit_results);
    if !recommendations.is_empty() {
        println!("{}", "Recommendations:".bold());
        for (i, rec) in recommendations.iter().enumerate() {
            println!("  {}. {rec}", i + 1);
        }
    }

    // Also save to specified path if requested
    if let Some(out_path) = json_output {
        std::fs::write(out_path, &json)?;
        println!(
            "\nJSON report also saved to: {}",
            out_path.display().to_string().cyan()
        );
    }

    Ok(())
}

fn print_exposure_section(exposure: &ExposureCheck) {
    println!("{}", "SECRETS EXPOSURE".bold());

    if !exposure.claudeignore_blocks_env {
        println!(
            "  {} .claudeignore missing — .env files are readable by agents",
            "🔴".red()
        );
    }
    if !exposure.gitignore_blocks_env {
        println!("  {} .gitignore missing .env patterns", "⚠️ ".yellow());
    }
    if exposure.claude_deny_rules.is_empty() {
        println!(
            "  {} No deny rules configured in Claude Code settings",
            "⚠️ ".yellow()
        );
    }
    for var in &exposure.dangerous_env_vars {
        println!(
            "  {} {} in env, inheritable by child processes",
            "🔴".red(),
            var.bold()
        );
    }

    if exposure.claudeignore_blocks_env
        && exposure.gitignore_blocks_env
        && exposure.dangerous_env_vars.is_empty()
    {
        println!("  {} Secret exposure checks passed", "✅".green());
    }

    println!();
}

fn print_mcp_result(result: &McpAuditResult) {
    let version_suffix = result
        .identity
        .version
        .as_deref()
        .map(|v| format!(" v{v}"))
        .unwrap_or_default();

    println!("  {}{}", result.identity.name.bold(), version_suffix);

    // Command analysis findings (pre-execution)
    if result.command_findings.is_empty() {
        println!("  ├─ Command:     Safe to execute");
    } else {
        for finding in &result.command_findings {
            let icon = severity_icon(&finding.severity);
            println!("  ├─ Command:     {icon} {}", finding.detail);
        }
    }

    // AgentAudit
    if let Some(ref aa) = result.registry.agent_audit {
        let rec_label = match aa.recommendation {
            leakwall_mcp::AgentAuditRecommendation::Safe => "SAFE \u{2705}".green().to_string(),
            leakwall_mcp::AgentAuditRecommendation::Caution => {
                "CAUTION \u{26a0}\u{fe0f}".yellow().to_string()
            }
            leakwall_mcp::AgentAuditRecommendation::Unsafe => "UNSAFE \u{1f534}".red().to_string(),
            leakwall_mcp::AgentAuditRecommendation::NotAudited => {
                "NOT AUDITED".dimmed().to_string()
            }
        };
        println!(
            "  \u{251c}\u{2500} AgentAudit:  {}/100 \u{2014} {rec_label}",
            aa.trust_score
        );
        let sb = &aa.severity_breakdown;
        println!(
            "  \u{2502}   \u{21b3} {} \u{00b7} C:{} H:{} M:{} L:{}",
            aa.audit_level, sb.critical, sb.high, sb.medium, sb.low
        );
        if let Some(ref url) = aa.url {
            println!("  \u{2502}   \u{21b3} {url}");
        }
    } else {
        println!("  \u{251c}\u{2500} AgentAudit:  {}", "NOT AUDITED".dimmed());
    }

    // CVEs
    if result.registry.cves.is_empty() {
        println!("  ├─ Known CVEs:  None");
    } else {
        for cve in &result.registry.cves {
            let patched = cve
                .fixed_version
                .as_ref()
                .map(|v| format!(" (PATCHED {v})"))
                .unwrap_or_default();
            println!("  ├─ Known CVEs:  {}{patched}", cve.id);
        }
    }

    // Local findings
    if result.local_findings.is_empty() {
        println!("  ├─ Local scan:  No poisoning detected");
    } else {
        for finding in &result.local_findings {
            println!("  ├─ Local scan:  {}", finding.detail);
        }
    }

    // Verdict
    let verdict_str = match result.verdict {
        Verdict::Safe => "SAFE ✅".green().to_string(),
        Verdict::SafeWithAdvisory => "SAFE (with advisory) ✅".green().to_string(),
        Verdict::Suspicious => "SUSPICIOUS ⚠️ — tool poisoning detected"
            .yellow()
            .to_string(),
        Verdict::Unsafe => "UNSAFE 🔴 — recommend removal".red().to_string(),
    };
    println!("  └─ Verdict:     {verdict_str}");
}

fn severity_icon(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::High => "⚠️ ",
        Severity::Medium => "🟡",
        Severity::Low | Severity::Info => "ℹ️ ",
    }
}

fn count_findings(
    exposure: &ExposureCheck,
    results: &[McpAuditResult],
) -> (usize, usize, usize, usize) {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    // Exposure findings
    if !exposure.claudeignore_blocks_env {
        critical += 1;
    }
    if !exposure.gitignore_blocks_env {
        medium += 1;
    }
    critical += exposure.dangerous_env_vars.len();

    // MCP findings (local + command analysis)
    for result in results {
        for finding in result
            .local_findings
            .iter()
            .chain(result.command_findings.iter())
        {
            match finding.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low | Severity::Info => low += 1,
            }
        }
    }

    (critical, high, medium, low)
}

fn audit_agent_configs() -> Vec<ConfigFinding> {
    let mut findings = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    // Check Claude Code settings
    let claude_settings = home.join(".claude/settings.json");
    if let Ok(content) = std::fs::read_to_string(&claude_settings) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            if val
                .get("enableAllProjectMcpServers")
                .and_then(|v| v.as_bool())
                == Some(true)
            {
                findings.push(ConfigFinding {
                    agent: leakwall_mcp::AgentType::ClaudeCode,
                    severity: Severity::Critical,
                    setting: "enableAllProjectMcpServers".into(),
                    current_value: "true".into(),
                    recommendation: "enableAllProjectMcpServers = true — disable for security"
                        .into(),
                });
            }
            if val.get("deny").is_none() {
                findings.push(ConfigFinding {
                    agent: leakwall_mcp::AgentType::ClaudeCode,
                    severity: Severity::High,
                    setting: "deny".into(),
                    current_value: "not set".into(),
                    recommendation: "No deny rules configured".into(),
                });
            }
        }
    }

    // Check for project-level Cursor MCP
    let cwd = std::env::current_dir().unwrap_or_default();
    let cursor_project = cwd.join(".cursor/mcp.json");
    if cursor_project.exists() {
        findings.push(ConfigFinding {
            agent: leakwall_mcp::AgentType::Cursor,
            severity: Severity::High,
            setting: "project mcp.json".into(),
            current_value: "present".into(),
            recommendation: "Project-level MCP config found (trust risk from cloned repos)".into(),
        });
    }

    // Check for autoApprove with dangerous tool patterns (Bash(*), etc.)
    check_auto_approve_dangers(&home, &cwd, &mut findings);

    // Check for gateway misconfigurations
    check_gateway_configs(&home, &cwd, &mut findings);

    findings
}

/// Check for autoApprove containing dangerous patterns like Bash(*).
fn check_auto_approve_dangers(
    home: &std::path::Path,
    cwd: &std::path::Path,
    findings: &mut Vec<ConfigFinding>,
) {
    let dangerous_patterns = ["Bash(*)", "Bash(", "shell(", "exec(", "execute("];

    let config_paths = [
        (
            leakwall_mcp::AgentType::ClaudeCode,
            home.join(".claude/settings.json"),
        ),
        (leakwall_mcp::AgentType::ClaudeCode, cwd.join(".mcp.json")),
        (
            leakwall_mcp::AgentType::Cursor,
            home.join(".cursor/mcp.json"),
        ),
        (
            leakwall_mcp::AgentType::Cursor,
            cwd.join(".cursor/mcp.json"),
        ),
    ];

    for (agent, path) in &config_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                check_auto_approve_value(&val, agent.clone(), &dangerous_patterns, findings);
            }
        }
    }
}

fn check_auto_approve_value(
    val: &serde_json::Value,
    agent: leakwall_mcp::AgentType,
    dangerous_patterns: &[&str],
    findings: &mut Vec<ConfigFinding>,
) {
    // Check top-level autoApprove
    if let Some(auto_approve) = val.get("autoApprove").and_then(|v| v.as_array()) {
        for item in auto_approve {
            if let Some(s) = item.as_str() {
                for pattern in dangerous_patterns {
                    if s.contains(pattern) {
                        findings.push(ConfigFinding {
                            agent: agent.clone(),
                            severity: Severity::Critical,
                            setting: "autoApprove".into(),
                            current_value: s.to_string(),
                            recommendation: format!(
                                "autoApprove contains dangerous pattern '{pattern}' \
                                 — removes human-in-the-loop for shell commands"
                            ),
                        });
                    }
                }
            }
        }
    }

    // Check per-server autoApprove in mcpServers
    if let Some(servers) = val
        .get("mcpServers")
        .or_else(|| val.get("mcp_servers"))
        .and_then(|v| v.as_object())
    {
        for (_name, config) in servers {
            if let Some(auto_approve) = config.get("autoApprove").and_then(|v| v.as_array()) {
                for item in auto_approve {
                    if let Some(s) = item.as_str() {
                        for pattern in dangerous_patterns {
                            if s.contains(pattern) {
                                findings.push(ConfigFinding {
                                    agent: agent.clone(),
                                    severity: Severity::Critical,
                                    setting: "mcpServers.autoApprove".into(),
                                    current_value: s.to_string(),
                                    recommendation: format!(
                                        "autoApprove contains dangerous pattern \
                                         '{pattern}' — removes human-in-the-loop \
                                         for shell commands"
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Check for gateway misconfigurations.
fn check_gateway_configs(
    home: &std::path::Path,
    cwd: &std::path::Path,
    findings: &mut Vec<ConfigFinding>,
) {
    let gateway_configs = [
        home.join(".openclaw/config.json"),
        home.join(".openclaw/config.toml"),
        cwd.join("openclaw.json"),
        cwd.join("openclaw.toml"),
        cwd.join("gateway.json"),
        cwd.join("gateway.toml"),
    ];

    for path in &gateway_configs {
        if !path.exists() {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(path) {
            let lower = content.to_lowercase();

            // Check for gateway bound to 0.0.0.0
            if lower.contains("0.0.0.0") {
                findings.push(ConfigFinding {
                    agent: leakwall_mcp::AgentType::ClaudeCode,
                    severity: Severity::Critical,
                    setting: "gateway bind address".into(),
                    current_value: "0.0.0.0".into(),
                    recommendation: format!(
                        "Gateway bound to 0.0.0.0 in {} — bind to 127.0.0.1 instead",
                        path.display()
                    ),
                });
            }

            // Check for authentication disabled
            if (lower.contains("\"auth\"") && lower.contains("false"))
                || lower.contains("auth_enabled = false")
                || lower.contains("\"authentication\": false")
            {
                findings.push(ConfigFinding {
                    agent: leakwall_mcp::AgentType::ClaudeCode,
                    severity: Severity::Critical,
                    setting: "gateway authentication".into(),
                    current_value: "disabled".into(),
                    recommendation: format!(
                        "Authentication disabled in {} — enable authentication",
                        path.display()
                    ),
                });
            }

            // Check for default passwords
            let default_passwords = ["password", "admin", "changeme", "default", "12345", "test"];
            for pwd in &default_passwords {
                if lower.contains(&format!("\"password\": \"{pwd}\""))
                    || lower.contains(&format!("password = \"{pwd}\""))
                {
                    findings.push(ConfigFinding {
                        agent: leakwall_mcp::AgentType::ClaudeCode,
                        severity: Severity::Critical,
                        setting: "gateway password".into(),
                        current_value: format!("default password '{pwd}'"),
                        recommendation: format!(
                            "Default password detected in {} — use a strong password",
                            path.display()
                        ),
                    });
                    break;
                }
            }
        }
    }
}

fn generate_recommendations(exposure: &ExposureCheck, results: &[McpAuditResult]) -> Vec<String> {
    let mut recs = Vec::new();

    // Unsafe servers
    for result in results {
        if result.verdict == Verdict::Unsafe {
            recs.push(format!(
                "Remove {} or upgrade to patched version",
                result.identity.name
            ));
        }
    }

    // Servers with dangerous commands
    for result in results {
        let has_dangerous_cmd = result.command_findings.iter().any(|f| {
            f.finding_type == FindingType::DangerousCommand && f.severity >= Severity::High
        });
        if has_dangerous_cmd && result.verdict != Verdict::Unsafe {
            recs.push(format!(
                "Review command configuration for MCP server '{}'",
                result.identity.name
            ));
        }
    }

    // Exposure
    if !exposure.claudeignore_blocks_env {
        recs.push("Add .env patterns to .claudeignore".into());
    }
    if exposure.claude_deny_rules.is_empty() {
        recs.push("Set deny rules in Claude Code settings.json".into());
    }

    // Hash changes
    for result in results {
        for change in &result.hash_changes {
            if change.change_type == HashChangeType::Modified {
                recs.push(format!(
                    "Investigate modified tool definition in {}",
                    result.identity.name
                ));
            }
        }
    }

    // Always recommend runtime protection
    recs.push("Run `leakwall run -- <agent-command>` for runtime protection".into());

    recs
}

fn build_json_report(
    score: i32,
    risk: &str,
    exposure: &ExposureCheck,
    results: &[McpAuditResult],
    config_findings: &[ConfigFinding],
) -> serde_json::Value {
    // Build per-server command analysis summaries
    let command_analysis: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| !r.command_findings.is_empty())
        .map(|r| {
            serde_json::json!({
                "server": r.identity.name,
                "findings": r.command_findings,
            })
        })
        .collect();

    serde_json::json!({
        "score": score,
        "risk_level": risk,
        "timestamp": Utc::now().to_rfc3339(),
        "exposure": exposure,
        "mcp_audits": results,
        "command_analysis": command_analysis,
        "config_findings": config_findings,
    })
}

/// Silently sync bundled security data to ~/.leakwall at scan start.
/// Errors are debug-logged and never fail the scan.
async fn sync_security_data(lw_dir: &std::path::Path, force_refresh: bool) {
    // 1. Sync CVE database from bundled data
    let cve_dest = lw_dir.join("cve_cache.json");
    for src in &["data/cve_cache.json"] {
        let src = std::path::Path::new(src);
        if src.exists() {
            if let Err(e) = std::fs::copy(src, &cve_dest) {
                tracing::debug!("CVE sync skipped: {e}");
            }
            break;
        }
    }

    // 2. Sync secret patterns from bundled data
    let patterns_dest = lw_dir.join("patterns.toml");
    for src in &["data/patterns.toml"] {
        let src = std::path::Path::new(src);
        if src.exists() {
            if let Ok(bundled) = std::fs::read_to_string(src) {
                let needs_update = std::fs::read_to_string(&patterns_dest)
                    .map(|current| current != bundled)
                    .unwrap_or(true);
                if needs_update {
                    let _ = std::fs::write(&patterns_dest, &bundled);
                }
            }
            break;
        }
    }

    // 3. Force-refresh AgentAudit catalog if --refresh (otherwise lazy 24h TTL handles it)
    if force_refresh {
        if let Err(e) = leakwall_mcp::registry::fetch_and_cache_catalog().await {
            tracing::debug!("catalog refresh skipped: {e}");
        }
    }
}

fn print_skill_analysis(analysis: &leakwall_skills::SkillAnalysis) {
    let path_str = analysis.path.display().to_string();
    let scope_str = format!("[{}]", analysis.scope);

    if analysis.findings.is_empty() {
        println!("  {} {scope_str}", path_str.dimmed());
        println!("  └─ Verdict: {}", "SAFE ✅".green());
    } else {
        println!("  {} {scope_str}", path_str.bold());
        let has_critical = analysis
            .findings
            .iter()
            .any(|f| f.severity >= leakwall_skills::Severity::Critical);

        for finding in &analysis.findings {
            let icon = match finding.severity {
                leakwall_skills::Severity::Critical => "🔴",
                leakwall_skills::Severity::High => "⚠️ ",
                leakwall_skills::Severity::Medium => "🟡",
                _ => "ℹ️ ",
            };
            println!(
                "  ├─ {icon} {} (line {})",
                finding.detail, finding.line_number
            );
        }

        let verdict = if has_critical {
            "MALICIOUS 🔴".red().to_string()
        } else {
            "REVIEW REQUIRED ⚠️".yellow().to_string()
        };
        println!("  └─ Verdict: {verdict}");
    }
    println!();
}
