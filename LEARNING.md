# Aegis Learning Guide

## What Is Aegis?

Aegis is a security tool for developers who use AI coding agents. It's a single program you install on your machine — no cloud accounts, no subscriptions, no telemetry. Everything runs locally.

It answers one question: **"Is my AI agent leaking my secrets?"**

When you use tools like Claude Code, Cursor, Codex, Aider, or Windsurf, those AI agents can read your API keys, database passwords, and cloud credentials from your files. They then send HTTP requests to external APIs (Anthropic, OpenAI, etc.) to do their work. Aegis sits between your agent and the internet, watching every request for leaked secrets, and can warn you, redact the secrets, or block the request entirely.

---

## The Problem

AI coding agents have broad access to your machine. They can read `.env` files, access `~/.aws/credentials`, browse your filesystem, and make HTTP requests. This creates three ways your secrets can leak:

1. **Secret exfiltration** -- An agent (or a compromised tool it uses) can embed your API keys, passwords, and tokens into outbound API requests, either accidentally or because it was tricked.
2. **MCP tool poisoning** -- MCP (Model Context Protocol) servers give agents extra capabilities (like reading databases or running shell commands). A malicious MCP server can inject hidden instructions into its tool descriptions that trick agents into leaking your data.
3. **Configuration misuse** -- Dangerous settings like `autoApprove: ["Bash(*)"]` remove human oversight entirely, letting agents run any shell command without asking.

### Real-World Incidents

| Incident | What Happened |
|----------|---------------|
| CVE-2025-59536 / CVE-2026-21852 | Check Point found exploitable vulnerabilities in Claude Code (Feb 2026) |
| Knostic / The Register (Jan 2026) | `.claudeignore` doesn't actually block `.env` access -- Claude auto-loads secrets |
| OpenClaw/Clawdbot (Jan 2026) | Thousands of API keys leaked via exposed gateways with default passwords |
| Cisco research | 26% of 31,000 agent skills contain at least one vulnerability |
| AgentAudit (Feb 2026) | 118 security findings across 68 MCP packages |
| BlueRock research | 36.7% of MCP servers are vulnerable to SSRF |
| CVE-2025-68145/68143/68144 | Anthropic's own `mcp-server-git` has a remote code execution chain |
| Supabase/Cursor | Agent leaked integration tokens via SQL injection in support tickets |

---

## What Can Aegis Do?

Aegis has four commands, each covering a different layer of protection:

```
aegis scan     Audit MCP servers, configs, and security posture
aegis run      Real-time HTTPS proxy that catches secrets in flight
aegis watch    Background daemon that monitors files for changes
aegis report   Generate HTML/SARIF/JSON reports from scan results
```

Think of it as layers:

```
[scan]  Find problems before they happen
[run]   Catch leaks in real-time while you work
[watch] Monitor for changes when you're not looking
[report] Document everything for your team or CI/CD
```

---

## Command 1: `aegis scan`

**What it does in plain terms:** Looks at every MCP server your AI agents are configured to use, connects to each one, examines every tool it offers, and checks whether any of them are malicious, vulnerable, or misconfigured. Also checks whether your secrets are properly protected.

### What It Checks

#### 1. Secrets Exposure

Are your secrets adequately protected?
- Does `.claudeignore` list `.env`?
- Does `.gitignore` list `.env`?
- Does Claude Code have `deny` rules configured?
- Are secret-bearing environment variables exposed?
- Are there plaintext secrets in non-gitignored config files?

#### 2. MCP Server Discovery

Automatically finds MCP configs across 7 AI agent types:

| Agent | Config Locations |
|-------|-----------------|
| Claude Desktop | OS-specific app data paths |
| Claude Code | `~/.claude/settings.json`, `./.mcp.json`, `./.claude/settings.json` |
| Cursor | `~/.cursor/mcp.json`, `./.cursor/mcp.json` |
| VS Code | `~/.vscode/mcp.json`, `./.vscode/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Continue.dev | `~/.continue/config.json` |

#### 3. Tool Poisoning Detection

Connects to each MCP server, lists its tools, and scans every tool's name, description, and input schema for malicious content:

**Injection patterns (45+ patterns):**
- Direct instructions: `also read`, `also send`, `forward to`, `ignore previous`, `override`
- File access: `~/.ssh`, `~/.env`, `~/.aws`, `/etc/passwd`, `.credentials`
- Exfiltration commands: `curl`, `wget`, `nc`, `netcat`, `base64 -`
- Hidden markers: `<IMPORTANT>`, `<SYSTEM>`, `exfiltrate`, `steal`

**Unicode obfuscation:** Characters that are invisible but can hide malicious instructions:
- Zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
- RTL/LTR overrides (U+202A - U+202E) -- can make text visually appear different from what it actually says
- Tag characters (U+E0001 - U+E007F) -- invisible Unicode tags

**Dangerous capabilities:**
- Shell access (`exec`, `shell`, `bash`, `run_command`)
- Unrestricted file access (`read_file`, `write_file`, `filesystem`)
- Network access (`http_request`, `fetch`, `download`, `webhook`)

#### 4. External Registry Cross-Reference

Queries three security databases in parallel (5s timeout each):

| Source | What It Returns |
|--------|----------------|
| **AgentAudit** (api.agentaudit.dev) | Trust score (0-100), security findings |
| **MCP Trust** (api.mcp-trust.com) | Risk level (Low/Medium/High/Critical), vulnerabilities |
| **CVE Database** (bundled) | Known CVEs matched by package name and version |

Results are cached for 24 hours. Use `--refresh` to bypass cache.

#### 5. Hash Pinning (Rug Pull Detection)

Every tool definition is SHA-256 hashed and stored in `~/.aegis/tool_hashes.json`. On subsequent scans, if a tool's hash changes, it's flagged as a potential **rug pull** -- where a previously trusted tool silently changes its behavior (e.g., a benign "read file" tool suddenly starts exfiltrating data).

#### 6. Skill File Analysis

Scans AI agent instruction files (Markdown/YAML/TOML "skills" that tell agents how to behave) for dangerous content:

- **Shell commands** -- detects `rm -rf`, `curl`, `wget`, `sudo`, `eval`, `nc`, reverse shell patterns
- **External URLs** -- flags outbound URLs (excluding localhost)
- **Sensitive file references** -- `~/.ssh`, `~/.aws`, `/etc/shadow`, `~/.git-credentials`
- **Base64 obfuscation** -- decodes base64 blobs and checks if they contain dangerous commands hidden inside
- **Unicode tricks** -- zero-width chars, RTL overrides, invisible tag characters
- **Prompt injection** -- patterns like `ignore previous instructions`, `<IMPORTANT>`, `disregard`

Skill files are found in:
- `~/.claude/skills/` (global)
- `./.claude/skills/` (per-project)
- `~/.openclaw/skills/`
- `./.aider.conf.yml`

Each finding has a severity (Info/Low/Medium/High/Critical) and a complexity score based on the number of shell commands, URLs, and file references.

#### 7. Agent Configuration Audit

Checks for dangerous settings:
- `enableAllProjectMcpServers: true` in Claude Code (Critical)
- Missing `deny` rules (High)
- `autoApprove` containing `Bash(*)`, `shell(`, `exec(`, `execute(` (Critical)
- Gateway bound to `0.0.0.0` instead of `127.0.0.1` (Critical)
- Authentication disabled on gateways (Critical)
- Default passwords: `password`, `admin`, `changeme`, `default`, `12345` (Critical)

#### 8. Verdict and Scoring

Each MCP server gets a verdict:

| Verdict | Condition |
|---------|-----------|
| **Unsafe** | Any tool poisoning, any Critical finding, trust score < 40, or Critical/High risk level |
| **Suspicious** | Any tool definition hash change detected |
| **SafeWithAdvisory** | Any High severity finding |
| **Safe** | None of the above |

Overall score: starts at 100, deducts -20 per Critical, -10 per High, -5 per Medium, -1 per Low.

| Score | Risk Level |
|-------|------------|
| 80-100 | LOW RISK |
| 50-79 | MODERATE RISK |
| 0-49 | HIGH RISK |

### Usage

```bash
aegis scan                    # Standard scan with cache
aegis scan --refresh          # Force fresh registry lookups
aegis scan --json report.json # Save additional JSON copy
aegis scan --trust-project    # Trust project-scoped MCP servers
```

---

## Command 2: `aegis run`

**What it does in plain terms:** Wraps any AI agent command with an invisible HTTPS proxy. Every API call the agent makes passes through Aegis first. Aegis decrypts the traffic, scans it for your secrets, takes action (warn/redact/block), then forwards it to the real API server. You see everything happening in a live terminal dashboard.

### How It Works (Step by Step)

```
Your Agent (Claude Code, Cursor, etc.)
    |
    | HTTP CONNECT (encrypted)
    v
Aegis Proxy (127.0.0.1:9090)
    |
    | Decrypt --> Scan body for secrets --> Apply action
    v
Real API (api.anthropic.com, api.openai.com, etc.)
```

1. Aegis generates a local CA certificate (`~/.aegis/ca.pem`) -- this is what lets it decrypt HTTPS traffic
2. Starts an HTTPS proxy on `127.0.0.1:9090` (or a custom port with `-p`)
3. Waits for the proxy to confirm it's ready (if the port is already in use, it exits with a clear error instead of spawning your agent with a broken proxy)
4. Spawns your agent with proxy environment variables set (`HTTPS_PROXY`, `SSL_CERT_FILE`, etc.)
5. Intercepts CONNECT tunnels to AI API domains only
6. Generates per-host TLS certificates signed by the Aegis CA
7. Decrypts, scans, and re-encrypts traffic
8. Displays a live terminal dashboard (or writes a JSONL log in headless mode)

### What "MITM Proxy" Means

MITM stands for "man-in-the-middle." Normally when your agent talks to `api.anthropic.com` over HTTPS, the traffic is encrypted end-to-end -- nobody can read it. Aegis creates its own certificate authority (CA), generates fake certificates for each API domain, and presents those to your agent. Your agent trusts them because Aegis sets environment variables pointing to its CA. This lets Aegis decrypt the traffic, scan it, then re-encrypt and forward it. It's the same technique corporate firewalls use, but running locally and only targeting AI API domains.

### Intercepted Domains

Only these 9 AI API domains are decrypted and scanned:

| Domain | Service |
|--------|---------|
| api.anthropic.com | Claude API |
| api.openai.com | OpenAI API |
| api.groq.com | Groq |
| api.mistral.ai | Mistral |
| api.together.xyz | Together AI |
| api.fireworks.ai | Fireworks AI |
| generativelanguage.googleapis.com | Google Gemini |
| api.cohere.com | Cohere |
| api.deepseek.com | DeepSeek |

All other HTTPS traffic (GitHub, npm, pip, etc.) passes through untouched as a raw TCP relay -- Aegis never sees that data.

### How Secrets Are Found

Aegis uses a two-layer scanning engine:

**Layer 1 -- Known Secrets (Aho-Corasick):**

At startup, Aegis scans your machine for actual secret values:
- `.env`, `.env.local`, `.env.production` files (in your project and home directory)
- Cloud credentials: `~/.aws/credentials`, `~/.azure/credentials`, GCP configs
- SSH keys (warns only), `.npmrc`, `.docker/config.json`, `.kube/config`, `.netrc`, `.pypirc`, `.git-credentials`
- Shell environment variables (excluding safe ones like `PATH`, `HOME`, `SHELL`, etc.)

Every secret value 4+ characters long gets "fingerprinted" -- Aegis creates multiple encoded versions (raw, URL-encoded, base64, JSON-escaped, prefix/suffix for long values) and builds a fast string-matching automaton (Aho-Corasick). This can scan at ~2 GB/s and finds your exact secrets even if they've been encoded.

**Layer 2 -- Pattern Matching (17 Regex Patterns):**

Even if Aegis doesn't know your exact secret values, it recognizes secret formats:

| Pattern | What It Matches | Severity |
|---------|----------------|----------|
| AWS Access Key | `AKIA...` (20 chars) | Critical |
| AWS Secret Key | 40-char alphanumeric with AWS context | Critical |
| GitHub PAT (classic) | `ghp_...` | Critical |
| GitHub PAT (fine-grained) | `github_pat_...` | Critical |
| Stripe Live Key | `sk_live_...` | Critical |
| Stripe Test Key | `sk_test_...` | Medium |
| Slack Bot Token | `xoxb-...` | Critical |
| OpenAI API Key | `sk-...T3BlbkFJ...` | Critical |
| Anthropic API Key | `sk-ant-...` (90+ chars) | Critical |
| Google API Key | `AIza...` | High |
| npm Token | `npm_...` | High |
| JWT Token | `eyJ...eyJ...` | High |
| Private Key | `-----BEGIN ... PRIVATE KEY-----` | Critical |
| Database URL | `postgres://`, `mysql://` with credentials | Critical |
| Bearer Token | `Bearer ...` (long tokens) | Medium |

### JSON-Aware Scanning

API request bodies are JSON. Aegis doesn't scan the raw JSON text (which would break escape sequences). Instead, it:
1. Parses the JSON
2. Extracts each string value
3. Scans each string individually
4. If redacting, replaces the secret in the string value and re-serializes valid JSON

This means redacted requests are always valid JSON -- the API on the other end won't get a broken request.

### Thinking Block Safety

When Claude's API returns "thinking" blocks (signed content that proves the model actually generated it), Aegis strips those before scanning. This prevents redaction from breaking Claude's cryptographic signatures on thinking blocks, which would cause the API to reject the request.

### Three Protection Modes

| Mode | What Happens When a Secret Is Found |
|------|-------------------------------------|
| **Warn** (default) | Logs the detection, forwards the request unchanged. You see it in the dashboard. |
| **Redact** | Replaces secrets with `[AEGIS:pattern_name:REDACTED]` markers, forwards the modified request. The API call still works but without your secret. |
| **Block** | Drops the entire request and returns HTTP 403 to the agent. The API call fails. |

Mode can be changed at runtime by pressing `m` in the dashboard.

### SSE Streaming Support

LLM APIs return responses as Server-Sent Events (SSE) -- a streaming format where data arrives in small chunks. Aegis handles this natively:
- Parses each SSE event as it arrives
- Scans the `data` field of each chunk for secrets
- Uses JSON-aware scanning even for SSE chunks
- Forwards chunks without buffering (no latency impact)

### Behavioral Anomaly Detection

Beyond pattern matching, Aegis tracks the behavior of your agent's API calls and flags anomalies:

- **New Destination** -- After a warmup period (10+ requests), a request to a never-before-seen API host is flagged. This catches agents suddenly talking to unexpected servers.
- **Volume Spike** -- If a request body is more than 3x the average size (and over 10 KB), it's flagged. Large payloads could mean an agent is dumping your entire codebase.
- **High Entropy Payload** -- Detects credential-shaped data using Shannon entropy analysis (threshold: 4.5 bits/byte). Strings that are 16-512 chars, have mixed case + digits + special chars, and high randomness are likely secrets.
- **Known Credential Prefixes** -- Recognizes `sk_`, `ghp_`, `AKIA`, `sk-ant-`, `xoxb-`, `eyJ` (JWT), `Bearer`, `Basic` and similar prefixes regardless of entropy.

### Allowlist System

Not every secret in an API request is a leak. Your Anthropic API key *should* be sent to `api.anthropic.com`. Aegis has an allowlist system:

**Automatic provider mapping (on by default):**
- `anthropic_api_key` is expected at `api.anthropic.com`
- `openai_api_key` is expected at `api.openai.com`
- `stripe_live` is expected at `api.stripe.com`
- `github_pat` is expected at `api.github.com`

**Custom rules** can be added for your own API keys and services, with wildcard domain support (`*.stripe.com`).

### Live Dashboard

```
+------------------------------------------------------------------+
| aegis run -- claude                                              |
| Mode: WARN  |  Elapsed: 05:32  |  Requests: 47                 |
+------------------------------------------------------------------+
| 14:23:01  [OK]      POST api.anthropic.com/v1/messages           |
| 14:23:05  [OK]      POST api.anthropic.com/v1/messages           |
| 14:23:12  [WARNED]  POST api.openai.com/v1/chat/completions     |
|           ^ aws_access_key detected -- warned                    |
| 14:23:15  [BLOCKED] POST api.anthropic.com/v1/messages           |
|           ^ github_pat, stripe_live detected -- blocked          |
+------------------------------------------------------------------+
| Caught: 3  |  Warned: 1  |  Scanned: 2.4 MB                    |
+------------------------------------------------------------------+
| [q] quit  [m] mode  [up/down] scroll                            |
+------------------------------------------------------------------+
```

**Keyboard controls:** `q` quit, `m` cycle mode, arrow keys scroll.

### Headless Mode

For CI/CD or when you don't want a TUI (e.g., wrapping an agent that uses the terminal itself):

```bash
aegis run -H -- claude    # Headless mode
```

- Suppresses all non-error output to avoid corrupting the child process's terminal
- Writes JSONL event log to `~/.aegis/logs/live.log`
- Monitor in real-time from another terminal: `tail -f ~/.aegis/logs/live.log`

### Stdio Interception (MCP Server Monitoring)

Some MCP servers communicate over stdin/stdout instead of HTTP. Aegis can intercept these too:
- Spawns the MCP server process with piped stdio
- Parses every line as JSON-RPC 2.0
- Scans all messages for secrets using the same two-layer scanner
- Emits events: `SecretDetected`, `ToolCall`, `ServerStarted`, `ServerExited`
- Has a 10 MB per-line safety limit to prevent memory exhaustion from malformed servers

### Port Conflict Handling

If you try to run a second `aegis run` while one is already running on the same port:
- Aegis detects the port is in use **before** spawning your agent
- Exits immediately with a clear error: `port 9090 already in use — another aegis instance may be running. Use -p to pick a different port.`
- Your agent is never started with a misconfigured proxy (which would cause authentication errors)

### Session Reports

On exit, Aegis prints a summary and saves a JSON report containing:
- Agent command and PID
- Session duration
- Total requests and bytes scanned
- Every detected secret (pattern name, count, action taken)

### Usage

```bash
aegis run -- claude                        # Wrap Claude Code in warn mode
aegis run -m redact -- cursor              # Redact secrets from Cursor traffic
aegis run -m block -p 8080 -- aider        # Block mode on port 8080
aegis run -H -- claude                     # Headless mode (no TUI)
aegis run -- npx @anthropic/claude-code    # Works with any command
```

---

## Command 3: `aegis watch`

**What it does in plain terms:** Runs in the background and watches your filesystem for security-relevant changes. If someone (or something) modifies your MCP configs, changes a skill file, or touches a secret file, Aegis notices and can send you a desktop notification.

### What It Monitors

- **MCP config files** -- Detects when servers are added, removed, or modified in any of the 7 agent config locations
- **Tool definition hashes** -- Watches `~/.aegis/tool_hashes.json` for rug pull detection
- **Skill files** -- Monitors `~/.claude/skills/` and `./.claude/skills/` for changes
- **Secret files** -- `.env`, `.env.local`, `.env.production`, `~/.aws/credentials`
- **Agent configs** -- Watches for weakened security settings (e.g., someone adding `autoApprove`)

### How It Works

- Uses OS-level filesystem notifications (`inotify` on Linux, `FSEvents` on macOS) via the `notify` crate
- Events are debounced with a 2-second window (multiple rapid changes become one event)
- Communicates with the CLI over a Unix domain socket (`~/.aegis/aegis.sock`) using JSON messages
- PID file with file locking prevents duplicate daemon instances
- Desktop notifications via `notify-rust`, rate-limited to one per event type per 5 minutes (critical events bypass this)

### Usage

```bash
aegis watch --daemon        # Start as background daemon
aegis watch --foreground    # Run in foreground (useful for debugging)
aegis watch --status        # Check if daemon is running, see event count
aegis watch --stop          # Stop the running daemon
```

---

## Command 4: `aegis report`

**What it does in plain terms:** Takes the scan results Aegis has collected and generates reports in different formats -- HTML for humans, SARIF for CI/CD tools, JSON for scripts.

### Output Formats

**HTML Report:**
- Self-contained HTML file with embedded CSS
- Visual security score (green/yellow/red)
- Detailed findings table with severity, description, and remediation
- Session summaries if proxy data is available
- Saved to `~/.aegis/reports/report-YYYY-MM-DD.html`

**SARIF 2.1.0:**
- Standard format used by GitHub Code Scanning, VS Code, and other security tools
- Severity mapping: Critical/High = error, Medium = warning, Low/Info = note
- Can be uploaded to GitHub to show findings directly in pull request diffs

**JSON:**
- Machine-readable format for scripting and automation
- Includes all findings with severity, type, source, detail, and remediation

### Trend Analysis

If you have multiple scan reports, Aegis can compare them:
- **Improving** -- Score went up since last scan
- **Stable** -- Score unchanged
- **Worsening** -- Score went down
- **Insufficient** -- Need at least 2 reports to compare

### Cost Estimation

Aegis can estimate how much your AI agent sessions cost by analyzing intercepted API traffic:
- Extracts token counts from response headers (`x-usage-input-tokens`) or response JSON bodies
- Falls back to `body_bytes / 4` as a rough token estimate
- Applies provider-specific pricing (Claude, GPT-4, etc.)

### Usage

```bash
aegis report                      # Print JSON to stdout
aegis report --html               # Generate HTML report
aegis report --html --open        # Generate and open in browser
aegis report --format sarif       # SARIF for CI/CD
aegis report --format json        # JSON for scripting
```

---

## Configuration

Aegis loads config from `./aegis.toml` (project) or `~/.aegis/config.toml` (global). CLI flags override config file values.

```toml
proxy_port = 9090
mode = "WarnOnly"        # "WarnOnly", "Redact", or "Block"

[mcp_scan]
enabled = true
connect_timeout_secs = 10

[registry]
enabled = true
cache_ttl_hours = 24
```

---

## Architecture

Ten Rust crates in a Cargo workspace:

```
aegis-cli (binary: "aegis")
  |
  +-- aegis-secrets      Secret discovery, fingerprints, Aho-Corasick + regex scanner
  |
  +-- aegis-mcp          MCP config discovery, tool poisoning, registry queries, CVE matching
  |
  +-- aegis-proxy        MITM TLS proxy, CA cert gen, request interception, redaction
  |     +-- aegis-secrets
  |
  +-- aegis-tui          ratatui dashboard, event stream, session reports
  |     +-- aegis-proxy
  |
  +-- aegis-skills       Skill file discovery and static analysis
  |
  +-- aegis-watch        Filesystem monitoring daemon, IPC, desktop notifications
  |     +-- aegis-mcp, aegis-secrets, aegis-skills
  |
  +-- aegis-behavior     Behavioral anomaly detection, data-shape classification, allowlists
  |
  +-- aegis-report       HTML/SARIF/JSON report generation, trend analysis, cost estimation
  |
  +-- aegis-stdio        Stdio interception for MCP servers, JSON-RPC parsing, secret scanning
```

### Key Design Choices

- **`tokio` async runtime** with `spawn_blocking` for CPU-heavy work (regex scanning, Aho-Corasick matching)
- **`bytes::Bytes`** for zero-copy data handling in the proxy hot path
- **`broadcast::channel`** for fanning events from the proxy to the TUI and log consumers
- **`DashMap`** for concurrent in-memory TLS certificate caching
- **`Arc<RwLock<ScanMode>>`** for changing protection mode at runtime without restarting
- **No `unsafe` code** anywhere in the codebase
- **`thiserror`** for typed errors in library crates, **`anyhow`** for ergonomic errors in the CLI binary
- **`subtle::ConstantTimeEq`** for timing-attack-resistant proxy auth comparison
- **`fs2`** file locking for PID files and hash pin storage (prevents race conditions)
- **`semver`** for proper semantic version comparison in CVE matching

### Security Hardening

The codebase has been through a 28-point security audit. Key protections:

- Constant-time proxy authentication (prevents timing attacks)
- Oversized body blocking (413 error instead of silently forwarding unscanned bodies)
- Private/RFC1918 address blocking on passthrough tunnels (prevents SSRF)
- File locking for PID files and shared state (prevents race conditions)
- IPC message size limits (1 MB) and pipe line limits (10 MB) (prevents memory exhaustion)
- Symlink traversal prevention in file discovery (prevents path traversal attacks)
- UTF-8 boundary-safe string slicing throughout (prevents panics on multi-byte characters)
- No `unwrap()` or `expect()` in library code (only in tests)
- CA private key permissions enforced (chmod 600 on Unix)

---

## Files Aegis Creates

| Path | Created By | Purpose |
|------|-----------|---------|
| `~/.aegis/ca.pem` | `aegis run` | Local CA certificate (1-year validity, ECDSA P-256) |
| `~/.aegis/ca-key.pem` | `aegis run` | CA private key (chmod 600) |
| `~/.aegis/ca-bundle.pem` | `aegis run` | Combined system CAs + Aegis CA |
| `~/.aegis/tool_hashes.json` | `aegis scan` | SHA-256 hashes of MCP tool definitions |
| `~/.aegis/registry_cache.json` | `aegis scan` | Cached registry lookup results (24h TTL) |
| `~/.aegis/reports/scan-*.json` | `aegis scan` | JSON scan reports |
| `~/.aegis/reports/report-*.html` | `aegis report` | HTML reports |
| `~/.aegis/logs/session-*.json` | `aegis run` | JSON session logs |
| `~/.aegis/logs/live.log` | `aegis run -H` | JSONL event log (headless mode) |
| `~/.aegis/aegis.pid` | `aegis watch` | Daemon PID file (with file lock) |
| `~/.aegis/aegis.sock` | `aegis watch` | Unix domain socket for IPC |
| `~/.aegis/daemon.log` | `aegis watch` | Daemon log file |

---

## Typical Workflow

```bash
# Step 1: Audit your MCP servers and agent configs
aegis scan

# Step 2: Fix any Critical/High findings from the scan report

# Step 3: Start the background watcher (optional)
aegis watch --daemon

# Step 4: Run your AI agent with protection
aegis run -- claude

# Step 5: Review the session report after your coding session
aegis report --html --open

# Step 6: For CI/CD, generate SARIF output
aegis report --format sarif > results.sarif
```

---

## Glossary

| Term | Meaning |
|------|---------|
| **MCP** | Model Context Protocol -- a standard for giving AI agents access to tools (databases, APIs, shell, etc.) |
| **MITM** | Man-in-the-middle -- intercepting encrypted traffic by presenting a trusted fake certificate |
| **CA** | Certificate Authority -- the entity that signs TLS certificates. Aegis creates a local one. |
| **Aho-Corasick** | A fast string-matching algorithm that can search for thousands of patterns simultaneously in one pass |
| **SSE** | Server-Sent Events -- a streaming protocol used by LLM APIs to send responses in chunks |
| **SARIF** | Static Analysis Results Interchange Format -- a JSON standard for reporting security findings |
| **Rug pull** | When a previously trusted tool silently changes its behavior to become malicious |
| **Shannon entropy** | A measure of randomness in data. Secrets (random strings) have high entropy; natural text has low entropy. |
| **JSON-RPC** | A protocol for remote procedure calls using JSON. MCP stdio servers use this to communicate. |
| **Fingerprint** | Multiple encoded versions of a secret (raw, base64, URL-encoded, etc.) used for matching |

---

## What Makes Aegis Different

| | Snyk mcp-scan | Cisco MCP Scanner | LLM Guard | AgentAudit | **Aegis** |
|---|---|---|---|---|---|
| MCP static scan | Yes | Yes | No | Yes | **Yes** |
| Registry cross-ref | Partial | Partial | No | Own DB | **Yes (3 sources)** |
| Secret exposure audit | No | No | No | No | **Yes** |
| Runtime network protection | No | No | Partial | No | **Yes** |
| Secret exfil blocking | No | No | No | No | **Yes** |
| Rug pull detection | Yes | No | No | Yes | **Yes** |
| Skill file analysis | No | No | No | No | **Yes** |
| Behavioral anomaly detection | No | No | No | No | **Yes** |
| Stdio MCP monitoring | No | No | No | No | **Yes** |
| File change watching | No | No | No | No | **Yes** |
| SARIF/HTML reporting | No | No | No | No | **Yes** |
| Cost estimation | No | No | No | No | **Yes** |
| Single binary, offline | No (Python) | No (Python) | No (Python) | No (Node) | **Yes (Rust)** |

Aegis is the only tool that **scans, protects, monitors, and reports** in a single binary, works fully offline, and requires zero external dependencies.
