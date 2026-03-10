# LeakWall — AI Agent Security Platform

## Project Overview

LeakWall is a single Rust binary that protects developers from AI coding agent security failures. It provides four commands:
- `leakwall scan` — audit MCP servers, skill files, configs, and cross-reference external registries
- `leakwall run` — runtime HTTPS MITM proxy with live TUI dashboard or headless JSONL logging
- `leakwall watch` — background daemon monitoring filesystem for security-relevant changes
- `leakwall report` — generate HTML/SARIF/JSON reports from scan results

## Build & Test Commands

```bash
cargo build                       # Debug build
cargo test                        # Run all 156 unit tests
cargo clippy -- -D warnings       # Lint (zero warnings enforced)
cargo fmt --check                 # Verify formatting
cargo build --release             # Optimized release binary
cargo install --path crates/leakwall-cli  # Install to ~/.cargo/bin
```

All four checks must pass before committing. Run `cargo fmt` to auto-fix formatting.

## Architecture

Ten crates in a Cargo workspace (`crates/*`):

```
leakwall-cli (binary: "leakwall")
├── leakwall-secrets    — secret discovery, fingerprinting, Aho-Corasick + regex scanning
├── leakwall-mcp        — MCP config discovery, tool poisoning detection, AgentAudit registry queries, CVE matching
├── leakwall-proxy      — MITM TLS proxy (hyper + rustls), CA cert gen, request interception, redaction
│   └── leakwall-secrets
├── leakwall-tui        — ratatui dashboard, event stream, session/scan reports
│   └── leakwall-proxy
├── leakwall-skills     — skill file discovery and static security analysis
├── leakwall-watch      — filesystem monitoring daemon, IPC, desktop notifications
│   ├── leakwall-mcp
│   ├── leakwall-secrets
│   └── leakwall-skills
├── leakwall-behavior   — behavioral anomaly detection, data-shape classification, allowlists
├── leakwall-report     — HTML/SARIF/JSON report generation, trend analysis, cost estimation
└── leakwall-stdio      — stdio interception for MCP servers, JSON-RPC parsing, secret scanning
```

## Key Conventions

### Error Handling
- **Library crates**: `thiserror` enums (`SecretError`, `ProxyError`, `McpError`, `TuiError`, `SkillsError`, `WatchError`, `BehaviorError`, `ReportError`, `StdioError`)
- **CLI binary**: `anyhow::Result` with `.context()` for human-readable messages
- **No `unwrap()` or `expect()` in library code** — only in tests and `main.rs`

### Async
- `tokio` runtime, `#[tokio::main]` only on the binary crate
- `spawn_blocking` for CPU-intensive work (Aho-Corasick scanning, regex matching)
- `broadcast::channel` for proxy → TUI event fan-out and stdio → event fan-out
- `Arc<RwLock<T>>` for shared mutable state, `DashMap` for cert cache
- `oneshot::channel` for proxy bind readiness signaling

### Security
- `subtle::ConstantTimeEq` for proxy auth comparison (prevents timing attacks)
- `fs2::FileExt` for file locking on PID files, hash pins, and cache files
- `semver` for proper semantic version comparison in CVE matching
- `std::sync::OnceLock` for infallible lazy regex compilation (no `expect()`)
- No `unsafe` code anywhere
- CA private key permissions enforced (chmod 600 on Unix)
- IPC message size limit: 1 MB; pipe line size limit: 10 MB
- Symlink traversal prevention: `follow_links(false)` on WalkDir
- Private/RFC1918 address blocking on passthrough tunnels
- Oversized request bodies return 413 instead of forwarding unscanned
- UTF-8 boundary-safe string slicing throughout (use `char_indices()` or `.get()`, never `&s[..n]`)
- Strip `proxy-authorization` header from forwarded requests (prevents auth token leaking upstream)
- No `as u32`/`as u16` narrowing casts — use `u32::try_from(val).unwrap_or(u32::MAX)` to prevent silent truncation
- Percent-encode all URI-special characters (`%` first, then `#`, `?`, space, `\`) in generated URIs

### Correctness
- Async file writes must be flushed after each write for real-time log consumers (`tail -f`)
- IPC command handlers must trigger the actual operation, not just return acknowledgement
- Deletion/removal detection: iterate the stored/old state to find missing items, not just the current state
- Don't run state-comparison logic on empty/default inputs (e.g., skip hash pin check when tool list is empty due to `--no-exec`)
- Guard math functions against degenerate inputs (empty data → early return 0.0, avoid NaN/Inf)
- After case-folding, use the folded string's `.len()` for byte offset calculations, not the original

### Code Style
- `.rustfmt.toml`: max_width=100, field_init_shorthand, try_shorthand
- `#[instrument]` on async functions, `tracing::{debug, info, warn}` for logging
- `bytes::Bytes` in the proxy hot path (zero-copy via Arc)

## Directory Layout

```
crates/
  leakwall-cli/src/        main.rs, cmd_scan.rs, cmd_run.rs, cmd_watch.rs, cmd_report.rs, config.rs
  leakwall-secrets/src/    lib.rs, discovery.rs, patterns.rs, fingerprint.rs, scanner.rs
  leakwall-mcp/src/        lib.rs, discover.rs, connect.rs, analyze.rs, registry.rs, cve.rs, hashpin.rs, cross_origin.rs, command_analysis.rs
  leakwall-proxy/src/      lib.rs, proxy.rs, ca.rs, intercept.rs, stream.rs, redact.rs, process.rs
  leakwall-tui/src/        lib.rs, dashboard.rs, events.rs, report.rs
  leakwall-skills/src/     lib.rs, discover.rs, analyze.rs, parser.rs
  leakwall-watch/src/      lib.rs, daemon.rs, watcher.rs, mcp_monitor.rs, secret_monitor.rs, skills_monitor.rs, notifier.rs
  leakwall-behavior/src/   lib.rs, profile.rs, data_shape.rs, allowlist.rs
  leakwall-report/src/     lib.rs, json.rs, html.rs, sarif.rs, trend.rs, cost.rs
  leakwall-stdio/src/      lib.rs, jsonrpc.rs, pipe.rs
data/
  patterns.toml         17 regex patterns for secret detection
  cve_cache.json        Bundled CVE database
tests/fixtures/         Sample .env files, MCP configs, HTTP requests
```

## CLI Subcommands

- `leakwall scan [--refresh] [--json PATH] [--trust-project]` — audit MCP servers, skill files, exposure checks, output scored report
  Security data (CVE database, patterns, registry catalog) syncs automatically at scan start; `--refresh` forces a catalog re-fetch.
- `leakwall run [-m warn|redact|block] [-p PORT] [-T/--tui] -- <command>` — MITM proxy (headless by default, `--tui` for dashboard)
- `leakwall watch [--daemon|--foreground|--status|--stop] [--quiet]` — filesystem monitoring daemon
- `leakwall report [--html] [--open] [--format json|sarif]` — report generation

### Scan Modes (`-m`)
- **warn** — detect secrets, log them, forward request unchanged
- **redact** (default) — replace secrets with `[LEAKWALL:<pattern>:REDACTED]` markers, forward sanitized request
- **block** — return 403 and drop the entire request

### Headless Mode (default)
- Headless is the default — just run `leakwall run -- <command>`
- Suppresses all non-error tracing to avoid corrupting the child process terminal
- Writes JSONL event log to `~/.leakwall/logs/live.log`
- Monitor in real-time: `tail -f ~/.leakwall/logs/live.log`
- Use `-T` / `--tui` to launch the interactive TUI dashboard instead

## Proxy Architecture

### MITM TLS Flow
1. Child process connects via `HTTPS_PROXY` → LeakWall proxy on `127.0.0.1:PORT`
2. CONNECT tunnel with Basic auth (`leakwall:<random-token>`)
3. Proxy signals readiness via `oneshot` channel before child is spawned — if bind fails (port in use), child is never started
4. For intercepted domains (LLM APIs): MITM with LeakWall-signed host cert
5. For other domains: TCP passthrough (no inspection, private addresses blocked)
6. Intercepted requests: scan body → apply mode action → forward to real server

### Intercepted Domains
`api.anthropic.com`, `api.openai.com`, `api.groq.com`, `api.mistral.ai`, `api.together.xyz`, `api.fireworks.ai`, `generativelanguage.googleapis.com`, `api.cohere.com`, `api.deepseek.com`

### CA Certificate Chain
- CA generated at `~/.leakwall/ca.pem` + `~/.leakwall/ca-key.pem` (ECDSA P-256)
- Host certs signed by CA, cached in-memory via `DashMap`
- **Critical**: `generate_host_cert()` must reconstruct CA params with BOTH `CommonName` AND `OrganizationName` to match the stored CA's subject DN — otherwise cert chain verification fails with `UnknownIssuer`
- Combined CA bundle at `~/.leakwall/ca-bundle.pem` (system CAs + LeakWall CA)

### Child Process Environment
```
HTTPS_PROXY / HTTP_PROXY  = http://leakwall:<token>@127.0.0.1:<port>
NODE_EXTRA_CA_CERTS       = ~/.leakwall/ca.pem        (Node.js / Bun)
SSL_CERT_FILE             = ~/.leakwall/ca-bundle.pem  (OpenSSL)
REQUESTS_CA_BUNDLE        = ~/.leakwall/ca-bundle.pem  (Python)
CURL_CA_BUNDLE            = ~/.leakwall/ca-bundle.pem  (curl)
```

### Redaction Design
- **JSON-aware**: parses request body as JSON, scans each decoded string value individually, re-serializes — avoids breaking JSON escape sequences
- **Thinking block safety**: strips signed `{"type":"thinking"}` blocks before redaction to prevent Anthropic API signature invalidation
- **Content-Length**: stripped from forwarded headers; reqwest recalculates from actual body

## Secret Discovery

### Sources Scanned at Startup
- `.env*` files (cwd + home)
- Cloud credentials (`.aws/credentials`, `.azure/credentials`, GCP)
- SSH keys (warn only), `.npmrc`, `.docker/config.json`, `.kube/config`, `.netrc`, `.pypirc`, `.git-credentials`
- Shell environment variables (excluding `PATH`, `HOME`, `SHELL`, ~30 additional non-secret prefixes)

### Fingerprinting
- **Two-tier minimum length**: secret-looking keys (KEY, SECRET, TOKEN, PASSWORD, URL, CONN, etc.) → 4 chars; all other keys → 8 chars
- **Common-value skiplist**: values like `true`, `false`, `localhost`, `development`, `production`, `debug`, `info`, `127.0.0.1` etc. are never fingerprinted regardless of key name — prevents false-positive redaction of common words in code
- Fingerprints: raw value, URL-encoded, base64-encoded, JSON-escaped, prefix/suffix for long values
- Aho-Corasick matching with **word-boundary checking** to prevent false positives on substrings (e.g., "test" won't match inside "testing")

### Two-Layer Scanner
1. **Aho-Corasick** (Layer 1): known secret values discovered from filesystem/env
2. **Regex patterns** (Layer 2): 17 format-based patterns (AWS keys, GitHub PATs, Stripe keys, etc.) from `data/patterns.toml`

## Behavioral Analysis

- **Destination profiling**: tracks per-host request stats, detects volume spikes (>3x average AND >10 KB), new destinations (after 10-request warmup)
- **Data shape classification**: Shannon entropy threshold 4.5, length filter 16-512 chars, heuristic scoring (mixed case + digits + special + no spaces >= 3), known prefix matching
- **Allowlist**: auto-provider map (e.g., `anthropic_api_key` → `api.anthropic.com`), custom rules with wildcard domain support

## Skill File Analysis

- Discovers skill files in `~/.claude/skills/`, `./.claude/skills/`, `~/.openclaw/skills/`, `./.aider.conf.yml`
- Scans for: shell commands (20 patterns), external URLs, sensitive file paths (15 patterns), base64 obfuscation, unicode tricks, prompt injection (18 patterns)
- Complexity score: `shell_commands * 10 + external_urls * 5 + file_references * 8 + line_count / 50`
- Symlink-safe: `follow_links(false)`, max depth 3

## AgentAudit Registry Integration

`leakwall scan` cross-references discovered MCP servers against the [AgentAudit](https://agentaudit.dev) registry — the only working external registry (MCP Trust has no API).

### API Endpoints (no auth required)
- `GET /api/check?package={slug}` — trust score + recommendation (Safe/Caution/Unsafe)
- `GET /api/findings?package={slug}` — detailed security findings per package
- `GET /api/packages` — full catalog (~193 packages) with slugs and source URLs

### Slug Resolution (5-tier)
AgentAudit uses **GitHub repo names** as slugs (e.g., `mcp-remote`, `servers`), not npm package names. Resolution order:
1. **Direct match** — try `package_name` as slug via `/api/check`
2. **Config name** — try `identity.name` (the MCP config key)
3. **Strip npm scope** — `@modelcontextprotocol/server-git` → `server-git`
4. **Known scope mappings** — `@anthropic/*` and `@modelcontextprotocol/*` → `"servers"` (monorepo)
5. **Catalog search** — match by `source_url` using **path-segment matching** (`/org/` not `org`)

### Critical Gotchas
- **Response shape**: severity counts (`critical`, `high`, `medium`, `low`) are flat top-level fields, NOT nested under `severity_breakdown`
- **Finding IDs**: integers in the API, parse with dual `as_str()` / `as_u64()` fallback
- **Slug != npm name**: most monorepo packages (e.g., `@anthropic/mcp-server-*`) map to a single slug `"servers"`
- **Substring matching pitfall**: never match org names as bare substrings — use path segments (`/anthropic/` not `anthropic`) to avoid `anthropic` matching `anthropics/anthropic-cookbook`
- **npx flag skipping**: `extract_identity()` skips args starting with `-` (e.g., `-y`, `--yes`) when finding package name
- **Test override**: `LEAKWALL_AGENTAUDIT_URL` env var overrides the base URL for wiremock tests

## Watch Daemon

- Filesystem monitoring via `notify` crate (inotify/FSEvents) with 2-second debounce
- IPC over Unix domain socket (`~/.leakwall/leakwall.sock`, chmod 600)
- PID file locking via `fs2::FileExt::try_lock_exclusive()`
- Desktop notifications via `notify-rust`, rate-limited 5 min per event type
- Process liveness check via `/proc/{pid}` metadata (no unsafe libc calls)

## Report Generation

- **JSON**: structured findings with severity, type, source, detail, remediation
- **HTML**: self-contained with embedded Tera template + CSS, visual score
- **SARIF 2.1.0**: for GitHub Code Scanning / IDE integration
- **Trends**: compares last two scan reports (Improving/Stable/Worsening/Insufficient)
- **Cost estimation**: extracts token counts from API response headers/bodies, applies provider-specific pricing

## Runtime Paths

- `~/.leakwall/ca.pem` / `~/.leakwall/ca-key.pem` — generated CA certificate
- `~/.leakwall/ca-bundle.pem` — combined system + LeakWall CA bundle
- `~/.leakwall/reports/` — JSON scan reports and HTML reports
- `~/.leakwall/logs/` — session logs (including `live.log` for headless mode)
- `~/.leakwall/tool_hashes.json` — hash pins for rug pull detection
- `~/.leakwall/registry_cache.json` — 24h TTL cache for registry lookups
- `~/.leakwall/package_catalog.json` — 24h TTL cache for AgentAudit package catalog (slug resolution)
- `~/.leakwall/leakwall.pid` — daemon PID file (with file lock)
- `~/.leakwall/leakwall.sock` — daemon IPC socket
- `~/.leakwall/daemon.log` — daemon log file

## Testing

Tests live in `#[cfg(test)]` modules at the bottom of source files. Test fixtures are in `tests/fixtures/`. Run individual crate tests with `cargo test -p leakwall-secrets`.

Key test areas: pattern compilation, AWS/GitHub/Stripe key detection, false positive avoidance, known secret Aho-Corasick matching, **common-value skiplist**, **two-tier min length**, CA/host cert generation, **cert chain verification** (issuer DN must match CA subject), SSE parsing, body redaction, tool poisoning detection, CVE version comparison (semver + naive fallback), skill analysis, behavioral profiling, data shape classification, allowlist matching, SARIF generation, trend analysis, cost estimation, JSON-RPC parsing, daemon IPC, **AgentAudit API parsing** (wiremock: check/findings/catalog endpoints, slug resolution, npm scope stripping, recommendation mapping).

## Documentation

- `LEARNING.md` — detailed learning guide covering what LeakWall does, how each command works, scanning engine internals, architecture, and glossary
- `LESSONS.md` — security lessons learned: bugs encountered, patterns to follow, things to avoid
- `aegis-phase1-architecture.md` — Phase 1 architecture design document
- `aegis-phase2-architecture.md` — Phase 2 architecture design document (daemon, skills scanning, behavioral analysis)
