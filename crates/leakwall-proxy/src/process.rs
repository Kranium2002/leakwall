use crate::ProxyError;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tracing::{info, instrument, warn};

/// System CA bundle paths to search (in order).
const SYSTEM_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/ssl/cert.pem",                  // macOS, Alpine
];

/// Create a combined CA bundle containing system CAs + the LeakWall CA.
///
/// The combined bundle is written to `lw_dir/ca-bundle.pem`.  If the system
/// bundle cannot be found, falls back to just the LeakWall CA with a warning.
fn create_combined_ca_bundle(
    ca_cert_path: &Path,
    lw_dir: &Path,
) -> Result<std::path::PathBuf, ProxyError> {
    let lw_ca = std::fs::read_to_string(ca_cert_path)
        .map_err(|e| ProxyError::ProcessSpawn(format!("read leakwall CA: {e}")))?;

    // Try to find the system CA bundle
    let system_bundle = std::env::var("SSL_CERT_FILE")
        .ok()
        .and_then(|p| {
            let path = Path::new(&p);
            if path.exists() {
                std::fs::read_to_string(path).ok()
            } else {
                None
            }
        })
        .or_else(|| {
            SYSTEM_CA_PATHS.iter().find_map(|p| {
                let path = Path::new(p);
                if path.exists() {
                    std::fs::read_to_string(path).ok()
                } else {
                    None
                }
            })
        });

    let combined = match system_bundle {
        Some(system_cas) => {
            format!("{system_cas}\n{lw_ca}")
        }
        None => {
            warn!("system CA bundle not found, using LeakWall CA only");
            lw_ca
        }
    };

    let bundle_path = lw_dir.join("ca-bundle.pem");
    std::fs::write(&bundle_path, &combined)
        .map_err(|e| ProxyError::ProcessSpawn(format!("write combined CA bundle: {e}")))?;

    Ok(bundle_path)
}

/// Spawn a child process with proxy environment variables set.
#[instrument(skip_all, fields(command = %command[0]))]
pub fn spawn_agent(
    command: &[String],
    proxy_port: u16,
    ca_cert_path: &Path,
    lw_dir: &Path,
    proxy_token: &str,
) -> Result<Child, ProxyError> {
    if command.is_empty() {
        return Err(ProxyError::ProcessSpawn("empty command".into()));
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Set proxy env vars with Basic auth credentials (both cases for compatibility)
    let proxy_url = format!("http://leakwall:{proxy_token}@127.0.0.1:{proxy_port}");
    cmd.env("HTTP_PROXY", &proxy_url);
    cmd.env("HTTPS_PROXY", &proxy_url);
    cmd.env("http_proxy", &proxy_url);
    cmd.env("https_proxy", &proxy_url);

    // Also provide the token separately for direct use
    cmd.env("LEAKWALL_PROXY_TOKEN", proxy_token);

    // Create combined CA bundle (system CAs + LeakWall CA)
    let ca_path = ca_cert_path.to_string_lossy().to_string();
    let bundle_path = create_combined_ca_bundle(ca_cert_path, lw_dir)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|e| {
            warn!(error = %e, "failed to create combined CA bundle, using leakwall CA only");
            ca_path.clone()
        });

    cmd.env("NODE_EXTRA_CA_CERTS", &ca_path); // Node.js (Claude Code) — wants just the extra cert
    cmd.env("REQUESTS_CA_BUNDLE", &bundle_path); // Python requests
    cmd.env("SSL_CERT_FILE", &bundle_path); // General OpenSSL
    cmd.env("CURL_CA_BUNDLE", &bundle_path); // curl

    // Inherit stdio for interactive agents
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let child = cmd
        .spawn()
        .map_err(|e| ProxyError::ProcessSpawn(format!("spawn '{}': {e}", command[0])))?;

    info!(
        pid = child.id(),
        command = %command.join(" "),
        "spawned agent process"
    );

    Ok(child)
}
