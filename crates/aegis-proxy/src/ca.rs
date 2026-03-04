use crate::{CertifiedKeyPair, ProxyError};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use std::path::Path;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info, instrument, warn};
use zeroize::Zeroizing;

/// Generate a self-signed CA certificate and key.
#[instrument]
pub fn generate_ca() -> Result<(String, Zeroizing<String>), ProxyError> {
    let mut params = CertificateParams::new(vec![])
        .map_err(|e| ProxyError::CaError(format!("CA params error: {e}")))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params
        .distinguished_name
        .push(DnType::CommonName, "Aegis Local CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Aegis Security");

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(365);

    let key_pair = KeyPair::generate()
        .map_err(|e| ProxyError::CaError(format!("key generation error: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ProxyError::CaError(format!("self-sign error: {e}")))?;

    info!("generated new CA certificate");
    Ok((cert.pem(), Zeroizing::new(key_pair.serialize_pem())))
}

/// Load or generate CA certificate, saving to ~/.aegis/.
pub fn load_or_generate_ca(aegis_dir: &Path) -> Result<(String, Zeroizing<String>), ProxyError> {
    let cert_path = aegis_dir.join("ca.pem");
    let key_path = aegis_dir.join("ca-key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| ProxyError::CaError(format!("read CA cert: {e}")))?;
        let key_pem = Zeroizing::new(
            std::fs::read_to_string(&key_path)
                .map_err(|e| ProxyError::CaError(format!("read CA key: {e}")))?,
        );
        debug!("loaded existing CA certificate");
        return Ok((cert_pem, key_pem));
    }

    // Generate new CA
    std::fs::create_dir_all(aegis_dir)
        .map_err(|e| ProxyError::CaError(format!("create dir: {e}")))?;

    let (cert_pem, key_pem) = generate_ca()?;

    std::fs::write(&cert_path, &cert_pem)
        .map_err(|e| ProxyError::CaError(format!("write CA cert: {e}")))?;
    std::fs::write(&key_path, key_pem.as_str())
        .map_err(|e| ProxyError::CaError(format!("write CA key: {e}")))?;

    // Hard error on Unix if key permissions cannot be set
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ProxyError::CaError(format!("set CA key permissions: {e}")))?;
    }

    #[cfg(windows)]
    {
        warn!(
            "CA key file permissions not automatically restricted on Windows. \
             Please restrict access to {}",
            key_path.display()
        );
    }

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "saved CA certificate"
    );
    Ok((cert_pem, key_pem))
}

/// Generate a certificate for a specific host, signed by the CA.
///
/// Note: `ca_cert_pem` is accepted but not parsed directly. The CA certificate
/// parameters are reconstructed from scratch because `rcgen` does not provide a
/// `from_ca_cert_pem` API. The reconstructed DN (CommonName + OrganizationName)
/// must exactly match the original CA subject for cert chain verification.
pub fn generate_host_cert(
    host: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<CertifiedKeyPair, ProxyError> {
    let _ = ca_cert_pem; // reserved for future use if rcgen adds PEM import
    let ca_key = KeyPair::from_pem(ca_key_pem)
        .map_err(|e| ProxyError::CaError(format!("parse CA key: {e}")))?;

    // Re-create the CA certificate params and self-sign with the loaded key.
    // This gives us a Certificate object we can use to sign host certs.
    let mut ca_params = CertificateParams::new(vec![])
        .map_err(|e| ProxyError::CaError(format!("CA params: {e}")))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Aegis Local CA");
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "Aegis Security");

    let now = OffsetDateTime::now_utc();
    ca_params.not_before = now;
    ca_params.not_after = now + Duration::days(365);

    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| ProxyError::CaError(format!("reconstruct CA cert: {e}")))?;

    let mut params = CertificateParams::new(vec![host.to_string()])
        .map_err(|e| ProxyError::CaError(format!("host cert params: {e}")))?;
    params.distinguished_name.push(DnType::CommonName, host);
    params.not_before = now;
    params.not_after = now + Duration::hours(24);

    let host_key =
        KeyPair::generate().map_err(|e| ProxyError::CaError(format!("host key gen: {e}")))?;
    let host_cert = params
        .signed_by(&host_key, &ca_cert, &ca_key)
        .map_err(|e| ProxyError::CaError(format!("sign host cert: {e}")))?;

    debug!(host = %host, "generated host certificate");
    Ok(CertifiedKeyPair {
        cert_pem: host_cert.pem(),
        key_pem: Zeroizing::new(host_key.serialize_pem()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca() {
        let (cert, key) = generate_ca().unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_host_cert() {
        let (ca_cert, ca_key) = generate_ca().unwrap();
        let host = generate_host_cert("api.example.com", &ca_cert, &ca_key).unwrap();
        assert!(host.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(host.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_host_cert_issuer_matches_ca_subject() {
        use rustls::client::danger::ServerCertVerifier;
        let (ca_cert_pem, ca_key_pem) = generate_ca().unwrap();
        let host = generate_host_cert("api.example.com", &ca_cert_pem, &ca_key_pem).unwrap();

        // Parse both certs and verify the host cert's issuer matches the CA's subject
        let ca_der: Vec<_> = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        let host_der: Vec<_> = rustls_pemfile::certs(&mut host.cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(ca_der.len(), 1);
        assert_eq!(host_der.len(), 1);

        // Verify chain using rustls: build a root store from the CA and verify the host cert
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(ca_der[0].to_vec()))
            .expect("add CA to root store");

        let verifier = rustls::client::WebPkiServerVerifier::builder(root_store.into())
            .build()
            .expect("build verifier");

        let host_cert_der = rustls::pki_types::CertificateDer::from(host_der[0].to_vec());
        let server_name = rustls::pki_types::ServerName::try_from("api.example.com").unwrap();
        let now = rustls::pki_types::UnixTime::now();
        let result = verifier.verify_server_cert(&host_cert_der, &[], &server_name, &[], now);
        assert!(result.is_ok(), "host cert must chain to CA: {result:?}");
    }
}
