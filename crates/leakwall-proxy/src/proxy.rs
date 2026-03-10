use crate::{ca, intercept, should_intercept, CertifiedKeyPair, ProxyError, ProxyState};
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing::{debug, info, instrument, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: Bytes) -> BoxBody {
    http_body_util::Full::new(data)
        .map_err(|never| match never {})
        .boxed()
}

/// Start the MITM proxy on the given port.
///
/// If `ready_tx` is provided, it will be sent `Ok(())` once the listener is
/// bound successfully, or `Err(ProxyError)` if binding fails.  This lets the
/// caller wait for the proxy to be ready before spawning a child process.
#[instrument(skip(state, ready_tx))]
pub async fn start_proxy(
    state: Arc<ProxyState>,
    ready_tx: Option<oneshot::Sender<Result<(), ProxyError>>>,
) -> Result<(), ProxyError> {
    let addr = SocketAddr::from(([127, 0, 0, 1], state.proxy_port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            if let Some(tx) = ready_tx {
                let _ = tx.send(Ok(()));
            }
            l
        }
        Err(e) => {
            let err = if e.kind() == std::io::ErrorKind::AddrInUse {
                ProxyError::BindError(format!(
                    "port {} already in use — another leakwall instance may be running. \
                     Use -p to pick a different port.",
                    state.proxy_port
                ))
            } else {
                ProxyError::BindError(format!("bind {addr}: {e}"))
            };
            if let Some(tx) = ready_tx {
                // Send a descriptive error back; we construct a second error
                // for the return because ProxyError is not Clone.
                let _ = tx.send(Err(ProxyError::BindError(err.to_string())));
            }
            return Err(err);
        }
    };

    info!(addr = %addr, "proxy listening");

    loop {
        let (stream, _peer) = listener.accept().await.map_err(ProxyError::Io)?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, _peer, state).await {
                debug!(peer = %_peer, error = %e, "connection error");
            }
        });
    }
}

/// Handle a single TCP connection.
async fn handle_connection(
    stream: TcpStream,
    _peer: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<(), ProxyError> {
    let io = TokioIo::new(stream);
    let state_clone = Arc::clone(&state);

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let state = Arc::clone(&state_clone);
                async move { handle_request(req, state).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| ProxyError::BindError(format!("serve error: {e}")))?;

    Ok(())
}

/// Verify proxy authentication via Basic auth (username "leakwall", password = proxy_token).
fn check_proxy_auth(req: &Request<hyper::body::Incoming>, expected_token: &str) -> bool {
    let auth_header = match req.headers().get(hyper::header::PROXY_AUTHORIZATION) {
        Some(v) => v,
        None => return false,
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Expect "Basic <base64(leakwall:token)>"
    let encoded = match auth_str.strip_prefix("Basic ") {
        Some(e) => e,
        None => return false,
    };

    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let credentials = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let expected = format!("leakwall:{expected_token}");
    credentials.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Handle a single HTTP request (either CONNECT tunnel or direct proxy).
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Check proxy authentication
    if !check_proxy_auth(&req, &state.proxy_token) {
        debug!("proxy auth challenge — sending 407 for credential negotiation");
        return Ok(Response::builder()
            .status(407)
            .header("Proxy-Authenticate", "Basic realm=\"leakwall-proxy\"")
            .body(full_body(Bytes::from(
                "[LEAKWALL] Proxy authentication required",
            )))
            .unwrap_or_else(|_| Response::new(full_body(Bytes::new()))));
    }

    if req.method() == Method::CONNECT {
        // HTTPS tunnel request
        let host = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        handle_connect(req, host, state).await
    } else {
        // Direct HTTP request (shouldn't happen for HTTPS proxy, but handle gracefully)
        Ok(Response::builder()
            .status(400)
            .body(full_body(Bytes::from(
                "Direct HTTP not supported — use CONNECT tunnel",
            )))
            .unwrap_or_else(|_| Response::new(full_body(Bytes::new()))))
    }
}

/// Handle CONNECT method — set up TLS tunnel.
async fn handle_connect(
    req: Request<hyper::body::Incoming>,
    host: String,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let host_only = host.split(':').next().unwrap_or(&host).to_string();

    // Respond 200 to establish tunnel
    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if should_intercept(&host_only) {
                    if let Err(e) = handle_intercepted_tunnel(io, &host_only, &host, state).await {
                        debug!(host = %host_only, error = %e, "MITM tunnel error");
                    }
                } else if let Err(e) = handle_passthrough_tunnel(io, &host).await {
                    debug!(host = %host_only, error = %e, "passthrough tunnel error");
                }
            }
            Err(e) => {
                warn!(error = %e, "upgrade failed");
            }
        }
    });

    Ok(Response::new(full_body(Bytes::new())))
}

/// Handle an intercepted tunnel — MITM TLS, scan traffic.
async fn handle_intercepted_tunnel<I>(
    client_io: I,
    host: &str,
    host_port: &str,
    state: Arc<ProxyState>,
) -> Result<(), ProxyError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Get or generate certificate for this host
    let cert_pair = get_or_create_cert(host, &state)?;

    // Set up TLS acceptor for the client side
    let tls_config = make_server_tls_config(&cert_pair)?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let tls_stream = tls_acceptor
        .accept(client_io)
        .await
        .map_err(|e| ProxyError::TlsError(format!("client TLS accept: {e}")))?;

    let tls_io = TokioIo::new(tls_stream);

    // Connect to the real server
    let real_host = host_port.to_string();
    let state_clone = Arc::clone(&state);

    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(
            tls_io,
            service_fn(move |req| {
                let state = Arc::clone(&state_clone);
                let host = real_host.clone();
                async move { intercept::handle_intercepted_request(req, &host, state).await }
            }),
        )
        .await
        .map_err(|e| ProxyError::TlsError(format!("intercepted serve: {e}")))?;

    Ok(())
}

/// Handle a passthrough tunnel — simple TCP forwarding, no inspection.
async fn handle_passthrough_tunnel<I>(client_io: I, host_port: &str) -> Result<(), ProxyError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Block connections to private/internal networks
    let host = host_port.split(':').next().unwrap_or(host_port);
    if is_private_address(host) {
        return Err(ProxyError::BindError(format!(
            "blocked connection to private address: {host_port}"
        )));
    }

    let server_stream = TcpStream::connect(host_port)
        .await
        .map_err(|e| ProxyError::BindError(format!("connect to {host_port}: {e}")))?;

    let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
    let (mut server_reader, mut server_writer) = tokio::io::split(server_stream);

    let c2s = tokio::io::copy(&mut client_reader, &mut server_writer);
    let s2c = tokio::io::copy(&mut server_reader, &mut client_writer);

    tokio::select! {
        r = c2s => { debug!(bytes = ?r.ok(), "client->server copy done"); }
        r = s2c => { debug!(bytes = ?r.ok(), "server->client copy done"); }
    }

    Ok(())
}

fn get_or_create_cert(host: &str, state: &ProxyState) -> Result<Arc<CertifiedKeyPair>, ProxyError> {
    if let Some(cached) = state.cert_cache.get(host) {
        return Ok(Arc::clone(&cached));
    }

    let pair = ca::generate_host_cert(host, &state.ca_cert_pem, &state.ca_key_pem)?;
    let pair = Arc::new(pair);
    state.cert_cache.insert(host.to_string(), Arc::clone(&pair));
    Ok(pair)
}

fn make_server_tls_config(
    cert_pair: &CertifiedKeyPair,
) -> Result<rustls::ServerConfig, ProxyError> {
    let cert_chain = rustls_pemfile::certs(&mut cert_pair.cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .map(|c| rustls::pki_types::CertificateDer::from(c.to_vec()))
        .collect::<Vec<_>>();

    let key = rustls_pemfile::private_key(&mut cert_pair.key_pem.as_bytes())
        .map_err(|e| ProxyError::TlsError(format!("parse key: {e}")))?
        .ok_or_else(|| ProxyError::TlsError("no private key found".into()))?;

    let config = rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .map_err(|e| ProxyError::TlsError(format!("server config: {e}")))?;

    Ok(config)
}

fn is_private_address(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        }
    } else {
        // For hostnames, block "localhost" variants
        let lower = host.to_lowercase();
        lower == "localhost" || lower.ends_with(".local") || lower.ends_with(".internal")
    }
}
