use crate::stream::SseParser;
use crate::{redact, Action, ProxyError, ProxyEvent, ProxyState, RequestLog, ScanMode};
use bytes::Bytes;
use chrono::Utc;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper::body::Frame;
use hyper::{Request, Response};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, instrument, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(data: Bytes) -> BoxBody {
    use http_body_util::Full;
    Full::new(data).map_err(|never| match never {}).boxed()
}

/// Strip signed thinking blocks from the request body to prevent signature
/// invalidation when secrets are redacted. The model regenerates thinking on
/// the next turn, so removing these is safe.
fn strip_thinking_blocks(body: &[u8]) -> Bytes {
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Bytes::from(body.to_vec());
    };

    let Some(messages) = json.get_mut("messages").and_then(|m| m.as_array_mut()) else {
        return Bytes::from(body.to_vec());
    };

    let mut changed = false;
    for msg in messages.iter_mut() {
        let Some(content) = msg.get_mut("content").and_then(|c| c.as_array_mut()) else {
            continue;
        };
        let before = content.len();
        content.retain(|block| block.get("type").and_then(|t| t.as_str()) != Some("thinking"));
        if content.len() != before {
            changed = true;
        }
    }

    if changed {
        serde_json::to_vec(&json)
            .map(Bytes::from)
            .unwrap_or_else(|_| Bytes::from(body.to_vec()))
    } else {
        Bytes::from(body.to_vec())
    }
}

fn empty_body() -> BoxBody {
    full_body(Bytes::new())
}

/// Handle an intercepted HTTPS request — scan body, apply action, forward.
#[instrument(skip(req, state), fields(host = %host))]
pub async fn handle_intercepted_request(
    req: Request<hyper::body::Incoming>,
    host: &str,
    state: Arc<ProxyState>,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // Collect request body
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            warn!(error = %e, "failed to read request body");
            return Ok(Response::builder()
                .status(502)
                .body(full_body(Bytes::from(
                    "[LEAKWALL] Failed to read request body",
                )))
                .unwrap_or_else(|_| Response::new(empty_body())));
        }
    };

    // Strip signed thinking blocks before scanning/redacting to avoid
    // invalidating their cryptographic signatures.
    let body_bytes = strip_thinking_blocks(&body_bytes);
    let body_size = body_bytes.len();

    // Check body size limit — skip scanning if too large
    let skip_scan = body_size > state.max_body_size;
    if skip_scan {
        let current_mode = state.mode.read().await.clone();
        match current_mode {
            ScanMode::Block => {
                warn!(
                    host = %host,
                    body_size,
                    max = state.max_body_size,
                    "request body exceeds max size, BLOCKED (block mode)"
                );
                let _ = state.event_tx.send(ProxyEvent::RequestIntercepted {
                    timestamp: Utc::now(),
                    host: host.to_string(),
                    method: method.clone(),
                    path: path.clone(),
                    body_size,
                    scan_result: leakwall_secrets::scanner::ScanResult {
                        matches: vec![],
                        scan_duration: std::time::Duration::ZERO,
                        body_size,
                    },
                    action: Action::Blocked,
                });
                return Ok(Response::builder()
                    .status(413)
                    .body(full_body(Bytes::from(
                        "[LEAKWALL] Request blocked — payload too large to scan",
                    )))
                    .unwrap_or_else(|_| Response::new(empty_body())));
            }
            ScanMode::Redact => {
                warn!(
                    host = %host,
                    body_size,
                    max = state.max_body_size,
                    "request body exceeds max size, BLOCKED (redact mode)"
                );
                let _ = state.event_tx.send(ProxyEvent::RequestIntercepted {
                    timestamp: Utc::now(),
                    host: host.to_string(),
                    method: method.clone(),
                    path: path.clone(),
                    body_size,
                    scan_result: leakwall_secrets::scanner::ScanResult {
                        matches: vec![],
                        scan_duration: std::time::Duration::ZERO,
                        body_size,
                    },
                    action: Action::Blocked,
                });
                return Ok(Response::builder()
                    .status(413)
                    .body(full_body(Bytes::from(
                        "[LEAKWALL] Request blocked — payload too large to scan",
                    )))
                    .unwrap_or_else(|_| Response::new(empty_body())));
            }
            ScanMode::WarnOnly => {
                warn!(
                    host = %host,
                    body_size,
                    max = state.max_body_size,
                    "request body exceeds max size, skipping scan (warn mode)"
                );
            }
        }
    }

    // Scan for secrets using spawn_blocking (unless oversized)
    let scan_result = if skip_scan {
        leakwall_secrets::scanner::ScanResult {
            matches: vec![],
            scan_duration: std::time::Duration::ZERO,
            body_size,
        }
    } else {
        let scanner = Arc::clone(&state.scanner);
        let scan_bytes = body_bytes.clone();
        tokio::task::spawn_blocking(move || scanner.scan(&scan_bytes))
            .await
            .unwrap_or_else(|_| leakwall_secrets::scanner::ScanResult {
                matches: vec![],
                scan_duration: std::time::Duration::ZERO,
                body_size,
            })
    };

    // Read the current mode from shared state
    let current_mode = state.mode.read().await.clone();

    // Determine action based on scan results and mode
    let (action, forward_body) = if scan_result.is_clean() {
        (Action::Passed, body_bytes)
    } else {
        match current_mode {
            ScanMode::WarnOnly => {
                warn!(
                    host = %host,
                    matches = scan_result.matches.len(),
                    "secrets detected (warn mode)"
                );
                (Action::Warned, body_bytes)
            }
            ScanMode::Redact => {
                // Use JSON-aware redaction to avoid breaking JSON escape
                // sequences and producing invalid request bodies.
                let (redacted, count) = redact::redact_json_body(&body_bytes, &state.scanner);
                info!(
                    host = %host,
                    redacted = count,
                    "secrets redacted"
                );
                (Action::Redacted { count }, redacted)
            }
            ScanMode::Block => {
                warn!(
                    host = %host,
                    matches = scan_result.matches.len(),
                    "request BLOCKED — secrets detected"
                );
                // Emit event before returning 403
                let _ = state.event_tx.send(ProxyEvent::RequestIntercepted {
                    timestamp: Utc::now(),
                    host: host.to_string(),
                    method: method.clone(),
                    path: path.clone(),
                    body_size,
                    scan_result: scan_result.clone(),
                    action: Action::Blocked,
                });

                return Ok(Response::builder()
                    .status(403)
                    .body(full_body(Bytes::from(
                        "[LEAKWALL] Request blocked — secret exfiltration detected",
                    )))
                    .unwrap_or_else(|_| Response::new(empty_body())));
            }
        }
    };

    // Emit event
    let _ = state.event_tx.send(ProxyEvent::RequestIntercepted {
        timestamp: Utc::now(),
        host: host.to_string(),
        method: method.clone(),
        path: path.clone(),
        body_size,
        scan_result: scan_result.clone(),
        action: action.clone(),
    });

    // Log request — use actual redaction count when available
    let matches_count = match &action {
        Action::Redacted { count } => *count,
        _ => scan_result.matches.len(),
    };
    let log_entry = RequestLog {
        timestamp: Utc::now(),
        host: host.to_string(),
        method: method.clone(),
        path: path.clone(),
        body_size,
        matches_count,
        action: action.clone(),
    };
    state.session_log.write().await.push(log_entry);

    // Forward request to real server
    let forward_result = forward_request(host, parts, forward_body, &state).await;

    match forward_result {
        Ok(resp) => Ok(resp),
        Err(e) => {
            let _ = state.event_tx.send(ProxyEvent::ProxyError {
                message: format!("forward error: {e}"),
            });
            Ok(Response::builder()
                .status(502)
                .body(full_body(Bytes::from(format!("[LEAKWALL] Proxy error: {e}"))))
                .unwrap_or_else(|_| Response::new(empty_body())))
        }
    }
}

/// Forward a request to the real destination server.
///
/// For SSE responses (Content-Type: text/event-stream), streams the response
/// body chunk-by-chunk, scanning each chunk for secrets. For non-SSE responses,
/// buffers the full body (with size limit) and returns it.
async fn forward_request(
    host: &str,
    parts: hyper::http::request::Parts,
    body: Bytes,
    state: &Arc<ProxyState>,
) -> Result<Response<BoxBody>, ProxyError> {
    let host_only = host.split(':').next().unwrap_or(host);
    let url = format!(
        "https://{host_only}{}",
        parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

    let method = match parts.method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut req_builder = state.http_client.request(method, &url);

    // Copy relevant headers
    for (name, value) in &parts.headers {
        if let Ok(v) = value.to_str() {
            let name_str = name.as_str();
            if name_str != "host"
                && name_str != "proxy-connection"
                && name_str != "proxy-authorization"
                && name_str != "content-length"
            {
                req_builder = req_builder.header(name_str, v);
            }
        }
    }

    let response = req_builder
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| ProxyError::TlsError(format!("forward request: {e}")))?;

    let status = response.status().as_u16();

    // Copy response headers
    let mut resp_builder = Response::builder().status(status);
    for (name, value) in response.headers() {
        resp_builder = resp_builder.header(name.clone(), value.clone());
    }

    // Check if this is an SSE response
    let is_sse = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_sse {
        // Stream SSE response: scan each chunk before forwarding
        let scanner = Arc::clone(&state.scanner);
        let event_tx = state.event_tx.clone();
        let host_owned = host.to_string();
        let max_body_size = state.max_body_size;
        let mode = Arc::clone(&state.mode);

        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(64);

        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            let mut parser = SseParser::new();
            let mut total_streamed: usize = 0;

            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        total_streamed += chunk.len();

                        // Skip scanning if we've exceeded body size limit
                        let skip_scan = total_streamed > max_body_size;
                        if skip_scan {
                            debug!(
                                host = %host_owned,
                                total = total_streamed,
                                "SSE stream exceeds max body size, skipping scan"
                            );
                        }

                        // Determine what to forward based on scan results
                        let mut should_block = false;
                        let mut forward_chunk = chunk.clone();

                        if !skip_scan {
                            // Scan the entire chunk for secrets
                            let scan_clone = Arc::clone(&scanner);
                            let chunk_vec = chunk.to_vec();
                            let chunk_len = chunk.len();
                            let scan_result =
                                tokio::task::spawn_blocking(move || scan_clone.scan(&chunk_vec))
                                    .await
                                    .unwrap_or_else(|_| leakwall_secrets::scanner::ScanResult {
                                        matches: vec![],
                                        scan_duration: std::time::Duration::ZERO,
                                        body_size: chunk_len,
                                    });

                            if !scan_result.is_clean() {
                                let current_mode = mode.read().await.clone();

                                // Apply mode action first so we get actual counts
                                let action = match current_mode {
                                    ScanMode::Block => {
                                        should_block = true;
                                        Action::Blocked
                                    }
                                    ScanMode::Redact => {
                                        let (redacted, count) =
                                            redact::redact_json_body(&chunk, &scanner);
                                        forward_chunk = redacted;
                                        Action::Redacted { count }
                                    }
                                    ScanMode::WarnOnly => Action::Warned,
                                };
                                let _ = event_tx.send(ProxyEvent::RequestIntercepted {
                                    timestamp: Utc::now(),
                                    host: host_owned.clone(),
                                    method: "SSE".to_string(),
                                    path: "response-stream".to_string(),
                                    body_size: chunk_len,
                                    scan_result: scan_result.clone(),
                                    action,
                                });
                            }

                            // Also feed the parser for structured event tracking
                            if let Err(e) = parser.feed(&chunk) {
                                warn!(error = %e, "SSE parser buffer overflow");
                            }
                        }

                        if should_block {
                            // Send an error frame and close the stream
                            let err_frame = Frame::data(Bytes::from(
                                "[LEAKWALL] Response blocked - secret detected in stream",
                            ));
                            let _ = tx.send(Ok(err_frame)).await;
                            break;
                        }

                        // Forward the (possibly redacted) chunk
                        let frame = Frame::data(forward_chunk);
                        if tx.send(Ok(frame)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "SSE stream chunk error");
                        break;
                    }
                }
            }
        });

        let body_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let stream_body = http_body_util::StreamBody::new(body_stream);
        let boxed: BoxBody = BodyExt::boxed(stream_body);

        let hyper_resp = resp_builder
            .body(boxed)
            .unwrap_or_else(|_| Response::new(empty_body()));

        Ok(hyper_resp)
    } else {
        // Non-SSE: buffer the full response (with size limit)
        let resp_body = response
            .bytes()
            .await
            .map_err(|e| ProxyError::TlsError(format!("read response: {e}")))?;

        let resp_size = resp_body.len();
        let skip_scan = resp_size > state.max_body_size;
        let current_mode = state.mode.read().await.clone();

        if skip_scan {
            warn!(
                host = %host,
                resp_size,
                max = state.max_body_size,
                "response body exceeds max size, skipping scan"
            );
        }

        let final_body = if skip_scan {
            Bytes::from(resp_body.to_vec())
        } else {
            // Scan the response body for secrets
            let scanner = Arc::clone(&state.scanner);
            let scan_bytes = resp_body.to_vec();
            let scan_result = tokio::task::spawn_blocking(move || scanner.scan(&scan_bytes))
                .await
                .unwrap_or_else(|_| leakwall_secrets::scanner::ScanResult {
                    matches: vec![],
                    scan_duration: std::time::Duration::ZERO,
                    body_size: resp_size,
                });

            if scan_result.is_clean() {
                Bytes::from(resp_body.to_vec())
            } else {
                match &current_mode {
                    ScanMode::WarnOnly => {
                        warn!(
                            host = %host,
                            matches = scan_result.matches.len(),
                            "secrets detected in response (warn mode)"
                        );
                        let _ = state.event_tx.send(ProxyEvent::RequestIntercepted {
                            timestamp: Utc::now(),
                            host: host.to_string(),
                            method: "RESPONSE".to_string(),
                            path: url.clone(),
                            body_size: resp_size,
                            scan_result,
                            action: Action::Warned,
                        });
                        Bytes::from(resp_body.to_vec())
                    }
                    ScanMode::Redact => {
                        let (redacted, count) =
                            redact::redact_json_body(&resp_body, &state.scanner);
                        info!(
                            host = %host,
                            redacted = count,
                            "secrets redacted from response"
                        );
                        let _ = state.event_tx.send(ProxyEvent::RequestIntercepted {
                            timestamp: Utc::now(),
                            host: host.to_string(),
                            method: "RESPONSE".to_string(),
                            path: url.clone(),
                            body_size: resp_size,
                            scan_result,
                            action: Action::Redacted { count },
                        });
                        redacted
                    }
                    ScanMode::Block => {
                        warn!(
                            host = %host,
                            matches = scan_result.matches.len(),
                            "response BLOCKED — secrets detected"
                        );
                        let _ = state.event_tx.send(ProxyEvent::RequestIntercepted {
                            timestamp: Utc::now(),
                            host: host.to_string(),
                            method: "RESPONSE".to_string(),
                            path: url.clone(),
                            body_size: resp_size,
                            scan_result,
                            action: Action::Blocked,
                        });
                        return Ok(Response::builder()
                            .status(502)
                            .body(full_body(Bytes::from(
                                "[LEAKWALL] Response blocked - secret detected",
                            )))
                            .unwrap_or_else(|_| Response::new(empty_body())));
                    }
                }
            }
        };

        let hyper_resp = resp_builder
            .body(full_body(final_body))
            .unwrap_or_else(|_| Response::new(empty_body()));

        Ok(hyper_resp)
    }
}
