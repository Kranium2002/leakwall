use crate::ProxyError;
use bytes::Bytes;

/// Default maximum SSE parser buffer size (1 MB).
pub const DEFAULT_SSE_MAX_BUFFER: usize = 1024 * 1024;

/// SSE event parsed from a streaming response.
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub data: String,
    pub id: Option<String>,
}

/// Parse SSE events from a byte stream.
///
/// Uses zero-copy approach where possible — the input bytes are
/// sliced rather than copied.
pub struct SseParser {
    buffer: Vec<u8>,
    max_buffer_size: usize,
}

impl SseParser {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer_size: DEFAULT_SSE_MAX_BUFFER,
        }
    }

    pub fn with_max_buffer(max_buffer_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer_size,
        }
    }

    /// Feed bytes into the parser and extract complete events.
    pub fn feed(&mut self, chunk: &Bytes) -> Result<Vec<SseEvent>, ProxyError> {
        if self.buffer.len() + chunk.len() > self.max_buffer_size {
            self.buffer.clear();
            return Err(ProxyError::SseStream(format!(
                "SSE buffer exceeded {} bytes, discarding",
                self.max_buffer_size
            )));
        }

        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();

        while let Some((pos, sep_len)) = find_double_newline(&self.buffer) {
            let event_bytes = self.buffer[..pos].to_vec();
            self.buffer.drain(..pos + sep_len);

            if let Some(event) = parse_event(&event_bytes) {
                events.push(event);
            }
        }

        Ok(events)
    }
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Find a double-newline event separator per the SSE spec.
///
/// Returns `(position, separator_length)` so the caller knows how many bytes
/// to skip.  Checks `\r\n\r\n` first (longest match), then `\n\n`, then `\r\r`.
fn find_double_newline(data: &[u8]) -> Option<(usize, usize)> {
    // Check for \r\n\r\n (4 bytes) first
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, 4));
    }
    // Then \n\n (2 bytes)
    if let Some(pos) = data.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, 2));
    }
    // Then \r\r (2 bytes)
    if let Some(pos) = data.windows(2).position(|w| w == b"\r\r") {
        return Some((pos, 2));
    }
    None
}

fn parse_event(data: &[u8]) -> Option<SseEvent> {
    let text = String::from_utf8_lossy(data);
    let mut event_type = None;
    let mut data_lines = Vec::new();
    let mut id = None;

    // Split on \n, \r\n, or \r to handle all SSE line endings
    for raw_line in text.split(['\n', '\r']) {
        let line = raw_line.trim_end();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event_type = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("id:") {
            id = Some(value.trim().to_string());
        }
    }

    if data_lines.is_empty() && event_type.is_none() {
        return None;
    }

    Some(SseEvent {
        event_type,
        data: data_lines.join("\n"),
        id,
    })
}

/// Tee bytes — clone the byte stream for scanning while passing through.
pub fn tee_bytes(original: &Bytes) -> (Bytes, Bytes) {
    (original.clone(), original.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_parser() {
        let mut parser = SseParser::new();
        let chunk = Bytes::from("event: message\ndata: hello\n\nevent: done\ndata: bye\n\n");
        let events = parser.feed(&chunk).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "hello");
        assert_eq!(events[1].data, "bye");
    }

    #[test]
    fn test_sse_partial_chunks() {
        let mut parser = SseParser::new();
        let events1 = parser.feed(&Bytes::from("event: message\n")).unwrap();
        assert!(events1.is_empty());
        let events2 = parser.feed(&Bytes::from("data: hello\n\n")).unwrap();
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0].data, "hello");
    }

    #[test]
    fn test_sse_buffer_overflow() {
        let mut parser = SseParser::with_max_buffer(32);
        // Feed enough data to exceed the 32-byte limit
        let result = parser.feed(&Bytes::from(
            "data: this is a really long message that exceeds limit\n\n",
        ));
        assert!(result.is_err());
    }

    #[test]
    fn test_sse_crlf_separator() {
        let mut parser = SseParser::new();
        let chunk =
            Bytes::from("event: message\r\ndata: hello\r\n\r\nevent: done\r\ndata: bye\r\n\r\n");
        let events = parser.feed(&chunk).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "hello");
        assert_eq!(events[1].data, "bye");
    }

    #[test]
    fn test_sse_cr_separator() {
        let mut parser = SseParser::new();
        let chunk = Bytes::from("event: message\rdata: hello\r\revent: done\rdata: bye\r\r");
        let events = parser.feed(&chunk).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "hello");
        assert_eq!(events[1].data, "bye");
    }
}
