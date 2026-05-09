/// HTTP CONNECT proxy connector.
///
/// Protocol:
///   Client → Proxy:  `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n[Proxy-Authorization: Basic <b64>]\r\n\r\n`
///   Proxy  → Client: `HTTP/1.x 200 …\r\n…\r\n\r\n`
///
/// After the proxy returns 200 the TCP connection is a raw tunnel to the
/// target.  No extra dependencies — base64 encoding is inlined.
use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::{ProxyConnector, ProxyStream, ProxyTarget};

// ── Connector ─────────────────────────────────────────────────────────────────

/// HTTP CONNECT connector.
pub struct HttpConnector {
    server: SocketAddr,
    auth: Option<(String, String)>,
}

impl HttpConnector {
    /// Create a new HTTP CONNECT connector.
    ///
    /// `auth` is an optional `(username, password)` pair used for
    /// `Proxy-Authorization: Basic` authentication.
    pub fn new(server: SocketAddr, auth: Option<(String, String)>) -> Self {
        Self { server, auth }
    }
}

#[async_trait]
impl ProxyConnector for HttpConnector {
    async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream> {
        let stream = TcpStream::connect(self.server)
            .await
            .with_context(|| format!("TCP connect to HTTP proxy {}", self.server))?;

        let stream = do_connect(stream, target, self.auth.as_ref()).await?;

        Ok(ProxyStream { inner: stream })
    }
}

// ── Implementation ────────────────────────────────────────────────────────────

async fn do_connect(
    stream: TcpStream,
    target: &ProxyTarget,
    auth: Option<&(String, String)>,
) -> Result<TcpStream> {
    let target_str = target.to_string();

    // ── Build request ─────────────────────────────────────────────────────────
    let mut request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n",
        target = target_str,
    );

    if let Some((user, pass)) = auth {
        let credentials = base64_encode(format!("{}:{}", user, pass).as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", credentials));
    }

    request.push_str("\r\n");

    // Wrap in a BufReader for line-oriented response reading.
    // We need the raw stream back after reading, so we use into_inner().
    let mut buf_stream = BufReader::new(stream);

    buf_stream
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .context("HTTP CONNECT: write request")?;

    // ── Read status line ──────────────────────────────────────────────────────
    // e.g. "HTTP/1.1 200 Connection established\r\n"
    let mut status_line = String::new();
    buf_stream
        .read_line(&mut status_line)
        .await
        .context("HTTP CONNECT: read status line")?;

    let status_line = status_line.trim_end_matches(['\r', '\n']);

    tracing::debug!("HTTP CONNECT: status line: {:?}", status_line);

    // Parse status code from "HTTP/x.y NNN …"
    let status_code = parse_status_code(status_line)?;

    if status_code != 200 {
        bail!(
            "HTTP CONNECT to {} failed with status {}",
            target_str,
            status_code
        );
    }

    // ── Drain remaining response headers ─────────────────────────────────────
    // Headers end at the first blank line.
    loop {
        let mut line = String::new();
        buf_stream
            .read_line(&mut line)
            .await
            .context("HTTP CONNECT: read header line")?;

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        tracing::trace!("HTTP CONNECT: skipping header: {:?}", trimmed);
    }

    tracing::debug!("HTTP CONNECT: tunnel established to {}", target_str);

    // Return the inner stream (BufReader may have buffered bytes, but for
    // HTTP CONNECT the proxy MUST NOT send data before the blank line, so the
    // buffer should be empty at this point).
    Ok(buf_stream.into_inner())
}

/// Extract the three-digit HTTP status code from a status line.
fn parse_status_code(status_line: &str) -> Result<u16> {
    // Format: "HTTP/x.y NNN reason"
    let mut parts = status_line.splitn(3, ' ');

    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        bail!(
            "HTTP CONNECT: expected HTTP response, got: {:?}",
            status_line
        );
    }

    let code_str = parts
        .next()
        .with_context(|| format!("HTTP CONNECT: malformed status line: {:?}", status_line))?;

    let code: u16 = code_str
        .parse()
        .with_context(|| format!("HTTP CONNECT: invalid status code {:?}", code_str))?;

    Ok(code)
}

// ── Inline base64 encoder ─────────────────────────────────────────────────────

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` as standard (padded) base64.
fn base64_encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let combined = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_ALPHABET[((combined >> 18) & 0x3F) as usize]);
        out.push(B64_ALPHABET[((combined >> 12) & 0x3F) as usize]);

        if chunk.len() > 1 {
            out.push(B64_ALPHABET[((combined >> 6) & 0x3F) as usize]);
        } else {
            out.push(b'=');
        }

        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(combined & 0x3F) as usize]);
        } else {
            out.push(b'=');
        }
    }

    // SAFETY: B64_ALPHABET contains only ASCII.
    unsafe { String::from_utf8_unchecked(out) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_credentials() {
        // "Aladdin:open sesame" → "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        assert_eq!(
            base64_encode(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn parse_status_code_ok() {
        assert_eq!(
            parse_status_code("HTTP/1.1 200 Connection established").unwrap(),
            200
        );
        assert_eq!(
            parse_status_code("HTTP/1.0 407 Proxy Auth Required").unwrap(),
            407
        );
    }

    #[test]
    fn parse_status_code_err() {
        assert!(parse_status_code("GARBAGE").is_err());
        assert!(parse_status_code("HTTP/1.1 abc reason").is_err());
    }
}
