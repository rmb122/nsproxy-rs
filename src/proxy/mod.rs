pub mod direct;
pub mod http;
pub mod socks5;

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// A fully parsed outbound route.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProxyConfig {
    Direct,
    Socks5 {
        addr: SocketAddr,
        auth: Option<(String, String)>,
    },
    Http {
        addr: SocketAddr,
        auth: Option<(String, String)>,
    },
}

impl ProxyConfig {
    /// Parse `direct` or a supported proxy URL.
    pub fn parse(value: &str) -> Result<Self> {
        if value == "direct" {
            return Ok(Self::Direct);
        }

        enum Kind {
            Socks5,
            Http,
        }

        let (kind, rest) = if let Some(rest) = value.strip_prefix("socks5://") {
            (Kind::Socks5, rest)
        } else if let Some(rest) = value.strip_prefix("socks://") {
            (Kind::Socks5, rest)
        } else if let Some(rest) = value.strip_prefix("http://") {
            (Kind::Http, rest)
        } else {
            bail!(
                "unsupported proxy '{}'; use direct, socks5://, socks://, or http://",
                value
            );
        };

        let (auth, host_port) = if let Some(at_pos) = rest.rfind('@') {
            let auth_str = &rest[..at_pos];
            let host_port = &rest[at_pos + 1..];
            let mut parts = auth_str.splitn(2, ':');
            let user = parts.next().unwrap_or("").to_string();
            let pass = parts.next().unwrap_or("").to_string();
            if user.is_empty() {
                bail!("empty username in proxy URL");
            }
            (Some((user, pass)), host_port)
        } else {
            (None, rest)
        };

        let addr: SocketAddr = host_port
            .parse()
            .with_context(|| format!("invalid proxy address: '{host_port}'"))?;

        Ok(match kind {
            Kind::Socks5 => Self::Socks5 { addr, auth },
            Kind::Http => Self::Http { addr, auth },
        })
    }

    pub async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream> {
        match self {
            Self::Direct => direct::DirectConnector.connect(target).await,
            Self::Socks5 { addr, auth } => {
                socks5::Socks5Connector::new(*addr, auth.clone())
                    .connect(target)
                    .await
            }
            Self::Http { addr, auth } => {
                http::HttpConnector::new(*addr, auth.clone())
                    .connect(target)
                    .await
            }
        }
    }
}

impl std::fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Socks5 { addr, .. } => write!(f, "socks5://{addr}"),
            Self::Http { addr, .. } => write!(f, "http://{addr}"),
        }
    }
}

/// Target for proxy connection.
#[derive(Debug, Clone)]
pub enum ProxyTarget {
    /// Domain name — sent to proxy for remote DNS resolution (anti-leak).
    Domain { host: String, port: u16 },
    /// IP address.
    Ip { addr: IpAddr, port: u16 },
}

impl std::fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyTarget::Domain { host, port } => write!(f, "{}:{}", host, port),
            ProxyTarget::Ip { addr, port } => write!(f, "{}:{}", addr, port),
        }
    }
}

/// Trait for proxy connectors.
#[async_trait]
pub trait ProxyConnector: Send + Sync {
    async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream>;
}

/// Bidirectional stream after proxy handshake completes.
pub struct ProxyStream {
    pub inner: TcpStream,
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn parses_direct_and_proxy_urls() {
        assert_eq!(ProxyConfig::parse("direct").unwrap(), ProxyConfig::Direct);
        assert!(matches!(
            ProxyConfig::parse("socks5://127.0.0.1:1080").unwrap(),
            ProxyConfig::Socks5 { auth: None, .. }
        ));
        assert!(matches!(
            ProxyConfig::parse("http://user:pass@127.0.0.1:8080").unwrap(),
            ProxyConfig::Http { auth: Some(_), .. }
        ));
    }

    #[test]
    fn rejects_unknown_or_invalid_proxies() {
        assert!(ProxyConfig::parse("").is_err());
        assert!(ProxyConfig::parse("ftp://127.0.0.1:21").is_err());
        assert!(ProxyConfig::parse("socks5://not-an-address").is_err());
    }
}
