pub mod http;
pub mod socks5;

use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

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
