//! Direct connector — opens a TCP connection straight to the target
//! from the host (i.e. outside the namespace) without going through any
//! upstream proxy.
//!
//! Used by the `--bypass` rule engine: traffic that matches a bypass rule
//! is dispatched here instead of through the configured SOCKS5/HTTP proxy.

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::net::TcpStream;

use super::{ProxyConnector, ProxyStream, ProxyTarget};

/// Connector that simply does `TcpStream::connect` to the target.
///
/// For domain targets the host's resolver is used.  Note that DNS leakage
/// is not a concern here — the user explicitly opted in by adding a
/// bypass rule that matches the domain.
pub struct DirectConnector;

#[async_trait]
impl ProxyConnector for DirectConnector {
    async fn connect(&self, target: &ProxyTarget) -> Result<ProxyStream> {
        let stream = match target {
            ProxyTarget::Ip { addr, port } => TcpStream::connect((*addr, *port))
                .await
                .with_context(|| format!("direct TCP connect to {addr}:{port}"))?,
            ProxyTarget::Domain { host, port } => TcpStream::connect((host.as_str(), *port))
                .await
                .with_context(|| format!("direct TCP connect to {host}:{port}"))?,
        };

        tracing::debug!("direct: connected to {}", target);
        Ok(ProxyStream { inner: stream })
    }
}
