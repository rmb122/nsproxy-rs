use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use anyhow::{Context, Result, bail};

/// A validated host-to-namespace TCP port publication.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PublishSpec {
    pub host_ip: Ipv4Addr,
    pub host_port: u16,
    pub namespace_port: u16,
}

impl PublishSpec {
    pub fn host_addr(self) -> SocketAddrV4 {
        SocketAddrV4::new(self.host_ip, self.host_port)
    }
}

/// A publication whose host-side listener has already been bound.
#[derive(Debug)]
pub struct BoundPublish {
    pub spec: PublishSpec,
    pub listener: TcpListener,
}

/// A bound listener registered with the parent's Tokio runtime.
#[derive(Debug)]
pub struct RegisteredPublish {
    pub spec: PublishSpec,
    pub listener: tokio::net::TcpListener,
}

/// Parse repeatable Docker-style TCP publication specifications.
///
/// Accepted forms are `HOST_PORT:NS_PORT[/tcp]` and
/// `HOST_IP:HOST_PORT:NS_PORT[/tcp]`. Only numeric IPv4 addresses and TCP are
/// supported.
pub fn parse_publish_specs(specs: &[String]) -> Result<Vec<PublishSpec>> {
    let mut host_endpoints = HashSet::new();
    let mut parsed = Vec::with_capacity(specs.len());

    for raw in specs {
        let spec = parse_publish_spec(raw)?;
        if !host_endpoints.insert((spec.host_ip, spec.host_port)) {
            bail!("duplicate published TCP endpoint {}", spec.host_addr());
        }
        parsed.push(spec);
    }

    Ok(parsed)
}

fn parse_publish_spec(raw: &str) -> Result<PublishSpec> {
    let (address, protocol) = match raw.split_once('/') {
        Some((address, protocol)) => (address, protocol),
        None => (raw, "tcp"),
    };

    if protocol != "tcp" {
        bail!("unsupported publish protocol {protocol:?} in {raw:?}; only tcp is supported");
    }

    let fields: Vec<&str> = address.split(':').collect();
    let (host_ip, host_port, namespace_port) = match fields.as_slice() {
        [host_port, namespace_port] => (
            Ipv4Addr::UNSPECIFIED,
            parse_port(host_port, "host", raw)?,
            parse_port(namespace_port, "namespace", raw)?,
        ),
        [host_ip, host_port, namespace_port] => (
            host_ip
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid host IPv4 address {host_ip:?} in {raw:?}"))?,
            parse_port(host_port, "host", raw)?,
            parse_port(namespace_port, "namespace", raw)?,
        ),
        _ => {
            bail!(
                "invalid publish specification {raw:?}: expected [HOST_IP:]HOST_PORT:NS_PORT[/tcp]"
            )
        }
    };

    Ok(PublishSpec {
        host_ip,
        host_port,
        namespace_port,
    })
}

fn parse_port(value: &str, side: &str, raw: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .with_context(|| format!("invalid {side} port {value:?} in {raw:?}"))?;
    if port == 0 {
        bail!("{side} port must be between 1 and 65535 in {raw:?}");
    }
    Ok(port)
}

/// Bind all host listeners before the namespace command is allowed to start.
pub fn bind_publish_specs(specs: &[PublishSpec]) -> Result<Vec<BoundPublish>> {
    specs
        .iter()
        .copied()
        .map(|spec| {
            let host_addr = spec.host_addr();
            let listener = TcpListener::bind(host_addr)
                .with_context(|| format!("bind published TCP endpoint {host_addr}"))?;
            listener
                .set_nonblocking(true)
                .with_context(|| format!("make published TCP endpoint {host_addr} nonblocking"))?;
            Ok(BoundPublish { spec, listener })
        })
        .collect()
}

/// Register already-bound listeners with the active Tokio runtime.
pub fn register_publish_specs(bound: Vec<BoundPublish>) -> Result<Vec<RegisteredPublish>> {
    bound
        .into_iter()
        .map(|published| {
            let host_addr = published.spec.host_addr();
            let listener = tokio::net::TcpListener::from_std(published.listener)
                .with_context(|| format!("register published TCP endpoint {host_addr}"))?;
            Ok(RegisteredPublish {
                spec: published.spec,
                listener,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(specs: &[&str]) -> Result<Vec<PublishSpec>> {
        parse_publish_specs(
            &specs
                .iter()
                .map(|spec| (*spec).to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn parses_supported_forms_and_defaults() {
        assert_eq!(
            parse(&["8080:80"]).unwrap(),
            [PublishSpec {
                host_ip: Ipv4Addr::UNSPECIFIED,
                host_port: 8080,
                namespace_port: 80,
            }]
        );
        assert_eq!(
            parse(&["127.0.0.1:8443:443/tcp"]).unwrap(),
            [PublishSpec {
                host_ip: Ipv4Addr::LOCALHOST,
                host_port: 8443,
                namespace_port: 443,
            }]
        );
    }

    #[test]
    fn accepts_multiple_distinct_publications() {
        let specs = parse(&["127.0.0.1:8080:80", "127.0.0.1:8443:443/tcp"]).unwrap();
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn rejects_invalid_syntax_addresses_ports_and_protocols() {
        for spec in [
            "",
            "80",
            "127.0.0.1:80",
            "name:8080:80",
            "[::1]:8080:80",
            "127.0.0.1:0:80",
            "127.0.0.1:8080:0",
            "127.0.0.1:65536:80",
            "127.0.0.1:8080:80/udp",
            "127.0.0.1:8080:80/TCP",
            "127.0.0.1:8080:80/tcp/extra",
        ] {
            assert!(parse(&[spec]).is_err(), "accepted invalid spec {spec:?}");
        }
    }

    #[test]
    fn rejects_duplicate_host_endpoint() {
        assert!(parse(&["127.0.0.1:8080:80", "127.0.0.1:8080:81/tcp"]).is_err());
    }

    #[test]
    fn bind_failure_is_reported() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let spec = PublishSpec {
            host_ip: Ipv4Addr::LOCALHOST,
            host_port: port,
            namespace_port: 80,
        };

        assert!(bind_publish_specs(&[spec]).is_err());
    }
}
