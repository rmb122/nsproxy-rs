use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

use crate::config::net::{DNS_ADDR, DNS_PORT};
use crate::fake_dns::{self, FakeDns};
use crate::proxy::ProxyTarget;

const UDP_META_COUNT: usize = 16;
const UDP_BUF_SIZE: usize = 4096;

/// Owns the intercepted DNS socket and its fake-IP mapping.
pub(super) struct DnsInterceptor {
    handle: SocketHandle,
    fake_dns: FakeDns,
}

impl DnsInterceptor {
    pub(super) fn new(sockets: &mut SocketSet<'static>) -> Self {
        let rx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_COUNT],
            vec![0u8; UDP_BUF_SIZE],
        );
        let tx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_COUNT],
            vec![0u8; UDP_BUF_SIZE],
        );
        let mut socket = udp::Socket::new(rx_buf, tx_buf);
        socket
            .bind(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(DNS_ADDR)),
                port: DNS_PORT,
            })
            .expect("bind DNS UDP socket");

        Self {
            handle: sockets.add(socket),
            fake_dns: FakeDns::new(),
        }
    }

    pub(super) fn process(&mut self, sockets: &mut SocketSet<'static>) {
        let socket = sockets.get_mut::<udp::Socket>(self.handle);
        while socket.can_recv() {
            let mut dns_buf = [0u8; 1500];
            let Ok((len, meta)) = socket.recv_slice(&mut dns_buf) else {
                break;
            };
            let data = &dns_buf[..len];
            let Some((id, domain, qtype)) = fake_dns::parse_query(data) else {
                continue;
            };

            let response = if qtype == 1 {
                let ip = self.fake_dns.resolve(&domain);
                tracing::debug!("DNS: {domain} → {ip}");
                fake_dns::build_a_response(id, &domain, ip)
            } else {
                tracing::debug!("DNS: {domain} qtype={qtype} → empty");
                fake_dns::build_empty_response(id, &domain, qtype)
            };

            if socket.can_send() {
                let _ = socket.send_slice(&response, meta.endpoint);
            }
        }
    }

    /// Recover the original domain for fake IPs, otherwise retain the numeric
    /// destination used by the namespace application.
    pub(super) fn target_for(&self, addr: std::net::Ipv4Addr, port: u16) -> ProxyTarget {
        if self.fake_dns.is_fake_ip(addr)
            && let Some(domain) = self.fake_dns.lookup(addr)
        {
            return ProxyTarget::Domain {
                host: domain.to_string(),
                port,
            };
        }

        ProxyTarget::Ip {
            addr: std::net::IpAddr::V4(addr),
            port,
        }
    }
}
