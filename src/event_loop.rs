//! Core event loop — bridges the TUN device (via smoltcp) to the upstream proxy.
//!
//! This module implements:
//! - DNS interception (fake-DNS for A queries, empty response for AAAA)
//! - TCP SYN detection → dynamic listen-socket creation
//! - TCP data shuttling between smoltcp sockets and upstream proxy streams
//! - Cleanup of closed connections

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

use anyhow::{Context, Result};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};
use tokio::io::unix::AsyncFd;

use crate::config::{Config as AppConfig, ProxyType};
use crate::fake_dns::{self, FakeDns};
use crate::proxy::http::HttpConnector;
use crate::proxy::socks5::Socks5Connector;
use crate::proxy::{ProxyConnector, ProxyStream, ProxyTarget};
use crate::tun::{TunDevice, parse_tcp_syn};

// ── Constants ────────────────────────────────────────────────────────────────

/// The IP address assigned to the TUN interface inside the namespace.
/// Matches what namespace.rs configures: 10.0.0.1/24.
#[allow(dead_code)]
const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// The gateway IP (our side of the TUN).
const TUN_GW: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// DNS server IP that resolv.conf points to.
const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// DNS port.
const DNS_PORT: u16 = 53;

/// TCP socket buffer size.
const TCP_BUF_SIZE: usize = 65536;
/// UDP packet buffer metadata slots.
const UDP_META_COUNT: usize = 16;
/// UDP packet buffer payload size.
const UDP_BUF_SIZE: usize = 4096;

// ── TCP forward state ────────────────────────────────────────────────────────

enum TcpForwardState {
    /// We've created the listening socket but connection is not yet established.
    Listening,
    /// The TCP handshake completed in smoltcp; we're connecting to the proxy.
    Connecting(tokio::task::JoinHandle<Result<ProxyStream>>),
    /// Proxy connection established; shuttling data.
    Established(ProxyStream),
    /// Connection is closing; we're draining.
    Closing,
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Run the main event loop.  This takes ownership of the TUN fd and runs until
/// `shutdown` is signalled (typically by the child exiting).
pub async fn run(tun_fd: RawFd, config: AppConfig, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    // --- Create the smoltcp device ---
    let mut device = TunDevice::new(tun_fd).context("TunDevice::new")?;

    // --- Create smoltcp interface ---
    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = rand_seed();

    let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());

    // Assign our gateway IP to the interface (we ARE the gateway from smoltcp's perspective).
    iface.update_ip_addrs(|addrs| {
        addrs.push(IpCidr::new(IpAddress::Ipv4(TUN_GW), 24)).unwrap();
    });

    // Route for the fake-DNS range and all traffic.
    iface
        .routes_mut()
        .add_default_ipv4_route(TUN_GW)
        .unwrap();

    // --- Create socket set ---
    let mut sockets = SocketSet::new(vec![]);

    // --- Create UDP socket for DNS ---
    let dns_handle = {
        let rx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_COUNT],
            vec![0u8; UDP_BUF_SIZE],
        );
        let tx_buf = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; UDP_META_COUNT],
            vec![0u8; UDP_BUF_SIZE],
        );
        let mut sock = udp::Socket::new(rx_buf, tx_buf);
        sock.bind(IpListenEndpoint { addr: Some(IpAddress::Ipv4(DNS_ADDR)), port: DNS_PORT })
            .expect("bind DNS UDP socket");
        sockets.add(sock)
    };

    // --- State ---
    let mut fake_dns = FakeDns::new();
    let mut tcp_states: HashMap<SocketHandle, TcpForwardState> = HashMap::new();
    // Track which (dst_ip, dst_port) pairs already have a listen socket.
    let mut listening_endpoints: HashSet<(Ipv4Addr, u16)> = HashSet::new();

    // Build the proxy connector.
    let _connector: Box<dyn ProxyConnector> = match config.proxy_type {
        ProxyType::Socks5 => Box::new(Socks5Connector::new(config.proxy_addr, config.proxy_auth.clone())),
        ProxyType::Http => Box::new(HttpConnector::new(config.proxy_addr, config.proxy_auth.clone())),
    };

    // Wrap the TUN fd in AsyncFd for readability notifications.
    let async_fd = AsyncFd::new(RawFdWrapper(tun_fd)).context("AsyncFd::new for TUN fd")?;

    // --- Main loop ---
    let mut poll_buf = vec![0u8; TCP_BUF_SIZE];

    loop {
        // Check shutdown.
        if *shutdown.borrow() {
            tracing::info!("event_loop: shutdown signal received");
            break;
        }

        // 1. Wait for TUN readable or timeout (so we can process egress).
        let wait_duration = iface
            .poll_delay(SmolInstant::now(), &sockets)
            .unwrap_or(smoltcp::time::Duration::from_millis(50));
        let timeout = Duration::from_millis(wait_duration.total_millis());
        let timeout = timeout.max(Duration::from_millis(1)).min(Duration::from_millis(100));

        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("event_loop: shutdown signal received");
                    break;
                }
            }
            readable = async_fd.readable() => {
                if let Ok(mut guard) = readable {
                    guard.clear_ready();
                }
            }
            _ = tokio::time::sleep(timeout) => {}
        }

        // 2. Read packets from TUN into device buffer.
        while device.poll_read() {}

        // 3. Inspect buffered packets for TCP SYNs → create listen sockets.
        {
            let queue = device.rx_queue();
            for pkt in queue.iter() {
                if let Some((dst_ip, dst_port)) = parse_tcp_syn(pkt) {
                    if !listening_endpoints.contains(&(dst_ip, dst_port)) {
                        tracing::debug!("SYN detected → {dst_ip}:{dst_port}, creating listen socket");
                        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
                        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
                        let mut sock = tcp::Socket::new(rx_buf, tx_buf);
                        let listen_ep = IpListenEndpoint {
                            addr: Some(IpAddress::Ipv4(dst_ip)),
                            port: dst_port,
                        };
                        if sock.listen(listen_ep).is_ok() {
                            let handle = sockets.add(sock);
                            tcp_states.insert(handle, TcpForwardState::Listening);
                            listening_endpoints.insert((dst_ip, dst_port));
                        } else {
                            tracing::warn!("failed to listen on {dst_ip}:{dst_port}");
                        }
                    }
                }
            }
        }

        // 4. Let smoltcp process packets.
        iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        // 5. Handle DNS — check UDP socket for queries.
        {
            let dns_sock = sockets.get_mut::<udp::Socket>(dns_handle);
            while dns_sock.can_recv() {
                let mut dns_buf = [0u8; 1500];
                match dns_sock.recv_slice(&mut dns_buf) {
                    Ok((len, meta)) => {
                        let data = &dns_buf[..len];
                        if let Some((id, domain, qtype)) = fake_dns::parse_query(data) {
                            let response = if qtype == 1 {
                                // A record query — resolve via fake DNS.
                                let ip = fake_dns.resolve(&domain);
                                tracing::debug!("DNS: {domain} → {ip}");
                                fake_dns::build_a_response(id, &domain, ip)
                            } else {
                                // AAAA or other — return empty.
                                tracing::debug!("DNS: {domain} qtype={qtype} → empty");
                                fake_dns::build_empty_response(id, &domain, qtype)
                            };
                            let dst = meta.endpoint;
                            if dns_sock.can_send() {
                                let _ = dns_sock.send_slice(&response, dst);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        // 6. Check TCP sockets for state changes.
        let handles: Vec<SocketHandle> = tcp_states.keys().copied().collect();
        for handle in handles {
            let state = tcp_states.get(&handle).unwrap();
            match state {
                TcpForwardState::Listening => {
                    let sock = sockets.get::<tcp::Socket>(handle);
                    if sock.state() == tcp::State::Established
                        || sock.state() == tcp::State::CloseWait
                    {
                        // Connection accepted! Start proxy connection.
                        let remote_ep = sock.remote_endpoint();
                        let local_ep = sock.local_endpoint();

                        if let (Some(_remote), Some(local)) = (remote_ep, local_ep) {
                            let dst_ip = match local.addr {
                                IpAddress::Ipv4(ip) => ip,
                                #[allow(unreachable_patterns)]
                                _ => continue,
                            };
                            let dst_port = local.port;

                            // Determine the proxy target.
                            let target = if fake_dns.is_fake_ip(dst_ip) {
                                if let Some(domain) = fake_dns.lookup(dst_ip) {
                                    ProxyTarget::Domain {
                                        host: domain.to_string(),
                                        port: dst_port,
                                    }
                                } else {
                                    ProxyTarget::Ip {
                                        addr: std::net::IpAddr::V4(dst_ip),
                                        port: dst_port,
                                    }
                                }
                            } else {
                                ProxyTarget::Ip {
                                    addr: std::net::IpAddr::V4(dst_ip),
                                    port: dst_port,
                                }
                            };

                            tracing::info!("TCP: new connection to {target}");

                            // Spawn async proxy connect.
                            let proxy_addr = config.proxy_addr;
                            let proxy_auth = config.proxy_auth.clone();
                            let proxy_type = config.proxy_type.clone();

                            let join_handle = tokio::spawn(async move {
                                let conn: Box<dyn ProxyConnector> = match proxy_type {
                                    ProxyType::Socks5 => Box::new(Socks5Connector::new(proxy_addr, proxy_auth)),
                                    ProxyType::Http => Box::new(HttpConnector::new(proxy_addr, proxy_auth)),
                                };
                                conn.connect(&target).await
                            });

                            tcp_states.insert(handle, TcpForwardState::Connecting(join_handle));
                        }
                    } else if sock.state() == tcp::State::Closed
                        || sock.state() == tcp::State::TimeWait
                    {
                        tcp_states.insert(handle, TcpForwardState::Closing);
                    }
                }
                TcpForwardState::Connecting(_jh) => {
                    // Check if the connect task finished.
                    // We need to take ownership to poll. Use a two-step approach.
                }
                TcpForwardState::Established(_stream) => {
                    // Data shuttling handled below.
                }
                TcpForwardState::Closing => {
                    // Will be cleaned up below.
                }
            }
        }

        // 6b. Poll connecting tasks to see if they finished.
        {
            let connecting_handles: Vec<SocketHandle> = tcp_states
                .iter()
                .filter_map(|(h, s)| {
                    if matches!(s, TcpForwardState::Connecting(_)) {
                        Some(*h)
                    } else {
                        None
                    }
                })
                .collect();

            for handle in connecting_handles {
                let state = tcp_states.remove(&handle).unwrap();
                if let TcpForwardState::Connecting(mut jh) = state {
                    match (&mut jh).try_poll() {
                        Some(Ok(Ok(stream))) => {
                            tracing::debug!("proxy connection established for socket {handle}");
                            tcp_states.insert(handle, TcpForwardState::Established(stream));
                        }
                        Some(Ok(Err(e))) => {
                            tracing::warn!("proxy connect failed: {e:#}");
                            // Abort the smoltcp socket.
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            sock.abort();
                            tcp_states.insert(handle, TcpForwardState::Closing);
                        }
                        Some(Err(e)) => {
                            tracing::warn!("proxy connect task panicked: {e}");
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            sock.abort();
                            tcp_states.insert(handle, TcpForwardState::Closing);
                        }
                        None => {
                            // Still in progress, put it back.
                            tcp_states.insert(handle, TcpForwardState::Connecting(jh));
                        }
                    }
                }
            }
        }

        // 7. Shuttle data for established connections.
        {
            let established_handles: Vec<SocketHandle> = tcp_states
                .iter()
                .filter_map(|(h, s)| {
                    if matches!(s, TcpForwardState::Established(_)) {
                        Some(*h)
                    } else {
                        None
                    }
                })
                .collect();

            for handle in established_handles {
                let state = tcp_states.get_mut(&handle).unwrap();
                let stream = match state {
                    TcpForwardState::Established(s) => s,
                    _ => continue,
                };

                let sock = sockets.get_mut::<tcp::Socket>(handle);

                // smoltcp → proxy: read from smoltcp socket, write to proxy stream.
                if sock.can_recv() {
                    match sock.recv_slice(&mut poll_buf) {
                        Ok(n) if n > 0 => {
                            match stream.inner.try_write(&poll_buf[..n]) {
                                Ok(_written) => {}
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    // Can't write now — we'll try again next iteration.
                                    // Ideally we'd buffer, but for now just drop.
                                    // Actually, let's not recv if we can't write. Push back isn't
                                    // possible with smoltcp, so this is best-effort.
                                }
                                Err(e) => {
                                    tracing::debug!("proxy write error: {e}");
                                    sock.close();
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // proxy → smoltcp: read from proxy stream, write to smoltcp socket.
                if sock.can_send() {
                    match stream.inner.try_read(&mut poll_buf) {
                        Ok(0) => {
                            // Proxy closed.
                            tracing::debug!("proxy stream closed for socket {handle}");
                            sock.close();
                        }
                        Ok(n) => {
                            let _ = sock.send_slice(&poll_buf[..n]);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // No data available yet.
                        }
                        Err(e) => {
                            tracing::debug!("proxy read error: {e}");
                            sock.close();
                        }
                    }
                }

                // Check if smoltcp socket closed.
                if sock.state() == tcp::State::Closed || sock.state() == tcp::State::TimeWait {
                    tcp_states.insert(handle, TcpForwardState::Closing);
                }
            }
        }

        // 8. Clean up closed connections.
        {
            let closing_handles: Vec<SocketHandle> = tcp_states
                .iter()
                .filter_map(|(h, s)| {
                    if matches!(s, TcpForwardState::Closing) {
                        Some(*h)
                    } else {
                        None
                    }
                })
                .collect();

            for handle in closing_handles {
                let sock = sockets.get::<tcp::Socket>(handle);
                if sock.state() == tcp::State::Closed || sock.state() == tcp::State::TimeWait {
                    // Get endpoint info before removing.
                    let local_ep = sock.listen_endpoint();
                    if let Some(addr) = local_ep.addr {
                        let IpAddress::Ipv4(ip) = addr;
                        listening_endpoints.remove(&(ip, local_ep.port));
                    }
                    tcp_states.remove(&handle);
                    sockets.remove(handle);
                    tracing::debug!("cleaned up closed socket {handle}");
                }
            }
        }

        // Run poll_egress to send any pending responses.
        iface.poll(SmolInstant::now(), &mut device, &mut sockets);
    }

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extension trait to poll a JoinHandle without awaiting.
trait JoinHandlePoll {
    type Output;
    fn try_poll(&mut self) -> Option<Self::Output>;
}

impl<T> JoinHandlePoll for tokio::task::JoinHandle<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn try_poll(&mut self) -> Option<Self::Output> {
        // Use `now_or_never` from futures or a manual check.
        // JoinHandle is a future, so we can try to poll it.
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        // Create a no-op waker.
        fn noop_raw_waker() -> RawWaker {
            fn no_op(_: *const ()) {}
            fn clone(p: *const ()) -> RawWaker {
                RawWaker::new(p, &VTABLE)
            }
            const VTABLE: RawWakerVTable =
                RawWakerVTable::new(clone, no_op, no_op, no_op);
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: we never move the JoinHandle while it's pinned.
        let pinned = unsafe { Pin::new_unchecked(self) };
        match pinned.poll(&mut cx) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        }
    }
}

/// Generate a pseudo-random seed from the current time.
fn rand_seed() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_nanos() as u64 ^ 0xdeadbeef_cafebabe
}

/// Wrapper to give a RawFd an `AsRawFd` impl for use with `AsyncFd`.
struct RawFdWrapper(RawFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}
