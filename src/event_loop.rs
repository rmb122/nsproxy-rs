//! Core event loop — bridges the TUN device (via smoltcp) to the upstream proxy.
//!
//! This module implements:
//! - DNS interception (fake-DNS for A queries, empty response for AAAA)
//! - TCP SYN detection → dynamic listen-socket creation
//! - TCP data shuttling between smoltcp sockets and upstream proxy streams
//! - Cleanup of closed connections

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};
use tokio::io::unix::AsyncFd;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::Config as AppConfig;
use crate::config::net::{DNS_ADDR, DNS_PORT, TUN_ADDR, TUN_GW, TUN_PREFIX};
use crate::fake_dns::{self, FakeDns};
use crate::proxy::{ProxyStream, ProxyTarget};
use crate::publish::{PublishSpec, RegisteredPublish};
use crate::tun::{TunDevice, parse_tcp_syn};

// ── Constants ────────────────────────────────────────────────────────────────

/// TCP socket buffer size.
const TCP_BUF_SIZE: usize = 65536;
/// Maximum time to retain a socket whose inbound TCP handshake has not completed.
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(32);
/// UDP packet buffer metadata slots.
const UDP_META_COUNT: usize = 16;
/// UDP packet buffer payload size.
const UDP_BUF_SIZE: usize = 4096;
/// Dynamic source ports used for host-to-namespace published connections.
const PUBLISH_PORT_MIN: u16 = 49152;
const PUBLISH_PORT_MAX: u16 = 65535;
/// Accepted host sockets waiting to be attached to smoltcp.
const PUBLISH_ACCEPT_QUEUE: usize = 128;

// ── TCP forward state ────────────────────────────────────────────────────────

enum TcpForwardState {
    /// We've created the listening socket but connection is not yet established.
    Listening { created_at: Instant },
    /// The TCP handshake completed in smoltcp; we're connecting to the proxy.
    Connecting(tokio::task::JoinHandle<Result<ProxyStream>>),
    /// Proxy connection established; shuttling data.
    Established(TcpForwardCtx),
    /// Connection is closing; we're draining.
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyReadState {
    Open,
    Eof,
    Failed,
}

/// Context for an established TCP forwarding connection.
struct TcpForwardCtx {
    stream: ProxyStream,
    /// Data read from proxy, waiting to be written to smoltcp socket.
    proxy_to_app: Vec<u8>,
    /// Whether the upstream is still readable, reached a normal EOF, or failed.
    proxy_read_state: ProxyReadState,
}

// ── Published TCP state ──────────────────────────────────────────────────────

struct AcceptedPublishedTcp {
    stream: TcpStream,
    peer_addr: SocketAddr,
    spec: PublishSpec,
}

enum PublishedTcpState {
    /// SYN has been sent through the TUN and the namespace handshake is pending.
    Connecting {
        stream: TcpStream,
        peer_addr: SocketAddr,
        created_at: Instant,
    },
    /// Namespace connection established; shuttle data in both directions.
    Established(PublishedTcpCtx),
    /// RST/FIN has been driven through smoltcp and the socket can be removed.
    Closing,
}

struct PublishedTcpCtx {
    stream: TcpStream,
    peer_addr: SocketAddr,
    /// Bytes already read from the host peer but not yet queued in smoltcp.
    host_to_namespace: Vec<u8>,
    /// An EOF was observed on either side; stop host reads and close the whole
    /// connection once the forwarding queues have drained.
    close_after_drain: bool,
}

struct PublishedPortAllocator {
    next: u16,
    used: HashSet<u16>,
}

impl PublishedPortAllocator {
    fn new() -> Self {
        Self {
            next: PUBLISH_PORT_MIN,
            used: HashSet::new(),
        }
    }

    fn allocate(&mut self) -> Option<u16> {
        let capacity = usize::from(PUBLISH_PORT_MAX - PUBLISH_PORT_MIN) + 1;
        for _ in 0..capacity {
            let candidate = self.next;
            self.next = if candidate == PUBLISH_PORT_MAX {
                PUBLISH_PORT_MIN
            } else {
                candidate + 1
            };
            if self.used.insert(candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn release(&mut self, port: u16) {
        self.used.remove(&port);
    }
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Run the main event loop.  This takes ownership of the TUN fd and runs until
/// `shutdown` is signalled (typically by the child exiting).
pub async fn run(
    tun_fd: RawFd,
    config: AppConfig,
    registered_publishes: Vec<RegisteredPublish>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    // --- Create the smoltcp device ---
    let mut device = TunDevice::new(tun_fd).context("TunDevice::new")?;

    // --- Create smoltcp interface ---
    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = rand_seed();

    let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());

    // Add our gateway IP. With any_ip=true set below, smoltcp will accept
    // packets for ANY destination, not just this IP.
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(TUN_GW), TUN_PREFIX))
            .unwrap();
    });

    // Route for the fake-DNS range and all traffic.
    iface.routes_mut().add_default_ipv4_route(TUN_GW).unwrap();

    // Accept packets for ANY destination IP (not just our own).
    // This is essential: apps connect to fake IPs (198.18.x.x) and real IPs,
    // all of which arrive at our TUN. Without this, smoltcp drops them.
    iface.set_any_ip(true);

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
        sock.bind(IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(DNS_ADDR)),
            port: DNS_PORT,
        })
        .expect("bind DNS UDP socket");
        sockets.add(sock)
    };

    // Wrap the TUN fd in AsyncFd for readability notifications before
    // spawning any background accept tasks.
    let async_fd = AsyncFd::new(RawFdWrapper(tun_fd)).context("AsyncFd::new for TUN fd")?;

    // --- State ---
    let mut fake_dns = FakeDns::new();
    let mut tcp_states: HashMap<SocketHandle, TcpForwardState> = HashMap::new();
    // Track which (src_ip, src_port, dst_ip, dst_port) 4-tuples already have a listen socket.
    // This prevents duplicate sockets for SYN retransmits, while allowing
    // multiple connections to the same dst_ip:dst_port (different src ports).
    let mut listening_endpoints: HashSet<(Ipv4Addr, u16, Ipv4Addr, u16)> = HashSet::new();
    // Reverse map: socket handle → 4-tuple, for cleanup
    let mut handle_to_endpoint: HashMap<SocketHandle, (Ipv4Addr, u16, Ipv4Addr, u16)> =
        HashMap::new();

    let mut published_states: HashMap<SocketHandle, PublishedTcpState> = HashMap::new();
    let mut published_handle_to_port: HashMap<SocketHandle, u16> = HashMap::new();
    let mut published_ports = PublishedPortAllocator::new();

    // Each listener gets a small accept task. Accepted streams are handed back
    // to this single owner of the smoltcp Interface and SocketSet.
    let (accepted_tx, mut accepted_rx) = mpsc::channel(PUBLISH_ACCEPT_QUEUE);
    let mut accept_tasks = Vec::with_capacity(registered_publishes.len());
    for published in registered_publishes {
        let listener = published.listener;
        let tx = accepted_tx.clone();
        let spec = published.spec;
        accept_tasks.push(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        if tx
                            .send(AcceptedPublishedTcp {
                                stream,
                                peer_addr,
                                spec,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            "accept failed on published TCP endpoint {}: {error}",
                            spec.host_addr()
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }));
    }
    // Keep one sender alive so recv() remains pending when there are no
    // publications (or if all accept tasks terminate).
    let _accepted_tx = accepted_tx;

    // --- Main loop ---

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
        let timeout = timeout
            .max(Duration::from_millis(1))
            .min(Duration::from_millis(100));

        let mut accepted_connections = Vec::new();
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("event_loop: shutdown signal received");
                    break;
                }
            }
            accepted = accepted_rx.recv() => {
                if let Some(accepted) = accepted {
                    accepted_connections.push(accepted);
                }
            }
            readable = async_fd.readable() => {
                if let Ok(mut guard) = readable {
                    guard.clear_ready();
                }
            }
            _ = tokio::time::sleep(timeout) => {}
        }

        // Drain connections already accepted without delaying TUN processing.
        while let Ok(accepted) = accepted_rx.try_recv() {
            accepted_connections.push(accepted);
        }

        // 2. Read packets from TUN into device buffer.
        while device.poll_read() {}

        // 3. Inspect buffered packets for TCP SYNs → create listen sockets.
        {
            let queue = device.rx_queue();
            for pkt in queue.iter() {
                if let Some((src_ip, src_port, dst_ip, dst_port)) = parse_tcp_syn(pkt) {
                    let key = (src_ip, src_port, dst_ip, dst_port);
                    if !listening_endpoints.contains(&key) {
                        tracing::debug!(
                            "SYN detected → {dst_ip}:{dst_port}, creating listen socket"
                        );
                        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
                        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
                        let mut sock = tcp::Socket::new(rx_buf, tx_buf);
                        // Listen with addr: None so smoltcp accepts packets to ANY dst IP
                        // (traffic to fake IPs like 198.18.x.x arrives at our TUN)
                        let listen_ep = IpListenEndpoint {
                            addr: None,
                            port: dst_port,
                        };
                        if sock.listen(listen_ep).is_ok() {
                            let handle = sockets.add(sock);
                            tcp_states.insert(
                                handle,
                                TcpForwardState::Listening {
                                    created_at: Instant::now(),
                                },
                            );
                            listening_endpoints.insert(key);
                            handle_to_endpoint.insert(handle, key);
                        } else {
                            tracing::warn!("failed to listen on {dst_ip}:{dst_port}");
                        }
                    }
                }
            }
        }

        // 3b. Turn newly accepted host streams into active smoltcp connections
        // to the namespace TUN address. The TUN gateway and an allocated
        // ephemeral port are used as the source, so the namespace never sees
        // the real external peer address.
        for accepted in accepted_connections {
            let Some(local_port) = published_ports.allocate() else {
                tracing::warn!(
                    "published TCP source-port pool exhausted; dropping connection from {}",
                    accepted.peer_addr
                );
                continue;
            };

            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let mut sock = tcp::Socket::new(rx_buf, tx_buf);
            let remote = (IpAddress::Ipv4(TUN_ADDR), accepted.spec.namespace_port);
            let local = (IpAddress::Ipv4(TUN_GW), local_port);

            if let Err(error) = sock.connect(iface.context(), remote, local) {
                tracing::warn!(
                    "failed to connect published TCP peer {} to {}:{}: {error}",
                    accepted.peer_addr,
                    TUN_ADDR,
                    accepted.spec.namespace_port
                );
                published_ports.release(local_port);
                continue;
            }

            let handle = sockets.add(sock);
            tracing::debug!(
                "published TCP peer {} -> {}:{} using {}:{} (socket {handle})",
                accepted.peer_addr,
                TUN_ADDR,
                accepted.spec.namespace_port,
                TUN_GW,
                local_port
            );
            published_states.insert(
                handle,
                PublishedTcpState::Connecting {
                    stream: accepted.stream,
                    peer_addr: accepted.peer_addr,
                    created_at: Instant::now(),
                },
            );
            published_handle_to_port.insert(handle, local_port);
        }

        // 4. Let smoltcp process packets.
        iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        // Debug: print TCP socket states
        for (handle, state) in tcp_states.iter() {
            if matches!(state, TcpForwardState::Listening { .. }) {
                let sock = sockets.get::<tcp::Socket>(*handle);
                let s = sock.state();
                if s != tcp::State::Listen {
                    tracing::debug!(
                        "socket {handle}: state={s:?} local={:?} remote={:?}",
                        sock.local_endpoint(),
                        sock.remote_endpoint()
                    );
                }
            }
        }

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
                TcpForwardState::Listening { created_at } => {
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

                            let proxy = config.proxy_for(&target).clone();
                            tracing::info!("TCP: new connection to {target} via {proxy}");

                            let join_handle =
                                tokio::spawn(async move { proxy.connect(&target).await });

                            tcp_states.insert(handle, TcpForwardState::Connecting(join_handle));
                        }
                    } else if sock.state() == tcp::State::Closed
                        || sock.state() == tcp::State::TimeWait
                    {
                        tcp_states.insert(handle, TcpForwardState::Closing);
                    } else if created_at.elapsed() >= TCP_HANDSHAKE_TIMEOUT {
                        tracing::debug!(
                            "TCP handshake timed out for socket {handle} in state {:?}",
                            sock.state()
                        );
                        let sock = sockets.get_mut::<tcp::Socket>(handle);
                        sock.abort();
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
                    match jh.try_poll() {
                        Some(Ok(Ok(stream))) => {
                            tracing::debug!("proxy connection established for socket {handle}");
                            tcp_states.insert(
                                handle,
                                TcpForwardState::Established(TcpForwardCtx {
                                    stream,
                                    proxy_to_app: Vec::new(),
                                    proxy_read_state: ProxyReadState::Open,
                                }),
                            );
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
                            // Proxy connect still in progress. If the client
                            // meanwhile reset / closed the smoltcp socket,
                            // there's no one left to hand the stream to —
                            // abort the task so it doesn't linger (e.g. a
                            // hung proxy connect waiting on Linux TCP timeout
                            // would otherwise stay pending for minutes).
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            let client_gone = matches!(
                                sock.state(),
                                tcp::State::Closed
                                    | tcp::State::Closing
                                    | tcp::State::TimeWait
                                    | tcp::State::FinWait1
                                    | tcp::State::FinWait2
                                    | tcp::State::LastAck
                            );
                            if client_gone {
                                tracing::debug!(
                                    "client gone while proxy connecting (socket {handle}, state {:?}); aborting connect",
                                    sock.state()
                                );
                                jh.abort();
                                sock.abort();
                                tcp_states.insert(handle, TcpForwardState::Closing);
                            } else {
                                // Still in progress, put it back.
                                tcp_states.insert(handle, TcpForwardState::Connecting(jh));
                            }
                        }
                    }
                }
            }
        }

        // 6c. Check namespace-side handshakes for published TCP connections.
        {
            let connecting_handles: Vec<SocketHandle> = published_states
                .iter()
                .filter_map(|(handle, state)| {
                    matches!(state, PublishedTcpState::Connecting { .. }).then_some(*handle)
                })
                .collect();

            for handle in connecting_handles {
                let state = published_states.remove(&handle).unwrap();
                let PublishedTcpState::Connecting {
                    stream,
                    peer_addr,
                    created_at,
                } = state
                else {
                    unreachable!();
                };
                let sock = sockets.get_mut::<tcp::Socket>(handle);

                if matches!(
                    sock.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    tracing::info!(
                        "TCP publish: connected host peer {peer_addr} (socket {handle})"
                    );
                    published_states.insert(
                        handle,
                        PublishedTcpState::Established(PublishedTcpCtx {
                            stream,
                            peer_addr,
                            host_to_namespace: Vec::new(),
                            close_after_drain: false,
                        }),
                    );
                } else if matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait) {
                    tracing::debug!(
                        "namespace refused published TCP peer {peer_addr} (socket {handle})"
                    );
                    published_states.insert(handle, PublishedTcpState::Closing);
                } else if created_at.elapsed() >= TCP_HANDSHAKE_TIMEOUT {
                    tracing::warn!(
                        "published TCP handshake timed out for host peer {peer_addr} (socket {handle})"
                    );
                    sock.abort();
                    published_states.insert(handle, PublishedTcpState::Closing);
                } else {
                    published_states.insert(
                        handle,
                        PublishedTcpState::Connecting {
                            stream,
                            peer_addr,
                            created_at,
                        },
                    );
                }
            }
        }

        // 7. Shuttle data for established connections.
        {
            let mut tmp_buf = vec![0u8; TCP_BUF_SIZE];
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
                let ctx = match state {
                    TcpForwardState::Established(c) => c,
                    _ => continue,
                };

                let sock = sockets.get_mut::<tcp::Socket>(handle);

                // --- App → Proxy direction ---
                // Read from smoltcp rx buffer and write to proxy.
                // Use recv() callback which gives us only one contiguous slice
                // (safe with ring buffer), and consume only what we successfully wrote.
                if sock.may_recv() && sock.can_recv() {
                    let stream_inner = &ctx.stream.inner;
                    let result = sock.recv(|data| {
                        if data.is_empty() {
                            return (0, Ok(0));
                        }
                        match stream_inner.try_write(data) {
                            Ok(written) => (written, Ok(written)),
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => (0, Ok(0)),
                            Err(e) => (0, Err(e)),
                        }
                    });
                    match result {
                        Ok(Err(e)) => {
                            tracing::debug!("proxy write error: {e}");
                            sock.abort();
                        }
                        Err(_) => {} // RecvError - socket not in a state to recv
                        _ => {}
                    }
                }

                // --- Proxy → App direction ---
                // 1. Read from proxy into proxy_to_app buffer (if buffer has space
                //    AND we haven't already seen EOF/error). A normal EOF waits
                //    for queued response data below; an error resets immediately.
                if ctx.proxy_read_state == ProxyReadState::Open
                    && ctx.proxy_to_app.len() < TCP_BUF_SIZE
                {
                    let space = TCP_BUF_SIZE - ctx.proxy_to_app.len();
                    match ctx.stream.inner.try_read(&mut tmp_buf[..space]) {
                        Ok(0) => {
                            // Proxy EOF — defer close until the buffer is drained.
                            tracing::debug!("proxy stream closed for socket {handle}");
                            ctx.proxy_read_state = ProxyReadState::Eof;
                        }
                        Ok(n) => {
                            ctx.proxy_to_app.extend_from_slice(&tmp_buf[..n]);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            tracing::debug!("proxy read error: {e}");
                            ctx.proxy_read_state = ProxyReadState::Failed;
                            sock.abort();
                        }
                    }
                }
                // 2. Drain proxy_to_app buffer into smoltcp socket
                if !ctx.proxy_to_app.is_empty() && sock.can_send() {
                    // Only write up to the free space in smoltcp's tx buffer
                    let free_space = TCP_BUF_SIZE.saturating_sub(sock.send_queue());
                    let send_len = free_space.min(ctx.proxy_to_app.len());
                    if send_len > 0 {
                        match sock.send_slice(&ctx.proxy_to_app[..send_len]) {
                            Ok(n) => {
                                ctx.proxy_to_app.drain(..n);
                            }
                            Err(_) => {
                                tracing::debug!("smoltcp send error for socket {handle}");
                                sock.abort();
                            }
                        }
                    }
                }

                // 3. After a normal upstream EOF, abort only once all response
                // bytes have been acknowledged by the client.
                let drained_after_eof = ctx.proxy_read_state == ProxyReadState::Eof
                    && ctx.proxy_to_app.is_empty()
                    && sock.send_queue() == 0
                    && sock.may_send();
                if drained_after_eof {
                    sock.abort();
                }

                // Client half-close remains intentionally unsupported: either
                // closed half aborts the whole connection.
                if !sock.may_recv() || !sock.may_send() {
                    sock.abort();
                    tcp_states.insert(handle, TcpForwardState::Closing);
                }
            }
        }

        // 7b. Shuttle data for host-to-namespace published connections.
        {
            let mut tmp_buf = vec![0u8; TCP_BUF_SIZE];
            let established_handles: Vec<SocketHandle> = published_states
                .iter()
                .filter_map(|(handle, state)| {
                    matches!(state, PublishedTcpState::Established(_)).then_some(*handle)
                })
                .collect();

            for handle in established_handles {
                let state = published_states.get_mut(&handle).unwrap();
                let PublishedTcpState::Established(ctx) = state else {
                    continue;
                };
                let sock = sockets.get_mut::<tcp::Socket>(handle);
                let mut failed = false;

                // --- Host peer -> namespace service ---
                if !ctx.close_after_drain && ctx.host_to_namespace.len() < TCP_BUF_SIZE {
                    let space = TCP_BUF_SIZE - ctx.host_to_namespace.len();
                    match ctx.stream.try_read(&mut tmp_buf[..space]) {
                        Ok(0) => {
                            tracing::debug!(
                                "published TCP host peer {} reached EOF (socket {handle})",
                                ctx.peer_addr
                            );
                            ctx.close_after_drain = true;
                        }
                        Ok(read) => ctx.host_to_namespace.extend_from_slice(&tmp_buf[..read]),
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => {
                            tracing::debug!(
                                "published TCP read error from host peer {}: {error}",
                                ctx.peer_addr
                            );
                            failed = true;
                        }
                    }
                }

                if !ctx.host_to_namespace.is_empty() && sock.can_send() {
                    let free_space = TCP_BUF_SIZE.saturating_sub(sock.send_queue());
                    let send_len = free_space.min(ctx.host_to_namespace.len());
                    if send_len > 0 {
                        match sock.send_slice(&ctx.host_to_namespace[..send_len]) {
                            Ok(sent) => {
                                ctx.host_to_namespace.drain(..sent);
                            }
                            Err(error) => {
                                tracing::debug!(
                                    "published TCP send error to namespace for peer {}: {error}",
                                    ctx.peer_addr
                                );
                                failed = true;
                            }
                        }
                    }
                }

                // --- Namespace service -> host peer ---
                if sock.can_recv() {
                    let host_stream = &ctx.stream;
                    let result = sock.recv(|data| {
                        if data.is_empty() {
                            return (0, Ok(0));
                        }
                        match host_stream.try_write(data) {
                            Ok(written) => (written, Ok(written)),
                            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                (0, Ok(0))
                            }
                            Err(error) => (0, Err(error)),
                        }
                    });
                    if let Ok(Err(error)) = result {
                        tracing::debug!(
                            "published TCP write error to host peer {}: {error}",
                            ctx.peer_addr
                        );
                        failed = true;
                    }
                }

                // Published connections deliberately do not preserve a TCP
                // half-close. Once either side reaches EOF, stop host reads and
                // close the whole bridge after its forwarding queues drain.
                if !sock.may_recv() && sock.recv_queue() == 0 {
                    ctx.close_after_drain = true;
                }

                let namespace_closed =
                    matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait);
                let drained_after_eof = ctx.close_after_drain
                    && ctx.host_to_namespace.is_empty()
                    && sock.send_queue() == 0
                    && sock.recv_queue() == 0;
                if failed || namespace_closed || drained_after_eof {
                    if !namespace_closed {
                        sock.abort();
                    }
                    published_states.insert(handle, PublishedTcpState::Closing);
                }
            }
        }

        // 8. Drive smoltcp so everything queued during this iteration is
        // actually flushed to the TUN interface:
        //   - DNS responses queued by `dns_sock.send_slice` in step 5,
        //   - TCP payload queued by `sock.send_slice` in step 7,
        //   - RST/FIN queued by `sock.abort()` / `sock.close()` in step 7.
        //
        // This MUST run before the cleanup in step 9: smoltcp's
        // `Socket::abort()` only marks the socket as "needs to send RST",
        // and the packet is emitted by the next `Interface::poll`. If we
        // removed the socket from the set first, smoltcp would have nothing
        // to emit on and the client would never see an RST/FIN — the
        // application (e.g. curl) would hang waiting for the server.
        iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        // 9. Clean up closed connections. By this point any RST/FIN they
        // had pending has already been transmitted by the poll above, so
        // it is safe to drop them from the set.
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
                // Deliberately no abort() here: the socket has already
                // been driven through poll(); a fresh abort would queue a
                // *new* RST that would be lost when we remove the socket.
                if let Some(key) = handle_to_endpoint.remove(&handle) {
                    listening_endpoints.remove(&key);
                }
                tcp_states.remove(&handle);
                sockets.remove(handle);
                tracing::debug!("cleaned up closed socket {handle}");
            }
        }

        {
            let closing_handles: Vec<SocketHandle> = published_states
                .iter()
                .filter_map(|(handle, state)| {
                    matches!(state, PublishedTcpState::Closing).then_some(*handle)
                })
                .collect();

            for handle in closing_handles {
                published_states.remove(&handle);
                sockets.remove(handle);
                if let Some(port) = published_handle_to_port.remove(&handle) {
                    published_ports.release(port);
                }
                tracing::debug!("cleaned up published TCP socket {handle}");
            }
        }
    }

    // Abort any in-flight proxy connect tasks so they don't linger past
    // event-loop shutdown. Dropping a JoinHandle does NOT cancel the task.
    for (_, state) in tcp_states.drain() {
        if let TcpForwardState::Connecting(jh) = state {
            jh.abort();
        }
    }
    for task in accept_tasks {
        task.abort();
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
            const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
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

#[cfg(test)]
mod published_port_tests {
    use super::*;

    #[test]
    fn allocator_returns_unique_ports_and_reuses_released_port() {
        let mut allocator = PublishedPortAllocator::new();
        let first = allocator.allocate().unwrap();
        let second = allocator.allocate().unwrap();
        assert_ne!(first, second);

        allocator.release(first);
        allocator.next = first;
        assert_eq!(allocator.allocate(), Some(first));
    }

    #[test]
    fn allocator_wraps_and_reports_exhaustion() {
        let mut allocator = PublishedPortAllocator::new();
        allocator.next = PUBLISH_PORT_MAX;
        assert_eq!(allocator.allocate(), Some(PUBLISH_PORT_MAX));
        assert_eq!(allocator.allocate(), Some(PUBLISH_PORT_MIN));

        while allocator.allocate().is_some() {}
        assert_eq!(allocator.allocate(), None);
    }
}
