use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpAddress;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::{TCP_BUF_SIZE, TCP_HANDSHAKE_TIMEOUT, new_tcp_socket};
use crate::config::net::{TUN_ADDR, TUN_GW};
use crate::publish::{PublishSpec, RegisteredPublish};

const PORT_MIN: u16 = 49152;
const PORT_MAX: u16 = 65535;
const ACCEPT_QUEUE: usize = 128;

struct AcceptedConnection {
    stream: TcpStream,
    peer_addr: SocketAddr,
    spec: PublishSpec,
}

enum State {
    Connecting {
        stream: TcpStream,
        peer_addr: SocketAddr,
        created_at: Instant,
    },
    Established(ConnectionContext),
    Closing,
}

struct ConnectionContext {
    stream: TcpStream,
    peer_addr: SocketAddr,
    host_to_namespace: Vec<u8>,
    close_after_drain: bool,
}

struct PortAllocator {
    next: u16,
    used: HashSet<u16>,
}

impl PortAllocator {
    fn new() -> Self {
        Self {
            next: PORT_MIN,
            used: HashSet::new(),
        }
    }

    fn allocate(&mut self) -> Option<u16> {
        let capacity = usize::from(PORT_MAX - PORT_MIN) + 1;
        for _ in 0..capacity {
            let candidate = self.next;
            self.next = if candidate == PORT_MAX {
                PORT_MIN
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

/// Owns host listeners and every host-originated connection into the namespace.
pub(super) struct PublishedTcp {
    states: HashMap<SocketHandle, State>,
    handle_to_port: HashMap<SocketHandle, u16>,
    ports: PortAllocator,
    accepted_rx: mpsc::Receiver<AcceptedConnection>,
    _accepted_tx: mpsc::Sender<AcceptedConnection>,
    pending: Vec<AcceptedConnection>,
    accept_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl PublishedTcp {
    pub(super) fn new(publishes: Vec<RegisteredPublish>) -> Self {
        let (accepted_tx, accepted_rx) = mpsc::channel(ACCEPT_QUEUE);
        let mut accept_tasks = Vec::with_capacity(publishes.len());

        for published in publishes {
            let listener = published.listener;
            let tx = accepted_tx.clone();
            let spec = published.spec;
            accept_tasks.push(tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer_addr)) => {
                            if tx
                                .send(AcceptedConnection {
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

        Self {
            states: HashMap::new(),
            handle_to_port: HashMap::new(),
            ports: PortAllocator::new(),
            accepted_rx,
            _accepted_tx: accepted_tx,
            pending: Vec::new(),
            accept_tasks,
        }
    }

    /// Wait for one host connection and stage it for the next event-loop tick.
    pub(super) async fn wait_for_accept(&mut self) {
        if let Some(accepted) = self.accepted_rx.recv().await {
            self.pending.push(accepted);
        }
    }

    /// Drain all accepted host streams and initiate corresponding smoltcp
    /// connections to the namespace TUN address.
    pub(super) fn attach_accepted(
        &mut self,
        interface: &mut Interface,
        sockets: &mut SocketSet<'static>,
    ) {
        while let Ok(accepted) = self.accepted_rx.try_recv() {
            self.pending.push(accepted);
        }

        for accepted in self.pending.drain(..) {
            let Some(local_port) = self.ports.allocate() else {
                tracing::warn!(
                    "published TCP source-port pool exhausted; dropping connection from {}",
                    accepted.peer_addr
                );
                continue;
            };

            let mut socket = new_tcp_socket();
            let remote = (IpAddress::Ipv4(TUN_ADDR), accepted.spec.namespace_port);
            let local = (IpAddress::Ipv4(TUN_GW), local_port);
            if let Err(error) = socket.connect(interface.context(), remote, local) {
                tracing::warn!(
                    "failed to connect published TCP peer {} to {}:{}: {error}",
                    accepted.peer_addr,
                    TUN_ADDR,
                    accepted.spec.namespace_port
                );
                self.ports.release(local_port);
                continue;
            }

            let handle = sockets.add(socket);
            tracing::debug!(
                "published TCP peer {} -> {}:{} using {}:{} (socket {handle})",
                accepted.peer_addr,
                TUN_ADDR,
                accepted.spec.namespace_port,
                TUN_GW,
                local_port
            );
            self.states.insert(
                handle,
                State::Connecting {
                    stream: accepted.stream,
                    peer_addr: accepted.peer_addr,
                    created_at: Instant::now(),
                },
            );
            self.handle_to_port.insert(handle, local_port);
        }
    }

    pub(super) fn process(&mut self, sockets: &mut SocketSet<'static>) {
        self.poll_connecting(sockets);
        self.shuttle_established(sockets);
    }

    fn poll_connecting(&mut self, sockets: &mut SocketSet<'static>) {
        let handles: Vec<_> = self
            .states
            .iter()
            .filter_map(|(handle, state)| {
                matches!(state, State::Connecting { .. }).then_some(*handle)
            })
            .collect();

        for handle in handles {
            let State::Connecting {
                stream,
                peer_addr,
                created_at,
            } = self.states.remove(&handle).unwrap()
            else {
                unreachable!();
            };
            let socket = sockets.get_mut::<tcp::Socket>(handle);

            if matches!(
                socket.state(),
                tcp::State::Established | tcp::State::CloseWait
            ) {
                tracing::info!("TCP publish: connected host peer {peer_addr} (socket {handle})");
                self.states.insert(
                    handle,
                    State::Established(ConnectionContext {
                        stream,
                        peer_addr,
                        host_to_namespace: Vec::new(),
                        close_after_drain: false,
                    }),
                );
            } else if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                tracing::debug!(
                    "namespace refused published TCP peer {peer_addr} (socket {handle})"
                );
                self.states.insert(handle, State::Closing);
            } else if created_at.elapsed() >= TCP_HANDSHAKE_TIMEOUT {
                tracing::warn!(
                    "published TCP handshake timed out for host peer {peer_addr} (socket {handle})"
                );
                socket.abort();
                self.states.insert(handle, State::Closing);
            } else {
                self.states.insert(
                    handle,
                    State::Connecting {
                        stream,
                        peer_addr,
                        created_at,
                    },
                );
            }
        }
    }

    fn shuttle_established(&mut self, sockets: &mut SocketSet<'static>) {
        let handles: Vec<_> = self
            .states
            .iter()
            .filter_map(|(handle, state)| matches!(state, State::Established(_)).then_some(*handle))
            .collect();
        let mut tmp_buf = vec![0u8; TCP_BUF_SIZE];

        for handle in handles {
            let State::Established(context) = self.states.get_mut(&handle).unwrap() else {
                continue;
            };
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            let mut failed = false;

            if !context.close_after_drain && context.host_to_namespace.len() < TCP_BUF_SIZE {
                let space = TCP_BUF_SIZE - context.host_to_namespace.len();
                match context.stream.try_read(&mut tmp_buf[..space]) {
                    Ok(0) => {
                        tracing::debug!(
                            "published TCP host peer {} reached EOF (socket {handle})",
                            context.peer_addr
                        );
                        context.close_after_drain = true;
                    }
                    Ok(read) => context
                        .host_to_namespace
                        .extend_from_slice(&tmp_buf[..read]),
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => {
                        tracing::debug!(
                            "published TCP read error from host peer {}: {error}",
                            context.peer_addr
                        );
                        failed = true;
                    }
                }
            }

            if !context.host_to_namespace.is_empty() && socket.can_send() {
                let free_space = TCP_BUF_SIZE.saturating_sub(socket.send_queue());
                let send_len = free_space.min(context.host_to_namespace.len());
                if send_len > 0 {
                    match socket.send_slice(&context.host_to_namespace[..send_len]) {
                        Ok(sent) => {
                            context.host_to_namespace.drain(..sent);
                        }
                        Err(error) => {
                            tracing::debug!(
                                "published TCP send error to namespace for peer {}: {error}",
                                context.peer_addr
                            );
                            failed = true;
                        }
                    }
                }
            }

            if socket.can_recv() {
                let stream = &context.stream;
                let result = socket.recv(|data| {
                    if data.is_empty() {
                        return (0, Ok(0));
                    }
                    match stream.try_write(data) {
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
                        context.peer_addr
                    );
                    failed = true;
                }
            }

            if !socket.may_recv() && socket.recv_queue() == 0 {
                context.close_after_drain = true;
            }

            let namespace_closed =
                matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait);
            let drained_after_eof = context.close_after_drain
                && context.host_to_namespace.is_empty()
                && socket.send_queue() == 0
                && socket.recv_queue() == 0;
            if failed || namespace_closed || drained_after_eof {
                if !namespace_closed {
                    socket.abort();
                }
                self.states.insert(handle, State::Closing);
            }
        }
    }

    pub(super) fn cleanup(&mut self, sockets: &mut SocketSet<'static>) {
        let handles: Vec<_> = self
            .states
            .iter()
            .filter_map(|(handle, state)| matches!(state, State::Closing).then_some(*handle))
            .collect();

        for handle in handles {
            self.states.remove(&handle);
            sockets.remove(handle);
            if let Some(port) = self.handle_to_port.remove(&handle) {
                self.ports.release(port);
            }
            tracing::debug!("cleaned up published TCP socket {handle}");
        }
    }
}

impl Drop for PublishedTcp {
    fn drop(&mut self) {
        for task in &self.accept_tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_returns_unique_ports_and_reuses_released_port() {
        let mut allocator = PortAllocator::new();
        let first = allocator.allocate().unwrap();
        let second = allocator.allocate().unwrap();
        assert_ne!(first, second);

        allocator.release(first);
        allocator.next = first;
        assert_eq!(allocator.allocate(), Some(first));
    }

    #[test]
    fn allocator_wraps_and_reports_exhaustion() {
        let mut allocator = PortAllocator::new();
        allocator.next = PORT_MAX;
        assert_eq!(allocator.allocate(), Some(PORT_MAX));
        assert_eq!(allocator.allocate(), Some(PORT_MIN));

        while allocator.allocate().is_some() {}
        assert_eq!(allocator.allocate(), None);
    }
}
