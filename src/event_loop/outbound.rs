use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Instant;

use anyhow::Result;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

use super::dns::DnsInterceptor;
use super::{TCP_BUF_SIZE, TCP_HANDSHAKE_TIMEOUT, new_tcp_socket};
use crate::config::Config as AppConfig;
use crate::proxy::ProxyStream;
use crate::tun::{TunDevice, parse_tcp_syn};

type EndpointKey = (Ipv4Addr, u16, Ipv4Addr, u16);

enum State {
    Listening { created_at: Instant },
    Connecting(tokio::task::JoinHandle<Result<ProxyStream>>),
    Established(ForwardContext),
    Closing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyReadState {
    Open,
    Eof,
    Failed,
}

struct ForwardContext {
    stream: ProxyStream,
    proxy_to_app: Vec<u8>,
    proxy_read_state: ProxyReadState,
}

/// Owns all namespace-originated TCP state and upstream proxy tasks.
pub(super) struct OutboundTcp {
    states: HashMap<SocketHandle, State>,
    listening_endpoints: HashSet<EndpointKey>,
    handle_to_endpoint: HashMap<SocketHandle, EndpointKey>,
}

impl OutboundTcp {
    pub(super) fn new() -> Self {
        Self {
            states: HashMap::new(),
            listening_endpoints: HashSet::new(),
            handle_to_endpoint: HashMap::new(),
        }
    }

    /// Inspect packets before smoltcp consumes them so a matching listen socket
    /// exists when the SYN is processed.
    pub(super) fn observe_syns(&mut self, device: &TunDevice, sockets: &mut SocketSet<'static>) {
        for packet in device.rx_queue() {
            let Some((src_ip, src_port, dst_ip, dst_port)) = parse_tcp_syn(packet) else {
                continue;
            };
            let key = (src_ip, src_port, dst_ip, dst_port);
            if self.listening_endpoints.contains(&key) {
                continue;
            }

            tracing::debug!("SYN detected → {dst_ip}:{dst_port}, creating listen socket");
            let mut socket = new_tcp_socket();
            let endpoint = IpListenEndpoint {
                addr: None,
                port: dst_port,
            };
            if socket.listen(endpoint).is_err() {
                tracing::warn!("failed to listen on {dst_ip}:{dst_port}");
                continue;
            }

            let handle = sockets.add(socket);
            self.states.insert(
                handle,
                State::Listening {
                    created_at: Instant::now(),
                },
            );
            self.listening_endpoints.insert(key);
            self.handle_to_endpoint.insert(handle, key);
        }
    }

    pub(super) fn process(
        &mut self,
        sockets: &mut SocketSet<'static>,
        dns: &DnsInterceptor,
        config: &AppConfig,
    ) {
        self.log_listener_transitions(sockets);
        self.update_listeners(sockets, dns, config);
        self.poll_connecting(sockets);
        self.shuttle_established(sockets);
    }

    fn log_listener_transitions(&self, sockets: &SocketSet<'static>) {
        for (handle, state) in &self.states {
            if !matches!(state, State::Listening { .. }) {
                continue;
            }
            let socket = sockets.get::<tcp::Socket>(*handle);
            if socket.state() != tcp::State::Listen {
                tracing::debug!(
                    "socket {handle}: state={:?} local={:?} remote={:?}",
                    socket.state(),
                    socket.local_endpoint(),
                    socket.remote_endpoint()
                );
            }
        }
    }

    fn update_listeners(
        &mut self,
        sockets: &mut SocketSet<'static>,
        dns: &DnsInterceptor,
        config: &AppConfig,
    ) {
        let handles: Vec<_> = self.states.keys().copied().collect();
        for handle in handles {
            let State::Listening { created_at } = self.states[&handle] else {
                continue;
            };
            let socket = sockets.get::<tcp::Socket>(handle);

            if matches!(
                socket.state(),
                tcp::State::Established | tcp::State::CloseWait
            ) {
                let Some(local) = socket.local_endpoint() else {
                    continue;
                };
                let IpAddress::Ipv4(dst_ip) = local.addr;
                let target = dns.target_for(dst_ip, local.port);
                let proxy = config.proxy_for(&target).clone();
                tracing::info!("TCP: new connection to {target} via {proxy}");
                let task = tokio::spawn(async move { proxy.connect(&target).await });
                self.states.insert(handle, State::Connecting(task));
            } else if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                self.states.insert(handle, State::Closing);
            } else if created_at.elapsed() >= TCP_HANDSHAKE_TIMEOUT {
                tracing::debug!(
                    "TCP handshake timed out for socket {handle} in state {:?}",
                    socket.state()
                );
                sockets.get_mut::<tcp::Socket>(handle).abort();
                self.states.insert(handle, State::Closing);
            }
        }
    }

    fn poll_connecting(&mut self, sockets: &mut SocketSet<'static>) {
        let handles: Vec<_> = self
            .states
            .iter()
            .filter_map(|(handle, state)| matches!(state, State::Connecting(_)).then_some(*handle))
            .collect();

        for handle in handles {
            let State::Connecting(mut task) = self.states.remove(&handle).unwrap() else {
                unreachable!();
            };
            match task.try_poll() {
                Some(Ok(Ok(stream))) => {
                    tracing::debug!("proxy connection established for socket {handle}");
                    self.states.insert(
                        handle,
                        State::Established(ForwardContext {
                            stream,
                            proxy_to_app: Vec::new(),
                            proxy_read_state: ProxyReadState::Open,
                        }),
                    );
                }
                Some(Ok(Err(error))) => {
                    tracing::warn!("proxy connect failed: {error:#}");
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.states.insert(handle, State::Closing);
                }
                Some(Err(error)) => {
                    tracing::warn!("proxy connect task panicked: {error}");
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.states.insert(handle, State::Closing);
                }
                None => {
                    let socket = sockets.get_mut::<tcp::Socket>(handle);
                    let client_gone = matches!(
                        socket.state(),
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
                            socket.state()
                        );
                        task.abort();
                        socket.abort();
                        self.states.insert(handle, State::Closing);
                    } else {
                        self.states.insert(handle, State::Connecting(task));
                    }
                }
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

            if socket.may_recv() && socket.can_recv() {
                let stream = &context.stream.inner;
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
                    tracing::debug!("proxy write error: {error}");
                    socket.abort();
                }
            }

            if context.proxy_read_state == ProxyReadState::Open
                && context.proxy_to_app.len() < TCP_BUF_SIZE
            {
                let space = TCP_BUF_SIZE - context.proxy_to_app.len();
                match context.stream.inner.try_read(&mut tmp_buf[..space]) {
                    Ok(0) => {
                        tracing::debug!("proxy stream closed for socket {handle}");
                        context.proxy_read_state = ProxyReadState::Eof;
                    }
                    Ok(read) => context.proxy_to_app.extend_from_slice(&tmp_buf[..read]),
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => {
                        tracing::debug!("proxy read error: {error}");
                        context.proxy_read_state = ProxyReadState::Failed;
                        socket.abort();
                    }
                }
            }

            if !context.proxy_to_app.is_empty() && socket.can_send() {
                let free_space = TCP_BUF_SIZE.saturating_sub(socket.send_queue());
                let send_len = free_space.min(context.proxy_to_app.len());
                if send_len > 0 {
                    match socket.send_slice(&context.proxy_to_app[..send_len]) {
                        Ok(sent) => {
                            context.proxy_to_app.drain(..sent);
                        }
                        Err(_) => {
                            tracing::debug!("smoltcp send error for socket {handle}");
                            socket.abort();
                        }
                    }
                }
            }

            let drained_after_eof = context.proxy_read_state == ProxyReadState::Eof
                && context.proxy_to_app.is_empty()
                && socket.send_queue() == 0
                && socket.may_send();
            if drained_after_eof {
                socket.abort();
            }

            if !socket.may_recv() || !socket.may_send() {
                socket.abort();
                self.states.insert(handle, State::Closing);
            }
        }
    }

    /// Remove sockets only after the caller has driven pending RST/FIN packets
    /// through a second Interface::poll.
    pub(super) fn cleanup(&mut self, sockets: &mut SocketSet<'static>) {
        let handles: Vec<_> = self
            .states
            .iter()
            .filter_map(|(handle, state)| matches!(state, State::Closing).then_some(*handle))
            .collect();

        for handle in handles {
            if let Some(endpoint) = self.handle_to_endpoint.remove(&handle) {
                self.listening_endpoints.remove(&endpoint);
            }
            self.states.remove(&handle);
            sockets.remove(handle);
            tracing::debug!("cleaned up closed socket {handle}");
        }
    }
}

impl Drop for OutboundTcp {
    fn drop(&mut self) {
        for (_, state) in self.states.drain() {
            if let State::Connecting(task) = state {
                task.abort();
            }
        }
    }
}

trait JoinHandlePoll {
    type Output;
    fn try_poll(&mut self) -> Option<Self::Output>;
}

impl<T> JoinHandlePoll for tokio::task::JoinHandle<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn try_poll(&mut self) -> Option<Self::Output> {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop_raw_waker() -> RawWaker {
            fn no_op(_: *const ()) {}
            fn clone(pointer: *const ()) -> RawWaker {
                RawWaker::new(pointer, &VTABLE)
            }
            const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let pinned = unsafe { Pin::new_unchecked(self) };
        match pinned.poll(&mut context) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        }
    }
}
