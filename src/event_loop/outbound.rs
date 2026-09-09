use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
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
        self.shuttle_established(sockets);
    }

    pub(super) fn poll_ready(
        &mut self,
        sockets: &mut SocketSet<'static>,
        cx: &mut Context<'_>,
    ) -> Poll<()> {
        let mut ready = self.poll_connecting(sockets, cx);
        for (handle, state) in &self.states {
            let State::Established(context) = state else {
                continue;
            };
            let socket = sockets.get::<tcp::Socket>(*handle);
            if context.proxy_read_state == ProxyReadState::Open
                && context.proxy_to_app.len() < TCP_BUF_SIZE
            {
                ready |= context.stream.poll_read_ready(cx).is_ready();
            }
            if socket.can_recv() {
                ready |= context.stream.inner.poll_write_ready(cx).is_ready();
            }
        }
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
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

    fn poll_connecting(&mut self, sockets: &mut SocketSet<'static>, cx: &mut Context<'_>) -> bool {
        let mut ready = false;
        let handles: Vec<_> = self
            .states
            .iter()
            .filter_map(|(handle, state)| matches!(state, State::Connecting(_)).then_some(*handle))
            .collect();

        for handle in handles {
            let State::Connecting(mut task) = self.states.remove(&handle).unwrap() else {
                unreachable!();
            };
            match Pin::new(&mut task).poll(cx) {
                Poll::Ready(Ok(Ok(stream))) => {
                    ready = true;
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
                Poll::Ready(Ok(Err(error))) => {
                    ready = true;
                    tracing::warn!("proxy connect failed: {error:#}");
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.states.insert(handle, State::Closing);
                }
                Poll::Ready(Err(error)) => {
                    ready = true;
                    tracing::warn!("proxy connect task panicked: {error}");
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.states.insert(handle, State::Closing);
                }
                Poll::Pending => {
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
                        ready = true;
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
        ready
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
                match context.stream.try_read(&mut tmp_buf[..space]) {
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

#[cfg(test)]
mod tests {
    use super::super::tests::{WakeProbe, tcp_pair};
    use super::*;
    use crate::proxy::{ProxyConfig, ProxyTarget};
    use std::sync::Arc;
    use std::task::Waker;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn upstream_data_wakes_the_event_loop_and_respects_buffer_capacity() {
        let (stream, mut peer) = tcp_pair().await;
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(new_tcp_socket());
        let mut outbound = OutboundTcp::new();
        outbound.states.insert(
            handle,
            State::Established(ForwardContext {
                stream: ProxyStream::new(stream, Vec::new()),
                proxy_to_app: Vec::new(),
                proxy_read_state: ProxyReadState::Open,
            }),
        );
        let probe = Arc::new(WakeProbe::default());
        let waker = Waker::from(probe.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(outbound.poll_ready(&mut sockets, &mut cx).is_pending());
        peer.write_all(b"response").await.unwrap();
        probe.notified().await;
        assert!(outbound.poll_ready(&mut sockets, &mut cx).is_ready());

        let State::Established(context) = outbound.states.get_mut(&handle).unwrap() else {
            unreachable!()
        };
        context.proxy_to_app.resize(TCP_BUF_SIZE, 0);
        assert!(outbound.poll_ready(&mut sockets, &mut cx).is_pending());
    }

    #[tokio::test]
    async fn completed_connect_wakes_the_event_loop() {
        let (stream, _peer) = tcp_pair().await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut sockets = SocketSet::new(vec![]);
        let mut socket = new_tcp_socket();
        socket.listen(12345).unwrap();
        let handle = sockets.add(socket);
        let mut outbound = OutboundTcp::new();
        outbound.states.insert(
            handle,
            State::Connecting(tokio::spawn(async move {
                rx.await?;
                Ok(ProxyStream::new(stream, Vec::new()))
            })),
        );
        let probe = Arc::new(WakeProbe::default());
        let waker = Waker::from(probe.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(outbound.poll_ready(&mut sockets, &mut cx).is_pending());
        tx.send(()).unwrap();
        probe.notified().await;
        assert!(outbound.poll_ready(&mut sockets, &mut cx).is_ready());
        assert!(matches!(outbound.states[&handle], State::Established(_)));
    }

    #[tokio::test]
    async fn timed_out_proxy_connect_is_aborted_and_removed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy =
            ProxyConfig::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let target = ProxyTarget::Domain {
            host: "example.test".into(),
            port: 80,
        };
        let mut sockets = SocketSet::new(vec![]);
        let mut socket = new_tcp_socket();
        socket.listen(12345).unwrap();
        let handle = sockets.add(socket);
        let mut outbound = OutboundTcp::new();
        outbound.states.insert(
            handle,
            State::Connecting(tokio::spawn(async move { proxy.connect(&target).await })),
        );
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut request = [0; 1024];
        assert!(peer.read(&mut request).await.unwrap() > 0);
        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(32)).await;
        std::future::poll_fn(|cx| outbound.poll_ready(&mut sockets, cx)).await;
        tokio::time::resume();
        assert!(matches!(outbound.states[&handle], State::Closing));
        assert_eq!(
            sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Closed
        );
        outbound.cleanup(&mut sockets);
        assert!(outbound.states.is_empty());
        assert_eq!(sockets.iter().count(), 0);
    }
}
