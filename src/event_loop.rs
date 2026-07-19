//! Core event loop — drives the TUN-backed smoltcp stack and delegates protocol
//! state to focused DNS, outbound TCP, and published TCP components.

mod dns;
mod outbound;
mod published;

use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

use anyhow::{Context, Result};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::unix::AsyncFd;

use self::dns::DnsInterceptor;
use self::outbound::OutboundTcp;
use self::published::PublishedTcp;
use crate::config::Config as AppConfig;
use crate::config::net::{TUN_GW, TUN_PREFIX};
use crate::publish::RegisteredPublish;
use crate::tun::TunDevice;

const TCP_BUF_SIZE: usize = 65536;
const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(32);
const MAX_POLL_DELAY: Duration = Duration::from_millis(100);
const DEFAULT_POLL_DELAY: smoltcp::time::Duration = smoltcp::time::Duration::from_millis(50);

/// Run until the namespace command exits and signals shutdown.
pub async fn run(
    tun_fd: RawFd,
    config: AppConfig,
    registered_publishes: Vec<RegisteredPublish>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    EventLoop::new(tun_fd, config, registered_publishes)?
        .run(&mut shutdown)
        .await;
    Ok(())
}

/// Owns the smoltcp stack while protocol-specific components own their socket
/// handles and connection state.
struct EventLoop {
    config: AppConfig,
    device: TunDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    async_fd: AsyncFd<RawFdWrapper>,
    dns: DnsInterceptor,
    outbound: OutboundTcp,
    published: PublishedTcp,
}

impl EventLoop {
    fn new(
        tun_fd: RawFd,
        config: AppConfig,
        registered_publishes: Vec<RegisteredPublish>,
    ) -> Result<Self> {
        let mut device = TunDevice::new(tun_fd).context("TunDevice::new")?;
        let mut interface_config = Config::new(HardwareAddress::Ip);
        interface_config.random_seed = rand_seed();
        let mut interface = Interface::new(interface_config, &mut device, SmolInstant::now());

        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(TUN_GW), TUN_PREFIX))
                .unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(TUN_GW)
            .unwrap();
        // Namespace applications connect to both real and fake destination
        // addresses, all of which must be accepted from the TUN.
        interface.set_any_ip(true);

        let async_fd = AsyncFd::new(RawFdWrapper(tun_fd)).context("AsyncFd::new for TUN fd")?;
        let mut sockets = SocketSet::new(vec![]);
        let dns = DnsInterceptor::new(&mut sockets);

        Ok(Self {
            config,
            device,
            interface,
            sockets,
            async_fd,
            dns,
            outbound: OutboundTcp::new(),
            published: PublishedTcp::new(registered_publishes),
        })
    }

    async fn run(&mut self, shutdown: &mut tokio::sync::watch::Receiver<bool>) {
        while self.wait_for_work(shutdown).await {
            self.tick();
        }
        tracing::info!("event_loop: shutdown signal received");
    }

    /// Wait for TUN input, a host-side accepted connection, shutdown, or the
    /// next smoltcp timer deadline.
    async fn wait_for_work(&mut self, shutdown: &mut tokio::sync::watch::Receiver<bool>) -> bool {
        if *shutdown.borrow() {
            return false;
        }

        let poll_delay = self
            .interface
            .poll_delay(SmolInstant::now(), &self.sockets)
            .unwrap_or(DEFAULT_POLL_DELAY);
        let timeout = Duration::from_millis(poll_delay.total_millis())
            .max(Duration::from_millis(1))
            .min(MAX_POLL_DELAY);

        tokio::select! {
            biased;
            _ = shutdown.changed() => {}
            _ = self.published.wait_for_accept() => {}
            readable = self.async_fd.readable() => {
                if let Ok(mut guard) = readable {
                    guard.clear_ready();
                }
            }
            _ = tokio::time::sleep(timeout) => {}
        }

        !*shutdown.borrow()
    }

    /// Execute one complete stack iteration. The second Interface::poll must
    /// remain before cleanup so queued RST/FIN packets reach the TUN.
    fn tick(&mut self) {
        while self.device.poll_read() {}

        self.outbound.observe_syns(&self.device, &mut self.sockets);
        self.published
            .attach_accepted(&mut self.interface, &mut self.sockets);

        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);

        self.dns.process(&mut self.sockets);
        self.outbound
            .process(&mut self.sockets, &self.dns, &self.config);
        self.published.process(&mut self.sockets);

        self.interface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);

        self.outbound.cleanup(&mut self.sockets);
        self.published.cleanup(&mut self.sockets);
    }
}

pub(super) fn new_tcp_socket() -> tcp::Socket<'static> {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
    tcp::Socket::new(rx_buf, tx_buf)
}

fn rand_seed() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_nanos() as u64 ^ 0xdeadbeef_cafebabe
}

struct RawFdWrapper(RawFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}
