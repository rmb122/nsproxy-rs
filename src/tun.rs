//! smoltcp `Device` implementation backed by a Linux TUN file descriptor.
//!
//! The TUN fd is set to non-blocking mode on construction; from that point on
//! `libc::read` returns `EAGAIN` when no packet is available, which maps
//! cleanly to `Device::receive` returning `None`.
//!
//! A `VecDeque` buffer is used so we can pre-read packets, inspect them (for
//! TCP SYN detection), and then feed them to smoltcp.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// Maximum transmission unit for the TUN device.
const MTU: usize = 65000;

// ── TunDevice ────────────────────────────────────────────────────────────────

/// Wrapper around a raw TUN file descriptor that implements smoltcp's
/// [`Device`] trait.
///
/// Uses a `VecDeque` so callers can pre-read packets from the fd, inspect them
/// (e.g. to detect TCP SYNs), and then hand them to smoltcp via the `Device`
/// trait.
pub struct TunDevice {
    fd: RawFd,
    /// Buffered packets ready to deliver to smoltcp.
    rx_queue: VecDeque<Vec<u8>>,
}

impl TunDevice {
    /// Wrap `fd`.  Sets the fd to non-blocking mode immediately.
    ///
    /// # Safety
    /// `fd` must be a valid, open TUN device file descriptor.
    pub fn new(fd: RawFd) -> std::io::Result<Self> {
        // Set O_NONBLOCK so that `libc::read` never blocks.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            rx_queue: VecDeque::new(),
        })
    }

    /// Perform a non-blocking read from the TUN fd and push any received packet
    /// into `rx_queue`. Returns `true` if a packet was read.
    pub fn poll_read(&mut self) -> bool {
        let mut buf = vec![0u8; MTU + 100];
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n <= 0 {
            return false;
        }

        buf.truncate(n as usize);
        self.rx_queue.push_back(buf);
        true
    }

    /// Access the entire rx_queue for inspection (e.g. SYN detection).
    pub fn rx_queue(&self) -> &VecDeque<Vec<u8>> {
        &self.rx_queue
    }
}

// ── Device impl ───────────────────────────────────────────────────────────────

impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Pop the front packet from the buffer queue.
        let buf = self.rx_queue.pop_front()?;
        let rx = TunRxToken { buf };
        let tx = TunTxToken { fd: self.fd };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken { fd: self.fd })
    }
}

// ── RxToken ───────────────────────────────────────────────────────────────────

pub struct TunRxToken {
    buf: Vec<u8>,
}

impl RxToken for TunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buf)
    }
}

// ── TxToken ───────────────────────────────────────────────────────────────────

pub struct TunTxToken {
    fd: RawFd,
}

impl TxToken for TunTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);

        // Write the packet to the TUN device.
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("tun write error: {err}");
        }

        result
    }
}

// ── Packet inspection helpers ─────────────────────────────────────────────────

/// Parse a TCP SYN packet and return `(dst_ip, dst_port)`.
///
/// Returns `None` if the packet is not an IPv4 TCP SYN (without ACK).
/// Returns (src_ip, src_port, dst_ip, dst_port).
pub fn parse_tcp_syn(packet: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
    if packet.len() < 40 {
        return None;
    } // min IP(20) + TCP(20)
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let protocol = packet[9];
    if protocol != 6 {
        return None;
    } // not TCP
    if packet.len() < ihl + 20 {
        return None;
    }
    let tcp_offset = ihl;
    let flags = packet[tcp_offset + 13];
    let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN but not ACK
    if !is_syn {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset + 1]]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let dst_port = u16::from_be_bytes([packet[tcp_offset + 2], packet[tcp_offset + 3]]);
    Some((src_ip, src_port, dst_ip, dst_port))
}
