use std::net::{IpAddr, SocketAddr};

use crate::bypass::BypassMatcher;

#[derive(Debug, Clone)]
pub enum ProxyType {
    Socks5,
    Http,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_type: ProxyType,
    pub proxy_addr: SocketAddr,
    pub proxy_auth: Option<(String, String)>,
    pub command: Vec<String>,
    /// Pre-built matcher for `--bypass` rules. Connections whose target
    /// matches any rule skip the upstream proxy and connect directly from
    /// the host instead.
    pub bypass: BypassMatcher,
}

impl Config {
    /// True iff `host` matches a domain-side bypass rule.
    pub fn bypass_domain(&self, host: &str) -> bool {
        self.bypass.matches_domain(host)
    }

    /// True iff `ip` matches an IP/CIDR bypass rule.
    ///
    /// Accepts an `IpAddr` for caller convenience (the proxy layer uses
    /// the family-agnostic type), but the bypass engine itself is IPv4-only:
    /// any IPv6 destination is treated as "no bypass".
    pub fn bypass_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.bypass.matches_ip(v4),
            IpAddr::V6(_) => false,
        }
    }
}

/// Network-layer constants for the namespace. Kept in one place so that
/// changes to the TUN addressing plan don't need to be hunted down across
/// `namespace.rs` and `event_loop.rs`.
pub mod net {
    use std::net::Ipv4Addr;

    /// Name of the TUN interface created inside the namespace.
    ///
    /// We deliberately call it `eth0` rather than `tun0`: some software
    /// (systemd, NetworkManager scripts, various installers) probes for an
    /// interface named `eth*` to decide whether the machine is "online".
    /// Presenting the TUN as `eth0` keeps that heuristic happy.
    pub const TUN_NAME: &str = "eth0";

    /// Address assigned to the TUN interface inside the namespace
    /// (the guest side of the /31).
    pub const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(172, 23, 255, 255);

    /// Gateway IP — the host side of the /31 that smoltcp impersonates.
    /// Also used as the DNS server inside the namespace.
    pub const TUN_GW: Ipv4Addr = Ipv4Addr::new(172, 23, 255, 254);

    /// Prefix length of the TUN subnet. With /31 the two usable
    /// addresses are TUN_ADDR and TUN_GW (RFC 3021 point-to-point).
    pub const TUN_PREFIX: u8 = 31;

    /// Fake DNS server listening address (same machine as the gateway).
    pub const DNS_ADDR: Ipv4Addr = TUN_GW;

    /// Standard DNS port.
    pub const DNS_PORT: u16 = 53;

    /// MTU of the TUN interface. Larger than the classic 1500 so that a
    /// single smoltcp packet can carry a lot of payload without IP
    /// fragmentation inside the namespace.
    pub const TUN_MTU: u32 = 65000;
}
