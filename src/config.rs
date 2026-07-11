use std::net::IpAddr;

use crate::proxy::{ProxyConfig, ProxyTarget};
use crate::rule::RuleMatcher;

#[derive(Debug, Clone)]
pub struct Config {
    /// Route used when no rule matches the destination.
    pub default_proxy: ProxyConfig,
    pub command: Vec<String>,
    pub rules: RuleMatcher,
}

impl Config {
    /// Select the first applicable rule route, or fall back to `-x`.
    pub fn proxy_for(&self, target: &ProxyTarget) -> &ProxyConfig {
        let matched = match target {
            ProxyTarget::Domain { host, .. } => self.rules.match_domain(host),
            ProxyTarget::Ip { addr, .. } => match addr {
                IpAddr::V4(v4) => self.rules.match_ip(*v4),
                IpAddr::V6(_) => None,
            },
        };
        matched.unwrap_or(&self.default_proxy)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_rule_overrides_default_and_miss_falls_back() {
        let config = Config {
            default_proxy: ProxyConfig::Direct,
            command: Vec::new(),
            rules: RuleMatcher::from_specs(&["ip:1.1.1.1=socks5://127.0.0.1:1081"]).unwrap(),
        };

        let matched = ProxyTarget::Ip {
            addr: "1.1.1.1".parse().unwrap(),
            port: 443,
        };
        let missed = ProxyTarget::Ip {
            addr: "8.8.8.8".parse().unwrap(),
            port: 443,
        };

        assert!(matches!(
            config.proxy_for(&matched),
            ProxyConfig::Socks5 { .. }
        ));
        assert_eq!(config.proxy_for(&missed), &ProxyConfig::Direct);
    }
}
