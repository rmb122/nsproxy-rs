//! Efficient matcher for `--bypass` rules.
//!
//! A list of user-supplied specs is parsed once, up-front, into specialised
//! data structures so that the per-connection lookup is cheap regardless of
//! how many rules were supplied.
//!
//! - **Exact domain** (`domain:`) → [`HashSet`] for O(1) lookup.
//! - **Domain regex** (`domain-regex:`) → a single [`regex::RegexSet`]; all
//!   patterns are matched simultaneously in one DFA pass.
//! - **IPs / CIDRs** (`ip:`, `cidr:`) → a binary prefix trie per address
//!   family. Lookup walks at most one bit per level (32 hops for IPv4,
//!   128 for IPv6), independent of how many rules were inserted.
//!
//! `ip:` is equivalent to a `/32` (or `/128`) CIDR and is folded into the
//! same trie, so there is exactly one structure for IP-side matching.
//!
//! Spec format (one per `--bypass` flag):
//!
//! ```text
//! ip:<address>
//! cidr:<network>/<prefix>
//! domain:<host>             (case-insensitive)
//! domain-regex:<regex>
//! ```

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use regex::{Regex, RegexSet};

// ── PrefixTrie ───────────────────────────────────────────────────────────────

/// Binary trie keyed on the most-significant bits of an integer.
///
/// The same type is used for both IPv4 (width = 32) and IPv6 (width = 128);
/// the caller passes the appropriate width.  IPv4 addresses are widened to
/// `u128` and only the low 32 bits are used.
#[derive(Debug, Clone, Default)]
struct PrefixTrie {
    children: [Option<Box<PrefixTrie>>; 2],
    /// True iff some prefix terminates at this node, i.e. any address that
    /// reaches this point is a match.
    terminal: bool,
}

impl PrefixTrie {
    fn new() -> Self {
        Self::default()
    }

    /// Insert a network of `prefix` significant bits read from the top of
    /// `value` (counting from bit `width-1` downwards).
    fn insert(&mut self, value: u128, prefix: u8, width: u8) {
        debug_assert!(prefix <= width);
        let mut node = self;
        for i in 0..prefix {
            let shift = width - 1 - i;
            let bit = ((value >> shift) & 1) as usize;
            node = node.children[bit].get_or_insert_with(|| Box::new(PrefixTrie::new()));
        }
        node.terminal = true;
    }

    /// Return `true` if any inserted prefix matches `value`.
    fn contains(&self, value: u128, width: u8) -> bool {
        let mut node = self;
        if node.terminal {
            return true;
        }
        for i in 0..width {
            let shift = width - 1 - i;
            let bit = ((value >> shift) & 1) as usize;
            match node.children[bit].as_deref() {
                Some(child) => {
                    node = child;
                    if node.terminal {
                        return true;
                    }
                }
                None => return false,
            }
        }
        false
    }
}

// ── Parsed rule (internal) ───────────────────────────────────────────────────

/// Result of parsing a single rule string. Used only as an intermediate step
/// while building a [`BypassMatcher`]; the final matcher does not retain a
/// list of these.
enum BypassRule {
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
    Domain(String),
    DomainRegex(String),
}

impl BypassRule {
    fn parse(spec: &str) -> Result<Self> {
        let (kind, value) = spec
            .split_once(':')
            .with_context(|| format!("bypass rule '{spec}' is missing a '<kind>:' prefix"))?;

        match kind {
            "ip" => {
                let addr: IpAddr = value
                    .parse()
                    .with_context(|| format!("bypass rule '{spec}': invalid IP"))?;
                Ok(BypassRule::Ip(addr))
            }
            "cidr" => {
                let (net_str, prefix_str) = value
                    .split_once('/')
                    .with_context(|| format!("bypass rule '{spec}': CIDR must be 'addr/prefix'"))?;
                let network: IpAddr = net_str
                    .parse()
                    .with_context(|| format!("bypass rule '{spec}': invalid CIDR network"))?;
                let prefix: u8 = prefix_str
                    .parse()
                    .with_context(|| format!("bypass rule '{spec}': invalid CIDR prefix"))?;
                let max = match network {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                if prefix > max {
                    bail!("bypass rule '{spec}': prefix /{prefix} out of range (max /{max})");
                }
                Ok(BypassRule::Cidr { network, prefix })
            }
            "domain" => {
                if value.is_empty() {
                    bail!("bypass rule '{spec}': empty domain");
                }
                Ok(BypassRule::Domain(value.to_ascii_lowercase()))
            }
            "domain-regex" => {
                // Validate by compiling a single Regex so the user gets a
                // per-rule error message. The pattern is then handed to the
                // RegexSet later for batched matching.
                Regex::new(value)
                    .with_context(|| format!("bypass rule '{spec}': invalid regex"))?;
                Ok(BypassRule::DomainRegex(value.to_string()))
            }
            other => bail!(
                "bypass rule '{spec}': unknown kind '{other}' (expected ip / cidr / domain / domain-regex)"
            ),
        }
    }
}

// ── BypassMatcher ────────────────────────────────────────────────────────────

/// Pre-built matcher for a fixed set of bypass rules.
///
/// Construct once via [`BypassMatcher::from_specs`]; clone-on-demand is cheap
/// (the [`RegexSet`] is internally `Arc`-shared).
#[derive(Debug, Clone, Default)]
pub struct BypassMatcher {
    domains: HashSet<String>,
    domain_regex_set: Option<RegexSet>,
    cidr_v4: PrefixTrie,
    cidr_v6: PrefixTrie,
}

impl BypassMatcher {
    /// Parse a slice of rule specs and build the matcher.
    pub fn from_specs<S: AsRef<str>>(specs: &[S]) -> Result<Self> {
        let mut domains: HashSet<String> = HashSet::new();
        let mut regex_patterns: Vec<String> = Vec::new();
        let mut cidr_v4 = PrefixTrie::new();
        let mut cidr_v6 = PrefixTrie::new();

        for spec in specs {
            match BypassRule::parse(spec.as_ref())? {
                BypassRule::Domain(d) => {
                    domains.insert(d);
                }
                BypassRule::DomainRegex(s) => {
                    regex_patterns.push(s);
                }
                BypassRule::Ip(IpAddr::V4(v4)) => {
                    cidr_v4.insert(u128::from(u32::from(v4)), 32, 32);
                }
                BypassRule::Ip(IpAddr::V6(v6)) => {
                    cidr_v6.insert(u128::from(v6), 128, 128);
                }
                BypassRule::Cidr {
                    network: IpAddr::V4(v4),
                    prefix,
                } => {
                    cidr_v4.insert(u128::from(u32::from(v4)), prefix, 32);
                }
                BypassRule::Cidr {
                    network: IpAddr::V6(v6),
                    prefix,
                } => {
                    cidr_v6.insert(u128::from(v6), prefix, 128);
                }
            }
        }

        // Each pattern was already validated individually above, so this
        // RegexSet build cannot fail for syntax reasons; we still surface
        // any size/limit error.
        let domain_regex_set = if regex_patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(&regex_patterns).context("compile bypass RegexSet")?)
        };

        Ok(Self {
            domains,
            domain_regex_set,
            cidr_v4,
            cidr_v6,
        })
    }

    /// Match against a host name (e.g. as recovered from a fake-DNS lookup).
    pub fn matches_domain(&self, host: &str) -> bool {
        if self.domains.is_empty() && self.domain_regex_set.is_none() {
            return false;
        }
        // Exact match: lowercase the host and look it up.
        if !self.domains.is_empty() {
            let lower = host.to_ascii_lowercase();
            if self.domains.contains(&lower) {
                return true;
            }
        }
        // Single DFA pass over all regex patterns.
        if let Some(rs) = &self.domain_regex_set
            && rs.is_match(host)
        {
            return true;
        }
        false
    }

    /// Match against a numeric destination IP.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.cidr_v4.contains(u128::from(u32::from(v4)), 32),
            IpAddr::V6(v6) => self.cidr_v6.contains(u128::from(v6), 128),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    // ── parse / matcher round-trips ──────────────────────────────────────

    #[test]
    fn empty_matcher_matches_nothing() {
        let m: BypassMatcher = BypassMatcher::from_specs::<&str>(&[]).unwrap();
        assert!(!m.matches_domain("example.com"));
        assert!(!m.matches_ip(v4("1.2.3.4")));
    }

    #[test]
    fn ip_rule() {
        let m = BypassMatcher::from_specs(&["ip:1.2.3.4"]).unwrap();
        assert!(m.matches_ip(v4("1.2.3.4")));
        assert!(!m.matches_ip(v4("1.2.3.5")));
        assert!(!m.matches_domain("1.2.3.4"));
    }

    #[test]
    fn cidr_rule_v4() {
        let m = BypassMatcher::from_specs(&["cidr:10.0.0.0/8"]).unwrap();
        assert!(m.matches_ip(v4("10.0.0.1")));
        assert!(m.matches_ip(v4("10.255.255.255")));
        assert!(!m.matches_ip(v4("11.0.0.1")));
    }

    #[test]
    fn cidr_zero_prefix_matches_everything_in_family() {
        let m = BypassMatcher::from_specs(&["cidr:0.0.0.0/0"]).unwrap();
        assert!(m.matches_ip(v4("8.8.8.8")));
        assert!(m.matches_ip(v4("0.0.0.0")));
        assert!(m.matches_ip(v4("255.255.255.255")));
        // v6 trie is empty.
        assert!(!m.matches_ip(v6("2001:db8::1")));
    }

    #[test]
    fn cidr_full_prefix() {
        let m = BypassMatcher::from_specs(&["cidr:1.2.3.4/32"]).unwrap();
        assert!(m.matches_ip(v4("1.2.3.4")));
        assert!(!m.matches_ip(v4("1.2.3.5")));
    }

    #[test]
    fn cidr_v6() {
        let m = BypassMatcher::from_specs(&["cidr:2001:db8::/32"]).unwrap();
        assert!(m.matches_ip(v6("2001:db8::1")));
        assert!(m.matches_ip(v6("2001:db8:ffff::1")));
        assert!(!m.matches_ip(v6("2001:db9::1")));
        // v4 trie is empty.
        assert!(!m.matches_ip(v4("1.2.3.4")));
    }

    #[test]
    fn ip_v6_rule() {
        let m = BypassMatcher::from_specs(&["ip:2001:db8::1"]).unwrap();
        assert!(m.matches_ip(v6("2001:db8::1")));
        assert!(!m.matches_ip(v6("2001:db8::2")));
    }

    #[test]
    fn many_overlapping_cidrs_use_trie_correctly() {
        let m = BypassMatcher::from_specs(&[
            "cidr:10.0.0.0/8",
            "cidr:10.1.0.0/16", // strict subset of the above
            "cidr:192.168.0.0/16",
            "ip:8.8.8.8",
        ])
        .unwrap();
        assert!(m.matches_ip(v4("10.5.0.1")));
        assert!(m.matches_ip(v4("10.1.99.99")));
        assert!(m.matches_ip(v4("192.168.42.1")));
        assert!(m.matches_ip(v4("8.8.8.8")));
        assert!(!m.matches_ip(v4("8.8.4.4")));
        assert!(!m.matches_ip(v4("172.16.0.1")));
    }

    #[test]
    fn domain_exact_case_insensitive() {
        let m = BypassMatcher::from_specs(&["domain:Example.COM"]).unwrap();
        assert!(m.matches_domain("example.com"));
        assert!(m.matches_domain("EXAMPLE.COM"));
        assert!(!m.matches_domain("foo.example.com"));
    }

    #[test]
    fn domain_regex_set_combines_patterns() {
        let m =
            BypassMatcher::from_specs(&[r"domain-regex:.*\.asd\.com", r"domain-regex:^internal\."])
                .unwrap();
        assert!(m.matches_domain("a.asd.com"));
        assert!(m.matches_domain("x.y.asd.com"));
        assert!(m.matches_domain("internal.example.com"));
        assert!(!m.matches_domain("public.example.com"));
    }

    #[test]
    fn mixed_domain_rules() {
        let m =
            BypassMatcher::from_specs(&["domain:exact.local", r"domain-regex:.*\.corp$"]).unwrap();
        assert!(m.matches_domain("exact.local"));
        assert!(m.matches_domain("EXACT.LOCAL"));
        assert!(m.matches_domain("foo.corp"));
        assert!(!m.matches_domain("foo.org"));
    }

    // ── parse error paths ─────────────────────────────────────────────────

    #[test]
    fn rejects_unknown_kind() {
        assert!(BypassMatcher::from_specs(&["foo:bar"]).is_err());
    }

    #[test]
    fn rejects_missing_colon() {
        assert!(BypassMatcher::from_specs(&["ip-1.2.3.4"]).is_err());
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(BypassMatcher::from_specs(&["cidr:1.2.3.4"]).is_err());
        assert!(BypassMatcher::from_specs(&["cidr:1.2.3.4/40"]).is_err());
        assert!(BypassMatcher::from_specs(&["cidr:not-an-ip/8"]).is_err());
    }

    #[test]
    fn rejects_bad_regex() {
        assert!(BypassMatcher::from_specs(&["domain-regex:["]).is_err());
    }

    // ── PrefixTrie low-level ──────────────────────────────────────────────

    #[test]
    fn trie_insert_and_lookup_v4() {
        let mut t = PrefixTrie::new();
        // 192.168.0.0/16
        t.insert(0xC0A8_0000, 16, 32);
        assert!(t.contains(0xC0A8_0001, 32));
        assert!(t.contains(0xC0A8_FFFF, 32));
        assert!(!t.contains(0xC0A9_0000, 32));
    }

    #[test]
    fn trie_terminal_short_circuits() {
        let mut t = PrefixTrie::new();
        // /0 — root becomes terminal, every lookup matches immediately.
        t.insert(0, 0, 32);
        assert!(t.contains(0, 32));
        assert!(t.contains(u32::MAX as u128, 32));
    }
}
