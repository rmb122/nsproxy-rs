//! Efficient matcher for `--bypass` rules.
//!
//! A list of user-supplied specs is parsed once, up-front, into specialised
//! data structures so that the per-connection lookup is cheap regardless of
//! how many rules were supplied.
//!
//! - **Domains** (both `domain:` and `domain-regex:`) → a single
//!   [`regex::RegexSet`]. Literal-exact rules from `domain:` are escaped
//!   and wrapped as `(?i)^…$` so the original case-insensitive,
//!   anchored semantics are preserved; user-supplied regex from
//!   `domain-regex:` is taken verbatim. All patterns are matched
//!   simultaneously in one DFA pass, and the regex crate transparently
//!   reduces literal alternations to Aho-Corasick under the hood.
//! - **IPv4 / CIDR** (`ip:`, `cidr:`) → a binary prefix trie. Lookup walks
//!   at most one bit per level (≤ 32 hops), independent of how many rules
//!   were inserted. `ip:` is folded into the trie as a `/32` prefix.
//!
//! Only IPv4 is supported, mirroring the rest of nsproxy-rs (the TUN +
//! smoltcp + fake-DNS path is IPv4-only). IPv6 inputs in `ip:` / `cidr:`
//! are rejected at parse time.
//!
//! Spec format (one per `--bypass` flag):
//!
//! ```text
//! ip:<ipv4>
//! cidr:<ipv4>/<prefix>
//! domain:<host>             (case-insensitive)
//! domain-regex:<regex>
//! ```

use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use regex::{Regex, RegexSet};

// ── PrefixTrie ───────────────────────────────────────────────────────────────

/// Binary prefix trie keyed on the high bits of an IPv4 address.
///
/// Each level of the trie corresponds to one bit, walked from the
/// most-significant (bit 31) down to bit 0. A node is "terminal" iff some
/// inserted prefix ends here — any address that reaches a terminal node is
/// considered to match.
#[derive(Debug, Clone, Default)]
struct PrefixTrie {
    children: [Option<Box<PrefixTrie>>; 2],
    terminal: bool,
}

impl PrefixTrie {
    fn new() -> Self {
        Self::default()
    }

    /// Insert a network of `prefix` significant high bits of `value`.
    fn insert(&mut self, value: u32, prefix: u8) {
        debug_assert!(prefix <= 32);
        let mut node = self;
        for i in 0..prefix {
            let shift = 31 - i;
            let bit = ((value >> shift) & 1) as usize;
            node = node.children[bit].get_or_insert_with(|| Box::new(PrefixTrie::new()));
        }
        node.terminal = true;
    }

    /// Return `true` if any inserted prefix matches `value`.
    fn contains(&self, value: u32) -> bool {
        let mut node = self;
        if node.terminal {
            return true;
        }
        for i in 0..32 {
            let shift = 31 - i;
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
    Ip(Ipv4Addr),
    Cidr { network: Ipv4Addr, prefix: u8 },
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
                let addr: Ipv4Addr = value.parse().with_context(|| {
                    format!("bypass rule '{spec}': invalid IPv4 address (IPv6 is not supported)")
                })?;
                Ok(BypassRule::Ip(addr))
            }
            "cidr" => {
                let (net_str, prefix_str) = value
                    .split_once('/')
                    .with_context(|| format!("bypass rule '{spec}': CIDR must be 'addr/prefix'"))?;
                let network: Ipv4Addr = net_str.parse().with_context(|| {
                    format!(
                        "bypass rule '{spec}': invalid IPv4 CIDR network (IPv6 is not supported)"
                    )
                })?;
                let prefix: u8 = prefix_str
                    .parse()
                    .with_context(|| format!("bypass rule '{spec}': invalid CIDR prefix"))?;
                if prefix > 32 {
                    bail!("bypass rule '{spec}': prefix /{prefix} out of range (max /32)");
                }
                Ok(BypassRule::Cidr { network, prefix })
            }
            "domain" => {
                if value.is_empty() {
                    bail!("bypass rule '{spec}': empty domain");
                }
                // Stored verbatim — case-insensitivity is applied later by
                // wrapping the escaped pattern with `(?i)` when feeding the
                // RegexSet.
                Ok(BypassRule::Domain(value.to_string()))
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
    /// Combined matcher for both `domain:` and `domain-regex:` rules.
    /// Literal domain rules are escaped and wrapped as `(?i)^…$` before
    /// being added; regex rules are added verbatim.
    domains: Option<RegexSet>,
    /// IPv4 CIDR trie. `ip:` rules are stored as /32 prefixes here.
    cidr: PrefixTrie,
}

impl BypassMatcher {
    /// Parse a slice of rule specs and build the matcher.
    pub fn from_specs<S: AsRef<str>>(specs: &[S]) -> Result<Self> {
        let mut domain_patterns: Vec<String> = Vec::new();
        let mut cidr = PrefixTrie::new();

        for spec in specs {
            match BypassRule::parse(spec.as_ref())? {
                BypassRule::Domain(d) => {
                    // Escape any regex metacharacters so the literal is
                    // matched verbatim, then anchor with ^…$ and apply the
                    // (?i) flag to keep DNS-style case-insensitive matching.
                    domain_patterns.push(format!("(?i)^{}$", regex::escape(&d)));
                }
                BypassRule::DomainRegex(s) => {
                    domain_patterns.push(s);
                }
                BypassRule::Ip(v4) => {
                    cidr.insert(u32::from(v4), 32);
                }
                BypassRule::Cidr { network, prefix } => {
                    cidr.insert(u32::from(network), prefix);
                }
            }
        }

        // Each pattern was already validated individually above, so this
        // RegexSet build cannot fail for syntax reasons; we still surface
        // any size/limit error.
        let domains = if domain_patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(&domain_patterns).context("compile bypass RegexSet")?)
        };

        Ok(Self { domains, cidr })
    }

    /// Match against a host name (e.g. as recovered from a fake-DNS lookup).
    pub fn matches_domain(&self, host: &str) -> bool {
        match &self.domains {
            Some(rs) => rs.is_match(host),
            None => false,
        }
    }

    /// Match against a numeric IPv4 destination.
    pub fn matches_ip(&self, ip: Ipv4Addr) -> bool {
        self.cidr.contains(u32::from(ip))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        s.parse::<Ipv4Addr>().unwrap()
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
    fn cidr_rule() {
        let m = BypassMatcher::from_specs(&["cidr:10.0.0.0/8"]).unwrap();
        assert!(m.matches_ip(v4("10.0.0.1")));
        assert!(m.matches_ip(v4("10.255.255.255")));
        assert!(!m.matches_ip(v4("11.0.0.1")));
    }

    #[test]
    fn cidr_zero_prefix_matches_every_v4() {
        let m = BypassMatcher::from_specs(&["cidr:0.0.0.0/0"]).unwrap();
        assert!(m.matches_ip(v4("8.8.8.8")));
        assert!(m.matches_ip(v4("0.0.0.0")));
        assert!(m.matches_ip(v4("255.255.255.255")));
    }

    #[test]
    fn cidr_full_prefix() {
        let m = BypassMatcher::from_specs(&["cidr:1.2.3.4/32"]).unwrap();
        assert!(m.matches_ip(v4("1.2.3.4")));
        assert!(!m.matches_ip(v4("1.2.3.5")));
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

    #[test]
    fn rejects_ipv6() {
        // IPv6 is not supported anywhere in nsproxy-rs.
        assert!(BypassMatcher::from_specs(&["ip:2001:db8::1"]).is_err());
        assert!(BypassMatcher::from_specs(&["cidr:2001:db8::/32"]).is_err());
    }

    // ── PrefixTrie low-level ──────────────────────────────────────────────

    #[test]
    fn trie_insert_and_lookup() {
        let mut t = PrefixTrie::new();
        // 192.168.0.0/16
        t.insert(0xC0A8_0000, 16);
        assert!(t.contains(0xC0A8_0001));
        assert!(t.contains(0xC0A8_FFFF));
        assert!(!t.contains(0xC0A9_0000));
    }

    #[test]
    fn trie_terminal_short_circuits() {
        let mut t = PrefixTrie::new();
        // /0 — root becomes terminal, every lookup matches immediately.
        t.insert(0, 0);
        assert!(t.contains(0));
        assert!(t.contains(u32::MAX));
    }
}
