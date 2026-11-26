// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::Error;
use ahash::AHashSet;
use ipnet::IpNet;
use std::net::{AddrParseError, IpAddr};
use std::str::FromStr;

/// A merged, sorted inclusive range `[start, end]` of addresses within one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IpRange {
    start: u128,
    end: u128,
}

impl IpRange {
    /// Builds the inclusive range covered by a CIDR network.
    fn from_net(net: &IpNet) -> Self {
        let prefix = net.prefix_len();
        match net {
            IpNet::V4(net) => {
                let start = u32::from(net.network()) as u128;
                // Host mask via `checked_shr`: prefix 0 → all-ones (whole
                // space), prefix 32 → 0 (single host), no shift overflow.
                // `start` is the network address (host bits are 0), so OR-ing
                // the mask yields the broadcast address.
                let mask = u32::MAX.checked_shr(prefix as u32).unwrap_or(0);
                let end = start | (mask as u128);
                Self { start, end }
            },
            IpNet::V6(net) => {
                let start = u128::from(net.network());
                // Same checked-shift form: defined for every prefix 0..=128,
                // including both extremes (/0 and /128).
                let mask = u128::MAX.checked_shr(prefix as u32).unwrap_or(0);
                let end = start | mask;
                Self { start, end }
            },
        }
    }

    /// Merges an adjacent or overlapping range into this one, if possible.
    fn merge(&mut self, other: &IpRange) -> bool {
        if other.start > self.end.saturating_add(1) {
            return false;
        }
        if other.end > self.end {
            self.end = other.end;
        }
        true
    }

    /// Sorts, merges adjacent/overlapping ranges and validates invariants.
    fn normalize(mut ranges: Vec<IpRange>) -> Vec<IpRange> {
        ranges.sort_by_key(|r| (r.start, r.end));
        let mut merged: Vec<IpRange> = Vec::with_capacity(ranges.len());
        for range in ranges {
            // Every range must be non-empty and ordered, otherwise the binary
            // search in `is_match_addr` has no defined result.
            debug_assert!(
                range.start <= range.end,
                "IP range start must not exceed end: {range:?}"
            );
            match merged.last_mut() {
                // Merging adjacent/overlapping ranges into the last one.
                Some(last) => {
                    if !last.merge(&range) {
                        merged.push(range);
                    }
                },
                _ => merged.push(range),
            }
        }
        merged
    }
}

/// IpRules stores pre-parsed IP addresses and networks for efficient access control.
#[derive(Clone, Debug)]
pub struct IpRules {
    // Sorted, merged inclusive ranges, narrowed to u32 for IPv4 so that
    // lookups are cache-friendly.
    v4_ranges: Vec<(u32, u32)>,
    v6_ranges: Vec<IpRange>,
    // Use a HashSet for O(1) average time complexity for individual IP lookups.
    ip_set: AHashSet<IpAddr>,
}

impl IpRules {
    /// Creates a new IpRules instance from a list of IP addresses and/or CIDR networks.
    ///
    /// The input values are parsed and stored in optimized data structures for fast lookups.
    /// An entry that is neither is dropped; [`IpRules::try_new`] rejects it
    /// instead, which is what configuration validation wants.
    pub fn new<T: AsRef<str>>(values: &[T]) -> Self {
        Self::parse(values).0
    }

    /// Like [`IpRules::new`], but an entry that is neither an IP address nor
    /// a CIDR network is an error. A typo in an allow or deny list must fail
    /// validation rather than silently let traffic through or block it.
    pub fn try_new<T: AsRef<str>>(values: &[T]) -> Result<Self, Error> {
        let (rules, invalid) = Self::parse(values);
        if invalid.is_empty() {
            return Ok(rules);
        }
        Err(Error::Invalid {
            message: format!("ip or cidr: {}", invalid.join(", ")),
        })
    }

    /// Parses every entry, returning the rules and the entries that were
    /// neither an address nor a network.
    fn parse<T: AsRef<str>>(values: &[T]) -> (Self, Vec<String>) {
        let mut v4_ranges = vec![];
        let mut v6_ranges = vec![];
        let mut ip_set = AHashSet::new();
        let mut invalid = vec![];

        for item in values {
            let item_str = item.as_ref().trim();
            // Try parsing as a CIDR network first.
            if let Ok(value) = IpNet::from_str(item_str) {
                let range = IpRange::from_net(&value);
                if matches!(value, IpNet::V4(_)) {
                    v4_ranges.push((range.start as u32, range.end as u32));
                } else {
                    v6_ranges.push(range);
                }
            // If not a network, try parsing as a single IP address.
            } else if let Ok(value) = IpAddr::from_str(item_str) {
                ip_set.insert(value);
            } else {
                invalid.push(item_str.to_string());
            }
        }
        (
            Self {
                v4_ranges: IpRange::normalize(
                    v4_ranges
                        .into_iter()
                        .map(|(s, e)| IpRange {
                            start: s as u128,
                            end: e as u128,
                        })
                        .collect(),
                )
                .into_iter()
                .map(|r| (r.start as u32, r.end as u32))
                .collect(),
                v6_ranges: IpRange::normalize(v6_ranges),
                ip_set,
            },
            invalid,
        )
    }

    /// Checks if a given IP address matches any of the stored rules.
    ///
    /// This is the primary method for checking access. It parses the string
    /// and then performs the efficient matching logic.
    pub fn is_match(&self, ip: &str) -> Result<bool, AddrParseError> {
        let addr = ip.parse::<IpAddr>()?;
        Ok(self.is_match_addr(&addr))
    }

    /// A more performant version of `is_match` that accepts a pre-parsed `IpAddr`.
    ///
    /// This allows callers to avoid re-parsing the IP address if they already
    /// have it in `IpAddr` form.
    pub fn is_match_addr(&self, ip_addr: &IpAddr) -> bool {
        // First, perform a fast O(1) lookup in the HashSet.
        if self.ip_set.contains(ip_addr) {
            return true;
        }
        // If not found, binary-search the sorted, merged ranges. O(log n).
        match ip_addr {
            IpAddr::V4(addr) => {
                let value = u32::from(*addr);
                self.v4_ranges
                    .partition_point(|(start, _)| start <= &value)
                    .checked_sub(1)
                    .and_then(|idx| {
                        let (start, end) = self.v4_ranges[idx];
                        (start <= value && value <= end).then_some(true)
                    })
                    .unwrap_or(false)
            },
            IpAddr::V6(addr) => {
                let value = u128::from(*addr);
                self.v6_ranges
                    .partition_point(|r| r.start <= value)
                    .checked_sub(1)
                    .and_then(|idx| {
                        let range = self.v6_ranges[idx];
                        (range.start <= value && value <= range.end)
                            .then_some(true)
                    })
                    .unwrap_or(false)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ip_rules() {
        let rules = IpRules::new(&[
            "192.168.1.0/24", // A network
            "10.0.0.1",       // A single IP
            "2001:db8::/32",  // An IPv6 network
            "2001:db8:a::1",  // A single IPv6
            "not-an-ip",      // An invalid entry that should be ignored
        ]);

        // Check that the constructor correctly parsed and stored the rules.
        assert_eq!(rules.v4_ranges.len(), 1);
        assert_eq!(rules.v6_ranges.len(), 1);
        assert_eq!(rules.ip_set.len(), 2);

        // --- Test is_match_addr for performance-critical paths ---
        let ip_in_net_v4 = "192.168.1.100".parse().unwrap();
        let exact_ip_v4 = "10.0.0.1".parse().unwrap();
        let outside_ip_v4 = "192.168.2.1".parse().unwrap();

        let ip_in_net_v6 = "2001:db8:dead:beef::1".parse().unwrap();
        let exact_ip_v6 = "2001:db8:a::1".parse().unwrap();
        let outside_ip_v6 = "2001:db9::1".parse().unwrap();

        assert!(rules.is_match_addr(&ip_in_net_v4));
        assert!(rules.is_match_addr(&exact_ip_v4));
        assert!(!rules.is_match_addr(&outside_ip_v4));

        assert!(rules.is_match_addr(&ip_in_net_v6));
        assert!(rules.is_match_addr(&exact_ip_v6));
        assert!(!rules.is_match_addr(&outside_ip_v6));

        // --- Test is_match for user-facing convenience ---
        assert_eq!(rules.is_match("192.168.1.1"), Ok(true));
        assert_eq!(rules.is_match("10.0.0.1"), Ok(true));
        assert_eq!(rules.is_match("192.168.3.1"), Ok(false));
        // Test invalid IP string input for is_match
        assert!(rules.is_match("999.999.999.999").is_err());
    }

    #[test]
    fn test_try_new_rejects_invalid_entries() {
        let rules =
            IpRules::try_new(&[" 10.0.0.1 ", "192.168.1.0/24"]).unwrap();
        assert_eq!(rules.is_match("10.0.0.1"), Ok(true));

        let err = IpRules::try_new(&["10.0.0.1", "not-an-ip", "10.0.0/8"])
            .unwrap_err();
        assert_eq!("Invalid ip or cidr: not-an-ip, 10.0.0/8", err.to_string());
    }

    /// The naive linear-scan reference implementation used for
    /// differential testing against the binary-search implementation.
    struct NaiveIpRules {
        nets: Vec<IpNet>,
        ips: Vec<IpAddr>,
    }

    impl NaiveIpRules {
        fn is_match_addr(&self, ip_addr: &IpAddr) -> bool {
            self.ips.iter().any(|ip| ip == ip_addr)
                || self.nets.iter().any(|net| net.contains(ip_addr))
        }
    }

    #[test]
    fn test_ip_rules_differential() {
        // A simple deterministic xorshift PRNG keeps the test reproducible
        // without adding a random dependency.
        let mut seed: u64 = 0x2025_0421_dead_beef;
        let mut next_u64 = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for round in 0..50u32 {
            let mut nets = vec![];
            let mut ips = vec![];
            let mut entries: Vec<String> = vec![];
            // Small pool keeps ranges likely to overlap/be adjacent so that
            // merging is exercised; round variation gives coverage.
            let push_net =
                |prefix_len: u8,
                 host: u64,
                 nets: &mut Vec<IpNet>,
                 entries: &mut Vec<String>| {
                    let ipv4 = prefix_len <= 32;
                    // Mask host bits instead of shifting 1 by 0..=128, which
                    // would overflow for a /0 network.
                    let mask = |bits: u32| -> u128 {
                        if bits >= 128 {
                            u128::MAX
                        } else {
                            (1u128 << bits) - 1
                        }
                    };
                    let host: u128 = if ipv4 {
                        (host as u32 as u128) & mask(32 - prefix_len as u32)
                    } else {
                        (host as u128) & mask(128 - prefix_len as u32)
                    };
                    let net = if ipv4 {
                        IpNet::new(
                            IpAddr::V4(std::net::Ipv4Addr::from(
                                (host << (32 - prefix_len as u32)) as u32,
                            )),
                            prefix_len,
                        )
                        .unwrap()
                    } else {
                        IpNet::new(
                            IpAddr::V6(std::net::Ipv6Addr::from(
                                // A /0 network has no host bits; shifting by
                                // 128 would overflow, so special-case it.
                                if prefix_len == 0 {
                                    0
                                } else {
                                    host << (128 - prefix_len as u32)
                                },
                            )),
                            prefix_len,
                        )
                        .unwrap()
                    };
                    nets.push(net);
                    entries.push(net.to_string());
                };

            // Special-case and random prefixes, v4/v6 mixed.
            push_net(0, next_u64(), &mut nets, &mut entries);
            push_net(32, next_u64(), &mut nets, &mut entries);
            push_net(64, next_u64(), &mut nets, &mut entries);
            push_net(128, next_u64(), &mut nets, &mut entries);
            // Explicit IPv6 extremes the random generator never produces (its
            // v6 lower bound is 64): /0, /1, /127, /128 — the /0 case used to
            // overflow the range computation.
            for prefix in [0u8, 1, 127, 128] {
                let net = IpNet::new(
                    IpAddr::V6(std::net::Ipv6Addr::from(0x2001db8u128)),
                    prefix,
                )
                .unwrap();
                nets.push(net);
                entries.push(net.to_string());
            }
            for _ in 0..60 {
                push_net(
                    (next_u64() % 33) as u8,
                    next_u64(),
                    &mut nets,
                    &mut entries,
                );
                push_net(
                    64 + (next_u64() % 65) as u8,
                    next_u64(),
                    &mut nets,
                    &mut entries,
                );
            }
            // Adjacent, non-overlapping ranges.
            for i in 0..10u32 {
                let net = IpNet::new(
                    IpAddr::V4(std::net::Ipv4Addr::from(1000 + 2 * i)),
                    32,
                )
                .unwrap();
                nets.push(net);
                entries.push(net.to_string());
            }
            // Duplicate entries must be idempotent.
            for _ in 0..10 {
                let ip = if next_u64() % 2 == 0 {
                    IpAddr::from((next_u64() as u32).to_be_bytes())
                } else {
                    IpAddr::from(std::net::Ipv6Addr::from(next_u64() as u128))
                };
                ips.push(ip);
                entries.push(ip.to_string());
            }

            let rules = IpRules::new(&entries);
            let naive = NaiveIpRules { nets, ips };

            // Probe: rule endpoints, +/-1 around them, plus random addresses.
            let mut probes = vec![];
            for net in &naive.nets {
                let (s, e): (IpAddr, IpAddr) = match net {
                    IpNet::V4(n) => (n.network().into(), n.broadcast().into()),
                    IpNet::V6(n) => (n.network().into(), n.broadcast().into()),
                };
                for ip in [s, e] {
                    match ip {
                        IpAddr::V4(a) => {
                            let v = u32::from(a);
                            probes.push(IpAddr::V4(std::net::Ipv4Addr::from(
                                v.wrapping_sub(1),
                            )));
                            probes
                                .push(IpAddr::V4(std::net::Ipv4Addr::from(v)));
                            probes.push(IpAddr::V4(std::net::Ipv4Addr::from(
                                v.wrapping_add(1),
                            )));
                        },
                        IpAddr::V6(a) => {
                            let v = u128::from(a);
                            probes.push(IpAddr::V6(std::net::Ipv6Addr::from(
                                v.wrapping_sub(1),
                            )));
                            probes
                                .push(IpAddr::V6(std::net::Ipv6Addr::from(v)));
                            probes.push(IpAddr::V6(std::net::Ipv6Addr::from(
                                v.wrapping_add(1),
                            )));
                        },
                    }
                }
            }
            for _ in 0..500 {
                probes.push(if next_u64() % 2 == 0 {
                    IpAddr::from((next_u64() as u32).to_be_bytes())
                } else {
                    IpAddr::from(std::net::Ipv6Addr::from(next_u64() as u128))
                });
            }

            let mut mismatches = vec![];
            for ip in &probes {
                if rules.is_match_addr(ip) != naive.is_match_addr(ip) {
                    mismatches.push(format!("round {round}: {ip}"));
                }
            }
            assert!(
                mismatches.is_empty(),
                "differential mismatches:\n{}",
                mismatches.join("\n")
            );
        }
    }
}
