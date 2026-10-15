use std::net::IpAddr;

use axum::http::HeaderMap;

pub enum TrustedProxies {
    All,
    Only(Vec<IpAddr>),
}

impl TrustedProxies {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            Self::All => true,
            Self::Only(ips) => ips.contains(ip),
        }
    }

    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let mut ip = peer.to_canonical();
        if !self.contains(&ip) {
            return ip;
        }

        let entries = headers
            .get_all("x-forwarded-for")
            .iter()
            .rev()
            .flat_map(|value| value.to_str().unwrap_or_default().rsplit(','));

        for entry in entries {
            let Ok(next) = entry.trim().parse::<IpAddr>() else {
                break;
            };
            ip = next.to_canonical();
            if !self.contains(&ip) {
                break;
            }
        }

        ip
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use axum::http::{HeaderMap, HeaderValue};

    use super::TrustedProxies;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn ignores_header_from_untrusted_peer() {
        let headers = forwarded(&["203.0.113.7"]);
        assert_eq!(
            TrustedProxies::Only(Vec::new()).client_ip(ip("198.51.100.1"), &headers),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn takes_rightmost_untrusted_hop() {
        let trusted = TrustedProxies::Only(vec![ip("127.0.0.1"), ip("10.0.0.2")]);
        let headers = forwarded(&["192.0.2.66, 203.0.113.7", "10.0.0.2"]);
        assert_eq!(
            trusted.client_ip(ip("127.0.0.1"), &headers),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn canonicalizes_mapped_addresses() {
        let trusted = TrustedProxies::Only(vec![ip("127.0.0.1")]);
        let headers = forwarded(&["2001:db8::1"]);
        assert_eq!(
            trusted.client_ip(ip("::ffff:127.0.0.1"), &headers),
            ip("2001:db8::1")
        );
    }

    #[test]
    fn trusting_all_takes_leftmost_hop() {
        let headers = forwarded(&["192.0.2.66, 203.0.113.7", "10.0.0.2"]);
        assert_eq!(
            TrustedProxies::All.client_ip(ip("127.0.0.1"), &headers),
            ip("192.0.2.66")
        );
    }

    #[test]
    fn stops_at_malformed_entry() {
        let trusted = TrustedProxies::Only(vec![ip("127.0.0.1")]);
        let headers = forwarded(&["203.0.113.7, garbage"]);
        assert_eq!(
            trusted.client_ip(ip("127.0.0.1"), &headers),
            ip("127.0.0.1")
        );
    }
}
