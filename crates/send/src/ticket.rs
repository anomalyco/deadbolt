use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use data_encoding::BASE64URL_NOPAD;
use iroh::{EndpointAddr, PublicKey, RelayUrl};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Where links point. The ticket follows `#`, so it never reaches the server.
pub const LINK_BASE: &str = "https://deadbolt.pw/r";

const VERSION: u8 = 1;
const MAX_ADDRS: usize = 4;

/// Everything a receiver needs: how to reach the sender, the access secret it
/// proves (never sends) and the key the bundle is sealed with.
#[derive(Clone, PartialEq, Eq)]
pub struct SendTicket {
    /// The sender's iroh endpoint id.
    pub id: [u8; 32],
    /// The sender's home relay. Browsers can only connect through it.
    pub relay_url: Option<String>,
    /// The sender's direct addresses, for native receivers.
    pub direct_addrs: Vec<SocketAddr>,
    pub secret: Zeroizing<[u8; 32]>,
    pub key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for SendTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendTicket")
            .field("id", &data_encoding::HEXLOWER.encode(&self.id))
            .field("relay_url", &self.relay_url)
            .field("direct_addrs", &self.direct_addrs)
            .field("secret", &"<redacted>")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// How to reach a sender: what a [`SendTicket`] carries besides its secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderAddr {
    pub id: [u8; 32],
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
}

impl SendTicket {
    pub fn new(addr: SenderAddr, secret: Zeroizing<[u8; 32]>, key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            id: addr.id,
            relay_url: addr.relay_url,
            direct_addrs: addr.direct_addrs,
            secret,
            key,
        }
    }

    /// `version(1) || id(32) || secret(32) || key(32) || relay_len(1) || relay_url ||
    /// addr_count(1) || addr*`, each addr `4 || ipv4(4) || port(2)` or
    /// `6 || ipv6(16) || port(2)`, integers big-endian.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(160));
        out.push(VERSION);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(self.secret.as_ref());
        out.extend_from_slice(self.key.as_ref());
        let relay = self
            .relay_url
            .as_deref()
            .filter(|u| u.len() <= u8::MAX as usize)
            .unwrap_or("")
            .as_bytes();
        out.push(relay.len() as u8);
        out.extend_from_slice(relay);
        let addrs = &self.direct_addrs[..self.direct_addrs.len().min(MAX_ADDRS)];
        out.push(addrs.len() as u8);
        for addr in addrs {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(1)?[0] != VERSION {
            return Err(Error::InvalidLink("unsupported version".into()));
        }
        let id: [u8; 32] = r.array()?;
        let secret = Zeroizing::new(r.array()?);
        let key = Zeroizing::new(r.array()?);
        let relay_url = match r.take(1)?[0] as usize {
            0 => None,
            n => Some(
                String::from_utf8(r.take(n)?.to_vec())
                    .map_err(|_| Error::InvalidLink("relay url is not utf-8".into()))?,
            ),
        };
        let count = r.take(1)?[0] as usize;
        if count > MAX_ADDRS {
            return Err(Error::InvalidLink("too many addresses".into()));
        }
        let mut direct_addrs = Vec::with_capacity(count);
        for _ in 0..count {
            let ip = match r.take(1)?[0] {
                4 => IpAddr::V4(Ipv4Addr::from(r.array::<4>()?)),
                6 => IpAddr::V6(Ipv6Addr::from(r.array::<16>()?)),
                _ => return Err(Error::InvalidLink("bad address family".into())),
            };
            direct_addrs.push(SocketAddr::new(ip, u16::from_be_bytes(r.array()?)));
        }
        if !r.0.is_empty() {
            return Err(Error::InvalidLink("trailing bytes".into()));
        }
        PublicKey::from_bytes(&id).map_err(|_| Error::InvalidLink("invalid endpoint id".into()))?;
        if let Some(url) = &relay_url {
            url.parse::<RelayUrl>()
                .map_err(|_| Error::InvalidLink("invalid relay url".into()))?;
        }
        Ok(Self {
            id,
            relay_url,
            direct_addrs,
            secret,
            key,
        })
    }

    /// The link: [`LINK_BASE`] `#` the unpadded base64url of [`Self::to_bytes`].
    pub fn link(&self) -> String {
        self.link_at(LINK_BASE)
    }

    /// The link on another receive page (a local site, for tests).
    pub fn link_at(&self, base: &str) -> String {
        format!("{base}#{self}")
    }

    pub(crate) fn endpoint_addr(&self) -> Result<EndpointAddr> {
        let id = PublicKey::from_bytes(&self.id)
            .map_err(|_| Error::InvalidLink("invalid endpoint id".into()))?;
        let mut addr = EndpointAddr::new(id);
        if let Some(url) = &self.relay_url {
            let url: RelayUrl = url
                .parse()
                .map_err(|_| Error::InvalidLink("invalid relay url".into()))?;
            addr = addr.with_relay_url(url);
        }
        for ip in &self.direct_addrs {
            addr = addr.with_ip_addr(*ip);
        }
        Ok(addr)
    }
}

/// The unpadded base64url of [`SendTicket::to_bytes`].
impl fmt::Display for SendTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64URL_NOPAD.encode(&self.to_bytes()))
    }
}

/// A whole link, or only what follows its `#`. Surrounding whitespace is ignored.
impl FromStr for SendTicket {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let body = s.rsplit_once('#').map_or(s, |(_, fragment)| fragment);
        let bytes = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(body.as_bytes())
                .map_err(|e| Error::InvalidLink(format!("bad encoding: {e}")))?,
        );
        Self::from_bytes(&bytes)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        bytes.copy_from_slice(self.take(N)?);
        Ok(bytes)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::InvalidLink("truncated".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket() -> SendTicket {
        SendTicket {
            id: *iroh::SecretKey::from_bytes(&[7; 32]).public().as_bytes(),
            relay_url: Some("https://use1-1.relay.n0.iroh-canary.iroh.link./".into()),
            direct_addrs: vec![
                "127.0.0.1:4242".parse().unwrap(),
                "[fe80::1]:9".parse().unwrap(),
            ],
            secret: Zeroizing::new([9; 32]),
            key: Zeroizing::new([5; 32]),
        }
    }

    #[test]
    fn links_round_trip() {
        let t = ticket();
        let link = t.link();
        assert!(link.starts_with("https://deadbolt.pw/r#"), "{link}");
        let fragment = link.split_once('#').unwrap().1;
        assert!(
            fragment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "{fragment}"
        );
        assert_eq!(link.parse::<SendTicket>().unwrap(), t);
        assert_eq!(fragment.parse::<SendTicket>().unwrap(), t);
        assert_eq!(
            format!("  {}\n", t.link_at("http://127.0.0.1:5197/r"))
                .parse::<SendTicket>()
                .unwrap(),
            t
        );
        let bare = SendTicket {
            relay_url: None,
            direct_addrs: vec![],
            ..t.clone()
        };
        assert_eq!(bare.to_string().parse::<SendTicket>().unwrap(), bare);
    }

    #[test]
    fn debug_hides_the_secrets() {
        let debug = format!("{:?}", ticket());
        assert!(
            !debug.contains("9, 9") && !debug.contains("5, 5"),
            "{debug}"
        );
    }

    #[test]
    fn links_cap_their_addresses() {
        let mut t = ticket();
        t.direct_addrs = (1..10)
            .map(|p| SocketAddr::from(([10, 0, 0, 1], p)))
            .collect();
        let back: SendTicket = t.to_string().parse().unwrap();
        assert_eq!(back.direct_addrs.len(), MAX_ADDRS);
    }

    #[test]
    fn garbage_is_rejected() {
        let s = ticket().to_string();
        assert!("".parse::<SendTicket>().is_err());
        assert!("https://deadbolt.pw/r#".parse::<SendTicket>().is_err());
        assert!(s[..s.len() - 4].parse::<SendTicket>().is_err());
        assert!(format!("{s}AA").parse::<SendTicket>().is_err());
        assert!("not base64!".parse::<SendTicket>().is_err());
        let mut bytes = ticket().to_bytes();
        bytes[0] = 2;
        assert!(SendTicket::from_bytes(&bytes).is_err());
    }
}
