//! Rendezvous: how the existing device finds the new one from the code alone.
//!
//! Both devices derive the same Ed25519 key from the code ([`PairingCode::lookup_secret`],
//! Argon2id). The new device signs a pkarr record under that key naming its endpoint
//! id and addresses, and publishes it through n0's pkarr relay (the one iroh's own
//! address lookup uses); the existing device derives the public key and resolves it.
//! Nothing published names the code, and only someone holding the code can compute the
//! key, so there is no public nameplate. When the code is used or the wait ends, the
//! record is replaced with one saying so.

use std::{path::PathBuf, sync::Arc, time::Duration};

use iroh::{
    Endpoint, RelayUrl, SecretKey,
    address_lookup::{N0_DNS_PKARR_RELAY_PROD, PkarrRelayClient},
    endpoint_info::{EndpointInfo, UserData},
};
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use zeroize::Zeroizing;

use crate::{
    PairingCode, PeerAddr, PeerId,
    error::{Error, Result},
};

// No `=`: iroh reads a TXT attribute only up to its second one.
const PREFIX: &str = "deadbolt-pair:";
const USED: &str = "used";
const CLOSED: &str = "closed";
const MAX_ADDRS: usize = 8;
const TTL: u32 = 30;

/// Where pairing records go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rendezvous {
    /// n0's public pkarr relay.
    N0,
    /// Files in a directory, one per record: for tests on one machine without n0.
    Dir(PathBuf),
}

/// The rendezvous key pair derived from a code.
pub(crate) struct Lookup {
    secret: SecretKey,
    pub(crate) public: PeerId,
}

impl Lookup {
    /// Blocking (Argon2id).
    pub(crate) fn derive(code: &PairingCode) -> Result<Self> {
        let seed: Zeroizing<[u8; 32]> = code.lookup_secret()?;
        let secret = SecretKey::from_bytes(&seed);
        let public = *secret.public().as_bytes();
        Ok(Self { secret, public })
    }

    pub(crate) async fn derive_async(code: &PairingCode) -> Result<Self> {
        let code = code.clone();
        tokio::task::spawn_blocking(move || Self::derive(&code))
            .await
            .map_err(|e| Error::InvalidCode(e.to_string()))?
    }
}

/// What a rendezvous record says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Record {
    /// The new device is waiting here.
    Waiting(PeerAddr),
    /// The code was used (or a wrong code was tried, which also ends it).
    Used,
    /// The new device stopped waiting: it expired or was cancelled.
    Closed,
}

impl Record {
    fn sign(&self, lookup: &Lookup) -> Result<SignedPacket> {
        let mut info = EndpointInfo::new(lookup.secret.public());
        let state = match self {
            Self::Waiting(addr) => {
                if let Some(url) = &addr.relay_url {
                    let url: RelayUrl = url
                        .parse()
                        .map_err(|_| Error::InvalidRelayUrl(url.clone()))?;
                    info = info.with_relay_url(url);
                }
                info =
                    info.with_ip_addrs(addr.direct_addrs.iter().take(MAX_ADDRS).copied().collect());
                crate::fmt_id(&addr.id)
            }
            Self::Used => USED.into(),
            Self::Closed => CLOSED.into(),
        };
        let data: UserData = format!("{PREFIX}{state}")
            .try_into()
            .map_err(|_| Error::Rendezvous("record too long".into()))?;
        info.with_user_data(Some(data))
            .to_pkarr_signed_packet(&lookup.secret, TTL)
            .map_err(|e| Error::Rendezvous(format!("encoding the record: {e}")))
    }

    fn parse(packet: &SignedPacket) -> Result<Self> {
        let info = EndpointInfo::from_pkarr_signed_packet(packet)
            .map_err(|e| Error::Rendezvous(format!("reading the record: {e}")))?;
        let state = info
            .user_data()
            .and_then(|d| d.as_ref().strip_prefix(PREFIX).map(str::to_owned))
            .ok_or_else(|| Error::Rendezvous("not a pairing record".into()))?;
        match state.as_str() {
            USED => Ok(Self::Used),
            CLOSED => Ok(Self::Closed),
            hex => {
                let id: PeerId = data_encoding::HEXLOWER
                    .decode(hex.as_bytes())
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| Error::Rendezvous("bad endpoint id in record".into()))?;
                iroh::PublicKey::from_bytes(&id)
                    .map_err(|_| Error::Rendezvous("bad endpoint id in record".into()))?;
                Ok(Self::Waiting(PeerAddr {
                    id,
                    relay_url: info.relay_urls().next().map(|u| u.to_string()),
                    direct_addrs: info.ip_addrs().take(MAX_ADDRS).copied().collect(),
                }))
            }
        }
    }
}

#[derive(Clone)]
pub(crate) enum Client {
    N0(Arc<PkarrRelayClient>),
    Dir(PathBuf),
}

impl Client {
    pub(crate) fn new(rendezvous: &Rendezvous, endpoint: &Endpoint) -> Result<Self> {
        Ok(match rendezvous {
            Rendezvous::N0 => {
                let url = N0_DNS_PKARR_RELAY_PROD
                    .parse()
                    .map_err(|e| Error::Rendezvous(format!("relay url: {e}")))?;
                let dns = endpoint
                    .dns_resolver()
                    .map_err(|e| Error::Rendezvous(e.to_string()))?
                    .clone();
                Self::N0(Arc::new(PkarrRelayClient::new(
                    url,
                    endpoint.tls_config().clone(),
                    dns,
                )))
            }
            Rendezvous::Dir(dir) => Self::Dir(dir.clone()),
        })
    }

    pub(crate) async fn publish(&self, lookup: &Lookup, record: &Record) -> Result<()> {
        let packet = record.sign(lookup)?;
        match self {
            Self::N0(client) => client
                .publish(&packet)
                .await
                .map_err(|e| Error::Rendezvous(format!("publishing: {e}"))),
            Self::Dir(dir) => {
                tokio::fs::create_dir_all(dir).await?;
                let path = dir.join(crate::fmt_id(&lookup.public));
                let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
                tokio::fs::write(&tmp, packet.as_bytes()).await?;
                tokio::fs::rename(&tmp, &path).await?;
                Ok(())
            }
        }
    }

    /// The record under `key`, if there is one younger than `max_age`.
    pub(crate) async fn resolve(&self, key: &PeerId, max_age: Duration) -> Result<Option<Record>> {
        let public =
            iroh::PublicKey::from_bytes(key).map_err(|e| Error::Rendezvous(e.to_string()))?;
        let packet = match self {
            Self::N0(client) => match client.resolve(public).await {
                Ok(packet) => packet,
                Err(error) => {
                    tracing::debug!(%error, "no pairing record yet");
                    return Ok(None);
                }
            },
            Self::Dir(dir) => match tokio::fs::read(dir.join(crate::fmt_id(key))).await {
                Ok(bytes) => SignedPacket::from_bytes(&bytes)
                    .map_err(|e| Error::Rendezvous(format!("bad record: {e}")))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            },
        };
        if packet.public_key() != public {
            return Err(Error::Rendezvous("record signed by another key".into()));
        }
        let now = Timestamp::now().as_micros();
        let age = Duration::from_micros(now.saturating_sub(packet.timestamp().as_micros()));
        if age > max_age {
            return Ok(None);
        }
        Record::parse(&packet).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup() -> Lookup {
        Lookup::derive(&"violin-garden-tiger-lamp".parse().unwrap()).unwrap()
    }

    #[test]
    fn records_round_trip_and_are_bound_to_the_key() {
        let lookup = lookup();
        let id = *SecretKey::from_bytes(&[3; 32]).public().as_bytes();
        let waiting = Record::Waiting(PeerAddr {
            id,
            relay_url: Some("https://relay.example.com./".into()),
            direct_addrs: vec!["127.0.0.1:4242".parse().unwrap()],
        });
        for record in [waiting, Record::Used, Record::Closed] {
            let packet = record.sign(&lookup).unwrap();
            assert_eq!(*packet.public_key().as_bytes(), lookup.public);
            assert_eq!(Record::parse(&packet).unwrap(), record);
        }
    }

    #[test]
    fn the_rendezvous_key_never_changes() {
        // Both devices must derive the same key from the same code across builds.
        assert_eq!(
            crate::fmt_id(&lookup().public),
            "951d3837dbd6c454c4e021718b0b49b426d4e1717d224f6b23d126aebecdcc76"
        );
    }

    #[tokio::test]
    async fn a_directory_serves_fresh_records_only() {
        let dir = tempfile::tempdir().unwrap();
        let client = Client::Dir(dir.path().to_path_buf());
        let lookup = lookup();
        assert_eq!(
            client
                .resolve(&lookup.public, Duration::from_secs(60))
                .await
                .unwrap(),
            None
        );
        client.publish(&lookup, &Record::Used).await.unwrap();
        assert_eq!(
            client
                .resolve(&lookup.public, Duration::from_secs(60))
                .await
                .unwrap(),
            Some(Record::Used)
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(
            client
                .resolve(&lookup.public, Duration::ZERO)
                .await
                .unwrap(),
            None
        );
    }
}
