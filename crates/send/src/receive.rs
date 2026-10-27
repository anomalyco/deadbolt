use std::time::Duration;

use iroh::{
    Endpoint, RelayMode,
    endpoint::{ConnectionError, PortmapperConfig, ReadError, ReadExactError, presets},
};
use n0_future::time::timeout;
use tracing::debug;

use crate::{
    Bundle, MAX_SEALED_LEN, SEND_ALPN, SendTicket, close,
    error::{Error, Result},
    open, proof, status,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
const LINGER_TIMEOUT: Duration = Duration::from_secs(5);
const READ_CHUNK: usize = 64 * 1024;

/// Which network an endpoint uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// n0's public relays (the only way a browser connects), plus direct
    /// connections outside browsers.
    Relays,
    /// No relays, bound to `127.0.0.1`. For tests.
    Local,
}

/// How far a [`receive`] got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Connecting,
    /// Connected; proving the link's secret.
    Proving,
    /// `received` of `total` sealed bytes.
    Downloading {
        received: usize,
        total: usize,
    },
    Decrypting,
}

/// A receiving endpoint: a fresh random key, no address publishing.
pub async fn receiver_endpoint(network: Network) -> Result<Endpoint> {
    let builder = Endpoint::builder(presets::Minimal).portmapper_config(PortmapperConfig::Disabled);
    let builder = match network {
        Network::Relays => builder.relay_mode(iroh::endpoint::default_relay_mode()),
        Network::Local => local(builder.relay_mode(RelayMode::Disabled))?,
    };
    builder.bind().await.map_err(|e| Error::Bind(e.to_string()))
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn local(builder: iroh::endpoint::Builder) -> Result<iroh::endpoint::Builder> {
    builder
        .clear_ip_transports()
        .bind_addr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|e| Error::Bind(e.to_string()))
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) fn local(_: iroh::endpoint::Builder) -> Result<iroh::endpoint::Builder> {
    Err(Error::Bind("browsers can only use relays".into()))
}

/// Fetches and opens the bundle a link points to, reporting `progress`.
pub async fn receive(
    endpoint: &Endpoint,
    ticket: &SendTicket,
    mut progress: impl FnMut(Progress),
) -> Result<Bundle> {
    progress(Progress::Connecting);
    let addr = ticket.endpoint_addr()?;
    let conn = match timeout(CONNECT_TIMEOUT, endpoint.connect(addr, SEND_ALPN)).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return Err(Error::Offline(e.to_string())),
        Err(_) => return Err(Error::Offline("timed out connecting".into())),
    };
    progress(Progress::Proving);
    let receiver = *endpoint.id().as_bytes();
    let result = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| closed(&e))?;
        let transcript = proof::transcript(&conn, &ticket.id, &receiver)?;
        send.write_all(&proof::prove(&ticket.secret, &transcript))
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?;
        let mut head = [0u8; 1];
        step(recv.read_exact(&mut head)).await?;
        match head[0] {
            status::OK => {}
            status::EXPIRED => return Err(Error::Expired),
            status::USED => return Err(Error::Used),
            status::REVOKED => return Err(Error::Revoked),
            other => return Err(Error::Protocol(format!("unknown status {other}"))),
        }
        let mut len = [0u8; 8];
        step(recv.read_exact(&mut len)).await?;
        let total = usize::try_from(u64::from_be_bytes(len)).unwrap_or(usize::MAX);
        if total > MAX_SEALED_LEN {
            return Err(Error::TooLarge {
                len: total,
                max: MAX_SEALED_LEN,
            });
        }
        let mut sealed = vec![0u8; total];
        let mut received = 0;
        progress(Progress::Downloading { received, total });
        while received < total {
            let end = (received + READ_CHUNK).min(total);
            step(recv.read_exact(&mut sealed[received..end])).await?;
            received = end;
            progress(Progress::Downloading { received, total });
        }
        send.write_all(&[1])
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?;
        send.finish().map_err(|e| Error::Protocol(e.to_string()))?;
        Ok(sealed)
    }
    .await;
    let sealed = match result {
        Ok(sealed) => sealed,
        Err(err) => {
            conn.close(close::PROTOCOL, b"failed");
            return Err(err);
        }
    };
    // Let the acknowledgement arrive: the sender closes once it has it.
    if timeout(LINGER_TIMEOUT, conn.closed()).await.is_err() {
        debug!("sender did not close after the acknowledgement");
        conn.close(close::DONE, b"received");
    }
    progress(Progress::Decrypting);
    let plaintext = open(&ticket.key, &sealed)?;
    Bundle::decode(&plaintext)
}

async fn step<T>(fut: impl Future<Output = std::result::Result<T, ReadExactError>>) -> Result<T> {
    match timeout(STEP_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(ReadExactError::ReadError(ReadError::ConnectionLost(e)))) => Err(closed(&e)),
        Ok(Err(e)) => Err(Error::Protocol(e.to_string())),
        Err(_) => Err(Error::Protocol("timed out".into())),
    }
}

fn closed(e: &ConnectionError) -> Error {
    match e {
        ConnectionError::ApplicationClosed(c) if c.error_code == close::UNKNOWN => Error::Unknown,
        e => Error::Protocol(e.to_string()),
    }
}
