//! Deadbolt Send in the agent: one [`Server`] (an iroh endpoint of its own,
//! with a fresh key each time the agent starts) serving sealed bundles from
//! memory. The agent never sees a content key, needs no unlock, and keeps
//! serving across locks; every share ends when the agent stops.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use data_encoding::{BASE64, HEXLOWER};
use deadbolt_send::{Network, Policy, Server, ShareInfo, ShareRequest, State};
use zeroize::Zeroizing;

use super::{Agent, Conversation, fail};
use crate::config;
use crate::protocol::{ErrorCode, Reply, Secret, SendInfo, SendState, SenderInfo};

/// The longest a share may stay open.
pub const MAX_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// The most opens a share may allow.
pub const MAX_OPENS: u32 = 100;

impl Agent {
    async fn send_server(&self) -> Result<Server> {
        let mut server = self.send_server.lock().await;
        if let Some(server) = server.as_ref() {
            return Ok(server.clone());
        }
        let network = if self.local_net {
            Network::Local
        } else {
            Network::Relays
        };
        let started = Server::spawn(network, Arc::new(config::now))
            .await
            .context("starting the send endpoint")?;
        *server = Some(started.clone());
        Ok(started)
    }

    /// The server if one started; sends made before exist only on it.
    async fn existing_send_server(&self) -> Option<Server> {
        self.send_server.lock().await.clone()
    }

    /// Ends every send: the agent is stopping.
    pub(super) async fn stop_sends(&self) {
        self.stopping.send_replace(true);
        if let Some(server) = self.send_server.lock().await.take() {
            server.shutdown().await;
        }
    }

    pub(super) async fn send_create(
        &self,
        secret: Secret,
        sealed: String,
        opens: u32,
        ttl_secs: u64,
        label: String,
    ) -> Result<Reply> {
        let secret = decode_secret(&secret)?;
        let sealed = BASE64
            .decode(sealed.as_bytes())
            .context("the sealed bundle is not base64")?;
        if !(1..=MAX_OPENS).contains(&opens) {
            bail!("opens must be between 1 and {MAX_OPENS}");
        }
        if ttl_secs == 0 || ttl_secs > MAX_TTL.as_secs() {
            bail!("a share lasts between 1 second and 7 days");
        }
        let server = self.send_server().await?;
        let info = server.add(ShareRequest {
            secret,
            sealed,
            policy: Policy {
                opens,
                expires_at: config::now() + ttl_secs,
            },
            label,
        })?;
        let addr = server.addr().await;
        Ok(Reply::SendCreated {
            send: send_info(&info),
            sender: SenderInfo {
                id: HEXLOWER.encode(&addr.id),
                relay_url: addr.relay_url,
                direct_addrs: addr.direct_addrs.iter().map(ToString::to_string).collect(),
            },
        })
    }

    pub(super) async fn send_list(&self) -> Reply {
        let sends = match self.existing_send_server().await {
            Some(server) => server.list().iter().map(send_info).collect(),
            None => Vec::new(),
        };
        Reply::Sends { sends }
    }

    pub(super) async fn send_show(&self, id: &str) -> Result<Reply> {
        let server = self.existing_send_server().await;
        let info = server
            .and_then(|s| s.get(id))
            .ok_or_else(|| not_found(id))?;
        Ok(Reply::Send {
            send: send_info(&info),
        })
    }

    pub(super) async fn send_revoke(&self, id: &str) -> Result<Reply> {
        let server = self.existing_send_server().await;
        let info = server
            .and_then(|s| s.revoke(id))
            .ok_or_else(|| not_found(id))?;
        Ok(Reply::Send {
            send: send_info(&info),
        })
    }

    pub(super) async fn send_wait(&self, id: &str, conv: &Conversation) -> Result<Reply> {
        let server = self
            .existing_send_server()
            .await
            .ok_or_else(|| not_found(id))?;
        let mut stopping = self.stopping.subscribe();
        let info = tokio::select! {
            info = server.wait(id) => info.ok_or_else(|| not_found(id))?,
            () = conv.closed() => bail!("the client hung up"),
            _ = stopping.wait_for(|stopping| *stopping) => {
                bail!("the deadbolt agent stopped, which ended the send")
            }
        };
        Ok(Reply::Send {
            send: send_info(&info),
        })
    }
}

fn decode_secret(secret: &Secret) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        HEXLOWER
            .decode(secret.expose().as_bytes())
            .context("the access secret is not hex")?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    if bytes.len() != out.len() {
        bail!("the access secret must be 32 bytes");
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn not_found(id: &str) -> anyhow::Error {
    fail(
        ErrorCode::NotFound,
        format!("no send {id:?} (sends end when the agent stops)"),
    )
}

fn send_info(info: &ShareInfo) -> SendInfo {
    SendInfo {
        id: info.id.clone(),
        label: info.label.clone(),
        size: info.size as u64,
        created: info.created,
        expires: info.share.policy.expires_at,
        opens: info.share.policy.opens,
        opened: info.share.opened.clone(),
        revoked: info.share.revoked_at,
        state: match info.state {
            State::Open => SendState::Open,
            State::PickedUp => SendState::PickedUp,
            State::Expired => SendState::Expired,
            State::Revoked => SendState::Revoked,
        },
    }
}
