//! Vault sync over deadbolt-net.
//!
//! The opaque heads blob is a JSON [`application::Hello`]: the sender's name and address,
//! hints about other members, and the core `Heads` of each vault it shares
//! with the receiver. Entries are sent for vaults both sides list and the
//! receiver is a member of, all membership entries first. Until the startup
//! round (membership with every reachable member) is done, only membership
//! entries are sent.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use deadbolt_core::{DeviceId, VaultId};
use deadbolt_net::application;
use deadbolt_net::{Blob, HandlerError, PeerId, SyncHandler};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::Daemon;
use super::session::{Addr, Loaded};
use crate::protocol::PeerSync;

pub const SYNC_INTERVAL: Duration = Duration::from_secs(30);
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(15);
/// Best-effort startup membership refresh. At the deadline peer data resumes
/// using the membership learned so far; normal background sync keeps retrying.
pub const STARTUP_TIMEOUT: Duration = SYNC_TIMEOUT.saturating_mul(2);
const STARTUP_RETRY: Duration = Duration::from_secs(1);

// Every frame core commits fits one sync frame, and a peer serving a session we
// opened never gives up before we do.
const _: () = assert!(deadbolt_core::MAX_FRAME_LEN <= deadbolt_net::DEFAULT_MAX_FRAME_LEN);
const _: () = assert!(deadbolt_core::MAX_FRAME_LEN <= deadbolt_pack::log::MAX_RECORD);
const _: () = assert!(SYNC_TIMEOUT.as_secs() * 2 <= deadbolt_net::INBOUND_SYNC_TIMEOUT.as_secs());

pub struct Handler(pub Arc<Daemon>);

fn handler_error(error: anyhow::Error) -> HandlerError {
    format!("{error:#}").into()
}

/// One incoming stream: removals it delivered, and whether item or label
/// changes still need forwarding once it completes.
#[derive(Default)]
pub struct Receiving {
    stream: application::ReceiveStream,
    pending_forward: bool,
}

impl SyncHandler for Handler {
    type ReceiveState = Receiving;

    async fn heads(&self, peer: PeerId) -> Result<Vec<u8>, HandlerError> {
        self.0
            .with(|s| hello(s, &s.device_of(&peer)?, Some(s.own_addr())))
            .map_err(handler_error)
    }

    async fn missing_for(
        &self,
        peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> Result<deadbolt_net::Outgoing<'_>, HandlerError> {
        let history = self
            .0
            .with(|s| {
                let ready = *self.0.ready.borrow();
                let peer = s.device_of(&peer)?;
                missing_for(s, &peer, &peer_heads, ready)
            })
            .map_err(handler_error)?;
        Ok(history.outgoing(|h| {
            self.0
                .with(|s| Ok(h.next(&**s, *self.0.ready.borrow())?))
                .map_err(handler_error)
        }))
    }

    async fn receive(
        &self,
        peer: PeerId,
        entries: Vec<Blob>,
        state: &mut Receiving,
        done: bool,
    ) -> Result<(), HandlerError> {
        let daemon = &self.0;
        let peer = daemon.with(|s| s.device_of(&peer)).map_err(handler_error)?;
        let Receiving {
            stream,
            pending_forward,
        } = state;
        daemon
            .with(|s| {
                let ready = *daemon.ready.borrow();
                let received = receive(s, &peer, entries, ready, stream);
                // Even an errored batch may have committed an earlier vault's removal.
                daemon.refresh(s);
                // Defer only item and label forwarding, not watcher delivery, admission
                // changes or enforcement. A sole sender already has its own delta.
                *pending_forward |= s.changes.edits.iter().any(|id| {
                    let vault = s.vault(id);
                    vault.members().any(|id| id != s.id && id != peer)
                });
                if !s.changes.devices.is_empty() || (done && received.is_ok() && *pending_forward) {
                    daemon.sync_now.notify_one();
                }
                received.map(drop)
            })
            .map_err(handler_error)
    }
}

pub(super) fn hello(s: &Loaded, peer: &DeviceId, addr: Option<Addr>) -> Result<Vec<u8>> {
    s.ensure_usable()?;
    Ok(application::hello(s, peer, addr)?)
}

pub(super) fn missing_for(
    s: &mut Loaded,
    peer: &DeviceId,
    bytes: &[u8],
    ready: bool,
) -> Result<application::OutgoingHistory> {
    s.ensure_usable()?;
    application::missing_for(s, peer, bytes, ready)
}

pub(super) fn receive(
    s: &mut Loaded,
    peer: &DeviceId,
    entries: Vec<Blob>,
    ready: bool,
    stream: &mut application::ReceiveStream,
) -> Result<usize> {
    s.ensure_usable()?;
    application::receive(s, peer, entries, ready, stream)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Attempt {
    Complete,
    Unreachable,
    Interrupted,
}

pub(super) fn barrier_complete(
    members: &HashSet<PeerId>,
    attempts: &BTreeMap<PeerId, Attempt>,
) -> bool {
    members.iter().all(|peer| {
        matches!(
            attempts.get(peer),
            Some(Attempt::Complete | Attempt::Unreachable)
        )
    })
}

/// The dial and exchange share one deadline. A remote membership refusal is a
/// completed contact; other post-connect errors leave the round interrupted.
async fn attempt<C, T>(
    connect: impl Future<Output = deadbolt_net::Result<C>>,
    exchange: impl FnOnce(C) -> T,
) -> (
    Attempt,
    std::result::Result<deadbolt_net::SyncOutcome, String>,
)
where
    T: Future<Output = deadbolt_net::Result<deadbolt_net::SyncOutcome>>,
{
    let deadline = tokio::time::Instant::now() + SYNC_TIMEOUT;
    let conn = match tokio::time::timeout_at(deadline, connect).await {
        Ok(Ok(conn)) => conn,
        // A peer at its inbound limit refuses the dial: it is there, so retry it.
        Ok(Err(error @ deadbolt_net::Error::Rejected(_))) => {
            return (Attempt::Interrupted, Err(error.to_string()));
        }
        Ok(Err(error)) => return (Attempt::Unreachable, Err(error.to_string())),
        Err(_) => return (Attempt::Unreachable, Err("dial timed out".into())),
    };
    match tokio::time::timeout_at(deadline, exchange(conn)).await {
        Ok(Ok(outcome)) => (Attempt::Complete, Ok(outcome)),
        Ok(Err(error @ deadbolt_net::Error::MembershipRejected(_))) => {
            (Attempt::Complete, Err(error.to_string()))
        }
        Ok(Err(error)) => (Attempt::Interrupted, Err(error.to_string())),
        Err(_) => (Attempt::Interrupted, Err("sync timed out".into())),
    }
}

/// Returns false only when the total startup budget expires. Round errors and
/// connected peers that fail mid-exchange are retried within the same budget.
async fn wait_for_membership<F: Future<Output = Result<bool>>>(
    mut round: impl FnMut() -> F,
) -> bool {
    tokio::time::timeout(STARTUP_TIMEOUT, async {
        loop {
            match round().await {
                Ok(true) => return,
                Ok(false) => {}
                Err(error) => warn!("startup sync failed: {error:#}"),
            }
            tokio::time::sleep(STARTUP_RETRY).await;
        }
    })
    .await
    .is_ok()
}

/// Syncs with every member of every vault, or only of `only`, concurrently.
pub async fn sync_all(daemon: &Arc<Daemon>, only: Option<VaultId>) -> Result<Vec<PeerSync>> {
    Ok(sync_round(daemon, only).await?.0)
}

async fn sync_round(
    daemon: &Arc<Daemon>,
    only: Option<VaultId>,
) -> Result<(Vec<PeerSync>, BTreeMap<PeerId, Attempt>)> {
    let (node, targets) = daemon.with(|s| {
        let peers = match only {
            Some(id) => s
                .vault(&id)
                .members()
                .filter(|member| *member != s.id)
                .map(|member| *member.as_bytes())
                .collect(),
            None => s.peer_set(),
        };
        let targets: Vec<_> = peers
            .into_iter()
            .map(|id| (id, s.addr_of(&DeviceId::from_bytes(id))))
            .collect();
        Ok((s.node.clone(), targets))
    })?;
    let mut tasks = JoinSet::new();
    for (id, addr) in targets {
        let node = node.clone();
        tasks.spawn(async move {
            // A member whose card hasn't arrived has no transport key to dial.
            let Some(addr) = addr else {
                let error = "no device card yet, so no transport key to dial".to_owned();
                return (id, Attempt::Unreachable, Err(error));
            };
            let (attempt, result) = attempt(node.connect(addr), |conn| async move {
                let result = conn.sync().await;
                conn.close();
                result
            })
            .await;
            (id, attempt, result)
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        results.push(joined?);
    }
    daemon.with(|s| {
        let connected = s.connected_devices(node.connected_peers());
        let attempts = results
            .iter()
            .map(|(id, attempt, _)| (*id, *attempt))
            .collect();
        let mut peers: Vec<PeerSync> = results
            .into_iter()
            .map(|(id, _, result)| {
                let device = s.device_info(&DeviceId::from_bytes(id), &connected);
                // A removed device is told its removal and sent nothing
                // else: say so, unless another vault is still shared.
                let peer = DeviceId::from_bytes(id);
                let removed: Vec<&str> = s
                    .vaults
                    .values()
                    .filter(|v| !v.is_member(&s.id) && (v.is_member(&peer) || v.was_removed(&s.id)))
                    .map(|v| v.name())
                    .collect();
                let shares = s
                    .vaults
                    .values()
                    .any(|v| v.is_member(&s.id) && v.is_member(&peer));
                let result = match result {
                    Ok(_) if !shares && !removed.is_empty() => Err(format!(
                        "rejected: this device was removed from {}",
                        removed.join(", ")
                    )),
                    result => result,
                };
                match result {
                    Ok(outcome) => PeerSync {
                        device,
                        sent: outcome.sent,
                        received: outcome.received,
                        error: None,
                    },
                    Err(error) => {
                        debug!(peer = %device.id, "sync failed: {error}");
                        PeerSync {
                            device,
                            sent: 0,
                            received: 0,
                            error: Some(error),
                        }
                    }
                }
            })
            .collect();
        peers.sort_by(|a, b| (&a.device.name, &a.device.id).cmp(&(&b.device.name, &b.device.id)));
        Ok((peers, attempts))
    })
}

/// The background sync loop, running while unlocked: a membership round with
/// every reachable member (bounded by [`STARTUP_TIMEOUT`]), then full syncs every [`SYNC_INTERVAL`] and
/// whenever something changed.
pub async fn run(daemon: Arc<Daemon>) {
    if !*daemon.ready.borrow() {
        let completed = wait_for_membership(|| async {
            let (_, attempts) = sync_round(&daemon, None).await?;
            // Include members learned during this round, not just its original targets.
            daemon.with(|s| {
                let complete = barrier_complete(&s.peer_set(), &attempts);
                if complete {
                    daemon.ready.send_replace(true);
                }
                Ok(complete)
            })
        })
        .await;
        if !completed {
            warn!("startup membership deadline reached; continuing with known membership");
            if daemon
                .with(|_| {
                    daemon.ready.send_replace(true);
                    Ok(())
                })
                .is_err()
            {
                return;
            }
        }
    }
    loop {
        if let Err(error) = sync_all(&daemon, None).await {
            warn!("sync failed: {error:#}");
        }
        tokio::select! {
            _ = tokio::time::sleep(SYNC_INTERVAL) => {}
            _ = daemon.sync_now.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadbolt_core::v2::{Frame, LogKind};
    use deadbolt_core::{Field, FieldType, Vault, VaultId};

    #[test]
    fn startup_requires_attempts_for_current_and_newly_discovered_peers() {
        assert!(!barrier_complete(
            &HashSet::from([[1; 32]]),
            &BTreeMap::new()
        ));
        assert!(!barrier_complete(
            &HashSet::from([[1; 32], [2; 32]]),
            &BTreeMap::from([([1; 32], Attempt::Complete)])
        ));
        assert!(barrier_complete(
            &HashSet::from([[1; 32]]),
            &BTreeMap::from([([1; 32], Attempt::Complete)])
        ));
        assert!(barrier_complete(
            &HashSet::from([[1; 32]]),
            &BTreeMap::from([([1; 32], Attempt::Unreachable)])
        ));
        assert!(!barrier_complete(
            &HashSet::from([[1; 32]]),
            &BTreeMap::from([([1; 32], Attempt::Interrupted)])
        ));
    }

    fn outcome() -> deadbolt_net::SyncOutcome {
        deadbolt_net::SyncOutcome {
            sent: 0,
            received: 0,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dial_failures_and_timeouts_are_unreachable_but_exchange_failures_are_not() {
        let failed_dial = attempt(
            async { Err::<(), _>(deadbolt_net::Error::Connect("offline".into())) },
            |_| async { Ok(outcome()) },
        )
        .await;
        assert_eq!(failed_dial.0, Attempt::Unreachable);
        let dial_timeout = attempt(
            std::future::pending::<deadbolt_net::Result<()>>(),
            |_| async { Ok(outcome()) },
        )
        .await;
        assert_eq!(dial_timeout.0, Attempt::Unreachable);
        let busy_dial = attempt(
            async { Err::<(), _>(deadbolt_net::Error::Rejected("too many connections".into())) },
            |_| async { Ok(outcome()) },
        )
        .await;
        assert_eq!(busy_dial.0, Attempt::Interrupted);
        let failed_exchange = attempt(async { Ok(()) }, |_| async {
            Err(deadbolt_net::Error::Closed("broken stream".into()))
        })
        .await;
        assert_eq!(failed_exchange.0, Attempt::Interrupted);
        let exchange_timeout = attempt(async { Ok(()) }, |_| std::future::pending()).await;
        assert_eq!(exchange_timeout.0, Attempt::Interrupted);
    }

    #[tokio::test]
    async fn remote_membership_refusal_completes_startup_contact() {
        let (result, error) = attempt(async { Ok(()) }, |_| async {
            Err(deadbolt_net::Error::MembershipRejected(
                "not a member".into(),
            ))
        })
        .await;
        assert!(error.is_err());
        assert_eq!(result, Attempt::Complete);
        assert!(barrier_complete(
            &HashSet::from([[1; 32]]),
            &BTreeMap::from([([1; 32], result)]),
        ));
        let (result, _) = attempt(async { Ok(()) }, |_| async {
            Err(deadbolt_net::Error::Rejected("pairing unavailable".into()))
        })
        .await;
        assert_eq!(result, Attempt::Interrupted);
    }

    #[tokio::test(start_paused = true)]
    async fn interrupted_round_retries_before_opening_and_flapping_has_a_total_bound() {
        let rounds = std::cell::Cell::new(0);
        assert!(
            wait_for_membership(|| async {
                rounds.set(rounds.get() + 1);
                let result = if rounds.get() == 1 {
                    Attempt::Interrupted
                } else {
                    Attempt::Complete
                };
                Ok(barrier_complete(
                    &HashSet::from([[1; 32]]),
                    &BTreeMap::from([([1; 32], result)]),
                ))
            })
            .await
        );
        assert_eq!(rounds.get(), 2);
        let start = tokio::time::Instant::now();
        assert!(!wait_for_membership(|| async { Ok(false) }).await);
        assert_eq!(start.elapsed(), STARTUP_TIMEOUT);
        let start = tokio::time::Instant::now();
        assert!(!wait_for_membership(std::future::pending::<Result<bool>>).await);
        assert_eq!(start.elapsed(), STARTUP_TIMEOUT);
    }

    const FAST: crate::disk::KdfParams = crate::disk::KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    use super::super::session::tests::{author, blob, local, peer};

    /// Adds devices seeded `seeds` to `vault`, as `s`.
    fn add_all(s: &mut Loaded, vault: VaultId, seeds: &[u8]) {
        let me = s.id;
        s.update(vault, |v, a| {
            for seed in seeds {
                let (keys, consent) = peer(*seed, &vault, &me);
                v.add(a, keys.device_id(), keys.kem_public(), consent)?;
                // Connections name a device by the transport key its card gives.
                v.card(a, keys.device_id(), keys.net_public(), "peer")?;
            }
            Ok(())
        })
        .unwrap();
    }

    // Drive the real wire reader up to a specific prefix without yielding to a timer.
    // A background round waiting on sync_now would consume the same permit we inspect.
    #[tokio::test]
    async fn forward_committed_prefixes_once_at_done() {
        use std::task::{Context, Waker};
        use tokio::io::{AsyncWriteExt, DuplexStream};

        // deadbolt/sync/1 tags, as sent by the scripted peer.
        const HEADS: u8 = 1;
        const ENTRY: u8 = 2;
        const DONE: u8 = 3;
        async fn frame(w: &mut DuplexStream, tag: u8, body: &[u8]) {
            w.write_u32(1 + body.len() as u32).await.unwrap();
            w.write_u8(tag).await.unwrap();
            w.write_all(body).await.unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::new(super::super::tests::test_paths(dir.path()), true, FAST);
        daemon
            .setup("test".to_owned().into(), "local".into())
            .await
            .unwrap();
        let sender = author(2);
        let third = author(3);
        let peer = *sender.keys().net_public().as_bytes();
        let (mut shared, mut sole_sender) = daemon
            .with(|s| {
                s.sync_task.take();
                s.health_task.take();
                let shared = s.create_vault("shared")?;
                add_all(s, shared, &[2, 3]);
                let two = s.create_vault("two")?;
                add_all(s, two, &[2]);
                let vaults = (s.vault(&shared).clone(), s.vault(&two).clone());
                daemon.refresh(s);
                Ok(vaults)
            })
            .unwrap();
        let handler = Handler(daemon.clone());
        let session = || {
            let (mut reader, writer) = tokio::io::duplex(8192);
            let handler = &handler;
            (
                writer,
                Box::pin(tokio::task::unconstrained(async move {
                    deadbolt_net::run_sync_session(
                        handler,
                        peer,
                        &mut tokio::io::sink(),
                        &mut reader,
                        deadbolt_net::DEFAULT_MAX_FRAME_LEN,
                        false,
                    )
                    .await
                    .unwrap()
                })),
            )
        };
        let cx = &mut Context::from_waker(Waker::noop());
        let woke = || {
            std::pin::pin!(daemon.sync_now.notified())
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        };
        let heads = handler.heads(peer).await.unwrap();
        assert!(!woke());
        let edit = |v: &mut Vault| {
            let (_, frame) = local(v, |w| {
                w.create_item(&sender, "login", Some("edit".into()), [])
            });
            blob(v, frame)
        };
        for final_duplicate in [false, true] {
            use crate::protocol::Change;
            let watcher = daemon.watchers.subscribe(false);
            let (mut wire, mut exchange) = session();
            frame(&mut wire, HEADS, &heads).await;
            let first = if final_duplicate {
                let frame = local(&mut shared, |w| w.rename(&sender, "new-label"));
                blob(&shared, frame)
            } else {
                edit(&mut shared)
            };
            frame(&mut wire, ENTRY, &first).await;
            assert!(exchange.as_mut().poll(cx).is_pending());
            assert!(
                !woke(),
                "neither a data prefix nor a label is a membership change"
            );
            // Completing an overlapping stream from the same peer must not flush
            // or consume this one's pending forward.
            let (mut other, concurrent) = session();
            frame(&mut other, HEADS, &heads).await;
            frame(&mut other, DONE, &[]).await;
            concurrent.await;
            assert!(!woke());

            frame(&mut wire, ENTRY, &edit(&mut sole_sender)).await;
            let last = if final_duplicate {
                edit(&mut sole_sender)
            } else {
                edit(&mut shared)
            };
            frame(&mut wire, ENTRY, &last).await;
            assert!(exchange.as_mut().poll(cx).is_pending());
            assert!(!woke());
            // Watches do not wait for DONE, lose the second vault or report a
            // label change as a device change.
            let seen = tokio::time::timeout(Duration::from_secs(5), watcher.next())
                .await
                .unwrap();
            let items = |v: &Vault| Change::Items {
                vault: v.id().to_string(),
            };
            assert_eq!(seen.len(), 2, "{seen:?}");
            assert!(seen.contains(&items(&sole_sender)));
            assert!(seen.contains(&if final_duplicate {
                Change::Vaults
            } else {
                items(&shared)
            }));
            if final_duplicate {
                frame(&mut wire, ENTRY, &last).await;
            }
            frame(&mut wire, DONE, &[]).await;
            exchange.await;
            assert!(woke(), "the final batch need not add anything");
        }
        // Abandon a dirty stream. A later exchange with new data *only* for
        // the sole sender must not inherit its pending forward or echo it.
        let (mut wire, mut cut) = session();
        frame(&mut wire, HEADS, &heads).await;
        frame(&mut wire, ENTRY, &edit(&mut shared)).await;
        assert!(cut.as_mut().poll(cx).is_pending());
        drop(cut);
        let (mut wire, next) = session();
        frame(&mut wire, HEADS, &heads).await;
        frame(&mut wire, ENTRY, &edit(&mut sole_sender)).await;
        frame(&mut wire, DONE, &[]).await;
        next.await;
        assert!(!woke());
        // Removing the third peer must wake and close its gate *before* DONE.
        let (mut wire, mut exchange) = session();
        frame(&mut wire, HEADS, &heads).await;
        let removal = local(&mut shared, |w| w.remove(&sender, third.id()));
        frame(&mut wire, ENTRY, &blob(&shared, removal)).await;
        assert!(exchange.as_mut().poll(cx).is_pending());
        assert!(woke());
        assert!(
            !daemon
                .members
                .read()
                .unwrap()
                .contains(third.id().as_bytes())
        );
        drop(exchange);
        daemon.lock().await;
    }

    /// The production sync handlers, ready, over a plain in-memory stream.
    struct Plain(std::sync::Mutex<Loaded>, std::sync::atomic::AtomicUsize);

    impl SyncHandler for Plain {
        type ReceiveState = application::ReceiveStream;

        async fn heads(&self, peer: PeerId) -> Result<Vec<u8>, HandlerError> {
            let s = self.0.lock().unwrap();
            hello(&s, &DeviceId::from_bytes(peer), None).map_err(handler_error)
        }

        async fn missing_for(
            &self,
            peer: PeerId,
            heads: Vec<u8>,
        ) -> Result<deadbolt_net::Outgoing<'_>, HandlerError> {
            let mut s = self.0.lock().unwrap();
            let history = missing_for(&mut s, &DeviceId::from_bytes(peer), &heads, true)
                .map_err(handler_error)?;
            Ok(history.outgoing(|h| Ok(h.next(&*self.0.lock().unwrap(), true)?)))
        }

        async fn receive(
            &self,
            peer: PeerId,
            entries: Vec<Blob>,
            stream: &mut application::ReceiveStream,
            _: bool,
        ) -> Result<(), HandlerError> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut s = self.0.lock().unwrap();
            receive(&mut s, &DeviceId::from_bytes(peer), entries, true, stream)
                .map(drop)
                .map_err(handler_error)
        }
    }

    /// A vault the size of a real one (thousands of imported items, large notes,
    /// one near the frame limit, edits one at a time) pairs to a new device and
    /// then syncs to it through the production handlers and sync protocol.
    #[tokio::test]
    async fn a_large_imported_vault_pairs_and_syncs() {
        use deadbolt_core::DataOp;
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut a = Loaded::setup(a_dir.path(), b"a", "alpha", FAST).unwrap();
        let mut b = Loaded::setup(b_dir.path(), b"b", "beta", FAST).unwrap();
        let vault = a.create_vault("personal").unwrap();
        let login = |i: usize| {
            DataOp::create(
                "login",
                Some(format!("Site {i}")),
                [
                    (
                        "password".into(),
                        Field::new(FieldType::Secret, format!("pw-{i}")),
                    ),
                    (
                        "username".into(),
                        Field::new(FieldType::Text, "me@example.com"),
                    ),
                    (
                        "url".into(),
                        Field::new(FieldType::Url, format!("https://{i}.example.com")),
                    ),
                    (
                        "notes".into(),
                        Field::new(FieldType::Note, "x".repeat(1 + i % 500)),
                    ),
                ],
            )
        };
        let note = |name: &str, len: usize| {
            let field = Field::new(FieldType::Secret, "n".repeat(len));
            DataOp::create("note", Some(name.into()), [("notes".into(), field)])
        };
        let import = |s: &mut Loaded, items: Vec<DataOp>| {
            s.update(vault, |v, a| Ok(v.create_items(a, items)?.0))
                .unwrap()
        };

        // Pair while the vault already holds a large import.
        let mut items: Vec<_> = (0..3000).map(login).collect();
        items.extend((0..4).map(|i| note(&format!("big {i}"), 1 << 20)));
        import(&mut a, items);
        let offer_blob = super::super::pairing::offer(&a, vault, b.id.as_bytes(), None).unwrap();
        let (offer, _) = super::super::pairing::read_offer(&offer_blob).unwrap();
        let join = super::super::pairing::join_blob(&b.keys(), "b", a.id, &vault, None).unwrap();
        let (welcome, _) =
            super::super::pairing::welcome(&mut a, vault, b.id, &join, None).unwrap();
        super::super::pairing::apply_welcome(
            &mut b,
            a.id,
            offer,
            super::super::pairing::test_replay(&a, welcome),
        )
        .unwrap();
        assert_eq!(b.vault(&vault).items().len(), 3004);

        // Then sync a second import, one item near the frame limit and single edits.
        let mut items: Vec<_> = (3000..6000).map(login).collect();
        items.push(note("huge", 13 << 20));
        let ids = import(&mut a, items);
        a.update(vault, |v, a| {
            for id in ids.iter().take(200) {
                let field = Field::new(FieldType::Secret, format!("edited-{id}"));
                v.write(a, vec![DataOp::set(*id, "password", field)])?;
            }
            Ok(())
        })
        .unwrap();
        let (a_id, b_id) = (*a.id.as_bytes(), *b.id.as_bytes());
        let a = Plain(std::sync::Mutex::new(a), Default::default());
        let b = Plain(std::sync::Mutex::new(b), Default::default());
        let (left, right) = tokio::io::duplex(64 * 1024);
        let (mut ar, mut aw) = tokio::io::split(left);
        let (mut br, mut bw) = tokio::io::split(right);
        let max = deadbolt_net::DEFAULT_MAX_FRAME_LEN;
        let (sent, received) = tokio::join!(
            deadbolt_net::run_sync_session(&a, b_id, &mut aw, &mut ar, max, false),
            deadbolt_net::run_sync_session(&b, a_id, &mut bw, &mut br, max, true),
        );
        assert_eq!(sent.unwrap().sent, received.unwrap().received);
        assert!(b.1.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        let (a, b) = (a.0.into_inner().unwrap(), b.0.into_inner().unwrap());
        // b holds all of a's history; past it, only its own card and the
        // checkpoints it compacted its large tail into after joining.
        let (bh, ah) = (b.vault(&vault).heads(), a.vault(&vault).heads());
        for (log, author, seq) in ah.iter().filter(|(_, d, _)| *d != b.id) {
            assert_eq!(
                (bh.get(log, &author), bh.tip(log, &author)),
                (seq, ah.tip(log, &author))
            );
        }
        for (log, author, _) in bh.iter().filter(|(l, d, _)| ah.tip(*l, d).is_none()) {
            assert_eq!((log, author), (LogKind::Data, b.id), "only b's own frames");
        }
        assert!(bh.get(LogKind::Data, &b.id) >= ah.get(LogKind::Data, &b.id));
        assert!(b.vault(&vault).base().is_some());
        assert_eq!(b.vault(&vault).items().len(), 6005);
    }

    #[test]
    fn bad_frames_do_not_discard_removals_beside_them() {
        let dir = tempfile::tempdir().unwrap();
        let mut target = Loaded::setup(dir.path(), b"test", "alpha", FAST).unwrap();
        let id = target.create_vault("personal").unwrap();
        add_all(&mut target, id, &[2]);
        let peer = author(2);
        let mut fork = target.vault(&id).clone();
        target
            .update(id, |v, _| {
                Ok(v.create_item(&peer, "login", Some("original".into()), [])?)
            })
            .unwrap();
        // The peer signs a second frame at the same position: an equivocation.
        let (_, twin) = local(&mut fork, |w| {
            w.create_item(&peer, "login", Some("fork".into()), [])
        });
        let mut source = target.vault(&id).clone();
        let me = target.author();
        let removal = local(&mut source, |w| w.remove(&me, peer.id()));
        let added = receive(
            &mut target,
            &peer.id(),
            vec![
                Blob::new(vec![255]),
                blob(&fork, twin),
                blob(&source, removal),
            ],
            true,
            &mut Default::default(),
        )
        .unwrap();
        assert!(added >= 1);
        assert!(!target.vault(&id).is_member(&peer.id()));
        let heads = target.vault(&id).heads();
        drop(target);
        let reopened = Loaded::open(dir.path(), b"test").unwrap();
        assert_eq!(reopened.vault(&id).heads(), heads);
        assert!(!reopened.vault(&id).is_member(&peer.id()));
    }

    /// The vault the peer seeded 2 is removed from by an honest member
    /// seeded 3, and the frames around it: the peer's and the member's
    /// writes from before the removal, the member's after it, and the peer's
    /// write made concurrently, which the removal's `last_seen_seq` excludes.
    struct Removal {
        target: Loaded,
        id: VaultId,
        before: Vec<(deadbolt_core::ItemId, Blob)>,
        removal: Blob,
        after: (deadbolt_core::ItemId, Blob),
        late: (deadbolt_core::ItemId, Blob),
        _dir: tempfile::TempDir,
    }

    fn removal(own: usize) -> Removal {
        let dir = tempfile::tempdir().unwrap();
        let mut target = Loaded::setup(dir.path(), b"test", "alpha", FAST).unwrap();
        let id = target.create_vault("personal").unwrap();
        add_all(&mut target, id, &[2, 3]);
        let (peer, honest) = (author(2), author(3));
        let mut source = target.vault(&id).clone();
        let mut before = Vec::new();
        for i in 0..own {
            let (item, f) = local(&mut source, |w| {
                w.create_item(&peer, "login", Some(format!("own {i}")), [])
            });
            before.push((item, blob(&source, f)));
        }
        let (item, f) = local(&mut source, |w| {
            w.create_item(&honest, "login", Some("relayed".into()), [])
        });
        before.push((item, blob(&source, f)));
        let mut concurrent = source.clone();
        let r = local(&mut source, |w| w.remove(&honest, peer.id()));
        let removal = blob(&source, r);
        let (item, f) = local(&mut source, |w| {
            w.create_item(&honest, "login", Some("after".into()), [])
        });
        let after = (item, blob(&source, f));
        let (item, f) = local(&mut concurrent, |w| {
            w.create_item(&peer, "login", Some("late".into()), [])
        });
        let late = (item, blob(&concurrent, f));
        Removal {
            target,
            id,
            before,
            removal,
            after,
            late,
            _dir: dir,
        }
    }

    #[test]
    fn a_batch_with_the_peers_removal_keeps_data_written_before_it() {
        let mut r = removal(1);
        let peer = author(2).id();
        let mut batch = vec![r.removal.clone()];
        batch.extend(r.before.iter().map(|(_, b)| b.clone()));
        batch.push(r.after.1.clone());
        let added = receive(&mut r.target, &peer, batch, true, &mut Default::default()).unwrap();
        assert_eq!(added, 4);
        let vault = r.target.vault(&r.id);
        assert!(!vault.is_member(&peer));
        let has = |item| vault.items().iter().any(|i| i.id == item);
        assert!(
            r.before.iter().all(|(item, _)| has(*item)),
            "data from before the removal"
        );
        // The honest member's later write counts whoever relays it: the peer
        // couldn't read or forge it, only pass it on.
        assert!(has(r.after.0));
        // Once the removal is known, nothing more from the peer is accepted,
        // not even a write it made before learning of it.
        let late = vec![r.late.1.clone()];
        let added = receive(&mut r.target, &peer, late, true, &mut Default::default()).unwrap();
        assert_eq!(added, 0);
        assert!(
            r.target
                .vault(&r.id)
                .items()
                .iter()
                .all(|i| i.id != r.late.0)
        );
    }

    /// A peer that sends a fixed list of frames and wants nothing back.
    struct Replay(Vec<Blob>);

    impl SyncHandler for Replay {
        type ReceiveState = ();

        async fn heads(&self, _: PeerId) -> Result<Vec<u8>, HandlerError> {
            let hello = application::Hello {
                v: 1,
                name: "peer".into(),
                addr: None,
                peers: BTreeMap::new(),
                vaults: BTreeMap::new(),
                members: BTreeMap::new(),
            };
            Ok(serde_json::to_vec(&hello)?)
        }

        async fn missing_for(
            &self,
            _: PeerId,
            _: Vec<u8>,
        ) -> Result<deadbolt_net::Outgoing<'_>, HandlerError> {
            Ok(Box::new(self.0.clone().into_iter().map(Ok)))
        }

        async fn receive(
            &self,
            _: PeerId,
            _: Vec<Blob>,
            _: &mut (),
            _: bool,
        ) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    /// The wire commits a stream in prefixes of 1, 2, 4, ... frames, so the
    /// peer's removal lands alone in the first batch and the data written
    /// before it in later ones. That data still lands; anything in a later
    /// stream from the peer does not.
    #[tokio::test]
    async fn a_streamed_removal_keeps_data_written_before_it_in_later_batches() {
        let r = removal(5);
        let peer_id = *author(2).id().as_bytes();
        let target_id = *r.target.id.as_bytes();
        let mut sent = vec![r.removal.clone()];
        sent.extend(r.before.iter().map(|(_, b)| b.clone()));
        let target = Plain(std::sync::Mutex::new(r.target), Default::default());
        let stream = |entries: Vec<Blob>| {
            let target = &target;
            async move {
                let (left, right) = tokio::io::duplex(64 * 1024);
                let (mut pr, mut pw) = tokio::io::split(left);
                let (mut tr, mut tw) = tokio::io::split(right);
                let max = deadbolt_net::DEFAULT_MAX_FRAME_LEN;
                let replay = Replay(entries);
                let (sent, received) = tokio::join!(
                    deadbolt_net::run_sync_session(&replay, target_id, &mut pw, &mut pr, max, true),
                    deadbolt_net::run_sync_session(target, peer_id, &mut tw, &mut tr, max, false),
                );
                assert_eq!(sent.unwrap().sent, received.unwrap().received);
            }
        };
        stream(sent).await;
        let batches = target.1.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            batches >= 3,
            "the stream was committed in {batches} batches"
        );
        {
            let s = target.0.lock().unwrap();
            let vault = s.vault(&r.id);
            assert!(!vault.is_member(&DeviceId::from_bytes(peer_id)));
            let has = |item| vault.items().iter().any(|i| i.id == item);
            assert!(
                r.before.iter().all(|(item, _)| has(*item)),
                "data from before the removal"
            );
        }
        // A later stream from the peer is refused, even a write it made before
        // learning of its removal.
        stream(vec![r.late.1.clone()]).await;
        let s = target.0.lock().unwrap();
        assert!(s.vault(&r.id).items().iter().all(|i| i.id != r.late.0));
    }

    fn two_shared_vaults() -> (tempfile::TempDir, Loaded, DeviceId, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let mut source = Loaded::setup(dir.path(), b"test", "alpha", FAST).unwrap();
        let mut vaults = BTreeMap::new();
        for name in ["first", "second"] {
            let id = source.create_vault(name).unwrap();
            add_all(&mut source, id, &[2]);
            source
                .update(id, |v, a| {
                    Ok(v.create_item(a, "login", Some("secret".into()), [])?)
                })
                .unwrap();
            vaults.insert(
                id.to_string(),
                data_encoding::HEXLOWER.encode(&deadbolt_core::Heads::default().encode()),
            );
        }
        let hello = serde_json::to_vec(&application::Hello {
            v: 1,
            name: "beta".into(),
            addr: None,
            peers: BTreeMap::new(),
            vaults,
            members: BTreeMap::new(),
        })
        .unwrap();
        (dir, source, author(2).id(), hello)
    }

    fn log_of(bytes: &[u8]) -> LogKind {
        Frame::decode(bytes).unwrap().header().kind.log_kind()
    }

    #[test]
    fn shared_sync_sends_all_membership_before_any_data() {
        let (_dir, mut source, peer, hello) = two_shared_vaults();
        let logs = |mut h: application::OutgoingHistory, s: &Loaded| {
            std::iter::from_fn(|| h.next(s, true).unwrap())
                .map(|bytes| log_of(&bytes))
                .collect::<Vec<_>>()
        };
        let all = logs(
            missing_for(&mut source, &peer, &hello, true).unwrap(),
            &source,
        );
        let first_data = all.iter().position(|log| *log == LogKind::Data).unwrap();
        assert!(all[first_data..].iter().all(|log| *log == LogKind::Data));
        let startup = logs(
            missing_for(&mut source, &peer, &hello, false).unwrap(),
            &source,
        );
        assert_eq!(startup, all[..first_data]);
    }

    /// Every frame of `vault`, as a new peer is sent them.
    fn everything(vault: &Vault) -> Vec<Blob> {
        let none = deadbolt_core::Heads::default();
        [LogKind::Member, LogKind::Data]
            .into_iter()
            .flat_map(|log| vault.missing(&none, log))
            .map(|f| Blob::new(f.encode()))
            .collect()
    }

    #[test]
    fn multi_vault_sync_omits_only_the_revoked_vault() {
        let (_dir, mut source, peer, hello) = two_shared_vaults();
        // Revoke the recipient after the first membership frame. Its vault
        // still has both member and data frames queued in this snapshot.
        let mut history = missing_for(&mut source, &peer, &hello, true).unwrap();
        let first = history.next(&source, true).unwrap().unwrap();
        let revoked = Frame::decode(&first).unwrap().header().vault;
        let kept = *source.vaults.keys().find(|id| **id != revoked).unwrap();
        let expected = everything(source.vault(&kept));
        source
            .update(revoked, |v, a| Ok(v.remove(a, peer)?))
            .unwrap();
        let remaining: Vec<_> = std::iter::from_fn(|| history.next(&source, true).transpose())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(remaining, expected);
    }

    #[test]
    fn multi_vault_sync_does_not_skip_a_vanished_frame() {
        let (_dir, mut source, peer, hello) = two_shared_vaults();
        let mut history = missing_for(&mut source, &peer, &hello, true).unwrap();
        history.next(&source, true).unwrap().unwrap();
        // Swap in views that lack the data frames the snapshot selected.
        let keys = source.keys();
        for id in source.vaults.keys().copied().collect::<Vec<_>>() {
            let members: Vec<Frame> = source
                .vault(&id)
                .frames()
                .filter(|f| f.header().kind.log_kind() == LogKind::Member)
                .cloned()
                .collect();
            source
                .vaults
                .insert(id, Vault::open(&keys, members).unwrap());
        }
        let result: Result<Vec<_>, _> =
            std::iter::from_fn(|| history.next(&source, true).transpose()).collect();
        assert!(matches!(result, Err(application::Error::Protocol(_))));
    }

    #[test]
    fn startup_does_not_accept_data() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::disk::init_with_params(dir.path(), b"test", &[1; 32], FAST).unwrap();
        let mut loaded = Loaded::from_unlocked(store).unwrap();
        let me = loaded.author();
        let root = deadbolt_core::v2::RecoverySecret::from_bytes([9; 32]);
        let (mut source, genesis) = Vault::create(&root, &me, "test", "device").unwrap();
        let id = source.id();
        loaded
            .vaults
            .insert(id, Vault::open(me.keys(), genesis).unwrap());
        let (_, frame) = local(&mut source, |w| {
            w.create_item(
                &me,
                "login",
                None,
                [("password".into(), Field::new(FieldType::Secret, "private"))],
            )
        });
        let entry = blob(&source, frame);
        let peer = loaded.id;
        let heads = hello(&loaded, &peer, None).unwrap();
        receive(
            &mut loaded,
            &peer,
            vec![entry.clone()],
            false,
            &mut Default::default(),
        )
        .unwrap();
        assert!(loaded.vault(&id).items().is_empty());
        receive(
            &mut loaded,
            &peer,
            vec![entry.clone()],
            true,
            &mut Default::default(),
        )
        .unwrap();
        assert!(
            missing_for(&mut loaded, &peer, &heads, false)
                .unwrap()
                .next(&loaded, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            missing_for(&mut loaded, &peer, &heads, true)
                .unwrap()
                .next(&loaded, true)
                .unwrap(),
            Some(entry)
        );
    }
}
