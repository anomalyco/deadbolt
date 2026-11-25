//! Regressions from round 2 of the model-based hunt (`tear`): one device's
//! sessions against a lying store, replaying each shrunk counterexample.
//!
//! - A: a stale LIST raised a false `RemoteRegressed` on a just-pushed frame.
//! - E: a pull between a backup restore and the first push adopted the
//!   store's pre-restore frame, so the push built on the wrong `seq 0`.
//! - F: listing the own stream strictly above the tip hid a wiped tip.

use deadbolt_core::v2::{Frame, FrameId, FrameKind, LogKind};
use deadbolt_core::{DeviceId, DeviceSecret, VaultId};

use super::fixture::{data_frame, device, genesis};
use crate::path::RemotePath;
use crate::{
    FaultyObjStore, ObjStore, Observed, Outbox, RemoteAnomaly, SelfRollback, SyncAnchor,
    check_fetched_as, check_self_rollback, plan_pull, plan_push, push,
};

/// One device: its own Data stream and what the store acknowledged.
#[derive(Clone)]
struct Device {
    seed: u8,
    vault: VaultId,
    chain: Vec<Frame>,
    anchor: SyncAnchor,
    salt: u8,
}

impl Device {
    fn new(vault: VaultId) -> Self {
        Self {
            seed: 1,
            vault,
            chain: Vec::new(),
            anchor: SyncAnchor::default(),
            salt: 0,
        }
    }

    fn sk(&self) -> DeviceSecret {
        device(self.seed)
    }

    fn me(&self) -> DeviceId {
        self.sk().device_id()
    }

    fn write(&mut self) {
        self.salt += 1;
        let prev = self.chain.last().map_or(FrameId::ZERO, Frame::id);
        let seq = self.chain.len() as u64;
        let frame = data_frame(&self.sk(), self.vault, seq, prev, self.salt, false);
        self.chain.push(frame);
    }

    fn path(&self, seq: u64) -> RemotePath {
        RemotePath::frame(self.vault, FrameKind::Data, self.me(), seq)
    }

    /// Checks its own streams, then pushes every frame above the
    /// acknowledged tip and records each one that landed.
    async fn push(&mut self, store: &FaultyObjStore) -> Vec<RemoteAnomaly> {
        let me = self.me();
        let found = check_self_rollback(store, &self.vault, &me, &self.anchor)
            .await
            .unwrap();
        if !found.is_empty() {
            return found;
        }
        let from = self
            .anchor
            .tip(LogKind::Data, &me)
            .map_or(0, |(seq, _)| seq as usize + 1);
        let unpushed = self.chain[from..].to_vec();
        let plan = plan_push(
            &self.vault,
            Outbox {
                frames: unpushed.clone(),
                ..Outbox::default()
            },
        )
        .unwrap();
        let report = push(store, &plan).await.unwrap();
        if let Some(stop) = report.stopped {
            return vec![stop];
        }
        for frame in &unpushed {
            self.anchor.observe(frame).unwrap();
        }
        Vec::new()
    }

    /// Plans a pull, then fetches and judges every frame it names.
    async fn pull(&mut self, store: &FaultyObjStore) -> Vec<RemoteAnomaly> {
        let me = self.me();
        let plan = plan_pull(store, &self.vault, &self.anchor, None)
            .await
            .unwrap();
        let mut out = plan.anomalies.clone();
        out.extend(plan.confirm_deferred(&self.anchor));
        let chain = self.chain.clone();
        let local = |log, seq: u64| {
            (log == LogKind::Data)
                .then(|| chain.get(usize::try_from(seq).ok()?).map(Frame::id))
                .flatten()
        };
        for path in plan
            .fetch
            .iter()
            .filter(|p| matches!(p, RemotePath::Frame { .. }))
        {
            let bytes = store.get(&path.to_name(), None).await.unwrap().unwrap();
            match check_fetched_as(&self.anchor, &me, local, path, &bytes) {
                Ok(frame) => {
                    if let Err(anomaly) = self.anchor.observe(&frame) {
                        out.push(anomaly);
                    }
                }
                Err(anomaly) => out.push(anomaly),
            }
        }
        out
    }
}

async fn vault() -> (VaultId, FaultyObjStore) {
    let (vault, _, members) = genesis(0);
    let store = FaultyObjStore::new();
    let plan = plan_push(
        &vault,
        Outbox {
            frames: members,
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();
    (vault, store)
}

/// A: `[Write{d:1}, FreezeList, Push{d:1}, Pull{d:1}]`. The anchor records
/// the own frame once its PUT lands, before an eventually consistent LIST
/// shows it; a direct GET tells the lag from a loss, so there is no alarm.
/// A frame that is really gone still alarms, stale LIST or not.
#[tokio::test]
async fn a_stale_list_is_no_regression_but_a_real_loss_still_is() {
    let (vault, store) = vault().await;
    let mut d = Device::new(vault);
    d.write();
    store.freeze_list();
    assert_eq!(d.push(&store).await, []);
    assert_eq!(
        d.pull(&store).await,
        [],
        "the LIST lags; GET finds the frame"
    );
    d.write();
    assert_eq!(
        d.push(&store).await,
        [],
        "the own tip is missing only from LIST"
    );

    // The store really drops the tip: GET agrees, behind the stale LIST and without it.
    let tip = d.path(1);
    let (me, tip_id) = (d.me(), d.chain[1].id());
    let lost = |max_seq| RemoteAnomaly::RemoteRegressed {
        log: LogKind::Data,
        author: me,
        expected_seq: 1,
        expected_id: tip_id,
        observed: Observed::Missing { max_seq },
    };
    store.wipe(|n| n == tip.to_name());
    assert_eq!(d.pull(&store).await, [lost(None)]);
    assert_eq!(d.clone().push(&store).await, [lost(None)]);
    store.heal();
    assert_eq!(d.pull(&store).await, [lost(Some(0))]);

    // Another valid frame under the anchored name, behind a LIST that lags
    // its PUT, is a swap.
    let other = data_frame(&d.sk(), vault, 1, d.chain[0].id(), 0x77, false);
    store.freeze_list();
    store.inner().plant(&tip.to_name(), &other.encode());
    assert_eq!(
        d.pull(&store).await,
        [RemoteAnomaly::RemoteRegressed {
            log: LogKind::Data,
            author: d.me(),
            expected_seq: 1,
            expected_id: d.chain[1].id(),
            observed: Observed::Different(other.id()),
        }]
    );
}

/// E: `[Backup, Write, Push, Restore, Write, Write, Pull, Push]`. The pull
/// used to anchor the store's pre-restore `seq 0`, so the push landed the
/// restored replica's `seq 1` on top of it. The pull now reports the
/// self-rollback, and the push refuses to build on it.
#[tokio::test]
async fn a_pull_after_a_restore_never_adopts_the_stores_own_frame() {
    let (vault, store) = vault().await;
    let mut d = Device::new(vault);
    let backup = d.clone();
    d.write();
    assert_eq!(d.push(&store).await, []);
    let pushed = d.chain[0].id();
    let mut d = Device {
        salt: 0x40,
        ..backup
    };
    d.write();
    d.write();
    assert_ne!(d.chain[0].id(), pushed);

    assert_eq!(
        d.pull(&store).await,
        [RemoteAnomaly::SelfRollback(SelfRollback {
            log: LogKind::Data,
            remote_ahead: Vec::new(),
            conflicting: Some(d.path(0)),
        })]
    );
    assert_eq!(d.anchor.tip(LogKind::Data, &d.me()), None);
    assert_eq!(
        d.push(&store).await,
        [RemoteAnomaly::SelfRollback(SelfRollback {
            log: LogKind::Data,
            remote_ahead: vec![d.path(0)],
            conflicting: None,
        })]
    );
    assert!(
        store.inner().peek(&d.path(1).to_name()).is_none(),
        "nothing landed on top of the pre-restore frame"
    );

    // A frame beyond the replica's tip is the store's too; one equal to the
    // replica's (a lost acknowledgement) just advances the anchor.
    let mut short = d.clone();
    short.chain.clear();
    assert_eq!(
        short.pull(&store).await,
        [RemoteAnomaly::SelfRollback(SelfRollback {
            log: LogKind::Data,
            remote_ahead: vec![d.path(0)],
            conflicting: None,
        })]
    );
    let mut acked = Device::new(vault);
    acked.chain = vec![store_frame(&store, &d.path(0)).await];
    assert_eq!(acked.pull(&store).await, []);
    assert_eq!(
        acked.anchor.tip(LogKind::Data, &acked.me()),
        Some((0, pushed))
    );
}

async fn store_frame(store: &FaultyObjStore, path: &RemotePath) -> Frame {
    Frame::decode(&store.get(&path.to_name(), None).await.unwrap().unwrap()).unwrap()
}

/// F: `[Write, Push, Write, Wipe{n:1}, Push, Pull]`. Listing the own stream
/// strictly above the acknowledged tip missed that the store wiped the tip
/// itself; the push then succeeded and the anchor moved past the hole.
#[tokio::test]
async fn a_wiped_own_tip_stops_the_next_push() {
    let (vault, store) = vault().await;
    let mut d = Device::new(vault);
    d.write();
    assert_eq!(d.push(&store).await, []);
    d.write();
    let tip = d.path(0).to_name();
    store.wipe(|n| n == tip);
    let lost = RemoteAnomaly::RemoteRegressed {
        log: LogKind::Data,
        author: d.me(),
        expected_seq: 0,
        expected_id: d.chain[0].id(),
        observed: Observed::Missing { max_seq: None },
    };
    assert_eq!(d.push(&store).await, std::slice::from_ref(&lost));
    assert!(store.inner().peek(&d.path(1).to_name()).is_none());
    assert_eq!(d.pull(&store).await, [lost]);

    // A tip an adopted checkpoint lets the store collect is no alarm.
    let me = d.me();
    let mut adopted = d.clone();
    adopted
        .anchor
        .adopt_checkpoint(&[(me, (0, d.chain[0].id()))].into())
        .unwrap();
    assert_eq!(
        check_self_rollback(&store, &vault, &me, &adopted.anchor)
            .await
            .unwrap(),
        []
    );
}
