//! Remote sync, zero-state recovery and local compaction end to end, each
//! device a real daemon session over its own sealed store, the remote an
//! in-memory store.

use std::path::Path;
use std::sync::Arc;

use deadbolt_core::v2::{CHECKPOINT_TRIGGER_FRAMES, EpochId};
use deadbolt_core::{Field, FieldType, VaultId};
use deadbolt_net::{Node, NodeConfig, PeerId};
use deadbolt_pack::{FsBlocks, PackReader, names};
use deadbolt_proto::daemon::RemoteInput;
use deadbolt_viewer::{PackViewer, ViewerKeyBundle};

use super::super::session::Loaded;
use super::super::{Daemon, Session, sync};
use super::store::tests::url;
use crate::protocol::{Command, Reply, Secret};

const FAST: crate::disk::KdfParams = crate::disk::KdfParams {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};

async fn start(dir: &Path, loaded: Loaded) -> Arc<Daemon> {
    let daemon = Daemon::new(super::super::tests::test_paths(dir), true, FAST);
    let node = Node::spawn(
        NodeConfig::local_only(loaded.node_key()),
        Arc::new(|_: &PeerId| false),
        sync::Handler(daemon.clone()),
    )
    .await
    .unwrap();
    *daemon.session.lock().unwrap() = Some(Session::new(loaded, node));
    daemon
}

async fn device(dir: &Path, seed: u8) -> Arc<Daemon> {
    drop(crate::disk::init_with_params(dir, b"test", &[seed; 32], FAST).unwrap());
    start(dir, Loaded::open(dir, b"test").unwrap()).await
}

fn webdav(name: &str) -> RemoteInput {
    RemoteInput::Webdav {
        url: url(name),
        username: None,
        password: None,
    }
}

#[test]
fn changing_s3_addressing_changes_the_anchor_target() {
    let vault = VaultId::from_bytes([1; 32]);
    let mut saved = super::Saved {
        remote: RemoteInput::S3 {
            endpoint: "https://example.com".into(),
            bucket: "vault".into(),
            region: "us-east-1".into(),
            prefix: String::new(),
            path_style: false,
            access_key_id: Secret::new("id"),
            secret_access_key: Secret::new("secret"),
            session_token: None,
        },
        last_sync: None,
    };
    let before = super::target(&vault, &saved);
    if let RemoteInput::S3 { path_style, .. } = &mut saved.remote {
        *path_style = true;
    }
    assert_ne!(before, super::target(&vault, &saved));
}

fn login(daemon: &Daemon, vault: VaultId, i: usize) {
    daemon
        .with(|s| {
            let fields = [
                (
                    "password".into(),
                    Field::new(FieldType::Secret, format!("pw{i}")),
                ),
                (
                    "url".into(),
                    Field::new(FieldType::Url, format!("https://s{i}.com/login")),
                ),
            ];
            s.update(vault, |w, a| {
                Ok(w.create_item(a, "login", Some(format!("Site {i}")), fields)?)
            })?;
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn a_lost_vault_comes_back_from_its_kit_and_store_alone() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = device(da.path(), 71).await;
    let (vault, words) = a.with(|s| s.create_vault_with_kit("personal")).unwrap();
    for i in 0..20 {
        login(&a, vault, i);
    }
    // A checkpoint, then writes on top of it.
    a.with(|s| s.checkpoint(vault)).unwrap();
    login(&a, vault, 20);
    let remote = webdav("lost-vault");
    let set = Command::RemoteSet {
        vault: None,
        remote: remote.clone(),
    };
    a.remote_command(set).await.unwrap();
    let Reply::RemoteSynced { report } = a
        .remote_command(Command::RemoteSync { vault: None })
        .await
        .unwrap()
    else {
        panic!("not a sync report");
    };
    assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
    assert!(report.pushed > 20, "{report:?}");
    assert!(
        report.collected > 0,
        "the store collects behind the checkpoint: {report:?}"
    );
    // A second pass finds nothing new and nothing wrong.
    let Reply::RemoteSynced { report } = a
        .remote_command(Command::RemoteSync { vault: None })
        .await
        .unwrap()
    else {
        panic!("not a sync report");
    };
    assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
    assert_eq!((report.pulled, report.pushed), (0, 0), "{report:?}");
    let (items, lost) = a.with(|s| Ok((s.vaults[&vault].items(), s.id))).unwrap();
    a.lock().await;
    drop(a);

    // Every device is gone: a new one has only the words and the store.
    let b = device(db.path(), 72).await;
    let recover = Command::Recover {
        vault: vault.to_string(),
        words: Secret::new(words.as_str()),
        remote,
    };
    let Reply::Vault { vault: info } = b.remote_command(recover).await.unwrap() else {
        panic!("not a vault");
    };
    assert_eq!(info.id, vault.to_string());
    b.with(|s| {
        let v = &s.vaults[&vault];
        assert_eq!(v.items(), items, "every item, bit for bit");
        assert!(v.base().is_some(), "folded from the checkpoint's pack");
        assert!(v.is_member(&s.id) && v.was_removed(&lost));
        Ok(())
    })
    .unwrap();
    b.lock().await;
    drop(b);
    let reopened = Loaded::open(db.path(), b"test").unwrap();
    assert_eq!(reopened.vaults[&vault].items(), items);
}

/// A device that wrote 21 logins over a checkpoint, synced to the store
/// `name` (collecting behind the checkpoint), and was lost: its vault,
/// kit, remote and items.
async fn lost(
    dir: &Path,
    seed: u8,
    name: &str,
) -> (
    VaultId,
    zeroize::Zeroizing<String>,
    RemoteInput,
    Vec<deadbolt_core::Item>,
) {
    let a = device(dir, seed).await;
    let (vault, words) = a.with(|s| s.create_vault_with_kit("personal")).unwrap();
    for i in 0..20 {
        login(&a, vault, i);
    }
    a.with(|s| s.checkpoint(vault)).unwrap();
    login(&a, vault, 20);
    let remote = webdav(name);
    let set = Command::RemoteSet {
        vault: None,
        remote: remote.clone(),
    };
    a.remote_command(set).await.unwrap();
    let Reply::RemoteSynced { report } = a
        .remote_command(Command::RemoteSync { vault: None })
        .await
        .unwrap()
    else {
        panic!("not a sync report");
    };
    assert!(report.collected > 0, "{report:?}");
    let items = a.with(|s| Ok(s.vaults[&vault].items())).unwrap();
    a.lock().await;
    (vault, words, remote, items)
}

/// The root's frames go to the store before anything is stored here: a
/// push that fails installs nothing, and running it again recovers,
/// building on what the failed push left.
#[tokio::test]
async fn a_failed_recovery_push_installs_nothing_and_a_retry_recovers() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (vault, words, remote, items) = lost(da.path(), 81, "failed-recovery-push").await;
    let b = device(db.path(), 82).await;
    let recover = || Command::Recover {
        vault: vault.to_string(),
        words: Secret::new(words.as_str()),
        remote: remote.clone(),
    };
    // The first PUT lands, but its answer is lost.
    let store = super::store::tests::faulty("failed-recovery-push");
    store.lose_put_responses(1);
    assert!(b.remote_command(recover()).await.is_err());
    b.with(|s| {
        assert!(!s.contains_vault(&vault), "nothing installed");
        assert!(super::load(s, &vault)?.is_none(), "no remote saved");
        Ok(())
    })
    .unwrap();

    store.heal();
    let Reply::Vault { vault: info } = b.remote_command(recover()).await.unwrap() else {
        panic!("not a vault");
    };
    assert_eq!(info.id, vault.to_string());
    b.with(|s| {
        let v = &s.vaults[&vault];
        assert_eq!(v.items(), items);
        assert!(v.is_member(&s.id) && v.members().count() == 1);
        assert!(super::load(s, &vault)?.is_some());
        Ok(())
    })
    .unwrap();
    let Reply::RemoteSynced { report } = b
        .remote_command(Command::RemoteSync { vault: None })
        .await
        .unwrap()
    else {
        panic!("not a sync report");
    };
    assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
}

/// A recovery anchors every frame it rebuilt from, the base's frontier
/// and the root's own: a pull straight after it has nothing to fetch.
#[tokio::test]
async fn a_recovery_anchors_what_it_rebuilt_so_its_first_sync_fetches_nothing_again() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (vault, words, remote, items) = lost(da.path(), 83, "anchored-recovery").await;
    let b = device(db.path(), 84).await;
    let id = b
        .install_recovered(
            &vault.to_string(),
            &Secret::new(words.as_str()),
            remote.clone(),
        )
        .await
        .unwrap();
    assert_eq!(id, vault);
    let anchor = b.with(|s| super::load_anchor(s, &vault)).unwrap();
    assert!(!anchor.compacted.is_empty(), "the base's frontier");
    let store = super::Remote::open(&remote).unwrap();
    let plan = deadbolt_remote::plan_pull(&store, &vault, &anchor, None)
        .await
        .unwrap();
    assert!(plan.anomalies.is_empty(), "{:?}", plan.anomalies);
    assert!(plan.deferred.is_empty(), "{:?}", plan.deferred);
    assert_eq!(plan.fetch, [], "nothing fetched twice");

    let Reply::RemoteSynced { report } = b
        .remote_command(Command::RemoteSync { vault: None })
        .await
        .unwrap()
    else {
        panic!("not a sync report");
    };
    assert!(report.anomalies.is_empty(), "{:?}", report.anomalies);
    assert_eq!(report.pulled, 0, "{report:?}");
    b.with(|s| {
        assert_eq!(s.vaults[&vault].items(), items);
        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn a_checkpoint_compacts_to_a_pack_the_viewer_fills_from() {
    let dir = tempfile::tempdir().unwrap();
    let a = device(dir.path(), 73).await;
    let vault = a.with(|s| s.create_vault("personal")).unwrap();
    // 500 frames make a checkpoint on their own.
    for i in 0..CHECKPOINT_TRIGGER_FRAMES as usize {
        login(&a, vault, i);
    }
    let generation = a
        .with(|s| Ok(s.store.pack_generation(vault)?))
        .unwrap()
        .expect("a checkpoint at 500 frames");
    let items = a.with(|s| Ok(s.vaults[&vault].items())).unwrap();
    a.lock().await;
    drop(a);

    // Reopened: VaultDir::open's pack is the fold's base.
    let loaded = Loaded::open(dir.path(), b"test").unwrap();
    let v = &loaded.vaults[&vault];
    assert!(v.base().is_some());
    assert_eq!(v.items(), items);

    // The same gen-<n>.pack opens in the viewer for a one-item fill.
    let vdir = dir.path().join("v").join(vault.to_string());
    let blocks = FsBlocks::open(&vdir).unwrap();
    let header = *PackReader::open(&blocks, &names::gen_pack(generation))
        .unwrap()
        .header();
    let key = v.epoch_key(&EpochId::from_bytes(header.epoch)).unwrap();
    let now = crate::config::now();
    let bundle =
        ViewerKeyBundle::derive_for_pack(key, &header, &loaded.keys().kem_public(), now + 3600);
    let viewer = PackViewer::open_dir(&vdir, &bundle, now).unwrap();
    let hits = viewer.lookup_site("https://s7.com/login").unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].title, "Site 7");
    let secret = viewer.fill_secret(&hits[0].item_id).unwrap();
    assert_eq!(secret.password.as_deref().map(String::as_str), Some("pw7"));
}

/// A pack replaces history only where the store shows it collected the
/// covered frames: a device holding every frame (or seeing them all still
/// listed) keeps folding from them, and a frontier past anything evidenced
/// is refused.
#[tokio::test]
async fn a_full_replica_never_trades_its_history_for_a_pack() {
    use deadbolt_core::v2::{FrameId, LogKind};
    use deadbolt_core::{DeviceId, Vault};
    use deadbolt_remote::{RemoteIndex, RemotePath, SyncAnchor};

    let dir = tempfile::tempdir().unwrap();
    let a = device(dir.path(), 74).await;
    let vault = a.with(|s| s.create_vault("personal")).unwrap();
    for i in 0..6 {
        login(&a, vault, i);
    }
    a.with(|s| s.checkpoint(vault)).unwrap();
    login(&a, vault, 6);
    a.with(|s| {
        let v = &s.vaults[&vault];
        let frontier = v.base().unwrap().meta.frontier.clone();
        let (f, payload) = v
            .checkpoints()
            .find(|(f, _)| Some(f.id) == v.base_checkpoint())
            .map(|(f, p)| (f.clone(), p.clone()))
            .unwrap();
        let names = |frames: &mut dyn Iterator<Item = &deadbolt_core::v2::Frame>| -> Vec<String> {
            frames
                .map(|f| {
                    let h = f.header();
                    RemotePath::frame(vault, h.kind, h.author, h.seq).to_name()
                })
                .collect()
        };
        let every = RemoteIndex::from_names(&vault, &names(&mut v.frames()));
        let none = SyncAnchor::default();
        assert!(!super::sync::collected_behind(
            v, &every, &none, &f, &payload, s.id
        ));

        // A replica missing the covered frames, the store listing only the tail.
        let above = |f: &&deadbolt_core::v2::Frame| {
            let h = f.header();
            h.kind.log_kind() == LogKind::Member
                || frontier.get(&h.author).is_none_or(|(seq, _)| h.seq > *seq)
        };
        let tail: Vec<_> = v.frames().filter(above).cloned().collect();
        let thin = Vault::open(&s.keys(), tail.iter().cloned())?;
        let listed = RemoteIndex::from_names(&vault, &names(&mut tail.iter()));
        assert!(super::sync::collected_behind(
            &thin, &listed, &none, &f, &payload, s.id
        ));
        // ...but every covered frame still listed: fetch them instead.
        assert!(!super::sync::collected_behind(
            &thin, &every, &none, &f, &payload, s.id
        ));
        // A frontier naming frames nothing evidences.
        let mut phantom = payload.clone();
        phantom
            .frontier
            .push((DeviceId::from_bytes([7; 32]), 40, FrameId::ZERO));
        assert!(!super::sync::collected_behind(
            &thin, &listed, &none, &f, &phantom, s.id
        ));
        Ok(())
    })
    .unwrap();
}

/// A data frame whose signer the vault can't admit yet (its `Add` isn't on
/// the store) is refused, and the anchor doesn't move over it: once the
/// `Add` lands, the next sync fetches and takes it.
#[tokio::test]
async fn a_refused_frame_is_fetched_again_once_its_signer_is_admitted() {
    use deadbolt_core::v2::{DeviceKeys, Frame, LogKind};
    use deadbolt_core::{Author, Vault, recovery};
    use deadbolt_remote::{Outbox, plan_push, push};

    let dir = tempfile::tempdir().unwrap();
    let a = device(dir.path(), 75).await;
    let (vault, words) = a.with(|s| s.create_vault_with_kit("personal")).unwrap();
    let remote = webdav("refused-frame");
    let set = Command::RemoteSet {
        vault: None,
        remote: remote.clone(),
    };
    a.remote_command(set).await.unwrap();
    let sync = || Command::RemoteSync { vault: None };
    a.remote_command(sync()).await.unwrap();

    // Elsewhere, the root admits P, and P writes before the Add is pushed.
    let root = recovery::decode(&words).unwrap();
    let held: Vec<Frame> = a
        .with(|s| Ok(s.vaults[&vault].frames().cloned().collect()))
        .unwrap();
    let mut rv = Vault::open_as(root.recovery_id(), &root.kem_secret(), held).unwrap();
    let p = Author::new(DeviceKeys::from_seed(&[0x51; 32]), 1_700_000_000_000);
    let consent = p.join_consent(&vault, &root.recovery_id());
    let mut add = Vec::new();
    rv.transact(
        |w| w.add_signed(&root.signing_key(), p.id(), p.keys().kem_public(), consent),
        |_, frames| {
            add.extend(frames.iter().map(|f| (*f).clone()));
            Ok::<_, deadbolt_core::Error>(())
        },
    )
    .unwrap();
    let mut pv = Vault::open(p.keys(), rv.frames().cloned()).unwrap();
    let mut written = Vec::new();
    let fields = [("password".into(), Field::new(FieldType::Secret, "pw"))];
    pv.transact(
        |w| w.create_item(&p, "login", Some("p".into()), fields),
        |_, frames| {
            written.extend(
                frames
                    .iter()
                    .filter(|f| f.header().kind.log_kind() == LogKind::Data)
                    .map(|f| (*f).clone()),
            );
            Ok::<_, deadbolt_core::Error>(())
        },
    )
    .unwrap();
    assert!(!written.is_empty());
    let store = super::Remote::open(&remote).unwrap();
    let upload = |frames: Vec<Frame>| {
        plan_push(
            &vault,
            Outbox {
                frames,
                ..Outbox::default()
            },
        )
        .unwrap()
    };
    push(&store, &upload(written.clone())).await.unwrap();

    a.remote_command(sync()).await.unwrap();
    let (tip, took) = a
        .with(|s| {
            let anchor = super::load_anchor(s, &vault)?;
            let v = &s.vaults[&vault];
            Ok((
                anchor.tip(LogKind::Data, &p.id()),
                written.iter().any(|f| v.frame(&f.id()).is_some()),
            ))
        })
        .unwrap();
    assert!(!took, "P isn't admitted yet");
    assert_eq!(tip, None, "the anchor stays behind what the vault refused");

    push(&store, &upload(add)).await.unwrap();
    a.remote_command(sync()).await.unwrap();
    let (tip, took) = a
        .with(|s| {
            let anchor = super::load_anchor(s, &vault)?;
            let v = &s.vaults[&vault];
            Ok((
                anchor.tip(LogKind::Data, &p.id()).map(|(seq, _)| seq),
                written.iter().all(|f| v.frame(&f.id()).is_some()),
            ))
        })
        .unwrap();
    assert!(took, "fetched again once P is admitted");
    assert_eq!(tip, Some(written.len() as u64 - 1));

    // A now cites P in its signed clock. The store keeps P in LIST while
    // returning 404 on GET: that name must not mask the cited frame.
    login(&a, vault, 999);
    a.remote_command(sync()).await.unwrap();
    let faulty = super::store::tests::faulty("refused-frame");
    faulty.freeze_list();
    let prefix = format!("{vault}/d/{}/", p.id());
    faulty.wipe(|name| name.starts_with(&prefix));
    let Reply::RemoteSynced { report } = a.remote_command(sync()).await.unwrap() else {
        panic!("not a sync report");
    };
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| a.contains("lost or swapped")),
        "{:?}",
        report.anomalies
    );
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| a.contains(&format!("withholds {}'s data frame", p.id()))),
        "{:?}",
        report.anomalies
    );
}

#[tokio::test]
async fn listed_own_frames_returning_404_cannot_clear_self_rollback() {
    use deadbolt_core::v2::LogKind;
    use deadbolt_remote::{Outbox, SyncAnchor, plan_push, push};

    let dir = tempfile::tempdir().unwrap();
    let a = device(dir.path(), 80).await;
    let vault = a
        .with(|s| s.create_vault_with_kit("personal").map(|(id, _)| id))
        .unwrap();
    login(&a, vault, 0);
    let (me, frames) = a
        .with(|s| Ok((s.id, s.vaults[&vault].frames().cloned().collect())))
        .unwrap();
    let store = super::Remote::open(&webdav("missing-own-frame")).unwrap();
    let plan = plan_push(
        &vault,
        Outbox {
            frames,
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();
    let mut anchor = SyncAnchor::default();
    let honest = a.sync_with(&store, vault, me, &mut anchor).await.unwrap();
    assert!(!honest.anomalies.iter().any(|a| a.contains("not pushing")));
    let faulty = super::store::tests::faulty("missing-own-frame");
    faulty.freeze_list();
    let prefix = format!("{vault}/d/{me}/");
    faulty.wipe(|n| n.starts_with(&prefix));
    let mut anchor = SyncAnchor::default();
    let report = a.sync_with(&store, vault, me, &mut anchor).await.unwrap();
    assert!(
        report.anomalies.iter().any(|a| a.contains("not pushing")),
        "{:?}",
        report.anomalies
    );
    assert_eq!(report.pushed, 0);
    assert!(anchor.tip(LogKind::Data, &me).is_none());
}

/// A compromised member uploads a checkpoint (`d/M/1.c`) and a poisoned pack
/// covering a frame of its own it never uploaded (`d/M/0`, a delete). Its
/// own listing is no evidence and no earlier member acked it, so an honest
/// full replica keeps its history.
#[tokio::test]
async fn a_member_cannot_vouch_for_its_own_poisoned_checkpoint() {
    use deadbolt_core::ops::{Change, DataOp};
    use deadbolt_core::v2::{DeviceKeys, Frame, PackCommitment};
    use deadbolt_core::{Author, Vault, recovery};
    use deadbolt_remote::{Outbox, plan_push, push};

    let dir = tempfile::tempdir().unwrap();
    let a = device(dir.path(), 76).await;
    let (vault, words) = a.with(|s| s.create_vault_with_kit("personal")).unwrap();
    login(&a, vault, 0);
    let remote = webdav("poisoned-checkpoint");
    let set = Command::RemoteSet {
        vault: None,
        remote: remote.clone(),
    };
    a.remote_command(set).await.unwrap();
    let sync = || Command::RemoteSync { vault: None };
    a.remote_command(sync()).await.unwrap();
    let (item, before) = a
        .with(|s| {
            let v = &s.vaults[&vault];
            Ok((v.items()[0].id, v.items()))
        })
        .unwrap();

    // The root admits M; M deletes A's item, then checkpoints over it.
    let root = recovery::decode(&words).unwrap();
    let held: Vec<Frame> = a
        .with(|s| Ok(s.vaults[&vault].frames().cloned().collect()))
        .unwrap();
    let mut rv = Vault::open_as(root.recovery_id(), &root.kem_secret(), held).unwrap();
    let m = Author::new(DeviceKeys::from_seed(&[0x4d; 32]), 1_700_000_000_000);
    let consent = m.join_consent(&vault, &root.recovery_id());
    let mut add = Vec::new();
    rv.transact(
        |w| w.add_signed(&root.signing_key(), m.id(), m.keys().kem_public(), consent),
        |_, frames| {
            add.extend(frames.iter().map(|f| (*f).clone()));
            Ok::<_, deadbolt_core::Error>(())
        },
    )
    .unwrap();
    let mut mv = Vault::open(m.keys(), rv.frames().cloned()).unwrap();
    let delete = DataOp::Edit {
        item,
        change: Change::Delete { at: None },
    };
    mv.transact(
        |w| w.write(&m, vec![delete]),
        |_, _| Ok::<_, deadbolt_core::Error>(()),
    )
    .unwrap();
    let made = mv
        .transact(
            |w| {
                w.checkpoint(&m, |pack, site| {
                    let input =
                        deadbolt_viewer::pack_input(pack, site, 1).map_err(|e| e.to_string())?;
                    Ok(deadbolt_pack::pack::encode(&input, site.key.as_bytes())
                        .map_err(|e| e.to_string())?
                        .bytes)
                })
            },
            |_, _| Ok::<_, deadbolt_core::Error>(()),
        )
        .unwrap();
    let checkpoint = mv.frame(&made.frame).unwrap().clone();
    assert_eq!(
        checkpoint.header().seq,
        1,
        "d/M/0 is the delete, never uploaded"
    );
    let store = super::Remote::open(&remote).unwrap();
    let plan = plan_push(
        &vault,
        Outbox {
            frames: add.into_iter().chain([checkpoint]).collect(),
            packs: vec![(PackCommitment::of(&made.sealed).hash, made.sealed.clone())],
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();

    let Reply::RemoteSynced { report } = a.remote_command(sync()).await.unwrap() else {
        panic!("not a sync report");
    };
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| a.contains("checkpoint covers frames")),
        "{:?}",
        report.anomalies
    );
    a.with(|s| {
        let v = &s.vaults[&vault];
        assert!(v.is_member(&m.id()));
        assert_ne!(
            v.base_checkpoint(),
            Some(made.frame),
            "the poisoned pack isn't the base"
        );
        assert_eq!(v.items(), before, "nothing the pack claims was applied");
        Ok(())
    })
    .unwrap();
}

/// B and C removed each other and A removed B: the vault parks on the
/// mutual removal. Recovering from the kit settles it (the root acts after
/// both, and neither is left), so the new device writes its card unparked,
/// and rotating the kit afterwards doesn't park it again.
#[tokio::test]
async fn recovery_settles_a_mutual_removal_no_one_is_left_to_choose() {
    use deadbolt_core::v2::{DeviceKeys, Frame, ParkingReason, RecoverySecret};
    use deadbolt_core::{Author, Vault};

    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = device(da.path(), 77).await;
    let (vault, words) = a.with(|s| s.create_vault_with_kit("personal")).unwrap();
    login(&a, vault, 0);
    let peer = |seed: u8| Author::new(DeviceKeys::from_seed(&[seed; 32]), 1_700_000_000_000);
    let (b, c) = (peer(0x0b), peer(0x0c));
    a.with(|s| {
        let me = s.id;
        s.update(vault, |w, author| {
            for p in [&b, &c] {
                let consent = p.join_consent(&vault, &me);
                w.add(author, p.id(), p.keys().kem_public(), consent)?;
            }
            Ok(())
        })?;
        Ok(())
    })
    .unwrap();
    let held = || -> Vec<Frame> {
        a.with(|s| Ok(s.vaults[&vault].frames().cloned().collect()))
            .unwrap()
    };
    let mut vb = Vault::open(b.keys(), held()).unwrap();
    let mut vc = Vault::open(c.keys(), held()).unwrap();
    let no = |_: &Vault, _: &[&Frame]| Ok::<_, deadbolt_core::Error>(());
    vb.transact(|w| w.remove(&b, c.id()), no).unwrap();
    vc.transact(|w| w.remove(&c, b.id()), no).unwrap();
    a.with(|s| {
        let frames: Vec<Frame> = vb.frames().chain(vc.frames()).cloned().collect();
        s.apply_fetched(vault, frames, Vec::new())?;
        let parked = s.vaults[&vault].parked().to_vec();
        assert!(
            parked
                .iter()
                .any(|r| matches!(r, ParkingReason::MutualRemoval { .. })),
            "{parked:?}"
        );
        s.update(vault, |w, author| Ok(w.remove(author, b.id())?))?;
        Ok(())
    })
    .unwrap();
    let remote = webdav("mutual-removal");
    let set = Command::RemoteSet {
        vault: None,
        remote: remote.clone(),
    };
    a.remote_command(set).await.unwrap();
    a.remote_command(Command::RemoteSync { vault: None })
        .await
        .unwrap();
    a.lock().await;
    drop(a);

    let d = device(db.path(), 78).await;
    let recover = Command::Recover {
        vault: vault.to_string(),
        words: Secret::new(words.as_str()),
        remote,
    };
    d.remote_command(recover).await.unwrap();
    d.with(|s| {
        let v = &s.vaults[&vault];
        assert!(v.parked().is_empty(), "{:?}", v.parked());
        assert!(v.is_member(&s.id));
        assert!(v.device_label(&s.id).is_some(), "the new device's card");
        Ok(())
    })
    .unwrap();

    // Handing the kit on retires the root that settled it; the settlement
    // stands.
    d.with(|s| {
        s.rotate_recovery(vault, &words, &RecoverySecret::from_bytes([0x52; 32]))?;
        let v = &s.vaults[&vault];
        assert!(v.parked().is_empty(), "{:?}", v.parked());
        Ok(())
    })
    .unwrap();
}

/// A compromised member M adds a puppet M2, uploads M2's second frame but
/// not its first (a delete), and its own checkpoint `d/M/0.c` over both
/// with empty membership heads (so it names no one who must have acked it)
/// and a poisoned pack. Heads that can't be the checkpoint's own refuse it,
/// and this device, synced already, never acked it: the replica keeps its
/// history.
#[tokio::test]
async fn a_puppet_and_empty_heads_cannot_vouch_for_a_poisoned_checkpoint() {
    poisoned_checkpoint(false).await;
}

#[tokio::test]
async fn a_listed_but_missing_frame_cannot_vouch_for_a_checkpoint() {
    poisoned_checkpoint(true).await;
}

async fn poisoned_checkpoint(phantom: bool) {
    use deadbolt_core::ops::{Change, DataOp};
    use deadbolt_core::v2::{DeviceKeys, Frame, LogKind, PackCommitment};
    use deadbolt_core::{Author, Vault, recovery};
    use deadbolt_remote::{Outbox, plan_push, push};

    let dir = tempfile::tempdir().unwrap();
    let a = device(dir.path(), 79).await;
    let (vault, words) = a.with(|s| s.create_vault_with_kit("personal")).unwrap();
    login(&a, vault, 0);
    let store_name = if phantom {
        "phantom-checkpoint"
    } else {
        "puppet-checkpoint"
    };
    let remote = webdav(store_name);
    let set = Command::RemoteSet {
        vault: None,
        remote: remote.clone(),
    };
    a.remote_command(set).await.unwrap();
    let sync = || Command::RemoteSync { vault: None };
    a.remote_command(sync()).await.unwrap();
    let (item, before) = a
        .with(|s| {
            let v = &s.vaults[&vault];
            Ok((v.items()[0].id, v.items()))
        })
        .unwrap();

    // The root admits M; M admits its puppet M2.
    let root = recovery::decode(&words).unwrap();
    let held: Vec<Frame> = a
        .with(|s| Ok(s.vaults[&vault].frames().cloned().collect()))
        .unwrap();
    let mut rv = Vault::open_as(root.recovery_id(), &root.kem_secret(), held).unwrap();
    let author = |seed: u8| Author::new(DeviceKeys::from_seed(&[seed; 32]), 1_700_000_000_000);
    let (m, m2) = (author(0x4d), author(0x4e));
    let consent = m.join_consent(&vault, &root.recovery_id());
    let mut uploads = Vec::new();
    rv.transact(
        |w| w.add_signed(&root.signing_key(), m.id(), m.keys().kem_public(), consent),
        |_: &Vault, fs: &[&Frame]| {
            uploads.extend(fs.iter().map(|f| (*f).clone()));
            Ok::<_, deadbolt_core::Error>(())
        },
    )
    .unwrap();
    let mut mv = Vault::open(m.keys(), rv.frames().cloned()).unwrap();
    let consent = m2.join_consent(&vault, &m.id());
    mv.transact(
        |w| w.add(&m, m2.id(), m2.keys().kem_public(), consent),
        |_: &Vault, fs: &[&Frame]| {
            uploads.extend(fs.iter().map(|f| (*f).clone()));
            Ok::<_, deadbolt_core::Error>(())
        },
    )
    .unwrap();
    // M2's frame 0 deletes A's item; frame 1 is all the store will show.
    let mut puppet = Vault::open(m2.keys(), mv.frames().cloned()).unwrap();
    let mut written = Vec::new();
    let delete = DataOp::Edit {
        item,
        change: Change::Delete { at: None },
    };
    puppet
        .transact(
            |w| w.write(&m2, vec![delete]),
            |_: &Vault, fs: &[&Frame]| {
                written.extend(fs.iter().map(|f| (*f).clone()));
                Ok::<_, deadbolt_core::Error>(())
            },
        )
        .unwrap();
    let fields = [("password".into(), Field::new(FieldType::Secret, "pw"))];
    puppet
        .transact(
            |w| w.create_item(&m2, "login", Some("m2".into()), fields),
            |_: &Vault, fs: &[&Frame]| {
                written.extend(fs.iter().map(|f| (*f).clone()));
                Ok::<_, deadbolt_core::Error>(())
            },
        )
        .unwrap();
    let written: Vec<Frame> = written
        .into_iter()
        .filter(|f| f.header().kind.log_kind() == LogKind::Data)
        .collect();
    assert_eq!(written.len(), 2);
    let kem = m.keys().kem_key();
    mv.transact(
        |w| w.apply(kem, written.clone()),
        |_, _| Ok::<_, deadbolt_core::Error>(()),
    )
    .unwrap();
    let made = mv
        .transact(
            |w| {
                w.checkpoint(&m, |pack, site| {
                    let input =
                        deadbolt_viewer::pack_input(pack, site, 1).map_err(|e| e.to_string())?;
                    Ok(deadbolt_pack::pack::encode(&input, site.key.as_bytes())
                        .map_err(|e| e.to_string())?
                        .bytes)
                })
            },
            |_, _| Ok::<_, deadbolt_core::Error>(()),
        )
        .unwrap();
    // The same checkpoint, re-signed with no membership heads.
    let (f, mut payload) = mv
        .checkpoints()
        .find(|(f, _)| f.id == made.frame)
        .map(|(f, p)| (f.clone(), p.clone()))
        .unwrap();
    assert_eq!(f.seq, 0, "d/M/0.c");
    payload.mheads = Vec::new();
    let key = mv.epoch_key(&f.epoch).unwrap().clone();
    let bad = payload
        .seal(m.keys().sign_key(), vault, f.seq, f.prev, f.epoch, &key)
        .unwrap();
    uploads.push(written[1].clone());
    uploads.push(bad.clone());
    let store = super::Remote::open(&remote).unwrap();
    let plan = plan_push(
        &vault,
        Outbox {
            frames: uploads,
            packs: vec![(PackCommitment::of(&made.sealed).hash, made.sealed.clone())],
            ..Outbox::default()
        },
    )
    .unwrap();
    push(&store, &plan).await.unwrap();

    let report = if phantom {
        let faulty = super::store::tests::faulty(store_name);
        faulty.freeze_list();
        let h = written[1].header();
        let name = deadbolt_remote::RemotePath::frame(vault, h.kind, h.author, h.seq).to_name();
        faulty.wipe(|n| n == name);
        let me = a.with(|s| Ok(s.id)).unwrap();
        let mut anchor = deadbolt_remote::SyncAnchor::default();
        let report = a.sync_with(&store, vault, me, &mut anchor).await.unwrap();
        assert!(!anchor.compacted.contains_key(&m2.id()));
        assert!(
            report.anomalies.iter().any(|a| a.contains("withholds")),
            "{:?}",
            report.anomalies
        );
        report
    } else {
        let Reply::RemoteSynced { report } = a.remote_command(sync()).await.unwrap() else {
            panic!("not a sync report");
        };
        report
    };
    assert!(
        report
            .anomalies
            .iter()
            .any(|a| a.contains("checkpoint covers frames")),
        "{:?}",
        report.anomalies
    );
    a.with(|s| {
        let v = &s.vaults[&vault];
        assert!(v.is_member(&m2.id()), "the puppet is admitted");
        assert!(v.frame(&bad.id()).is_some(), "the checkpoint is held");
        assert_ne!(
            v.base_checkpoint(),
            Some(bad.id()),
            "the poisoned pack isn't the base"
        );
        assert_eq!(v.items(), before, "nothing the pack claims was applied");
        Ok(())
    })
    .unwrap();
}
