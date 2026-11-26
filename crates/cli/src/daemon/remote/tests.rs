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
        let me = s.id;
        let frontier = v.base().unwrap().meta.frontier.clone();
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
            v, &every, &none, me, &frontier
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
            &thin, &listed, &none, me, &frontier
        ));
        // ...but every covered frame still listed: fetch them instead.
        assert!(!super::sync::collected_behind(
            &thin, &every, &none, me, &frontier
        ));
        // A frontier naming frames nothing evidences.
        let mut phantom = frontier.clone();
        phantom.insert(DeviceId::from_bytes([7; 32]), (40, FrameId::ZERO));
        assert!(!super::sync::collected_behind(
            &thin, &listed, &none, me, &phantom
        ));
        Ok(())
    })
    .unwrap();
}
