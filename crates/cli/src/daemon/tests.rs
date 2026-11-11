use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::connection::{invalid_request, request_line};
use super::lifecycle::drain_connections;
use super::*;
use crate::protocol::FieldInput;
use crate::protocol::PROTOCOL_VERSION;
use crate::protocol::Request;
use deadbolt_core::DeviceSecret;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

fn locked_daemon(dir: &std::path::Path) -> Arc<Daemon> {
    Daemon::new(test_paths(dir), true, deadbolt_store::KdfParams::DEFAULT)
}

pub(super) fn test_paths(dir: &std::path::Path) -> Paths {
    Paths {
        data: dir.into(),
        config: dir.join("config"),
        socket: dir.join("socket"),
        lock: dir.join("lock"),
        log: dir.join("log"),
    }
}

#[tokio::test(start_paused = true)]
async fn stop_reply_precedes_shutdown_even_with_backpressure() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = locked_daemon(dir.path());
    let (server, mut client) = UnixStream::pair().unwrap();
    server.writable().await.unwrap();
    let mut buffered = 0;
    loop {
        match server.try_write(&[0; 8192]) {
            Ok(n) => buffered += n,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    let mut request = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command: Command::Stop,
    })
    .unwrap();
    request.push(b'\n');
    client.write_all(&request).await.unwrap();
    let mut connections = JoinSet::new();
    connections.spawn(daemon.clone().handle(server, MAX_LINE));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), daemon.shutdown.notified())
            .await
            .is_err()
    );
    client.read_exact(&mut vec![0; buffered]).await.unwrap();
    tokio::time::timeout(IO_TIMEOUT, daemon.shutdown.notified())
        .await
        .unwrap();
    drain_connections(&mut connections).await;
    let mut reply = String::new();
    client.read_to_string(&mut reply).await.unwrap();
    assert!(matches!(
        serde_json::from_str::<Message>(&reply).unwrap(),
        Message::Ok { reply: Reply::Done }
    ));
}

#[tokio::test]
async fn a_locked_daemon_generates_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = locked_daemon(dir.path());
    let ask = |length, symbols| {
        let daemon = daemon.clone();
        async move {
            let (server, mut client) = UnixStream::pair().unwrap();
            let mut request = serde_json::to_vec(&Request {
                v: PROTOCOL_VERSION,
                claimed: None,
                command: Command::Generate {
                    length,
                    symbols,
                    url: None,
                },
            })
            .unwrap();
            request.push(b'\n');
            client.write_all(&request).await.unwrap();
            daemon.handle(server, MAX_LINE).await.unwrap();
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.unwrap();
            serde_json::from_str::<Message>(&reply).unwrap()
        }
    };
    match ask(12, false).await {
        Message::Ok {
            reply: Reply::Password { password },
        } => {
            assert_eq!(password.len(), 12);
            assert!(password.bytes().all(|b| b.is_ascii_alphanumeric()));
        }
        other => panic!("expected a password, got {other:?}"),
    }
    match ask(4, true).await {
        Message::Error { code, message, .. } => {
            assert_eq!(code, ErrorCode::Failed);
            assert_eq!(message, "a generated password must be 8 to 256 characters");
        }
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_drain_cancels_idle_connections() {
    let dir = tempfile::tempdir().unwrap();
    let (server, _client) = UnixStream::pair().unwrap();
    let mut connections = JoinSet::new();
    connections.spawn(locked_daemon(dir.path()).handle(server, MAX_LINE));
    let start = Instant::now();
    drain_connections(&mut connections).await;
    assert!(connections.is_empty());
    assert!(start.elapsed() < IO_TIMEOUT);
}

#[tokio::test]
async fn oversized_requests_finish_writing_and_receive_a_clean_error() {
    for newline in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let daemon = locked_daemon(dir.path());
        let (server, mut client) = UnixStream::pair().unwrap();
        let exchange = async {
            tokio::join!(daemon.handle(server, 64), async {
                // More than the socket buffer: replying early breaks this write.
                for _ in 0..128 {
                    client.write_all(&[b'x'; 8192]).await.unwrap();
                }
                if newline {
                    client.write_all(b"\n").await.unwrap();
                } else {
                    client.shutdown().await.unwrap();
                }
                let mut reply = String::new();
                client.read_to_string(&mut reply).await.unwrap();
                match serde_json::from_str::<Message>(&reply).unwrap() {
                    Message::Error { code, message, .. } => {
                        assert!(matches!(code, ErrorCode::Failed));
                        assert_eq!(message, "request too large");
                    }
                    _ => panic!("expected an oversized-request error"),
                }
            })
        };
        let (handled, ()) = tokio::time::timeout(IO_TIMEOUT, exchange).await.unwrap();
        handled.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn stop_notifies_shutdown_when_the_client_cannot_receive_its_reply() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = locked_daemon(dir.path());
    let (server, mut client) = UnixStream::pair().unwrap();
    let mut request = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command: Command::Stop,
    })
    .unwrap();
    request.push(b'\n');
    client.write_all(&request).await.unwrap();
    drop(client);
    assert!(daemon.clone().handle(server, MAX_LINE).await.is_err());
    tokio::time::timeout(Duration::from_secs(1), daemon.shutdown.notified())
        .await
        .unwrap();
}

#[tokio::test]
async fn ambiguous_append_closes_the_gate_and_cannot_be_reopened_by_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = locked_daemon(dir.path());
    let (mut loaded, fault) = session::tests::fault_store(dir.path(), [7; 32]);
    let id = loaded.create_vault("personal").unwrap();
    let peer = DeviceSecret::from_bytes(&[8; 32]);
    let consent = peer.join_consent(&id, &loaded.id);
    loaded
        .update(id, |v, key| Ok(v.add(key, peer.device_id(), consent)?))
        .unwrap();
    let members = daemon.members.clone();
    let node = Node::spawn(
        NodeConfig::local_only(*loaded.secret.to_bytes()),
        Arc::new(move |id: &PeerId| members.read().unwrap().contains(id)),
        sync::Handler(daemon.clone()),
    )
    .await
    .unwrap();
    let mut session = Session::new(loaded, node.clone());
    let background = tokio::spawn(std::future::pending::<()>());
    let aborted = background.abort_handle();
    session.sync_task = Some(AbortOnDrop(background));
    daemon.refresh(&mut session);
    *daemon.session.lock().unwrap() = Some(session);
    daemon.ready.send_replace(true);
    let peer_node = Node::spawn(
        NodeConfig::local_only(*peer.to_bytes()),
        Arc::new(|_: &PeerId| true),
        sync::Handler(daemon.clone()),
    )
    .await
    .unwrap();
    // Dial out so the tracked connection is installed on the exact node
    // whose membership is revoked below, without waiting for the accept task.
    let conn = node.connect(peer_node.addr()).await.unwrap();
    assert!(node.connected_peers().contains(peer.device_id().as_bytes()));
    fault.store(2, Ordering::SeqCst);
    let error = daemon
        .with(|s| s.update(id, |v, key| Ok(v.remove(key, peer.device_id())?)))
        .unwrap_err();
    assert!(error.to_string().contains("commit outcome is uncertain"));
    assert!(daemon.members.read().unwrap().is_empty());
    assert!(node.connected_peers().is_empty());
    assert!(!*daemon.ready.borrow());
    assert!(!daemon.status().unlocked);
    assert!(daemon.status().vaults.is_empty());
    assert!(daemon.with(|s| Ok(s.vault_infos())).is_err());
    assert!(daemon.with_data(|_| Ok(())).is_err());
    assert!(
        daemon
            .with(|_| {
                daemon.ready.send_replace(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!*daemon.ready.borrow());
    assert!(daemon.wait_ready().await.is_err());
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        daemon.unlock(zeroize::Zeroizing::new("wrong".into()), Some(0)),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(wrong_passphrase(&error));
    assert!(!daemon.status().unlocked);
    assert!(daemon.session.lock().unwrap().is_none());
    assert!(daemon.members.read().unwrap().is_empty());
    // A failed authentication discarded the old handle, not quarantine's
    // protection. A later normal Unlock must authenticate and replay.
    daemon
        .unlock(zeroize::Zeroizing::new("test".into()), Some(0))
        .await
        .unwrap();
    daemon
        .with(|s| {
            assert!(!s.vault(&id).is_member(&peer.device_id()));
            assert_eq!(s.vault(&id).entries().len(), 3);
            Ok(())
        })
        .unwrap();
    tokio::task::yield_now().await;
    assert!(aborted.is_finished());
    conn.close();
    daemon.lock().await;
    peer_node.shutdown().await;
    let reopened = Loaded::open(dir.path(), b"test").unwrap();
    assert!(!reopened.vault(&id).is_member(&peer.device_id()));
}

#[tokio::test]
async fn quarantine_unlock_authenticates_and_replays_without_a_separate_lock() {
    for biometric in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let daemon = locked_daemon(dir.path());
        let (mut loaded, fault) = session::tests::fault_store(dir.path(), [7; 32]);
        let id = loaded.create_vault("personal").unwrap();
        let key = deadbolt_store::generate_biometric_key().unwrap();
        loaded
            .store
            .set_biometric(&key, &make_valid_biometric_token(session::now()))
            .unwrap();
        let node = Node::spawn(
            NodeConfig::local_only(*loaded.secret.to_bytes()),
            Arc::new(|_: &PeerId| false),
            sync::Handler(daemon.clone()),
        )
        .await
        .unwrap();
        *daemon.session.lock().unwrap() = Some(Session::new(loaded, node));
        fault.store(2, Ordering::SeqCst);
        assert!(
            daemon
                .with(|s| s.update(id, |v, key| Ok(v.rename(key, "committed")?)))
                .is_err()
        );
        assert!(!daemon.status().unlocked);
        if biometric {
            crate::config::set_touch_id(&daemon.paths.config, true).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let called = calls.clone();
            let key = *key;
            *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
                assert!(!cancel.is_cancelled());
                called.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new(key))
            }));
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    daemon.unlock_biometric_with_reason(Some(0), "test recovery")
                )
                .await
                .unwrap()
                .unwrap()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        } else {
            // Concurrent explicit unlocks serialize teardown/open. Neither
            // may reopen the poisoned handle or duplicate the logged edit.
            let (a, b) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    daemon.unlock(Zeroizing::new("test".into()), Some(0)),
                    daemon.unlock(Zeroizing::new("test".into()), Some(0))
                )
            })
            .await
            .unwrap();
            a.unwrap();
            b.unwrap();
        }
        daemon
            .with(|s| {
                assert_eq!(s.vault(&id).name(), "committed");
                assert_eq!(s.vault(&id).entries().len(), 2);
                Ok(())
            })
            .unwrap();
        daemon.lock().await;
        assert!(daemon.session.lock().unwrap().is_none());
    }
}

#[tokio::test]
async fn quarantine_explicit_lock_still_closes_the_failed_handle() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = locked_daemon(dir.path());
    let (mut loaded, fault) = session::tests::fault_store(dir.path(), [7; 32]);
    let id = loaded.create_vault("personal").unwrap();
    let node = Node::spawn(
        NodeConfig::local_only(*loaded.secret.to_bytes()),
        Arc::new(|_: &PeerId| false),
        sync::Handler(daemon.clone()),
    )
    .await
    .unwrap();
    *daemon.session.lock().unwrap() = Some(Session::new(loaded, node));
    fault.store(2, Ordering::SeqCst);
    assert!(
        daemon
            .with(|s| s.update(id, |v, key| Ok(v.rename(key, "committed")?)))
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(5), daemon.lock())
        .await
        .unwrap();
    assert!(daemon.session.lock().unwrap().is_none());
    let loaded = Loaded::open(dir.path(), b"test").unwrap();
    assert_eq!(loaded.vault(&id).name(), "committed");
}

#[tokio::test]
async fn locking_wakes_membership_waiters_with_the_locked_error() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = locked_daemon(dir.path());
    let loaded = Loaded::setup(
        dir.path(),
        b"test",
        "device",
        deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap();
    let node = Node::spawn(
        NodeConfig::local_only(*loaded.secret.to_bytes()),
        Arc::new(|_: &PeerId| false),
        sync::Handler(daemon.clone()),
    )
    .await
    .unwrap();
    *daemon.session.lock().unwrap() = Some(Session::new(loaded, node));
    tokio::time::pause();
    let (error, ()) = tokio::join!(
        async {
            tokio::time::timeout(Duration::from_secs(2), daemon.wait_ready())
                .await
                .unwrap()
                .unwrap_err()
        },
        async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            daemon.lock().await;
        }
    );
    let error = error.downcast::<DaemonError>().unwrap();
    assert!(matches!(error.code, ErrorCode::Locked));
    assert_eq!(error.message, "locked: run `deadbolt unlock`");
}

#[test]
fn invalid_requests_are_described_without_their_values() {
    let line = r#"{"v":4,"cmd":"import","export":"hunter2","apply":"hunter2"}"#;
    let error = serde_json::from_str::<Request>(line).unwrap_err();
    assert!(error.to_string().contains("hunter2"), "serde quotes values");
    let message = invalid_request(&error).to_string();
    assert!(!message.contains("hunter2"), "{message}");
    assert!(
        message.starts_with("invalid request: not a request"),
        "{message}"
    );
}

#[tokio::test]
async fn line_limit_preserves_answers_and_rejects_unterminated_oversize() {
    let mut read = BufReader::new(&b"request\nyes\n"[..]);
    assert_eq!(
        request_line(&mut read, 7)
            .await
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("request")
    );
    assert_eq!(
        request_line(&mut read, 7)
            .await
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("yes")
    );
    let mut read = BufReader::new(&b"1234567890123456"[..]);
    assert!(request_line(&mut read, 7).await.is_err());
    let mut rest = String::new();
    read.read_to_string(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    let mut read = BufReader::new(&b"1234567890123456\nyes\n"[..]);
    assert!(request_line(&mut read, 7).await.is_err());
    assert_eq!(
        request_line(&mut read, 7)
            .await
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("yes")
    );
}

#[tokio::test]
async fn local_item_commands_work_immediately_after_unlock_with_offline_peers() {
    let dir = tempfile::tempdir().unwrap();
    let key = [51; 32];
    let store = deadbolt_store::init_with_params(
        dir.path(),
        b"test",
        key,
        deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap();
    drop(store);
    let mut loaded = Loaded::open(dir.path(), b"test").unwrap();
    let id = loaded.create_vault("personal").unwrap();
    let offline = DeviceSecret::from_bytes(&[52; 32]);
    loaded
        .update(id, |v, key| {
            Ok(v.add(
                key,
                offline.device_id(),
                offline.join_consent(&id, &key.device_id()),
            )?)
        })
        .unwrap();
    drop(loaded);
    let loaded = Loaded::open(dir.path(), b"test").unwrap();
    let daemon = locked_daemon(dir.path());
    let node = Node::spawn(
        NodeConfig::local_only(key),
        Arc::new(|_: &PeerId| false),
        sync::Handler(daemon.clone()),
    )
    .await
    .unwrap();
    *daemon.session.lock().unwrap() = Some(Session::new(loaded, node));
    // No startup task can open readiness: any local wait/gate is a regression.
    let (socket, _client) = UnixStream::pair().unwrap();
    let (_, write) = socket.into_split();
    let conv = Conversation {
        write: tokio::sync::Mutex::new(write),
        answers: tokio::sync::Mutex::new(mpsc::channel(1).1),
        closed: watch::channel(false).1,
    };
    let fields = || {
        vec![
            FieldInput {
                name: "password".into(),
                kind: None,
                value: "offline-value".into(),
            },
            FieldInput {
                name: "notes".into(),
                kind: None,
                value: "offline note".into(),
            },
        ]
    };
    let commands = vec![
        Command::ItemNew {
            vault: None,
            kind: "login".into(),
            name: Some("offline-login".into()),
            fields: fields(),
            favorite: false,
            tags: Vec::new(),
        },
        Command::ItemGet {
            vault: None,
            query: vec!["offline-login".into()],
            otp: false,
            ssh_private: false,
            files: Vec::new(),
            deleted: false,
        },
        Command::ItemList {
            vault: None,
            query: vec![],
            kind: None,
            deleted: false,
            tags: Vec::new(),
            favorites: false,
        },
        Command::ItemSet {
            vault: None,
            query: vec!["offline-login".into()],
            fields: fields(),
            name: None,
            unset: Vec::new(),
            favorite: None,
            add_tags: Vec::new(),
            remove_tags: Vec::new(),
        },
        Command::ItemUnset {
            vault: None,
            query: vec!["offline-login".into()],
            field: "notes".into(),
        },
        Command::Import {
            vault: None,
            export: "name,password\nimported,offline-import\n"
                .to_string()
                .into(),
            files: Vec::new(),
            apply: true,
        },
        Command::ItemRemove {
            vault: None,
            query: vec!["offline-login".into()],
        },
        Command::ItemRestore {
            vault: None,
            query: vec!["offline-login".into()],
        },
    ];
    for command in commands {
        tokio::time::timeout(Duration::from_secs(2), daemon.clone().run(command, &conv))
            .await
            .unwrap()
            .unwrap();
        assert!(!*daemon.ready.borrow());
    }
    assert!(
        daemon.with_data(|_| Ok(())).is_err(),
        "invitations must still wait"
    );
    tokio::time::pause();
    let (waited, ()) = tokio::join!(daemon.wait_ready(), async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        daemon.ready.send_replace(true);
    });
    waited.unwrap();
    daemon.with_data(|_| Ok(())).unwrap();
    daemon.ready.send_replace(false);
    let start = tokio::time::Instant::now();
    assert_eq!(
        daemon.wait_ready().await.unwrap_err().to_string(),
        "waiting for membership sync"
    );
    assert!(start.elapsed() >= sync::STARTUP_TIMEOUT);
    // Tokio's timer wheel rounds deadlines to millisecond ticks.
    assert!(start.elapsed() <= sync::STARTUP_TIMEOUT + Duration::from_millis(1));
    daemon.lock().await;
}

/// A daemon holding one empty vault, its `op` a script that records
/// its pid in `pid` and hangs.
async fn syncing_daemon(dir: &std::path::Path) -> (Arc<Daemon>, std::path::PathBuf) {
    let fast = deadbolt_store::KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let mut loaded = Loaded::setup(dir, b"test", "device", fast).unwrap();
    loaded.create_vault("personal").unwrap();
    let key = *loaded.store.device_secret();
    let daemon = locked_daemon(dir);
    let node = Node::spawn(
        NodeConfig::local_only(key),
        Arc::new(|_: &PeerId| false),
        sync::Handler(daemon.clone()),
    )
    .await
    .unwrap();
    *daemon.session.lock().unwrap() = Some(Session::new(loaded, node));
    let pid = dir.join("pid");
    let op = dir.join("op");
    fs::write(
        &op,
        format!("#!/bin/sh\necho $$ > '{}'\nexec sleep 30\n", pid.display()),
    )
    .unwrap();
    fs::set_permissions(&op, fs::Permissions::from_mode(0o755)).unwrap();
    *daemon.op_program.lock().unwrap() = Some(op);
    (daemon, pid)
}

pub(super) fn conversation() -> (Conversation, UnixStream, watch::Sender<bool>) {
    let (socket, client) = UnixStream::pair().unwrap();
    let (_, write) = socket.into_split();
    let (closed, closed_rx) = watch::channel(false);
    let conv = Conversation {
        write: tokio::sync::Mutex::new(write),
        answers: tokio::sync::Mutex::new(mpsc::channel(1).1),
        closed: closed_rx,
    };
    (conv, client, closed)
}

/// Seed only this test process's unlocked daemon. There is no corresponding
/// RPC, store row or environment switch. The caller must own the synthetic
/// session and know its passphrase; membership and proof checks still run.
#[cfg(target_os = "macos")]
pub(super) async fn designate_fixture_approver(
    daemon: &Daemon,
    vault: deadbolt_core::VaultId,
    device: DeviceId,
    fixture_passphrase: Zeroizing<String>,
) -> Result<()> {
    let (conv, _socket, _open) = conversation();
    daemon
        .experimental_approver_set(
            Some(&vault.to_string()),
            Some(&device.to_string()),
            Some(fixture_passphrase),
            &conv,
        )
        .await?;
    Ok(())
}

/// Manual two-stage proof: pair the fixture with the real phone, then read
/// after biometric enrollment. This is a Mac test host, not a stock CLI
/// operator: it opens only the synthetic fixture, invokes its production
/// inviter internally, and designates via the test-only proof helper. The
/// read goes through the unmodified Unix socket/audit-token boundary.
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "requires an isolated synthetic fixture and a real foreground mobile device"]
async fn paired_mobile_fixture_approval() -> Result<()> {
    use crate::protocol::{Check, Claim, Purpose};
    use anyhow::{anyhow, ensure};

    // The operator supplies the synthetic fixture. Never fall back to the
    // default store or accept arbitrary passphrases or item selectors.
    const PASS: &str = "synthetic-mobile-fixture-passphrase";
    const TITLE: &str = "Synthetic account 00000";
    const EXPECTED: &str = "synthetic-password-00000";
    let dir = std::path::PathBuf::from(
        std::env::var_os("DEADBOLT_MOBILE_FIXTURE_DIR")
            .context("set DEADBOLT_MOBILE_FIXTURE_DIR to the synthetic CLI fixture")?,
    );
    let expected_count = match dir.file_name().and_then(|name| name.to_str()) {
        Some("deadbolt-mobile-fixture-1000") => 1_000,
        Some("deadbolt-mobile-fixture-10000") => 10_000,
        _ => bail!("expected a named 1000- or 10000-item synthetic fixture"),
    };
    enum Stage {
        Pair(deadbolt_net::PairingCode),
        Read(DeviceId),
    }
    let stage = match (
        crate::config::test_env("DEADBOLT_MOBILE_PAIR_CODE").map(Zeroizing::new),
        crate::config::test_env("DEADBOLT_MOBILE_APPROVER_ID"),
    ) {
        (Some(code), None) => Stage::Pair(
            code.parse()
                .map_err(|_| anyhow!("invalid five-word code"))?,
        ),
        (None, Some(id)) => Stage::Read(DeviceId::from_bytes(
            session::unhex(&id).map_err(|_| anyhow!("invalid phone device id"))?,
        )),
        _ => {
            bail!("supply exactly one of DEADBOLT_MOBILE_PAIR_CODE or DEADBOLT_MOBILE_APPROVER_ID")
        }
    };
    let loaded = Loaded::open(&dir, PASS.as_bytes()).map_err(|_| anyhow!("cannot open fixture: confirm stock fixture daemon stopped and fixture passphrase matches"))?;
    ensure!(
        loaded.meta.device_name == "Synthetic fixture CLI"
            && loaded.vaults.len() == 1
            && loaded.unavailable.is_empty(),
        "wrong fixture identity"
    );
    let vault = loaded.resolve(None)?;
    let v = loaded.vault(&vault);
    ensure!(
        v.name() == "mobile-fixture" && v.is_member(&loaded.id),
        "not a current fixture vault"
    );
    match &stage {
        Stage::Pair(_) => ensure!(
            v.members().count() == 1,
            "pair mode requires the fresh, single-member fixture"
        ),
        Stage::Read(phone) => ensure!(
            v.members().count() == 2 && *phone != loaded.id && v.is_member(phone),
            "expected fixture CLI and named phone as the two paired members"
        ),
    }
    ensure!(
        v.iter_items().count() == expected_count,
        "wrong fixture item count"
    );
    let item = v
        .iter_items()
        .find(|i| {
            i.name.as_deref() == Some(TITLE)
                && i.kind == "login"
                && i.fields
                    .get("password")
                    .is_some_and(|f| f.value == EXPECTED)
        })
        .context("expected synthetic login missing")?
        .id;
    let refs = vec![format!("deadbolt://{vault}/{item}/password")];
    let runtime = tempfile::tempdir()?;
    let mut paths = test_paths(runtime.path());
    paths.data = dir;
    let env = crate::config::Environment::load();
    ensure!(
        !env.local_net,
        "unset DEADBOLT_NET=local for the real mobile peer"
    );
    let daemon = Daemon::new(paths, env.local_net, env.kdf);

    async fn request(daemon: &Arc<Daemon>, command: Command) -> Result<Message> {
        let (server, mut client) = UnixStream::pair()?;
        let (_, message) = tokio::try_join!(daemon.clone().handle(server, MAX_LINE), async {
            let request = Request {
                v: PROTOCOL_VERSION,
                command,
                claimed: Some(Claim {
                    caller: None,
                    opencode_session: Some("synthetic-mobile-approval-harness".into()),
                }),
            };
            client
                .write_all(&deadbolt_client::encode_json(b"", &request, b"\n")?)
                .await?;
            let reply = request_line(&mut BufReader::new(&mut client), 64 * 1024)
                .await?
                .context("no reply")?;
            serde_json::from_str(&reply).map_err(|_| anyhow!("invalid reply"))
        })?;
        Ok(message)
    }
    let run = async {
        daemon.start(loaded, None).await?;
        daemon.wait_ready().await?;
        let phone = match stage {
            Stage::Read(phone) => phone,
            Stage::Pair(code) => {
                let (conv, _socket, _open) = conversation();
                println!("APPROVAL_HARNESS_READY phase=pair vault={vault}");
                let paired =
                    pairing::pair(&daemon, &conv, code.to_string(), Some(vault.to_string()))
                        .await?;
                let Reply::Device { device, .. } = paired else {
                    bail!("pair did not return an admitted device")
                };
                let phone = DeviceId::from_bytes(session::unhex(&device.id)?);
                daemon.with_data(|s| {
                    let held = s.vault(&vault);
                    ensure!(
                        phone != s.id && held.is_member(&phone) && held.members().count() == 2,
                        "pair did not admit the remote member"
                    );
                    Ok(())
                })?;
                return Ok(format!(
                    "APPROVAL_HARNESS_PAIRED vault={vault} phone={phone}"
                ));
            }
        };
        let Message::Ok {
            reply: Reply::Status(status),
        } = request(&daemon, Command::Status).await?
        else {
            bail!("status failed")
        };
        ensure!(
            status.caller.check == Check::Signature
                && status.caller.pid == std::process::id()
                && status.caller.signature.is_some_and(|sig| sig.valid)
                && !daemon.can_verify(),
            "expected verified test host and no Mac biometric slot"
        );
        let plain = Command::Resolve {
            refs: refs.clone(),
            purpose: Purpose::Read,
        };
        let refused = request(&daemon, plain).await?;
        ensure!(
            matches!(
                refused,
                Message::Error {
                    code: ErrorCode::Forbidden,
                    ..
                }
            ),
            "ordinary AI resolve was not refused"
        );
        designate_fixture_approver(&daemon, vault, phone, Zeroizing::new(PASS.into())).await?;
        let read = || Command::ExperimentalMobileRead { refs: refs.clone() };
        println!(
            "APPROVAL_HARNESS_READY phase=allow caller=verified-mac-test-host vault={vault} phone={phone} item={item} field=password"
        );
        let first = request(&daemon, read()).await?;
        let Message::Ok {
            reply: Reply::Secrets { secrets },
        } = first
        else {
            bail!("first phone read was not approved")
        };
        ensure!(
            matches!(secrets.as_slice(), [s] if s.item == item.to_string() && s.vault == "mobile-fixture" && s.title == TITLE && s.field == "password" && s.value.expose() == EXPECTED),
            "answer did not release exactly the requested fixture field"
        );
        drop(secrets);
        println!(
            "APPROVAL_HARNESS_READY phase=deny first_release_count=1 phone={phone} item={item} field=password"
        );
        // The SAME read must ask again. Only a signed denial passes, not a
        // timeout, offline phone, local failure or an already-consumed allow.
        let second = request(&daemon, read()).await?;
        ensure!(
            matches!(second, Message::Error {code: ErrorCode::Forbidden, message, ..} if message.ends_with("read denied on approver")),
            "second read did not receive a signed denial"
        );
        Ok::<_, anyhow::Error>(
            "APPROVAL_HARNESS_PASS ordinary=refused first=one_field second=signed_denial".into(),
        )
    };
    let result = tokio::time::timeout(Duration::from_secs(240), run).await;
    tokio::time::timeout(Duration::from_secs(10), daemon.lock())
        .await
        .context("fixture shutdown timed out")?;
    println!("{}", result.context("phone proof exceeded 240 seconds")??);
    Ok(())
}

/// Add one origin-matched login to the already paired 10k Safari fixture.
/// Prepare offline first; serve only the replayed item on the ordinary network.
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "requires an explicitly named, paired synthetic Safari fixture"]
async fn paired_mobile_fixture_otp() -> Result<()> {
    use anyhow::ensure;
    use deadbolt_core::{Field, FieldType};
    use std::collections::BTreeMap;

    const TITLE: &str = "Synthetic OTP Safari";
    let dir = std::path::PathBuf::from(
        std::env::var_os("DEADBOLT_MOBILE_FIXTURE_DIR").context("set the fixture directory")?,
    );
    ensure!(
        dir.is_absolute()
            && dir.file_name().and_then(|s| s.to_str()) == Some("deadbolt-mobile-fixture-10000"),
        "expected an absolute, named 10k fixture directory"
    );
    let phone = DeviceId::from_bytes(session::unhex(
        &crate::config::env("DEADBOLT_MOBILE_APPROVER_ID").context("set the paired phone ID")?,
    )?);
    let serve = match crate::config::env("DEADBOLT_MOBILE_OTP_STAGE").as_deref() {
        Ok("prepare") => false,
        Ok("serve") => true,
        _ => bail!("set DEADBOLT_MOBILE_OTP_STAGE to prepare or serve"),
    };
    let open = || Loaded::open(&dir, b"synthetic-mobile-fixture-passphrase");
    let fields = |username: String, password: String, url: String| {
        BTreeMap::from([
            ("username".into(), Field::new(FieldType::Text, username)),
            ("password".into(), Field::new(FieldType::Secret, password)),
            ("url".into(), Field::new(FieldType::Url, url)),
            ("otp".into(), Field::new(FieldType::Otp, "JBSWY3DPEHPK3PXP")),
        ])
    };
    let otp = fields(
        "synthetic-otp@example.test".into(),
        "synthetic-password-otp".into(),
        "https://deadbolt-otp.i.vogel.dev".into(),
    );
    let inspect = |loaded: &Loaded| -> Result<_> {
        ensure!(
            loaded.meta.device_name == "Synthetic fixture CLI"
                && loaded.vaults.len() == 1
                && loaded.unavailable.is_empty(),
            "wrong fixture identity"
        );
        let vault = loaded.resolve(None)?;
        let v = loaded.vault(&vault);
        ensure!(
            v.name() == "mobile-fixture"
                && phone != loaded.id
                && v.members().count() == 2
                && v.is_member(&loaded.id)
                && v.is_member(&phone),
            "expected the fixture CLI and named phone as the only members"
        );
        let mut numbered: HashSet<_> = (0..10_000).map(|n| format!("{n:05}")).collect();
        let mut existing = None;
        for item in v.iter_items() {
            // The phone may also have synced its separate passkey fixture.
            if item.kind == "passkey" {
                continue;
            }
            ensure!(item.kind == "login", "unexpected fixture item kind");
            if item.name.as_deref() == Some(TITLE) {
                ensure!(
                    item.fields == otp && existing.replace(item.id).is_none(),
                    "wrong or duplicate Safari login"
                );
                continue;
            }
            let n = item
                .name
                .as_deref()
                .and_then(|n| n.strip_prefix("Synthetic account "))
                .context("unexpected login in synthetic fixture")?;
            ensure!(
                numbered.remove(n)
                    && item.fields
                        == fields(
                            format!("synthetic-{n}@example.test"),
                            format!("synthetic-password-{n}"),
                            format!("https://site-{n}.example.test")
                        ),
                "wrong or duplicate numbered fixture login"
            );
        }
        ensure!(numbered.is_empty(), "missing numbered fixture login");
        Ok((vault, existing))
    };
    let mut loaded = open()?;
    let (vault, existing) = inspect(&loaded)?;
    if !serve {
        let item = match existing {
            Some(item) => item,
            None => loaded.update(vault, |write, key| {
                Ok(write
                    .create_item(key, "login", Some(TITLE.into()), otp.clone())?
                    .0)
            })?,
        };
        drop(loaded);
        ensure!(
            inspect(&open()?)? == (vault, Some(item)),
            "signed login failed durable replay"
        );
        println!(
            "OTP_FIXTURE_PREPARED item={item} logins=10001 appended={}",
            existing.is_none()
        );
        return Ok(());
    }
    let item = existing.context("prepare the fixture offline before serving")?;
    let runtime = tempfile::tempdir()?;
    let mut paths = test_paths(runtime.path());
    paths.data = dir;
    let env = crate::config::Environment::load();
    ensure!(
        !env.local_net,
        "unset DEADBOLT_NET=local for the real mobile peer"
    );
    let daemon = Daemon::new(paths, env.local_net, env.kdf);
    let run = async {
        daemon.start(loaded, None).await?;
        daemon.wait_ready().await?;
        println!("OTP_FIXTURE_SERVING item={item} logins=10001 seconds=300");
        tokio::time::sleep(Duration::from_secs(300)).await;
        Ok(())
    };
    let result = tokio::time::timeout(Duration::from_secs(360), run).await;
    tokio::time::timeout(Duration::from_secs(10), daemon.lock())
        .await
        .context("fixture shutdown timed out")?;
    result.context("fixture serving timed out")?
}

fn sync_op() -> Command {
    Command::SyncOnePassword {
        vault: None,
        account: None,
        op_vaults: Vec::new(),
        dry_run: false,
    }
}

fn person() -> CallerInfo {
    CallerInfo {
        identified: true,
        ..CallerInfo::unverified("test terminal")
    }
}

async fn started(pid: &std::path::Path) -> String {
    for _ in 0..200 {
        if let Ok(pid) = fs::read_to_string(pid)
            && !pid.trim().is_empty()
        {
            return pid.trim().to_string();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("op never ran");
}

#[tokio::test]
async fn the_idle_lock_stops_a_stuck_sync_from_1password() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, pid) = syncing_daemon(dir.path()).await;
    let (conv, _client, _closed) = conversation();
    let syncing = {
        let daemon = daemon.clone();
        tokio::spawn(async move { daemon.dispatch(&person(), sync_op(), &conv).await })
    };
    let pid = started(&pid).await;

    // One at a time.
    let (conv, _client, _closed) = conversation();
    let error = daemon
        .clone()
        .dispatch(&person(), sync_op(), &conv)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "already syncing from 1Password: try again when it finishes"
    );

    // It does not hold the vault open.
    {
        let mut idle = daemon.idle.lock().unwrap();
        idle.timeout = Some(Duration::from_secs(1));
        idle.deadline = Some(Instant::now());
    }
    daemon.check_idle().await;
    assert!(!daemon.status().unlocked);
    let error = syncing.await.unwrap().unwrap_err();
    let error = error.downcast::<DaemonError>().unwrap();
    assert_eq!(error.code, ErrorCode::Locked);
    assert_eq!(error.message, INTERRUPTED);
    assert!(mirror::tests::gone(&pid).await, "op {pid} still running");
}

#[tokio::test]
async fn a_client_that_goes_away_stops_its_sync_from_1password() {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, pid) = syncing_daemon(dir.path()).await;
    let (conv, _client, closed) = conversation();
    let syncing = {
        let daemon = daemon.clone();
        tokio::spawn(async move { daemon.dispatch(&person(), sync_op(), &conv).await })
    };
    let pid = started(&pid).await;
    closed.send_replace(true);
    let error = syncing.await.unwrap().unwrap_err();
    assert_eq!(error.to_string(), "the sync from 1Password was cancelled");
    assert!(mirror::tests::gone(&pid).await, "op {pid} still running");
    assert!(daemon.status().unlocked);
    daemon.lock().await;
}

fn make_valid_biometric_token(now_secs: u64) -> Vec<u8> {
    let mut token = Vec::new();
    token.extend_from_slice(b"DBSE");
    token.push(1); // version
    token.push(1); // FLAG_BIOMETRY_CURRENT_SET
    token.extend_from_slice(&now_secs.to_le_bytes());
    token.extend_from_slice(b"payload");
    token
}

#[tokio::test]
async fn touch_id_set_off_clears_slot_and_updates_status() {
    let dir = tempfile::tempdir().unwrap();
    let loaded = Loaded::setup(
        dir.path(),
        b"test",
        "device",
        deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap();
    let now = session::now();
    let token = make_valid_biometric_token(now);
    let bio_key = deadbolt_store::generate_biometric_key().unwrap();
    loaded.store.set_biometric(&bio_key, &token).unwrap();
    drop(loaded);

    let daemon = locked_daemon(dir.path());
    *daemon.touch_id_available_override.lock().unwrap() = Some(true);
    crate::config::set_touch_id(&daemon.paths.config, true).unwrap();

    // While another handle holds `store.redb` open, `daemon.status()` still
    // reports `touch_id_ready = true` from in-memory metadata without
    // opening the store or hitting `Error::InUse`.
    let held = deadbolt_store::unlock(dir.path(), b"test").unwrap();
    let before = daemon.status();
    assert!(before.touch_id_available);
    assert!(before.touch_id_enabled);
    assert!(before.touch_id_ready);
    assert!(!before.touch_id_reset);
    drop(held);

    daemon.set_touch_id(false).await.unwrap();
    assert!(!Config::load(&daemon.paths.config).unwrap().touch_id());
    assert!(
        deadbolt_store::biometric_token(dir.path())
            .unwrap()
            .is_none()
    );
    let st = daemon.status();
    assert!(st.touch_id_available);
    assert!(!st.touch_id_enabled);
    assert!(!st.touch_id_ready);
    assert!(!st.touch_id_reset);
}

#[tokio::test]
async fn touch_id_coalesces_overlapping_requests_and_cancels_on_passphrase_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let fast = deadbolt_store::KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let loaded = Loaded::setup(dir.path(), b"test", "device", fast).unwrap();
    let now = session::now();
    let token = make_valid_biometric_token(now);
    let bio_key = deadbolt_store::generate_biometric_key().unwrap();
    loaded.store.set_biometric(&bio_key, &token).unwrap();
    drop(loaded);

    let daemon = Daemon::new(test_paths(dir.path()), true, fast);
    *daemon.touch_id_available_override.lock().unwrap() = Some(true);
    crate::config::set_touch_id(&daemon.paths.config, true).unwrap();

    // 1. Two overlapping `unlock_biometric` calls coalesce onto one unseal invocation.
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = calls.clone();
    let key_copy = *bio_key;
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
        calls_for_hook.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(80));
        Ok(Zeroizing::new(key_copy))
    }));

    let a1 = daemon.clone();
    let a2 = daemon.clone();
    let (r1, r2) = tokio::join!(a1.unlock_biometric(None), a2.unlock_biometric(None));
    r1.unwrap();
    r2.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(daemon.status().unlocked);
    daemon.lock().await;

    // 2. A cancelled prompt sets a short cooldown so an immediate retry is
    // rejected without invoking the helper again.
    let cancel_calls = Arc::new(AtomicUsize::new(0));
    let cancel_calls_hook = cancel_calls.clone();
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
        cancel_calls_hook.fetch_add(1, Ordering::SeqCst);
        Err(biometric::UnlockError::Cancelled)
    }));
    assert!(daemon.unlock_biometric(None).await.is_err());
    assert!(daemon.unlock_biometric(None).await.is_err());
    assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);

    // 3. Programmatic cancellation (e.g. `lock()`) does not arm the user-cancel
    // cooldown, so the next `unlock_biometric` call runs immediately.
    *daemon.biometric_cooldown_until.lock().unwrap() = None;
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
        while !cancel.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(biometric::UnlockError::Cancelled)
    }));
    let bio_daemon = daemon.clone();
    let bio_task = tokio::spawn(async move { bio_daemon.unlock_biometric(None).await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    daemon.lock().await;
    assert!(bio_task.await.unwrap().is_err());
    assert!(
        daemon.biometric_cooldown_until.lock().unwrap().is_none(),
        "programmatic cancel must not set user-cancel cooldown"
    );

    // 4. An `Invalidated` error from a cancelled flight (or when the stored token
    // no longer matches the unsealed token) must not wipe the current slot.
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
        cancel.cancel();
        Err(biometric::UnlockError::Invalidated("stale flight".into()))
    }));
    assert!(daemon.unlock_biometric(None).await.is_err());
    assert!(
        deadbolt_store::biometric_token(dir.path())
            .unwrap()
            .is_some(),
        "cancelled flight must not clear biometric slot"
    );
    assert!(daemon.status().touch_id_ready);
    assert!(!daemon.status().touch_id_reset);

    // 5. A passphrase unlock cancels an in-flight biometric prompt and clears cooldown.
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
        while !cancel.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(biometric::UnlockError::Cancelled)
    }));
    let bio_daemon = daemon.clone();
    let bio_task = tokio::spawn(async move { bio_daemon.unlock_biometric(None).await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    daemon
        .unlock(Zeroizing::new("test".into()), None)
        .await
        .unwrap();
    assert!(bio_task.await.unwrap().is_err());
    assert!(daemon.status().unlocked);
    daemon.lock().await;

    // 6. A genuine `Invalidated` error clears the matching slot and marks
    // `touch_id_reset = true`, whereas a fresh store with `touch_id = true`
    // that has never enrolled has `touch_id_reset = false`.
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
        Err(biometric::UnlockError::Invalidated(
            "biometry changed".into(),
        ))
    }));
    assert!(daemon.unlock_biometric(None).await.is_err());
    let reset_st = daemon.status();
    assert!(reset_st.touch_id_enabled);
    assert!(!reset_st.touch_id_ready);
    assert!(reset_st.touch_id_reset);

    let never_dir = tempfile::tempdir().unwrap();
    drop(Loaded::setup(never_dir.path(), b"test", "device", fast).unwrap());
    let never_daemon = Daemon::new(test_paths(never_dir.path()), true, fast);
    *never_daemon.touch_id_available_override.lock().unwrap() = Some(true);
    crate::config::set_touch_id(&never_daemon.paths.config, true).unwrap();
    let never_st = never_daemon.status();
    assert!(never_st.touch_id_enabled);
    assert!(!never_st.touch_id_ready);
    assert!(
        !never_st.touch_id_reset,
        "never-enrolled store must not report touch_id_reset"
    );
}

/// Unlocking (locked or not) and the proof for pairing share one backoff:
/// past five wrong passphrases even the right one waits, `rate-limited`.
#[tokio::test]
async fn every_passphrase_check_shares_one_backoff() {
    let dir = tempfile::tempdir().unwrap();
    let fast = deadbolt_store::KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let daemon = Daemon::new(test_paths(dir.path()), true, fast);
    let pass = |text: &str| Zeroizing::new(text.to_string());
    daemon.setup(pass("test"), "laptop".into()).await.unwrap();
    daemon.lock().await;
    for _ in 1..guesses::FREE_FAILURES {
        let error = daemon.unlock(pass("wrong"), None).await.unwrap_err();
        assert!(wrong_passphrase(&error), "{error:#}");
    }
    // A right one resets the count.
    daemon.unlock(pass("test"), Some(60)).await.unwrap();
    // Wrong ones while unlocked (asking for a longer timeout) count
    // too, and so do locked ones.
    for _ in 0..3 {
        let error = daemon.unlock(pass("wrong"), Some(0)).await.unwrap_err();
        assert!(wrong_passphrase(&error), "{error:#}");
    }
    daemon.lock().await;
    for _ in 0..2 {
        assert!(daemon.unlock(pass("wrong"), None).await.is_err());
    }
    let error = daemon.unlock(pass("test"), None).await.unwrap_err();
    assert_eq!(crate::client::code(&error), Some(ErrorCode::RateLimited));
    assert_eq!(
        error.to_string(),
        "Too many wrong passphrases. Try again in 30 s."
    );
    assert!(!daemon.status().unlocked);
}

/// Unlocking while unlocked may shorten the idle timeout as it is; a
/// longer one, or never, takes the right passphrase or a Touch ID prompt.
/// And a passphrase that doesn't open the store never cancels a prompt.
#[tokio::test]
async fn an_unverified_unlock_only_shortens_the_idle_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let fast = deadbolt_store::KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let loaded = Loaded::setup(dir.path(), b"test", "device", fast).unwrap();
    let token = make_valid_biometric_token(session::now());
    let bio_key = deadbolt_store::generate_biometric_key().unwrap();
    loaded.store.set_biometric(&bio_key, &token).unwrap();
    drop(loaded);
    let daemon = Daemon::new(test_paths(dir.path()), true, fast);
    *daemon.touch_id_available_override.lock().unwrap() = Some(true);
    crate::config::set_touch_id(&daemon.paths.config, true).unwrap();

    let prompts = Arc::new(AtomicUsize::new(0));
    let finger = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let key = *bio_key;
    let (counted, touched) = (prompts.clone(), finger.clone());
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_cancel| {
        counted.fetch_add(1, Ordering::SeqCst);
        if touched.load(Ordering::SeqCst) {
            Ok(Zeroizing::new(key))
        } else {
            Err(biometric::UnlockError::Cancelled)
        }
    }));
    let timeout = || daemon.idle.lock().unwrap().timeout.map(|t| t.as_secs());
    let pass = |text: &str| Zeroizing::new(text.to_string());

    daemon.unlock_biometric(Some(3600)).await.unwrap();
    assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (1, Some(3600)));

    daemon.unlock(pass("wrong"), Some(600)).await.unwrap();
    assert_eq!(timeout(), Some(600));
    for longer in [Some(7200), Some(0)] {
        let error = daemon.unlock(pass("wrong"), longer).await.unwrap_err();
        assert!(error.to_string().contains("wrong passphrase"), "{error}");
        assert_eq!(timeout(), Some(600));
    }
    daemon.unlock(pass("test"), Some(7200)).await.unwrap();
    assert_eq!(timeout(), Some(7200));
    daemon.unlock(pass("test"), Some(0)).await.unwrap();
    assert_eq!(timeout(), None);

    daemon.unlock_biometric(Some(60)).await.unwrap();
    assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (1, Some(60)));
    finger.store(false, Ordering::SeqCst);
    assert!(daemon.unlock_biometric(Some(0)).await.is_err());
    assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (2, Some(60)));
    *daemon.biometric_cooldown_until.lock().unwrap() = None;
    finger.store(true, Ordering::SeqCst);
    daemon.unlock_biometric(Some(0)).await.unwrap();
    assert_eq!((prompts.load(Ordering::SeqCst), timeout()), (3, None));
    assert!(daemon.status().unlocked);

    daemon.lock().await;
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let released = release.clone();
    *daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
        loop {
            if cancel.is_cancelled() {
                return Err(biometric::UnlockError::Cancelled);
            }
            if released.load(Ordering::SeqCst) {
                return Ok(Zeroizing::new(key));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }));
    let bio_daemon = daemon.clone();
    let bio_task = tokio::spawn(async move { bio_daemon.unlock_biometric(None).await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(daemon.unlock(pass("wrong"), None).await.is_err());
    release.store(true, Ordering::SeqCst);
    bio_task.await.unwrap().unwrap();
    assert!(daemon.status().unlocked);
    daemon.lock().await;
}
