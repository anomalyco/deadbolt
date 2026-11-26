//! The screen inside a daemon: what reaches it, in which order, who may
//! end a run, and what a refusal leaves in Activity.

use std::sync::Arc;

use deadbolt_client::peer::Peer;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::super::macos_autofill::SocketKind;
use super::super::passkeys::tests::daemon::conversation;
use super::super::tests::test_paths;
use super::*;
use crate::client::DaemonError;
use crate::protocol::{
    ActivityEntry, CallerClass, CallerInfo, Message, Outcome, PROTOCOL_VERSION, Request,
};

fn daemon() -> (Arc<Daemon>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let daemon = Daemon::new(
        test_paths(dir.path()),
        true,
        crate::disk::KdfParams::DEFAULT,
    );
    (daemon, dir)
}

/// This process, as the kernel names it over a socket.
fn me() -> Peer {
    let (one, _other) = UnixStream::pair().unwrap();
    Peer::of(&one).unwrap()
}

async fn ask(
    daemon: &Arc<Daemon>,
    socket: SocketKind,
    peer: Peer,
    command: Command,
) -> (Result<Reply>, Option<ActivityEntry>) {
    let (conv, _closed) = conversation();
    let request = Request {
        v: PROTOCOL_VERSION,
        command,
    };
    daemon
        .clone()
        .answer(socket, Ok(peer), request, &conv)
        .await
}

fn code(result: &Result<Reply>) -> Option<ErrorCode> {
    result
        .as_ref()
        .err()?
        .downcast_ref::<DaemonError>()
        .map(|e| e.code)
}

fn runs(daemon: &Daemon) -> bool {
    !daemon.taints.lock().unwrap().is_empty()
}

fn run_id(result: Result<Reply>) -> Secret {
    match result.unwrap() {
        Reply::RunTainted { run } => run,
        other => panic!("{other:?}"),
    }
}

/// The AutoFill socket (and the AutoFill extension anywhere) can't register
/// or end a run: the socket's access rules come before the run's screen.
#[tokio::test]
async fn the_autofill_socket_never_reaches_the_screen() {
    let (daemon, _dir) = daemon();
    let peer = me();
    // Not the extension, on its socket.
    for command in [
        Command::RunTaint,
        Command::RunUntaint {
            run: Secret::new("00"),
        },
    ] {
        let (result, entry) = ask(&daemon, SocketKind::AutoFill, peer, command).await;
        assert_eq!(code(&result), Some(ErrorCode::Forbidden));
        assert_eq!(entry.unwrap().outcome, Outcome::Refused);
    }
    // The extension itself, on either socket.
    let mut autofill = CallerInfo::unverified("autofill");
    autofill.identified = true;
    autofill.class = CallerClass::AutoFill;
    daemon.callers.cache_for_test(peer, autofill);
    for socket in [SocketKind::AutoFill, SocketKind::Control] {
        let (result, _) = ask(&daemon, socket, peer, Command::RunTaint).await;
        assert_eq!(code(&result), Some(ErrorCode::Forbidden), "{socket:?}");
    }
    assert!(!runs(&daemon));
}

/// Knowing a run's id isn't enough to end it: only its own process may.
#[tokio::test]
async fn only_the_runs_own_process_ends_it() {
    let (daemon, _dir) = daemon();
    let peer = me();
    let run = run_id(
        ask(&daemon, SocketKind::Control, peer, Command::RunTaint)
            .await
            .0,
    );
    let mut other = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let stranger = Peer {
        pid: other.id(),
        uid: peer.uid,
        token: None,
        pid_version: None,
    };
    let untaint = || Command::RunUntaint { run: run.clone() };
    let (result, entry) = ask(&daemon, SocketKind::Control, stranger, untaint()).await;
    assert_eq!(code(&result), Some(ErrorCode::Forbidden));
    assert_eq!(entry.unwrap().outcome, Outcome::Refused);
    assert!(runs(&daemon));
    let (result, entry) = ask(&daemon, SocketKind::Control, peer, untaint()).await;
    assert!(matches!(result, Ok(Reply::Done)), "{result:?}");
    assert!(entry.is_none(), "a run's own ending isn't an entry");
    assert!(!runs(&daemon));
    other.kill().unwrap();
    other.wait().unwrap();
}

/// A process inside a run reaching past its capability is refused, and the
/// refusal is in Activity; its harmless `status` isn't.
#[tokio::test]
async fn a_refused_probe_from_inside_a_run_is_an_activity_entry() {
    let (daemon, _dir) = daemon();
    let peer = me();
    let run = run_id(
        ask(&daemon, SocketKind::Control, peer, Command::RunTaint)
            .await
            .0,
    );
    let get = Command::ItemGet {
        vault: None,
        query: vec!["GitHub".into()],
        otp: false,
        ssh_private: false,
        files: vec![],
        deleted: false,
    };
    let (result, entry) = ask(&daemon, SocketKind::Control, peer, get).await;
    assert_eq!(code(&result), Some(ErrorCode::Forbidden));
    let entry = entry.expect("the refusal is recorded");
    assert_eq!(
        (entry.command.as_str(), entry.outcome),
        ("item-get", Outcome::Refused)
    );
    let (result, entry) = ask(&daemon, SocketKind::Control, peer, Command::Status).await;
    assert!(matches!(result, Ok(Reply::Status(_))));
    assert!(entry.is_none());
    let (result, _) = ask(
        &daemon,
        SocketKind::Control,
        peer,
        Command::RunUntaint { run },
    )
    .await;
    assert!(result.is_ok());
}

/// A request in another protocol is refused before the screen sees it, so
/// it can't register a run (or spend a run's capability).
#[tokio::test]
async fn another_protocols_request_is_refused_before_the_screen() {
    let (daemon, _dir) = daemon();
    let (server, client) = UnixStream::pair().unwrap();
    let serving = tokio::spawn(
        daemon
            .clone()
            .handle_on(server, 1 << 20, SocketKind::Control),
    );
    let request = Request {
        v: PROTOCOL_VERSION + 1,
        command: Command::RunTaint,
    };
    let (read, mut write) = client.into_split();
    let line = format!("{}\n", serde_json::to_string(&request).unwrap());
    write.write_all(line.as_bytes()).await.unwrap();
    let mut reply = String::new();
    BufReader::new(read).read_line(&mut reply).await.unwrap();
    match serde_json::from_str::<Message>(&reply).unwrap() {
        Message::Error { code, .. } => assert_eq!(code, ErrorCode::Version),
        other => panic!("{other:?}"),
    }
    serving.await.unwrap().unwrap();
    assert!(!runs(&daemon));
}
