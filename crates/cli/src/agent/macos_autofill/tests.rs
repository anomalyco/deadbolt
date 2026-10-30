use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt_client::peer::Peer;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::super::items::create;
use super::super::passkeys::tests::agent::unlocked;
use super::super::session::hex;
use super::*;
use crate::protocol::{
    AutofillService, AutofillServiceKind, Check, FieldInput, MAX_AUTOFILL_LINE, MAX_LINE, Message,
    Outcome, PROTOCOL_VERSION, Request,
};

const OTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

fn mark_peer_as(agent: &Agent, stream: &UnixStream, class: CallerClass, label: &str) {
    let peer = Peer::of(stream).unwrap();
    let mut info = CallerInfo::unverified(label);
    info.class = class;
    info.check = Check::Signature;
    info.pid = peer.pid;
    info.pid_version = peer.pid_version;
    info.uid = Some(peer.uid);
    agent.callers.cache_for_test(peer, info);
}

async fn send_on(
    agent: &Arc<Agent>,
    socket: SocketKind,
    caller: Option<(CallerClass, &str)>,
    command: Command,
) -> Message {
    let (server, mut client) = UnixStream::pair().unwrap();
    if let Some((class, label)) = caller {
        mark_peer_as(agent, &server, class, label);
    }
    let max = match socket {
        SocketKind::Control => MAX_LINE,
        SocketKind::AutoFill => MAX_AUTOFILL_LINE,
    };
    let mut raw = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command,
    })
    .unwrap();
    raw.push(b'\n');
    client.write_all(&raw).await.unwrap();
    agent.clone().handle_on(server, max, socket).await.unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).await.unwrap();
    serde_json::from_str(&reply).unwrap()
}

fn add_item(s: &mut Loaded, kind: &str, name: Option<&str>, fields: &[(&str, &str)]) -> LoginRef {
    let inputs = fields
        .iter()
        .map(|(n, v)| FieldInput {
            name: (*n).into(),
            kind: n.starts_with("url-").then(|| "url".into()),
            value: (*v).into(),
        })
        .collect();
    let info = create(s, None, kind, name.map(Into::into), inputs).unwrap();
    LoginRef {
        vault: hex(s.resolve(None).unwrap().as_bytes()),
        item: info.id,
    }
}

#[tokio::test]
async fn app_group_socket_checks_permissions_and_rejects_other_callers() {
    let root = tempfile::tempdir().unwrap();
    let container = root.path().join("group");
    fs::create_dir(&container).unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o755)).unwrap();

    let (listener, sock_path) = bind_in(&container).unwrap();
    assert_eq!(
        fs::metadata(&container).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(&sock_path).unwrap().permissions().mode() & 0o7777,
        0o600
    );

    let link = root.path().join("symlink-group");
    std::os::unix::fs::symlink(&container, &link).unwrap();
    assert!(bind_in(&link).is_err(), "symlink container must be refused");

    let f = unlocked().await;
    let agent = f.agent.clone();
    let accept_one = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        agent
            .handle_on(stream, MAX_AUTOFILL_LINE, SocketKind::AutoFill)
            .await
            .unwrap();
    });
    let mut client = UnixStream::connect(&sock_path).await.unwrap();
    let mut req = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command: Command::Status,
    })
    .unwrap();
    req.push(b'\n');
    client.write_all(&req).await.unwrap();
    let mut out = String::new();
    client.read_to_string(&mut out).await.unwrap();
    accept_one.await.unwrap();
    match serde_json::from_str::<Message>(&out).unwrap() {
        Message::Error { code, .. } => assert_eq!(code, ErrorCode::Forbidden),
        other => panic!("expected Forbidden on App Group socket, got {other:?}"),
    }

    // App and BrowserHost are also refused on the AutoFill socket, and
    // non-AutoFill callers cannot invoke Autofill* on the control socket.
    for class in [
        CallerClass::Caller,
        CallerClass::App,
        CallerClass::BrowserHost,
    ] {
        let msg = send_on(
            &f.agent,
            SocketKind::AutoFill,
            Some((class, "other")),
            Command::AutofillStatus,
        )
        .await;
        assert!(
            matches!(
                msg,
                Message::Error {
                    code: ErrorCode::Forbidden,
                    ..
                }
            ),
            "{class:?}: {msg:?}"
        );

        let ctrl = send_on(
            &f.agent,
            SocketKind::Control,
            Some((class, "other")),
            Command::AutofillIdentities,
        )
        .await;
        assert!(
            matches!(
                ctrl,
                Message::Error {
                    code: ErrorCode::Forbidden,
                    ..
                }
            ),
            "{class:?}: {ctrl:?}"
        );
    }
}

#[tokio::test]
async fn autofill_extension_is_confined_to_its_narrow_command_set() {
    let f = unlocked().await;
    let gh = f
        .agent
        .with(|s| {
            Ok(add_item(
                s,
                "login",
                Some("GitHub"),
                &[
                    ("url", "https://github.com"),
                    ("username", "octocat"),
                    ("password", "secret-pw"),
                ],
            ))
        })
        .unwrap();

    let forbidden = [
        Command::ItemGet {
            vault: None,
            query: vec![gh.item.clone()],
            otp: false,
            ssh_private: false,
            files: Vec::new(),
            deleted: false,
        },
        Command::ItemList {
            vault: None,
            query: Vec::new(),
            kind: None,
            deleted: false,
            tags: Vec::new(),
            favorites: false,
        },
        Command::TagList { vault: None },
        Command::ItemRemove {
            vault: None,
            query: vec![gh.item.clone()],
        },
        Command::ItemRestore {
            vault: None,
            query: vec![gh.item],
        },
        Command::Lock,
        Command::Stop,
        Command::VaultList,
        Command::Unlock {
            passphrase: Zeroizing::new("test".into()),
            timeout_secs: Some(0),
        },
        Command::UnlockBiometric {
            timeout_secs: Some(0),
        },
    ];

    for cmd in forbidden {
        for socket in [SocketKind::AutoFill, SocketKind::Control] {
            let reply = send_on(
                &f.agent,
                socket,
                Some((CallerClass::AutoFill, "macOS AutoFill")),
                cmd.clone(),
            )
            .await;
            assert!(
                matches!(
                    reply,
                    Message::Error {
                        code: ErrorCode::Forbidden,
                        ..
                    }
                ),
                "{socket:?} {cmd:?} -> {reply:?}"
            );
        }
    }
}

#[tokio::test]
async fn identities_are_deterministic_and_never_contain_secrets() {
    let f = unlocked().await;
    let pw_secret = "hunter2-super-secret";
    f.agent
        .with(|s| {
            add_item(
                s,
                "login",
                Some("GitHub"),
                &[
                    ("url", "https://github.com/login"),
                    ("url-2", "https://gist.github.com"),
                    ("username", "octocat"),
                    ("password", pw_secret),
                    ("otp", OTP_SECRET),
                ],
            );
            // Sign-in-with-only login has no password, so no password identity.
            add_item(
                s,
                "login",
                Some("Notion"),
                &[("url", "https://notion.so"), ("sign-in-with", "google")],
            );
            add_item(s, "note", Some("Diary"), &[("notes", "private-note-body")]);
            let new = passkeys::check_create(
                s,
                "https://github.com",
                Some("github.com"),
                &webauthn::b64(&[7; 32]),
                &webauthn::b64(b"octocat"),
                "octocat",
                &[],
            )
            .unwrap();
            passkeys::create_passkey(s, &new, false, 1_798_000_000).unwrap();
            Ok(())
        })
        .unwrap();

    let status = send_on(
        &f.agent,
        SocketKind::AutoFill,
        Some((CallerClass::AutoFill, "macOS AutoFill")),
        Command::AutofillStatus,
    )
    .await;
    let Message::Ok {
        reply:
            Reply::AutofillStatus {
                unlocked: true,
                identities_hash: Some(status_hash),
                ..
            },
    } = status
    else {
        panic!("unexpected status: {status:?}");
    };

    let msg = send_on(
        &f.agent,
        SocketKind::AutoFill,
        Some((CallerClass::AutoFill, "macOS AutoFill")),
        Command::AutofillIdentities,
    )
    .await;
    let serialized = serde_json::to_string(&msg).unwrap();
    assert!(!serialized.contains(pw_secret), "{serialized}");
    assert!(!serialized.contains(OTP_SECRET), "{serialized}");
    assert!(!serialized.contains("private-note-body"), "{serialized}");
    assert!(
        !serialized.contains("GitHub"),
        "titles stay out of password identities"
    );

    let Message::Ok {
        reply:
            Reply::AutofillIdentities {
                identities_hash,
                passwords,
                passkeys,
                one_time_codes,
            },
    } = msg
    else {
        panic!("unexpected reply: {msg:?}");
    };
    assert_eq!(identities_hash, status_hash);
    assert_eq!(passwords.len(), 2);
    assert_eq!(passwords[0].domain, "gist.github.com");
    assert_eq!(passwords[1].domain, "github.com");
    assert!(passwords.iter().all(|p| p.username == "octocat"));
    assert_eq!(one_time_codes.len(), 2);
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].rp_id, "github.com");
    assert_eq!(passkeys[0].username, "octocat");
}

#[tokio::test]
async fn password_and_otp_fills_check_domains_unlock_with_touch_id_and_gate_unassociated_apps() {
    let f = unlocked().await;
    let (sub_login, apex_login) = f
        .agent
        .with(|s| {
            let apex = add_item(
                s,
                "login",
                Some("Apex"),
                &[
                    ("url", "https://example.com"),
                    ("username", "apex-user"),
                    ("password", "apex-pw"),
                    ("otp", OTP_SECRET),
                ],
            );
            let sub = add_item(
                s,
                "login",
                Some("Mobile"),
                &[
                    ("url", "https://m.example.com/login"),
                    ("username", "mobile-user"),
                    ("password", "mobile-pw"),
                ],
            );
            Ok((sub, apex))
        })
        .unwrap();

    let auto = Some((CallerClass::AutoFill, "macOS AutoFill"));

    // Ranking puts `m.example.com` ahead of `example.com` when the system
    // passes `[m.example.com, example.com]`.
    let listed = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillList {
            services: vec![
                AutofillService {
                    identifier: "m.example.com".into(),
                    kind: AutofillServiceKind::Domain,
                },
                AutofillService {
                    identifier: "example.com".into(),
                    kind: AutofillServiceKind::Domain,
                },
            ],
            rp_id: None,
            allowed_credentials: Vec::new(),
            for_otp: false,
        },
    )
    .await;
    let Message::Ok {
        reply:
            Reply::AutofillList {
                logins,
                unassociated: false,
                ..
            },
    } = listed
    else {
        panic!("unexpected list: {listed:?}");
    };
    assert_eq!(logins.len(), 2);
    assert_eq!(logins[0].login, sub_login);
    assert_eq!(logins[1].login, apex_login);

    // Domain mismatch and insecure HTTP URLs are refused.
    for bad_service in [
        AutofillService {
            identifier: "gitlab.com".into(),
            kind: AutofillServiceKind::Domain,
        },
        AutofillService {
            identifier: "http://example.com/login".into(),
            kind: AutofillServiceKind::Url,
        },
        AutofillService {
            identifier: "github.io".into(),
            kind: AutofillServiceKind::Domain,
        },
    ] {
        let refused = send_on(
            &f.agent,
            SocketKind::AutoFill,
            auto,
            Command::AutofillFill {
                service: Some(bad_service),
                login: apex_login.clone(),
                want: vec![Fill::Username, Fill::Password],
                interactive: false,
            },
        )
        .await;
        assert!(
            matches!(
                refused,
                Message::Error {
                    code: ErrorCode::DomainMismatch,
                    ..
                }
            ),
            "{refused:?}"
        );
    }

    // Silent fill while unlocked returns username, password and computed TOTP.
    let filled = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillFill {
            service: Some(AutofillService {
                identifier: "example.com".into(),
                kind: AutofillServiceKind::Domain,
            }),
            login: apex_login.clone(),
            want: vec![Fill::Username, Fill::Password, Fill::Totp],
            interactive: false,
        },
    )
    .await;
    let Message::Ok {
        reply: Reply::AutofillFill { values, .. },
    } = filled
    else {
        panic!("unexpected fill: {filled:?}");
    };
    assert_eq!(values.username.as_deref(), Some("apex-user"));
    assert_eq!(
        values.password.as_ref().map(Secret::expose),
        Some("apex-pw")
    );
    assert_eq!(values.totp.as_ref().map(|c| c.expose().len()), Some(6));

    // Unassociated app (`service: None`): refused silently, asks Touch ID when interactive.
    let silent_unassoc = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillFill {
            service: None,
            login: apex_login.clone(),
            want: vec![Fill::Password],
            interactive: false,
        },
    )
    .await;
    assert!(matches!(
        silent_unassoc,
        Message::Error {
            code: ErrorCode::InteractionRequired,
            ..
        }
    ));

    let taps = Arc::new(AtomicUsize::new(0));
    let (key, seen) = (f.key, taps.clone());
    *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(key))
    }));
    let confirmed_unassoc = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillFill {
            service: None,
            login: apex_login.clone(),
            want: vec![Fill::Password],
            interactive: true,
        },
    )
    .await;
    assert!(matches!(
        confirmed_unassoc,
        Message::Ok {
            reply: Reply::AutofillFill { .. }
        }
    ));
    assert_eq!(taps.load(Ordering::SeqCst), 1);

    // Lock the vault: silent fill gets `Locked` without prompting Touch ID,
    // and interactive fill unlocks via Touch ID and fills in one call.
    f.agent.lock().await;
    let locked_silent = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillFill {
            service: Some(AutofillService {
                identifier: "example.com".into(),
                kind: AutofillServiceKind::Domain,
            }),
            login: apex_login.clone(),
            want: vec![Fill::Password],
            interactive: false,
        },
    )
    .await;
    assert!(matches!(
        locked_silent,
        Message::Error {
            code: ErrorCode::Locked,
            ..
        }
    ));
    assert_eq!(taps.load(Ordering::SeqCst), 1, "silent mode never prompts");

    let unlocked_and_filled = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillFill {
            service: Some(AutofillService {
                identifier: "example.com".into(),
                kind: AutofillServiceKind::Domain,
            }),
            login: apex_login,
            want: vec![Fill::Password],
            interactive: true,
        },
    )
    .await;
    assert!(matches!(
        unlocked_and_filled,
        Message::Ok {
            reply: Reply::AutofillFill { .. }
        }
    ));
    assert_eq!(taps.load(Ordering::SeqCst), 2);
    assert!(f.agent.status().unlocked);
}

#[tokio::test]
async fn passkey_hash_ceremonies_verify_signatures_coalesce_locked_touch_id_and_cancel() {
    let f = unlocked().await;
    let auto = Some((CallerClass::AutoFill, "macOS AutoFill"));
    let taps = Arc::new(AtomicUsize::new(0));
    let (key, seen) = (f.key, taps.clone());
    *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(key))
    }));

    let reg_hash = webauthn::b64(&[0x11; 32]);
    let created = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillPasskeyCreate {
            rp_id: "example.com".into(),
            client_data_hash: reg_hash.clone(),
            user_id: webauthn::b64(b"alex"),
            user_name: "alex".into(),
            user_display_name: "Alex".into(),
            exclude: Vec::new(),
            verify: Verify::Required,
            interactive: true,
        },
    )
    .await;
    let Message::Ok {
        reply:
            Reply::AutofillPasskeyCreated {
                passkey,
                credential_id,
                client_data_hash,
                authenticator_data,
                public_key,
                verified: true,
                ..
            },
    } = created
    else {
        panic!("unexpected registration: {created:?}");
    };
    assert_eq!(client_data_hash, reg_hash);
    assert_eq!(webauthn::unb64(&authenticator_data).unwrap()[32], 0x5d);
    assert_eq!(taps.load(Ordering::SeqCst), 1);

    // Excluded credential fails with `Exists` before Touch ID is asked again.
    let excluded = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillPasskeyCreate {
            rp_id: "example.com".into(),
            client_data_hash: reg_hash,
            user_id: webauthn::b64(b"alex"),
            user_name: "alex".into(),
            user_display_name: String::new(),
            exclude: vec![credential_id.clone()],
            verify: Verify::Required,
            interactive: true,
        },
    )
    .await;
    assert!(matches!(
        excluded,
        Message::Error {
            code: ErrorCode::Exists,
            ..
        }
    ));
    assert_eq!(taps.load(Ordering::SeqCst), 1);

    // Unlocked silent assertion with `Required` asks for interactive UI (`InteractionRequired`).
    let assert_hash = webauthn::b64(&[0x22; 32]);
    let needs_ui = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillPasskeyGet {
            rp_id: "example.com".into(),
            passkey: passkey.clone(),
            client_data_hash: assert_hash.clone(),
            verify: Verify::Required,
            interactive: false,
        },
    )
    .await;
    assert!(matches!(
        needs_ui,
        Message::Error {
            code: ErrorCode::InteractionRequired,
            ..
        }
    ));

    // Unlocked silent assertion with `Discouraged` signs immediately with UV=0.
    let silent_discouraged = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillPasskeyGet {
            rp_id: "example.com".into(),
            passkey: passkey.clone(),
            client_data_hash: assert_hash.clone(),
            verify: Verify::Discouraged,
            interactive: false,
        },
    )
    .await;
    let Message::Ok {
        reply:
            Reply::AutofillPasskeyAssertion {
                authenticator_data: disc_auth,
                verified: false,
                ..
            },
    } = silent_discouraged
    else {
        panic!("unexpected assertion: {silent_discouraged:?}");
    };
    assert_eq!(webauthn::unb64(&disc_auth).unwrap()[32], 0x19);
    assert_eq!(taps.load(Ordering::SeqCst), 1);

    // Lock the vault: interactive `AutofillPasskeyGet` with `Required`
    // unlocks AND signs with `UV = 1` in ONE Touch ID tap.
    f.agent.lock().await;
    let single_tap = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillPasskeyGet {
            rp_id: "example.com".into(),
            passkey: passkey.clone(),
            client_data_hash: assert_hash.clone(),
            verify: Verify::Required,
            interactive: true,
        },
    )
    .await;
    let Message::Ok {
        reply:
            Reply::AutofillPasskeyAssertion {
                authenticator_data: auth_b64,
                signature: sig_b64,
                verified: true,
                ..
            },
    } = single_tap
    else {
        panic!("unexpected assertion: {single_tap:?}");
    };
    assert_eq!(
        taps.load(Ordering::SeqCst),
        2,
        "one tap unlocked and verified"
    );
    assert!(f.agent.status().unlocked);

    let auth_bytes = webauthn::unb64(&auth_b64).unwrap();
    assert_eq!(auth_bytes[32], 0x1d);
    let mut signed_bytes = auth_bytes;
    signed_bytes.extend_from_slice(&[0x22; 32]);
    let vk = VerifyingKey::from_public_key_der(&webauthn::unb64(&public_key).unwrap()).unwrap();
    let sig = Signature::from_der(&webauthn::unb64(&sig_b64).unwrap()).unwrap();
    assert!(vk.verify(&signed_bytes, &sig).is_ok());

    // Hanging up while locked and waiting on Touch ID cancels the prompt.
    f.agent.lock().await;
    let started = Arc::new(tokio::sync::Notify::new());
    let started_in_hook = started.clone();
    let cancelled = Arc::new(AtomicUsize::new(0));
    let seen_cancel = cancelled.clone();
    *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
        started_in_hook.notify_one();
        for _ in 0..400 {
            if cancel.is_cancelled() {
                seen_cancel.fetch_add(1, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(biometric::UnlockError::Cancelled)
    }));
    let (server, mut client) = UnixStream::pair().unwrap();
    mark_peer_as(&f.agent, &server, CallerClass::AutoFill, "macOS AutoFill");
    let mut raw = serde_json::to_vec(&Request {
        v: PROTOCOL_VERSION,
        claimed: None,
        command: Command::AutofillPasskeyGet {
            rp_id: "example.com".into(),
            passkey,
            client_data_hash: assert_hash,
            verify: Verify::Required,
            interactive: true,
        },
    })
    .unwrap();
    raw.push(b'\n');
    client.write_all(&raw).await.unwrap();
    let agent = f.agent.clone();
    let task = tokio::spawn(async move {
        drop(
            agent
                .handle_on(server, MAX_AUTOFILL_LINE, SocketKind::AutoFill)
                .await,
        );
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .expect("Touch ID hook should start");
    drop(client);
    task.await.unwrap();
    for _ in 0..100 {
        if cancelled.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn activity_records_fills_and_passkeys_without_values_and_skips_lookups() {
    let f = unlocked().await;
    let pw = "never-log-this-password";
    let gh = f
        .agent
        .with(|s| {
            Ok(add_item(
                s,
                "login",
                Some("GitHub"),
                &[
                    ("url", "https://github.com"),
                    ("username", "octocat"),
                    ("password", pw),
                ],
            ))
        })
        .unwrap();
    let auto = Some((CallerClass::AutoFill, "macOS AutoFill"));

    // Lookups record no Activity entries.
    for lookup in [
        Command::Status,
        Command::AutofillStatus,
        Command::AutofillIdentities,
        Command::AutofillList {
            services: vec![AutofillService {
                identifier: "github.com".into(),
                kind: AutofillServiceKind::Domain,
            }],
            rp_id: None,
            allowed_credentials: Vec::new(),
            for_otp: false,
        },
    ] {
        let reply = send_on(&f.agent, SocketKind::AutoFill, auto, lookup).await;
        assert!(matches!(reply, Message::Ok { .. }), "{reply:?}");
    }
    let Reply::Activity { entries } = f.agent.activity_list(None, None, None).unwrap() else {
        unreachable!()
    };
    assert!(
        entries.is_empty(),
        "lookups must not add entries: {entries:?}"
    );

    // Fill records who, where and which fields, never the password.
    let filled = send_on(
        &f.agent,
        SocketKind::AutoFill,
        auto,
        Command::AutofillFill {
            service: Some(AutofillService {
                identifier: "github.com".into(),
                kind: AutofillServiceKind::Domain,
            }),
            login: gh,
            want: vec![Fill::Username, Fill::Password],
            interactive: false,
        },
    )
    .await;
    assert!(matches!(filled, Message::Ok { .. }));

    let Reply::Activity { entries } = f.agent.activity_list(None, None, None).unwrap() else {
        unreachable!()
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].caller.label, "macOS AutoFill");
    assert_eq!(entries[0].command, "autofill-fill");
    assert_eq!(entries[0].fields, ["username", "password"]);
    assert_eq!(entries[0].outcome, Outcome::Allowed);
    let raw = serde_json::to_string(&entries).unwrap();
    assert!(!raw.contains(pw), "{raw}");
}
