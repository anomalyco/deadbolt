use super::*;
use crate::protocol::Message;

fn json(envelope: &Envelope) -> Value {
    let frame = encode(envelope).unwrap();
    let len = u32::from_ne_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(len, frame.len() - 4);
    serde_json::from_slice(&frame[4..]).unwrap()
}

#[test]
fn replies_have_the_documented_shapes() {
    let fill = Envelope {
        id: Some("3".into()),
        body: Body::Fill {
            values: SiteValues {
                username: Some("octocat".into()),
                password: Some(Secret::new("hunter2")),
                totp: None,
            },
        },
    };
    assert_eq!(
        json(&fill),
        serde_json::json!({"id": "3", "type": "fill", "username": "octocat", "password": "hunter2"})
    );
    let list = Envelope {
        id: Some(2.into()),
        body: Body::List {
            site: "github.com".into(),
            accounts: vec![
                Account {
                    login: "a:b".into(),
                    vault: "personal".into(),
                    title: "GitHub".into(),
                    username: None,
                    has_password: true,
                    has_totp: false,
                    urls: vec!["https://github.com".into()],
                    sign_in: None,
                },
                Account {
                    login: "a:c".into(),
                    vault: "personal".into(),
                    title: "GitHub".into(),
                    username: None,
                    has_password: false,
                    has_totp: false,
                    urls: vec!["https://github.com".into()],
                    sign_in: Some(SignIn {
                        provider: "google".into(),
                        account: Some("dax@example.com".into()),
                    }),
                },
            ],
        },
    };
    assert_eq!(
        json(&list),
        serde_json::json!({"id": 2, "type": "list", "site": "github.com", "accounts": [
            {"ref": "a:b", "vault": "personal", "title": "GitHub", "hasPassword": true,
             "hasTotp": false, "urls": ["https://github.com"]},
            {"ref": "a:c", "vault": "personal", "title": "GitHub", "hasPassword": false,
             "hasTotp": false, "urls": ["https://github.com"],
             "signIn": {"provider": "google", "account": "dax@example.com"}}
        ]})
    );
    let changed = Envelope {
        id: None,
        body: Body::Changed { change: "locked" },
    };
    assert_eq!(
        json(&changed),
        serde_json::json!({"type": "changed", "change": "locked"})
    );
    let error = refuse(Value::Null, Refusal::bad("nope"));
    assert_eq!(
        json(&error),
        serde_json::json!({"id": null, "type": "error", "code": "bad_request", "message": "nope"})
    );
    let check = Envelope {
        id: Some("4".into()),
        body: Body::Check {
            status: SiteStatus::Update,
            matches: vec!["a:b".into()],
        },
    };
    assert_eq!(
        json(&check),
        serde_json::json!({"id": "4", "type": "check", "status": "update", "matches": ["a:b"]})
    );
    let generate = Envelope {
        id: Some("5".into()),
        body: Body::Generate {
            password: Secret::new("Xk3!"),
            generated: "abc".into(),
        },
    };
    assert_eq!(
        json(&generate),
        serde_json::json!({"id": "5", "type": "generate", "password": "Xk3!", "generated": "abc"})
    );
}

#[test]
fn a_reply_over_the_browser_limit_becomes_an_error() {
    let big = Envelope {
        id: Some("1".into()),
        body: Body::List {
            site: "github.com".into(),
            accounts: (0..20_000)
                .map(|i| Account {
                    login: format!("{i:0>129}"),
                    vault: "personal".into(),
                    title: "GitHub".into(),
                    username: None,
                    has_password: true,
                    has_totp: false,
                    urls: vec![],
                    sign_in: None,
                })
                .collect(),
        },
    };
    let reply = json(&big);
    assert_eq!(reply["type"], "error");
    assert_eq!(reply["code"], "failed");
    assert_eq!(reply["id"], "1");
}

#[test]
fn frames_fit_their_buffers_exactly() {
    let fill = Envelope {
        id: Some("3".into()),
        body: Body::Fill {
            values: SiteValues {
                username: None,
                password: Some(Secret::new("p".repeat(1000))),
                totp: None,
            },
        },
    };
    let frame = encode(&fill).unwrap();
    assert_eq!(frame.capacity(), frame.len());
}

#[test]
fn buckets_allow_a_burst_then_one_per_interval() {
    let start = Instant::now();
    let second = Duration::from_secs(1);
    let mut bucket = Bucket::new((3, second), start);
    assert!((0..3).all(|_| bucket.take(start)));
    assert!(!bucket.take(start));
    assert!(!bucket.take(start + second / 2));
    assert!(bucket.take(start + second));
    assert!(!bucket.take(start + second * 3 / 2));
    // A long pause refills to the burst, no more.
    let later = start + second * 100;
    assert!((0..3).all(|_| bucket.take(later)));
    assert!(!bucket.take(later));
    // Partial intervals carry over.
    assert!(!bucket.take(later + second * 7 / 10));
    assert!(bucket.take(later + second * 14 / 10));
    assert!(!bucket.take(later + second * 19 / 10));
    assert!(bucket.take(later + second * 2));
}

/// A fake daemon at `paths`: each connection gets the next of `script`'s
/// lines and is closed, round and round if `cycle`, else holding the
/// last connection open.
fn fake_daemon(paths: &Paths, script: Vec<Vec<Message>>, cycle: bool) {
    let listener = tokio::net::UnixListener::bind(&paths.socket).unwrap();
    tokio::spawn(async move {
        let count = script.len();
        let mut held = Vec::new();
        for n in 0.. {
            if !cycle && n == count {
                break;
            }
            let (mut conn, _) = listener.accept().await.unwrap();
            for message in &script[n % count] {
                let line = deadbolt_client::encode_json(b"", message, b"\n").unwrap();
                conn.write_all(&line).await.ok();
            }
            if !cycle && n + 1 == count {
                held.push(conn);
            }
        }
        std::future::pending::<()>().await;
        drop(held);
    });
}

fn test_paths(dir: &std::path::Path) -> Paths {
    Paths {
        data: dir.join("data"),
        config: dir.join("config"),
        socket: dir.join("s"),
        lock: dir.join("lock"),
        log: dir.join("log"),
    }
}

async fn pushes(paths: Paths, announce: bool, run: Duration) -> (Vec<Value>, bool) {
    let (frames, mut outbox) = mpsc::channel(1024);
    let announce = Arc::new(AtomicBool::new(announce));
    let watcher = tokio::spawn(watch(
        paths,
        frames,
        announce.clone(),
        Duration::from_millis(10),
    ));
    tokio::time::sleep(run).await;
    watcher.abort();
    let mut pushed = Vec::new();
    while let Ok(frame) = outbox.try_recv() {
        let body: Value = serde_json::from_slice(&frame[4..]).unwrap();
        pushed.push(body["change"].clone());
    }
    (pushed, announce.load(Ordering::SeqCst))
}

/// A daemon that won't be watched (another protocol) or hangs up
/// before watching isn't one that stopped.
#[tokio::test]
async fn a_refused_watch_is_no_change() {
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    let refused = Message::Error {
        code: ErrorCode::Version,
        message: "the daemon speaks protocol 6".into(),
        grant: None,
        passkeys: None,
    };
    fake_daemon(&paths, vec![vec![refused], vec![]], true);
    let (pushed, announce) = pushes(paths, false, Duration::from_millis(300)).await;
    assert_eq!(pushed, Vec::<Value>::new());
    assert!(!announce);
}

#[tokio::test]
async fn a_daemon_that_goes_away_is_announced_when_back() {
    let watching = || Message::Change {
        change: Change::Watching,
    };
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    fake_daemon(
        &paths,
        vec![
            vec![
                watching(),
                Message::Change {
                    change: Change::Locked,
                },
            ],
            vec![watching()],
        ],
        false,
    );
    let (pushed, announce) = pushes(paths, false, Duration::from_millis(300)).await;
    assert_eq!(pushed, ["locked", "stopped", "started"]);
    assert!(!announce);

    // Armed by a hello that found no daemon.
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    fake_daemon(&paths, vec![vec![watching()]], false);
    let (pushed, _) = pushes(paths, true, Duration::from_millis(300)).await;
    assert_eq!(pushed, ["started"]);
}

#[test]
fn refs_are_a_vault_id_and_an_item_id() {
    let vault = "ab".repeat(32);
    let item = "cd".repeat(16);
    let login = parse_ref(&format!("{vault}:{item}")).ok().unwrap();
    assert_eq!(format_ref(&login), format!("{vault}:{item}"));
    for bad in [
        "",
        ":",
        &vault,
        &format!("{vault}:"),
        &format!("{vault}:{}", &item[2..]),
        &format!("{vault}:{vault}"),
        &format!("{item}:{vault}"),
        &format!("{}:{item}", vault.to_uppercase()),
        &format!("{vault}:{item}:{item}"),
    ] {
        assert!(parse_ref(bad).is_err(), "{bad:?}");
    }
}

/// A passkey ceremony waits on Touch ID beside other requests, and a
/// cancel stops it and answers it.
#[tokio::test]
async fn passkey_ceremonies_answer_when_done_and_can_be_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    // A daemon that takes the request and never answers.
    fake_daemon(&paths, vec![vec![]], false);
    let mut host = Host::new(paths);
    let (frames, mut outbox) = mpsc::channel(16);
    let get = serde_json::json!({
        "id": "p1", "type": "passkey-get", "origin": "https://example.com",
        "ref": format!("{}:{}", "ab".repeat(32), "cd".repeat(16)),
        "challenge": "AAAAAAAAAAAAAAAAAAAAAA", "userVerification": "preferred",
    });
    let body = serde_json::to_vec(&get).unwrap();
    assert!(
        host.answer(&body, &frames).await.is_none(),
        "answered later"
    );
    let again = host.answer(&body, &frames).await.unwrap();
    assert_eq!(json(&again)["code"], "bad_request", "one per id");

    let cancel = br#"{"id": 9, "type": "passkey-cancel", "request": "p1"}"#;
    let cancelled = host.answer(cancel, &frames).await.unwrap();
    assert_eq!(
        json(&cancelled),
        serde_json::json!({"id": 9, "type": "passkey-cancelled", "found": true})
    );
    let frame = outbox.recv().await.unwrap();
    let answer: Value = serde_json::from_slice(&frame[4..]).unwrap();
    assert_eq!(
        answer,
        serde_json::json!({"id": "p1", "type": "error", "code": "cancelled",
                           "message": "the passkey request was cancelled"})
    );
    let none = host.answer(cancel, &frames).await.unwrap();
    assert_eq!(json(&none)["found"], false);
    assert!(outbox.try_recv().is_err());
}

/// Learning lines go to their session's own log, in order, readable by
/// this user only, without a daemon; a session id that isn't a UUID
/// never becomes a path.
#[tokio::test]
async fn learn_lines_append_to_the_sessions_log() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    let mut host = Host::new(paths.clone());
    let (frames, _outbox) = mpsc::channel(16);
    let session = "0b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b";
    for seq in 1..=2 {
        let request = serde_json::json!({
            "id": seq, "type": "learn", "session": session,
            "line": {"event": "step", "seq": seq, "inputs": [{"type": "email"}]},
        });
        let reply = host
            .answer(&serde_json::to_vec(&request).unwrap(), &frames)
            .await
            .unwrap();
        assert_eq!(
            json(&reply),
            serde_json::json!({"id": seq, "type": "learned"})
        );
    }
    let log = paths.learn_dir().join(format!("{session}.jsonl"));
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["seq"], 2);
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&log), 0o600);
    assert_eq!(mode(&paths.learn_dir()), 0o700);

    for bad in [
        "../../etc/passwd",
        "0B5D3C1E-8F6A-4F3E-9A7B-1C2D3E4F5A6B",
        "",
    ] {
        let request = serde_json::json!({"id": 9, "type": "learn", "session": bad, "line": {}});
        let reply = host
            .answer(&serde_json::to_vec(&request).unwrap(), &frames)
            .await
            .unwrap();
        assert_eq!(json(&reply)["code"], "bad_request", "{bad:?}");
    }
    let line_not_object =
        br#"{"id": 10, "type": "learn", "session": "0b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b", "line": [1]}"#;
    let reply = host.answer(line_not_object, &frames).await.unwrap();
    assert_eq!(json(&reply)["code"], "bad_request");
    assert_eq!(std::fs::read_dir(paths.learn_dir()).unwrap().count(), 1);

    // The popup's Download reads it back, whole lines at a time, and Delete removes it.
    let ask = |request: Value| serde_json::to_vec(&request).unwrap();
    let read = host
        .answer(
            &ask(serde_json::json!({"id": 11, "type": "learn-read", "session": session})),
            &frames,
        )
        .await
        .unwrap();
    assert_eq!(
        json(&read),
        serde_json::json!({"id": 11, "type": "learn-text", "text": text, "next": null})
    );
    let big = serde_json::json!({"event": "timeline", "events": ["x".repeat(40 * 1024)]});
    for _ in 0..8 {
        assert!(learn(&paths, session, big.as_object().unwrap()).is_ok());
    }
    let (mut offset, mut whole) = (0u64, String::new());
    loop {
        let part = host
            .answer(&ask(serde_json::json!({"id": 12, "type": "learn-read", "session": session, "offset": offset})), &frames)
            .await
            .unwrap();
        let part = json(&part);
        let chunk = part["text"].as_str().unwrap();
        assert!(chunk.ends_with('\n') && chunk.len() as u64 <= LEARN_READ);
        whole.push_str(chunk);
        match part["next"].as_u64() {
            Some(next) => offset = next,
            None => break,
        }
    }
    assert!(offset > 0);
    assert_eq!(whole, std::fs::read_to_string(&log).unwrap());
    for (id, found) in [(13, true), (14, false)] {
        let reply = host
            .answer(
                &ask(serde_json::json!({"id": id, "type": "learn-delete", "session": session})),
                &frames,
            )
            .await
            .unwrap();
        assert_eq!(
            json(&reply),
            serde_json::json!({"id": id, "type": "learn-deleted", "found": found})
        );
    }
    assert!(!log.exists());
    let gone = host
        .answer(
            &ask(serde_json::json!({"id": 15, "type": "learn-read", "session": session})),
            &frames,
        )
        .await
        .unwrap();
    assert_eq!(json(&gone)["code"], "not_found");
    let escape = host
        .answer(&ask(serde_json::json!({"id": 16, "type": "learn-delete", "session": "../../etc/passwd"})), &frames)
        .await
        .unwrap();
    assert_eq!(json(&escape)["code"], "bad_request");
}

/// A new session's log prunes logs past 30 days and beyond the newest 50,
/// oldest first, and leaves the session already being written alone; the
/// directory is tightened to 0700 even when it was there.
#[tokio::test]
async fn learn_logs_are_pruned_when_a_session_starts() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    let learn = paths.learn_dir();
    std::fs::create_dir_all(&learn).unwrap();
    std::fs::set_permissions(&learn, std::fs::Permissions::from_mode(0o755)).unwrap();
    let now = std::time::UNIX_EPOCH + Duration::from_secs(crate::config::now());
    let day = Duration::from_secs(24 * 60 * 60);
    let log = |i: u32| learn.join(format!("{i:08x}-0000-4000-8000-000000000000.jsonl"));
    // 12 logs, log(i) i days old, plus something that isn't a log.
    for i in 0..12 {
        let file = std::fs::File::create(log(i)).unwrap();
        file.set_modified(now - day * i - Duration::from_secs(60))
            .unwrap();
    }
    std::fs::write(learn.join("notes.txt"), "kept").unwrap();

    let mut host = Host::new(paths.clone());
    let (frames, _outbox) = mpsc::channel(16);
    let mut send = async |session: String| {
        let request = serde_json::json!({"id": 1, "type": "learn", "session": session, "line": {"event": "start"}});
        let reply = host
            .answer(&serde_json::to_vec(&request).unwrap(), &frames)
            .await
            .unwrap();
        assert_eq!(json(&reply)["type"], "learned");
    };
    // An ongoing session prunes nothing.
    send(log(9).file_stem().unwrap().to_str().unwrap().to_owned()).await;
    assert!(log(11).exists());
    let fresh = "0b5d3c1e-8f6a-4f3e-9a7b-1c2d3e4f5a6b";
    send(fresh.to_owned()).await;

    let mode = std::fs::metadata(&learn).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    // Past 7 days: gone, though 10 weren't reached.
    let kept: Vec<u32> = (0..12).filter(|i| log(*i).exists()).collect();
    assert_eq!(kept, (0..7).chain([9]).collect::<Vec<_>>());
    assert!(learn.join(format!("{fresh}.jsonl")).exists());
    assert!(learn.join("notes.txt").exists());

    // Then at most 10, oldest first: 9 more recent ones push out the 7
    // left from before and the two oldest of them.
    let recent = |i: u32| learn.join(format!("{i:08x}-1111-4000-8000-000000000000.jsonl"));
    for i in 0..9u32 {
        let file = std::fs::File::create(recent(i)).unwrap();
        file.set_modified(now - Duration::from_secs(u64::from(9 - i)))
            .unwrap();
    }
    send("ffffffff-2222-4000-8000-000000000000".to_owned()).await;
    let logs = std::fs::read_dir(&learn)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "jsonl")
        })
        .count();
    assert_eq!(logs, MAX_LEARN_LOGS);
    assert!((0..12).all(|i| i == 9 || !log(i).exists()));
    assert!(!recent(0).exists() && !recent(1).exists() && recent(2).exists());
    assert!(log(9).exists() && learn.join(format!("{fresh}.jsonl")).exists());
}

fn framed(request: Value) -> Vec<u8> {
    let body = serde_json::to_vec(&request).unwrap();
    let mut frame = u32::try_from(body.len()).unwrap().to_ne_bytes().to_vec();
    frame.extend(body);
    frame
}

/// A page flooding passkey calls keeps the daemon busy listing; another
/// tab's cancel is still answered at once.
#[tokio::test]
async fn a_cancel_is_not_stuck_behind_listing() {
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    // A daemon that takes every request and never answers.
    let listener = tokio::net::UnixListener::bind(&paths.socket).unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            held.push(conn);
        }
    });
    let mut host = Host::new(paths);
    let (frames, mut outbox) = mpsc::channel(16);
    let (mut browser, input) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(async move { host.serve(input, &frames).await });

    let get = serde_json::json!({
        "id": "p1", "type": "passkey-get", "origin": "https://example.com",
        "ref": format!("{}:{}", "ab".repeat(32), "cd".repeat(16)),
        "challenge": "AAAAAAAAAAAAAAAAAAAAAA", "userVerification": "preferred",
    });
    browser.write_all(&framed(get)).await.unwrap();
    for n in 0..5 {
        let list =
            serde_json::json!({"id": n, "type": "passkey-list", "origin": "https://flood.example"});
        browser.write_all(&framed(list)).await.unwrap();
    }
    let cancel = serde_json::json!({"id": "c1", "type": "passkey-cancel", "request": "p1"});
    browser.write_all(&framed(cancel)).await.unwrap();

    let mut answers = Vec::new();
    for _ in 0..2 {
        let frame = tokio::time::timeout(Duration::from_secs(5), outbox.recv())
            .await
            .expect("the cancel is answered while listing waits")
            .unwrap();
        answers.push(serde_json::from_slice::<Value>(&frame[4..]).unwrap());
    }
    answers.sort_by_key(|a| a["id"].to_string());
    assert_eq!(answers[0]["type"], "passkey-cancelled");
    assert_eq!(answers[0]["found"], true);
    assert_eq!(answers[1]["code"], "cancelled");
    assert!(outbox.try_recv().is_err(), "the lists still wait");
    serving.abort();
}

/// `forms` lists metadata in the documented shape, and `fill-form`
/// passes on only well-formed requests and hands back the values.
#[tokio::test]
async fn forms_and_fill_form_have_the_documented_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    let vault = "ab".repeat(32);
    let at = |item: &str| LoginRef {
        vault: vault.clone(),
        item: item.repeat(16),
    };
    let items = Message::Ok {
        reply: Reply::FormItems {
            identities: vec![FormIdentity {
                item: at("cd"),
                vault: "personal".into(),
                title: "Home".into(),
                summary: "Kit Langton · 123 Main St, Brooklyn".into(),
                fields: vec!["given-name".into(), "city".into()],
            }],
            cards: vec![FormCard {
                item: at("ef"),
                vault: "personal".into(),
                title: "Visa •••• 4242".into(),
                brand: Some("Visa".into()),
                last4: "4242".into(),
                expiry: Some("2028-08".into()),
                cardholder: None,
                billing: Some(at("cd")),
                fields: vec!["number".into(), "expiry".into()],
            }],
            can_verify: true,
        },
    };
    let filled = Message::Ok {
        reply: Reply::FormFill {
            kind: "card".into(),
            title: "Visa •••• 4242".into(),
            values: [("number".to_string(), Secret::new("4242424242424242"))].into(),
            verified: true,
        },
    };
    fake_daemon(&paths, vec![vec![items], vec![filled]], false);
    let mut host = Host::new(paths);
    let (frames, _outbox) = mpsc::channel(16);
    let mut ask = async |request: Value| {
        let body = serde_json::to_vec(&request).unwrap();
        json(&host.answer(&body, &frames).await.unwrap())
    };
    let origin = "https://shop.example.com";
    let home = format!("{vault}:{}", "cd".repeat(16));
    let visa = format!("{vault}:{}", "ef".repeat(16));
    assert_eq!(
        ask(
            serde_json::json!({"id": 1, "type": "forms", "origin": origin,
                               "kinds": ["card", "identity", "card"]})
        )
        .await,
        serde_json::json!({"id": 1, "type": "forms", "canVerify": true,
            "identities": [{"ref": home, "vault": "personal", "title": "Home",
                "summary": "Kit Langton · 123 Main St, Brooklyn",
                "fields": ["given-name", "city"]}],
            "cards": [{"ref": visa, "vault": "personal", "title": "Visa •••• 4242",
                "brand": "Visa", "last4": "4242", "expiry": "2028-08", "billing": home,
                "fields": ["number", "expiry"]}]})
    );
    // Refused before the daemon hears of them.
    for bad in [
        serde_json::json!({"id": 2, "type": "forms", "origin": origin, "kinds": []}),
        serde_json::json!({"id": 2, "type": "forms", "origin": origin, "kinds": ["login"]}),
        serde_json::json!({"id": 2, "type": "forms", "origin": "null", "kinds": ["card"]}),
        serde_json::json!({"id": 2, "type": "forms", "origin": "http://shop.example.com", "kinds": ["card"]}),
        serde_json::json!({"id": 2, "type": "fill-form", "origin": origin, "ref": visa, "fields": []}),
        serde_json::json!({"id": 2, "type": "fill-form", "origin": origin, "ref": visa, "fields": ["pin"]}),
        serde_json::json!({"id": 2, "type": "fill-form", "origin": origin, "ref": visa, "fields": ["passport"]}),
        serde_json::json!({"id": 2, "type": "fill-form", "origin": origin, "ref": "x", "fields": ["number"]}),
    ] {
        assert_eq!(ask(bad.clone()).await["code"], "bad_request", "{bad}");
    }
    assert_eq!(
        ask(
            serde_json::json!({"id": 3, "type": "fill-form", "origin": origin,
                               "ref": visa, "fields": ["number", "number"]})
        )
        .await,
        serde_json::json!({"id": 3, "type": "fill-form", "verified": true,
                           "values": {"number": "4242424242424242"}})
    );
}

/// `save-form` creates an item through `item-new` or changes one listed
/// for forms through `item-set`, with the form fields normalized and
/// never a security code; anything else is refused before the daemon
/// hears of it.
#[tokio::test]
async fn save_form_creates_or_changes_an_identity_or_card() {
    use tokio::io::AsyncBufReadExt;
    let dir = tempfile::tempdir().unwrap();
    let paths = test_paths(dir.path());
    let vault = "ab".repeat(32);
    let new_card = "ef".repeat(16);
    let listing = || Message::Ok {
        reply: Reply::FormItems {
            identities: Vec::new(),
            cards: vec![FormCard {
                item: LoginRef {
                    vault: vault.clone(),
                    item: new_card.clone(),
                },
                vault: "personal".into(),
                title: "Visa •••• 4242".into(),
                brand: Some("Visa".into()),
                last4: "4242".into(),
                expiry: Some("2028-08".into()),
                cardholder: None,
                billing: None,
                fields: vec!["number".into(), "expiry".into()],
            }],
            can_verify: true,
        },
    };
    let item = || Message::Ok {
        reply: Reply::Item {
            item: crate::protocol::ItemInfo {
                id: new_card.clone(),
                short: new_card[..4].into(),
                kind: "card".into(),
                label: "Visa •••• 4242".into(),
                detail: None,
                fields: Vec::new(),
                source: None,
                favorite: false,
                tags: Vec::new(),
                deleted_at: None,
            },
        },
    };
    // Answers each connection with the next reply, and keeps what it was asked.
    let script = vec![item(), listing(), listing(), item()];
    let asked = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let listener = tokio::net::UnixListener::bind(&paths.socket).unwrap();
    let kept = asked.clone();
    tokio::spawn(async move {
        for reply in script {
            let (conn, _) = listener.accept().await.unwrap();
            let (read, mut write) = conn.into_split();
            let mut line = String::new();
            tokio::io::BufReader::new(read)
                .read_line(&mut line)
                .await
                .unwrap();
            kept.lock()
                .unwrap()
                .push(serde_json::from_str(&line).unwrap());
            let reply = deadbolt_client::encode_json(b"", &reply, b"\n").unwrap();
            write.write_all(&reply).await.ok();
        }
    });
    let mut host = Host::new(paths);
    let (frames, _outbox) = mpsc::channel(16);
    let mut ask = async |request: Value| {
        let body = serde_json::to_vec(&request).unwrap();
        json(&host.answer(&body, &frames).await.unwrap())
    };
    let origin = "https://shop.example.com";
    let visa = format!("{vault}:{new_card}");
    for bad in [
        serde_json::json!({"id": 1, "type": "save-form", "origin": origin, "kind": "card",
                           "fields": {"number": "4242424242424242", "cvv": "123"}}),
        serde_json::json!({"id": 1, "type": "save-form", "origin": origin, "kind": "card",
                           "fields": {"number": "4242424242424242", "pin": "1234"}}),
        serde_json::json!({"id": 1, "type": "save-form", "origin": origin, "kind": "card",
                           "fields": {"expiry": "2028-08"}}),
        serde_json::json!({"id": 1, "type": "save-form", "origin": origin, "kind": "login",
                           "fields": {"username": "kit"}}),
        serde_json::json!({"id": 1, "type": "save-form", "origin": origin, "kind": "card", "ref": visa,
                           "fields": {"number": "4242424242424242"}}),
        serde_json::json!({"id": 1, "type": "save-form", "origin": origin, "kind": "identity", "ref": "x",
                           "fields": {"given-name": "Kit"}}),
        serde_json::json!({"id": 1, "type": "save-form", "origin": "null", "kind": "identity",
                           "fields": {"given-name": "Kit"}}),
    ] {
        assert_eq!(ask(bad.clone()).await["code"], "bad_request", "{bad}");
    }
    assert!(asked.lock().unwrap().is_empty());
    assert_eq!(
        ask(serde_json::json!({"id": 2, "type": "save-form", "origin": origin, "kind": "card",
            "fields": {"number": "4242 4242 4242 4242", "expiry": "08/28", "cardholder": "Kit Langton"}}))
        .await,
        serde_json::json!({"id": 2, "type": "save-form", "ref": visa, "created": true})
    );
    assert_eq!(
        ask(
            serde_json::json!({"id": 3, "type": "save-form", "origin": origin, "kind": "card",
            "ref": visa, "fields": {"expiry": "2030-09"}})
        )
        .await,
        serde_json::json!({"id": 3, "type": "save-form", "ref": visa, "created": false})
    );
    let asked = asked.lock().unwrap();
    let commands: Vec<&str> = asked.iter().map(|r| r["cmd"].as_str().unwrap()).collect();
    assert_eq!(
        commands,
        ["item-new", "form-items", "form-items", "item-set"]
    );
    assert_eq!(asked[0]["kind"], "card");
    assert_eq!(
        asked[0]["fields"],
        serde_json::json!([
            {"name": "cardholder", "kind": null, "value": "Kit Langton"},
            {"name": "expiry", "kind": null, "value": "2028-08"},
            {"name": "number", "kind": null, "value": "4242424242424242"},
        ])
    );
    assert_eq!(asked[3]["vault"], vault);
    assert_eq!(asked[3]["query"], serde_json::json!([new_card]));
    assert_eq!(
        asked[3]["fields"],
        serde_json::json!([{"name": "expiry", "kind": null, "value": "2030-09"}])
    );
}

/// Listing comes before anyone is asked, so it's limited like checks.
#[tokio::test]
async fn passkey_lists_are_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    // No daemon: each list that gets through says so.
    let mut host = Host::new(test_paths(dir.path()));
    let (frames, _outbox) = mpsc::channel(16);
    let list = br#"{"id": 1, "type": "passkey-list", "origin": "https://example.com"}"#;
    for _ in 0..passkeys::LISTS.0 {
        let answer = host.answer(list, &frames).await.unwrap();
        assert_eq!(json(&answer)["code"], "locked");
    }
    let answer = host.answer(list, &frames).await.unwrap();
    assert_eq!(json(&answer)["code"], "rate_limited");
}
