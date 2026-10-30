use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

fn human_health(device: &Device, args: &[&str]) -> String {
    let (ok, out, err) = detached(device, args, "");
    assert!(ok, "deadbolt {args:?} failed: {err}");
    out
}

#[test]
fn offline_health_flags_risks_skips_pins_syncs_ignores_and_refuses_ai() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);

    // Card with a 4-digit PIN: must never flag weak/reused.
    a.run(&[
        "new",
        "card",
        "--name",
        "Travel Visa",
        "number=4242424242424242",
        "pin=1234",
    ]);
    // Weak login on GitHub (also supports 2FA and passkeys).
    a.run(&[
        "new",
        "login",
        "--name",
        "GitHub",
        "url=https://github.com",
        "username=alex",
        "password=password",
    ]);
    // Two distinct accounts sharing one strong password -> reused.
    let shared = "Vq7#mRz2!pKx9@wLt4&nBe8";
    a.run(&[
        "new",
        "login",
        "--name",
        "Linear",
        "url=https://linear.app",
        "username=alex",
        &format!("password={shared}"),
    ]);
    a.run(&[
        "new",
        "database",
        "--name",
        "Staging DB",
        &format!("password={shared}"),
    ]);

    let text_out = human_health(&a, &["health"]);
    assert!(text_out.contains("2 reused, 1 weak"), "{text_out}");
    assert!(!text_out.contains("Travel Visa"), "{text_out}");
    assert!(!text_out.contains(shared), "never leak secrets");

    let json_out = human_health(&a, &["health", "--all", "--json"]);
    assert!(!json_out.contains(shared));
    let report: deadbolt_client::protocol::HealthReport = serde_json::from_str(&json_out).unwrap();
    assert_eq!(report.counts.risk_items, 3);
    assert_eq!(report.counts.weak, 1);
    assert_eq!(report.counts.reused, 2);
    assert_eq!(report.counts.missing_two_factor, 1);
    assert_eq!(report.counts.passkeys_available, 1);

    // AI callers (`OPENCODE_SESSION_ID`) are refused with exit code 4.
    let mut ai = a.cmd(&["health"]);
    ai.env("OPENCODE_SESSION_ID", "ses_test_123");
    let refused = a.output(&mut ai);
    assert_eq!(refused.status.code(), Some(4));

    // Ignore Weak on GitHub and sync to peer device `b`: `b` sees the ignore,
    // and changing GitHub's password on `b` lapses the ignore automatically.
    human_health(&a, &["health", "ignore", "GitHub", "weak"]);
    let b = Device::new();
    pair(&a, &b, "beta", None);
    eventually("b to receive synced health ignore", || {
        b.run(&["sync"]);
        let out = human_health(&b, &["health", "--json"]);
        let r: deadbolt_client::protocol::HealthReport = serde_json::from_str(&out).unwrap();
        r.counts.weak == 0 && r.counts.ignored == 1
    });

    b.run(&["set", "GitHub", "password=monkey123"]);
    let after = human_health(&b, &["health", "--json"]);
    let r: deadbolt_client::protocol::HealthReport = serde_json::from_str(&after).unwrap();
    assert_eq!(r.counts.weak, 1, "ignore lapsed on password change");
}

#[test]
fn hibp_range_checks_are_opt_in_padded_deduplicated_and_cached() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let range_hits = Arc::new(AtomicUsize::new(0));
    let hits_server = range_hits.clone();

    let server = std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut req_line = String::new();
            if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                continue;
            }
            if req_line.starts_with("GET /quit ") {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                break;
            }
            let mut padded = false;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                    break;
                }
                let lower = header.to_ascii_lowercase();
                if lower.starts_with("add-padding:") && lower.contains("true") {
                    padded = true;
                }
            }
            if req_line.starts_with("GET /breaches ") {
                let body = b"[]";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body);
                continue;
            }
            assert!(padded, "missing Add-Padding: true header on {req_line}");
            hits_server.fetch_add(1, Ordering::SeqCst);
            // SHA-1("password") = 5BAA6 + 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
            // Include `:0` padding entries to verify they are discarded.
            let body = if req_line.starts_with("GET /range/5BAA6 ") {
                "00000000000000000000000000000000000:0\r\n\
                 1E4C9B93F3F0682250B6CF8331B7EE68FD8:98765\r\n\
                 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"
            } else {
                "00000000000000000000000000000000000:0\r\n"
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });

    let hibp_url = format!("http://{addr}");
    let d = Device::new();
    let mut init = d.cmd(&["init", "--device-name", "alpha"]);
    init.env("DEADBOLT_HIBP_URL", &hibp_url);
    assert!(d.output(&mut init).status.success());

    // Two logins with the exact same leaked password ("password") -> deduplicated to 1 range GET!
    d.run(&[
        "new",
        "login",
        "--name",
        "Forum A",
        "username=a",
        "password=password",
    ]);
    d.run(&[
        "new",
        "login",
        "--name",
        "Forum B",
        "username=b",
        "password=password",
    ]);

    // Default (`breach_checks = false`): zero HTTP requests!
    let offline = human_health(&d, &["health", "--json"]);
    let rep: deadbolt_client::protocol::HealthReport = serde_json::from_str(&offline).unwrap();
    assert_eq!(rep.counts.breached, 0);
    assert_eq!(range_hits.load(Ordering::SeqCst), 0);

    // Explicit `--online`: 1 deduplicated range request, both items flagged Breached (98,765).
    let online = human_health(&d, &["health", "--online", "--json"]);
    let rep: deadbolt_client::protocol::HealthReport = serde_json::from_str(&online).unwrap();
    assert_eq!(rep.counts.breached, 2);
    assert_eq!(range_hits.load(Ordering::SeqCst), 1);

    // Lock, unlock, and `--online` again: cached in encrypted `store.redb` -> 0 extra range hits!
    d.run(&["lock"]);
    d.run(&["unlock"]);
    let cached = human_health(&d, &["health", "--online", "--json"]);
    let rep2: deadbolt_client::protocol::HealthReport = serde_json::from_str(&cached).unwrap();
    assert_eq!(rep2.counts.breached, 2);
    assert_eq!(range_hits.load(Ordering::SeqCst), 1);

    // Shut down local server cleanly.
    if let Ok(mut s) = std::net::TcpStream::connect(addr) {
        let _ = s.write_all(b"GET /quit HTTP/1.1\r\nHost: localhost\r\n\r\n");
    }
    let _ = server.join();
}
