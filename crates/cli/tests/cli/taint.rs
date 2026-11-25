//! `deadbolt run` taints its command: the command and everything it
//! starts get nothing from the daemon, found by their real ancestry, while
//! every other caller is served as before (`daemon/taint.rs`).

use super::*;

#[test]
fn a_run_and_everything_it_starts_get_nothing_from_the_daemon() {
    let a = Device::new();
    a.run(&["init"]);
    new(
        &a,
        &["login", "--name", "GitHub", &format!("token={TOKEN}")],
    );
    let read = ["read", "deadbolt://GitHub/token"];
    assert_eq!(a.run(&read).trim(), TOKEN);

    // The command, and a shell it starts, ask the same daemon for the
    // item, the reference and the list; each is refused. Status still
    // answers, so a client can tell which daemon it reached.
    let script = format!(
        r#"
        "{BIN}" get GitHub; echo "child=$?"
        sh -c '"{BIN}" read deadbolt://GitHub/token; echo "grandchild=$?"'
        sh -c 'sh -c "\"{BIN}\" ls; echo deep=\$?"'
        "{BIN}" lock; echo "lock=$?"
        "{BIN}" debug daemon status >/dev/null; echo "status=$?"
        "#
    );
    let (code, out, err) = piped_code(
        &a,
        &[
            "run",
            "--env",
            "T=deadbolt://GitHub/token",
            "--",
            "sh",
            "-c",
            &script,
        ],
        "",
    );
    assert_eq!(code, 0, "{err}");
    for denied in ["child", "grandchild", "deep", "lock"] {
        assert!(
            out.contains(&format!("{denied}=")) && !out.contains(&format!("{denied}=0")),
            "{denied}: {out}"
        );
    }
    assert!(out.contains("status=0"), "{out}");
    assert!(!out.contains(TOKEN) && !err.contains(TOKEN), "{out}{err}");
    assert_eq!(
        err.matches("process is running inside deadbolt run")
            .count(),
        4,
        "{err}"
    );

    // Once the run is over, the same caller is served again: nothing
    // lingers, and the daemon stayed unlocked.
    assert_eq!(a.run(&read).trim(), TOKEN);
    assert_eq!(a.state(), "unlocked");
}

#[test]
fn a_run_leaves_every_other_caller_alone() {
    let a = Device::new();
    a.run(&["init"]);
    new(
        &a,
        &["login", "--name", "GitHub", &format!("token={TOKEN}")],
    );
    let (ready, go) = (a.path("ready"), a.path("go"));
    // The command holds the run open until the test says go.
    let script = format!(
        "touch '{}'; while [ ! -e '{}' ]; do sleep 0.05; done",
        ready.display(),
        go.display()
    );
    let mut run = a
        .cmd(&[
            "run",
            "--env",
            "T=deadbolt://GitHub/token",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    eventually("the run to start", || ready.exists());
    // A process outside the run, started after it, reads as before.
    assert_eq!(a.run(&["read", "deadbolt://GitHub/token"]).trim(), TOKEN);
    assert!(a.run(&["ls"]).contains("GitHub"));
    std::fs::write(&go, "").unwrap();
    assert!(wait(&mut run, Duration::from_secs(30)).success());
}
