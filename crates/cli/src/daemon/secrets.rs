//! `resolve` for commands (`docs/secrets.md`): which callers may, and in
//! what form a value may leave ([`deadbolt_engine::secrets`] finds them).

use anyhow::{Result, anyhow, bail};
use deadbolt_engine::secrets::{find, named, reference_of};

use super::{Daemon, ErrorCode, fail};
use crate::protocol::{CallerClass, CallerInfo, Purpose, Reference, Reply};

/// The most references one `resolve` names.
const MAX_REFS: usize = 256;

impl Daemon {
    /// Answers `resolve`: the values `refs` name, for `purpose`.
    pub(super) fn resolve(
        &self,
        caller: &CallerInfo,
        refs: &[String],
        purpose: Purpose,
    ) -> Result<Reply> {
        if refs.is_empty() {
            bail!("name at least one reference");
        }
        if refs.len() > MAX_REFS {
            bail!("at most {MAX_REFS} references at once");
        }
        let parsed = refs
            .iter()
            .map(|r| Reference::parse(r).map_err(|e| anyhow!(e)))
            .collect::<Result<Vec<Reference>>>()?;
        if matches!(
            caller.class,
            CallerClass::BrowserHost | CallerClass::AutoFill
        ) {
            return Err(fail(
                ErrorCode::Forbidden,
                "this caller doesn't resolve references",
            ));
        }
        let found = self.with(|s| {
            let now = crate::config::wall_clock();
            parsed
                .iter()
                .map(|r| find(s, r, now))
                .collect::<Result<Vec<_>>>()
        })?;
        // A file goes only into a file `inject` writes; an environment
        // variable or a printed value is text.
        if purpose != Purpose::Inject
            && let Some(file) = found.iter().find(|f| f.file)
        {
            let use_ = if purpose == Purpose::Run {
                "`deadbolt run` puts values in the environment, which can't hold a file"
            } else {
                "`deadbolt read` (and `inject` to stdout) print text"
            };
            return Err(fail(
                ErrorCode::Failed,
                format!(
                    "{} is a file: {use_}. Write it out with `deadbolt inject -o FILE` from a template that is only {{{{ {} }}}}, or `deadbolt get -o FILE`",
                    named(file),
                    reference_of(file)
                ),
            ));
        }
        Ok(Reply::Secrets { secrets: found })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use deadbolt_core::totp::Totp;

    use super::super::caller;
    use super::super::session::Loaded;
    use crate::client::DaemonError;
    use crate::protocol::{Command, FieldInput};

    const NOW: u64 = 1_800_000_000;
    const OTP: &str = "JBSWY3DPEHPK3PXP";

    fn loaded(dir: &std::path::Path) -> Loaded {
        let params = deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let mut loaded = Loaded::setup(dir, b"test", "test", params).unwrap();
        loaded.create_vault("personal").unwrap();
        loaded
    }

    fn new(s: &mut Loaded, kind: &str, name: &str, fields: &[(&str, &str)]) -> String {
        let inputs = fields
            .iter()
            .map(|(name, value)| FieldInput {
                name: (*name).into(),
                kind: None,
                value: (*value).into(),
            })
            .collect();
        super::super::items::create(s, None, kind, Some(name.into()), inputs)
            .unwrap()
            .id
    }

    fn r(text: &str) -> Reference {
        Reference::parse(text).unwrap()
    }

    fn code(error: &anyhow::Error) -> Option<ErrorCode> {
        error.downcast_ref::<DaemonError>().map(|e| e.code)
    }

    #[test]
    fn references_find_one_item_by_title_or_short_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let github = new(
            &mut s,
            "login",
            "GitHub",
            &[("password", "hunter2"), ("token", "ghp_1"), ("otp", OTP)],
        );
        let at = Duration::from_secs(NOW);
        let found = find(&s, &r("deadbolt://personal/github/token"), at).unwrap();
        assert_eq!(found.value.expose(), "ghp_1");
        assert_eq!(
            (found.vault.as_str(), found.title.as_str()),
            ("personal", "GitHub")
        );
        assert_eq!(found.item, github);
        let by_id = format!("deadbolt://{}/password", &github[..6]);
        assert_eq!(find(&s, &r(&by_id), at).unwrap().value.expose(), "hunter2");
        // A one-time password gives its current code.
        let otp = find(&s, &r("deadbolt://GitHub/otp"), at).unwrap();
        let expected = Totp::parse(OTP).unwrap().code(NOW);
        assert_eq!(otp.value.expose(), expected);

        // A missing field lists the field names, never values.
        let error = find(&s, &r("deadbolt://GitHub/tokn"), at).err().unwrap();
        assert_eq!(code(&error), Some(ErrorCode::NotFound));
        let message = error.to_string();
        assert!(message.contains("otp, password, token"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
        // Search words aren't titles: "Git" names nothing.
        assert_eq!(
            code(&find(&s, &r("deadbolt://Git/token"), at).err().unwrap()),
            Some(ErrorCode::NotFound)
        );
        assert!(find(&s, &r("deadbolt://work/GitHub/token"), at).is_err());

        // Two items with one title: an error listing both by short id.
        let other = new(&mut s, "login", "GitHub", &[("password", "other")]);
        let error = find(&s, &r("deadbolt://GitHub/password"), at)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("names 2 items"), "{error}");
        assert!(
            error.contains(&github[..4]) && error.contains(&other[..4]),
            "{error}"
        );
        assert!(!error.contains("hunter2"), "{error}");
    }

    /// Any caller gets what it names while unlocked, whoever it is, for
    /// every purpose; only the browser host and
    /// macOS AutoFill, which never resolve references, are refused.
    #[tokio::test]
    async fn any_caller_resolves_while_unlocked() {
        let f = super::super::passkeys::tests::daemon::unlocked().await;
        f.daemon
            .with(|s| {
                new(s, "login", "GitHub", &[("token", "t0k3n")]);
                Ok(())
            })
            .unwrap();
        let refs = ["deadbolt://GitHub/token".to_string()];
        let callers = [
            CallerInfo::unverified("incomplete parent chain"),
            CallerInfo {
                identified: true,
                ..CallerInfo::unverified("zsh › deadbolt")
            },
        ];
        for caller in &callers {
            for purpose in [Purpose::Run, Purpose::Inject, Purpose::Read] {
                for _ in 0..30 {
                    let Reply::Secrets { secrets } =
                        f.daemon.resolve(caller, &refs, purpose).unwrap()
                    else {
                        panic!("expected secrets");
                    };
                    assert_eq!(secrets[0].value.expose(), "t0k3n");
                }
            }
        }
        for class in [CallerClass::BrowserHost, CallerClass::AutoFill] {
            let mut caller = CallerInfo::unverified("host");
            caller.identified = true;
            caller.class = class;
            let error = f.daemon.resolve(&caller, &refs, Purpose::Run).unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Forbidden));
        }
    }

    /// The socket identifies the process that connected, not whoever later
    /// writes the request. A peer that exited before it was identified is a
    /// caller like any other, and gets what any caller gets.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn answer_identifies_each_class_and_serves_unidentified_callers() {
        use super::super::macos_autofill::SocketKind;
        use crate::protocol::{Fill, LoginRef, PROTOCOL_VERSION, Request};
        use deadbolt_client::peer::{APP_ID, AUTOFILL_ID, DAEMON_ID, Peer, Process};
        use tokio::{net::UnixListener, process::Command as Child, time::timeout};

        let f = super::super::passkeys::tests::daemon::unlocked().await;
        let (conv, _closed) = super::super::passkeys::tests::daemon::conversation();
        let origin = "https://example.com";
        let login = f
            .daemon
            .with(|s| {
                Ok(LoginRef {
                    vault: s.resolve(None)?.to_string(),
                    item: new(
                        s,
                        "login",
                        "GitHub",
                        &[("url", origin), ("password", "fixture-pw")],
                    ),
                })
            })
            .unwrap();
        let fill = Command::SiteFill {
            origin: origin.into(),
            login,
            want: vec![Fill::Password],
        };
        let get = Command::ItemGet {
            vault: None,
            query: vec!["GitHub".into()],
            otp: false,
            ssh_private: false,
            files: vec![],
            deleted: false,
        };
        let answer = async |peer, command, socket| {
            f.daemon
                .clone()
                .answer(
                    socket,
                    Ok(peer),
                    Request {
                        v: PROTOCOL_VERSION,
                        command,
                    },
                    &conv,
                )
                .await
                .0
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let mut child = Child::new("python3").args(["-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.recv(1)"]).arg(path).kill_on_drop(true).spawn().unwrap();
        let wait = Duration::from_secs(10);
        let (stream, _) = timeout(wait, listener.accept()).await.unwrap().unwrap();
        let exited = Peer::of(&stream).unwrap();
        assert!(f.daemon.callers.identify(Ok(exited)).identified);
        drop(stream);
        // The connecting process is dead but its pid has not been reaped.
        use rustix::process::{Pid, WaitIdOptions, waitid};
        waitid(
            rustix::process::WaitId::Pid(Pid::from_raw(exited.pid as i32).unwrap()),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        )
        .unwrap();
        assert!(
            !f.daemon.callers.identify(Ok(exited)).identified,
            "a zombie is not a live peer"
        );
        assert!(
            timeout(wait, child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(matches!(
            answer(exited, get.clone(), SocketKind::Control)
                .await
                .unwrap(),
            Reply::Item { .. }
        ));
        assert!(matches!(
            answer(exited, fill.clone(), SocketKind::Control)
                .await
                .unwrap(),
            Reply::SiteFill { .. }
        ));

        let terminal = Process {
            ancestry_complete: true,
            ..Default::default()
        };
        for ((peer, info), class, command, socket) in [
            (
                caller::tests::signed(DAEMON_ID, terminal.clone()),
                CallerClass::Caller,
                get.clone(),
                SocketKind::Control,
            ),
            (
                caller::tests::signed(APP_ID, terminal.clone()),
                CallerClass::App,
                get,
                SocketKind::Control,
            ),
            (
                caller::tests::signed_host(vec![caller::tests::chrome()]),
                CallerClass::BrowserHost,
                fill,
                SocketKind::Control,
            ),
            (
                caller::tests::signed(AUTOFILL_ID, terminal),
                CallerClass::AutoFill,
                Command::AutofillIdentities,
                SocketKind::AutoFill,
            ),
        ] {
            assert!(info.identified);
            assert_eq!(info.class, class);
            f.daemon.callers.cache_for_test(peer, info);
            answer(peer, command, socket).await.unwrap();
        }
    }
}
