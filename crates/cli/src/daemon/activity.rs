//! The Activity list (`docs/design.md`, "Callers"): an entry for each
//! caller request and for the app's own reveals and copies,
//! naming items and fields, never values. Entries are sealed in `store.redb`
//! on this device; those made while locked wait in memory until an unlock.
//! [`ledger`] keeps all of it in budget.

use std::sync::Arc;

use crate::disk::{Budget, Dropped};
use anyhow::Result;
use deadbolt_client::peer::Peer;
use tracing::warn;

pub use deadbolt_engine::activity::{KEEP_SECS, Ledger, draft, ledger, reported};

use super::{Conversation, Daemon, caller, fail, session};
use crate::protocol::{
    ActivityEntry, CallerClass, CallerInfo, Command, ErrorCode, Outcome, Reply, Request, Tier,
};

/// What the store keeps, at most; past it the oldest entries go, counted.
const BUDGET: Budget = Budget {
    rows: 100_000,
    bytes: 64 << 20,
};
const DEFAULT_LIMIT: u32 = 500;
/// The most entries one `ActivityList` returns.
const MAX_LIMIT: u32 = 1_000;

/// The entry for the rows the store dropped to stay in budget.
fn past_budget(dropped: Dropped) -> ActivityEntry {
    ActivityEntry {
        id: dropped.last_id,
        time: dropped.last_time,
        caller: CallerInfo::unverified("Deadbolt"),
        tier: Tier::Always,
        command: ledger::PAST_BUDGET.into(),
        items: Vec::new(),
        fields: Vec::new(),
        outcome: Outcome::Allowed,
        more: dropped.count,
    }
}

impl Daemon {
    /// Answers `request` from `peer`, with its Activity entry if it gets
    /// one, to record before the reply goes.
    pub(super) async fn answer(
        self: Arc<Self>,
        socket: super::macos_autofill::SocketKind,
        peer: std::io::Result<Peer>,
        request: Request,
        conv: &Conversation,
    ) -> (Result<Reply>, Option<ActivityEntry>) {
        let daemon = self.clone();
        let kernel = peer.as_ref().ok().copied();
        let mut caller = tokio::task::spawn_blocking(move || daemon.callers.identify(peer))
            .await
            .unwrap_or_else(|_| caller::nobody());
        let draft = draft(&request.command, caller.class);
        let command = request.command;
        // A run's screen answers what it stops; a refusal there (a process
        // inside a run reaching for a secret) is an entry, its own runs'
        // registrations aren't.
        let mut recorded = true;
        let screened = match super::macos_autofill::check_access(socket, &caller, &command) {
            Err(error) => Some(Err(error)),
            Ok(()) => self.screen(kernel.as_ref(), &command).inspect(|screened| {
                recorded = screened.is_err();
            }),
        };
        let mut result = match screened {
            Some(result) => result,
            None => match command {
                command @ Command::ActivityReport { .. } => self.report(&caller, command),
                Command::Resolve { refs, purpose } => self.resolve(&caller, &refs, purpose),
                command @ (Command::Health { .. }
                | Command::HealthIgnore { .. }
                | Command::BreachChecksSet { .. }) => self.health_command(command).await,
                // Exporting an SSH private key asks the user each time.
                command @ Command::ItemGet { .. } => {
                    match self.verify_ssh_export(&caller, &command, conv).await {
                        Ok(()) => self.clone().dispatch(command, conv).await,
                        Err(error) => Err(error),
                    }
                }
                command => self.clone().dispatch(command, conv).await,
            },
        };
        ledger::bound_caller(&mut caller);
        if let Ok(Reply::Status(status)) = &mut result {
            status.caller = caller.clone();
        }
        let entry = draft
            .filter(|draft| recorded && draft.recorded(&result))
            .map(|draft| draft.finish(caller, session::now(), &result));
        (result, entry)
    }

    /// Records `entry`: stored now if unlocked, else held until an unlock.
    pub(super) fn record(&self, entry: ActivityEntry) {
        let session = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let mut ledger = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        let due = ledger.admit(entry);
        self.keep(session.as_ref().map(|s| &*s.store), &mut ledger, due);
    }

    /// Stores what was held while locked, if unlocked, with the folds of
    /// callers past their limit whose window has ended, or all of them
    /// (`all`, as the daemon locks or stops).
    pub(super) fn settle_activity(&self, all: bool) {
        let session = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let mut ledger = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        let due = ledger.due(session::now(), all);
        self.keep(session.as_ref().map(|s| &*s.store), &mut ledger, due);
    }

    fn keep(
        &self,
        store: Option<&crate::disk::Unlocked>,
        ledger: &mut Ledger,
        due: Vec<ActivityEntry>,
    ) {
        let Some(store) = store else {
            for entry in due {
                ledger.hold(entry);
            }
            return;
        };
        let mut entries = ledger.take_held();
        entries.extend(due);
        if entries.is_empty() {
            return;
        }
        let rows = entries
            .iter()
            .map(|entry| Ok((entry.time, serde_json::to_vec(entry)?)))
            .collect::<Result<Vec<_>>>();
        let stored = rows.and_then(|rows| {
            let keep_from = session::now().saturating_sub(KEEP_SECS);
            let rows = rows.iter().map(|(time, bytes)| (*time, bytes.as_slice()));
            Ok(store.activity_append(rows, keep_from, BUDGET)?)
        });
        match stored {
            Ok(_) => self.watchers.activity(),
            Err(error) => {
                warn!("storing activity: {error:#}");
                ledger.restore_held(entries);
            }
        }
    }

    /// Entries at or after `since` and before the id `before`, newest first.
    pub(super) fn activity_list(
        &self,
        since: Option<u64>,
        limit: Option<u32>,
        before: Option<u64>,
    ) -> Result<Reply> {
        self.settle_activity(false);
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let since = since.unwrap_or(0);
        let page = self.with(|s| Ok(s.store.activity_list(since, before, limit)?))?;
        // Entries of commands since removed (agent sign-ins) no longer read;
        // they're left out, and go as entries age past `KEEP_SECS`.
        let mut entries: Vec<ActivityEntry> = page
            .rows
            .into_iter()
            .filter_map(|row| {
                let mut entry: ActivityEntry = serde_json::from_slice(&row.bytes).ok()?;
                entry.id = row.id;
                Some(entry)
            })
            .collect();
        entries.extend(page.dropped.map(past_budget));
        Ok(Reply::Activity { entries })
    }

    /// Records the app's report of a reveal or copy. Only the app makes them.
    pub(super) fn report(&self, caller: &CallerInfo, command: Command) -> Result<Reply> {
        let Command::ActivityReport {
            action,
            vault,
            item,
            title,
            field,
        } = command
        else {
            return Err(fail(ErrorCode::Failed, "not a report"));
        };
        if caller.class != CallerClass::App {
            return Err(fail(
                ErrorCode::Failed,
                "only Deadbolt.app reports activity",
            ));
        }
        let time = session::now();
        self.record(reported(
            caller.clone(),
            time,
            action,
            vault,
            item,
            title,
            field,
        ));
        Ok(Reply::Done)
    }

    /// Exporting an SSH private key asks Touch ID each time, when it is on,
    /// for anyone but the app; anything else gets no further check here.
    async fn verify_ssh_export(
        &self,
        caller: &CallerInfo,
        command: &Command,
        conv: &Conversation,
    ) -> Result<()> {
        let Command::ItemGet {
            vault,
            query,
            ssh_private,
            deleted,
            ..
        } = command
        else {
            return Ok(());
        };
        if !ssh_private || caller.class == CallerClass::App || !self.can_verify() {
            return Ok(());
        }
        let Some(title) = self.with(|s| {
            let listing =
                super::items::Listing::pick(s.vault(&s.resolve(vault.as_deref())?), *deleted);
            let item = listing.find(query)?;
            Ok((item.kind == "ssh").then(|| deadbolt_core::listing::label(item)))
        })?
        else {
            return Ok(());
        };
        let reason = format!(
            "export the SSH private key of {title} ({})",
            clean_label(&caller.label)
        );
        let _busy = self.busy();
        self.verify_user(conv, crate::protocol::Verify::Required, &reason)
            .await?;
        Ok(())
    }
}

/// A caller's label as a Touch ID prompt can show it: one line, no quotes.
fn clean_label(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>()
        .trim()
        .replace(['"', '\u{201c}', '\u{201d}'], "'")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use zeroize::Zeroizing;

    use super::super::tests::test_paths;
    use super::*;
    use crate::protocol::{
        AppAction, FieldInput, FormKind, LoginRef, MAX_LINE, Message, PROTOCOL_VERSION, Request,
        Secret, SiteField,
    };

    const SECRET: &str = "correct-horse-battery-staple";

    async fn ask(daemon: &Arc<Daemon>, command: Command) -> Message {
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut line = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            command,
        })
        .unwrap();
        line.push(b'\n');
        client.write_all(&line).await.unwrap();
        daemon.clone().handle(server, MAX_LINE).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    fn get() -> Command {
        Command::ItemGet {
            vault: None,
            query: vec!["github".into()],
            otp: false,
            ssh_private: false,
            files: Vec::new(),
            deleted: false,
        }
    }

    async fn set_up(dir: &std::path::Path) -> Arc<Daemon> {
        let daemon = Daemon::new(test_paths(dir), true, crate::disk::KdfParams::DEFAULT);
        daemon
            .setup(Zeroizing::new("test".into()), "laptop".into())
            .await
            .unwrap();
        let vault = ask(
            &daemon,
            Command::VaultCreate {
                name: "personal".into(),
            },
        )
        .await;
        assert!(matches!(vault, Message::Ok { .. }), "{vault:?}");
        let made = ask(
            &daemon,
            Command::ItemNew {
                vault: None,
                kind: "login".into(),
                name: Some("github".into()),
                fields: vec![
                    FieldInput {
                        name: "username".into(),
                        kind: None,
                        value: "alex".into(),
                    },
                    FieldInput {
                        name: "password".into(),
                        kind: None,
                        value: SECRET.into(),
                    },
                ],
                favorite: false,
                tags: Vec::new(),
            },
        )
        .await;
        assert!(matches!(made, Message::Ok { .. }), "{made:?}");
        daemon
    }

    fn stored(daemon: &Daemon) -> Vec<ActivityEntry> {
        match daemon.activity_list(None, None, None).unwrap() {
            Reply::Activity { entries } => entries,
            other => panic!("expected activity, got {other:?}"),
        }
    }

    /// Entries name what was asked for and touched; the values themselves,
    /// written or read, never reach the store.
    #[tokio::test]
    async fn activity_never_stores_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        let read = ask(&daemon, get()).await;
        let Message::Ok {
            reply: Reply::Item { item },
        } = read
        else {
            panic!("expected the item, got {read:?}");
        };
        assert!(item.fields.iter().any(|f| f.value == SECRET));

        let rows = daemon
            .with(|s| Ok(s.store.activity_list(0, None, 100)?))
            .unwrap()
            .rows;
        assert_eq!(rows.len(), 3);
        for row in &rows {
            let text = String::from_utf8_lossy(&row.bytes);
            assert!(!text.contains(SECRET), "a value was stored: {text}");
            assert!(!text.contains("\"alex\""), "a value was stored: {text}");
        }
        let entries = stored(&daemon);
        let commands: Vec<_> = entries.iter().map(|e| e.command.as_str()).collect();
        assert_eq!(commands, ["item-get", "item-new", "vault-create"]);
        assert_eq!(entries[0].tier, Tier::Read);
        let mut read = entries[0].fields.clone();
        read.sort();
        assert_eq!(read, ["password", "username"]);
        assert_eq!(entries[0].items[0].title, "github");
        assert!(entries[0].items[0].id.is_some());
        assert_eq!(entries[1].fields, ["username", "password"]);
        assert!(entries.iter().all(|e| e.outcome == Outcome::Allowed));
        assert_eq!(entries[0].caller.class, CallerClass::Caller);
    }

    /// A generated password and its id never reach Activity, from the
    /// browser host or anyone else; the host's checks and drops aren't
    /// entries at all.
    #[tokio::test]
    async fn a_generated_password_never_reaches_activity() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        let origin = "https://signup.example.com".to_string();
        let generate = Command::SiteGenerate {
            origin: origin.clone(),
            field: SiteField::default(),
        };
        let made = ask(&daemon, generate.clone()).await;
        let Message::Ok {
            reply: reply @ Reply::SiteGenerated { .. },
        } = made
        else {
            panic!("expected a password, got {made:?}");
        };
        let Reply::SiteGenerated { password, id } = &reply else {
            unreachable!()
        };
        let (password, id) = (password.expose().to_string(), id.clone());
        let keep = Command::SiteGenerateKeep {
            origin: origin.clone(),
            id: id.clone(),
        };
        let kept = ask(&daemon, keep.clone()).await;
        assert!(matches!(kept, Message::Ok { .. }), "{kept:?}");

        // As the browser host: the same commands, with the replies they got.
        for (command, result) in [(&generate, Ok(reply)), (&keep, Ok(Reply::Done))] {
            let draft = draft(command, CallerClass::BrowserHost).expect("recorded");
            daemon.record(draft.finish(caller::nobody(), session::now(), &result));
        }
        for command in [
            Command::SiteGenerateCheck {
                origin: origin.clone(),
                field: SiteField::default(),
            },
            Command::SiteGenerateDrop {
                origin: origin.clone(),
                id: id.clone(),
            },
        ] {
            assert!(draft(&command, CallerClass::BrowserHost).is_none());
        }

        let rows = daemon
            .with(|s| Ok(s.store.activity_list(0, None, 100)?))
            .unwrap()
            .rows;
        for row in &rows {
            let text = String::from_utf8_lossy(&row.bytes);
            assert!(!text.contains(&password), "the password was stored: {text}");
            assert!(!text.contains(&id), "its id was stored: {text}");
        }
        let entries = stored(&daemon);
        let commands: Vec<_> = entries.iter().take(4).map(|e| e.command.as_str()).collect();
        assert_eq!(
            commands,
            [
                "site-generate-keep",
                "site-generate",
                "site-generate-keep",
                "site-generate"
            ]
        );
        for entry in &entries[..4] {
            assert_eq!(entry.items[0].title, origin);
            assert_eq!(entry.fields, ["password"]);
            assert_eq!(entry.outcome, Outcome::Allowed);
        }
        assert_eq!(entries[2].caller.class, CallerClass::Caller);
    }

    /// A request made while locked is listed after the next unlock, with
    /// the outcome it had.
    #[tokio::test]
    async fn entries_made_while_locked_are_kept_after_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        daemon.lock().await;
        let refused = ask(&daemon, get()).await;
        assert!(
            matches!(
                refused,
                Message::Error {
                    code: ErrorCode::Locked,
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(daemon.activity.lock().unwrap().held_len(), 1);

        daemon
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        assert!(daemon.activity.lock().unwrap().held_len() == 0);
        let entries = stored(&daemon);
        assert_eq!(entries[0].command, "item-get");
        assert_eq!(entries[0].outcome, Outcome::Locked);
        assert_eq!(entries[0].items[0].title, "github");

        daemon.lock().await;
        daemon
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        assert_eq!(stored(&daemon).len(), entries.len(), "stored once");
    }

    /// The app's own requests aren't entries, and only the app may report.
    #[tokio::test]
    async fn the_app_reports_and_callers_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        let report = Command::ActivityReport {
            action: AppAction::Copy,
            vault: None,
            item: "i1".into(),
            title: "github".into(),
            field: "password".into(),
        };
        let caller = daemon
            .callers
            .identify(Err(std::io::ErrorKind::Other.into()));
        assert!(daemon.report(&caller, report.clone()).is_err());
        let mut app = caller;
        app.class = CallerClass::App;
        assert!(draft(&get(), CallerClass::App).is_none());
        daemon.report(&app, report).unwrap();
        let entries = stored(&daemon);
        assert_eq!(entries[0].command, "copy");
        assert_eq!(entries[0].fields, ["password"]);
    }

    /// A client reading Activity on every change (the app, a caller's
    /// dashboard) adds no entries, so it can't wake itself again.
    #[tokio::test]
    async fn reading_activity_is_never_an_entry() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        let before = stored(&daemon);
        let changes = daemon.watchers.subscribe(false);
        for _ in 0..5 {
            let list = Command::ActivityList {
                since: None,
                limit: None,
                before: None,
            };
            let read = ask(&daemon, list).await;
            assert!(
                matches!(
                    read,
                    Message::Ok {
                        reply: Reply::Activity { .. }
                    }
                ),
                "{read:?}"
            );
        }
        assert_eq!(stored(&daemon), before);
        let woke = tokio::time::timeout(std::time::Duration::from_millis(500), changes.next());
        assert!(woke.await.is_err(), "no activity change");
        let list = Command::ActivityList {
            since: None,
            limit: None,
            before: None,
        };
        assert!(draft(&list, CallerClass::Caller).is_none());
        assert!(draft(&list, CallerClass::BrowserHost).is_none());
    }

    /// The browser host's class rests on its arguments, which a process can
    /// rewrite, so only its page look-ups go unrecorded: anything else it
    /// asks is an entry, as a caller's would be.
    #[test]
    fn the_browser_host_hides_only_its_look_ups() {
        let origin = "https://example.com".to_string();
        for command in [
            get(),
            Command::ItemRemove {
                vault: None,
                query: vec!["github".into()],
            },
            Command::DeviceRemove {
                vault: None,
                device: "d2".into(),
            },
        ] {
            assert!(
                draft(&command, CallerClass::BrowserHost).is_some(),
                "{command:?}"
            );
        }
        for command in [
            Command::Status,
            Command::SiteLogins {
                origin: origin.clone(),
            },
            Command::PasskeyList {
                origin,
                rp_id: None,
            },
        ] {
            assert!(
                draft(&command, CallerClass::BrowserHost).is_none(),
                "{command:?}"
            );
        }
    }

    /// The browser's form fills are entries for a card, naming the card and
    /// page and never a value, and not for an identity; its form look-ups
    /// are never entries. A caller's form fill always is.
    #[test]
    fn card_fills_are_entries_and_identity_fills_are_not() {
        let origin = "https://shop.example.com".to_string();
        let item = LoginRef {
            vault: "ab".repeat(32),
            item: "cd".repeat(16),
        };
        let fill = Command::FormFill {
            origin: origin.clone(),
            item: item.clone(),
            fields: vec!["number".into(), "cvv".into()],
        };
        let filled = |kind: &str| -> Result<Reply> {
            Ok(Reply::FormFill {
                kind: kind.into(),
                title: "Visa •••• 4242".into(),
                values: [("number".to_string(), Secret::new("4242424242424242"))].into(),
                verified: true,
            })
        };
        let browser = draft(&fill, CallerClass::BrowserHost).unwrap();
        assert!(!browser.recorded(&filled("identity")));
        assert!(browser.recorded(&filled("card")));
        let failed: Result<Reply> = Err(anyhow::anyhow!("Touch ID was cancelled"));
        assert!(browser.recorded(&failed), "a refused fill is an entry");
        let entry = browser.finish(CallerInfo::unverified("Chrome"), 1, &filled("card"));
        assert_eq!(entry.command, "form-fill");
        assert_eq!(entry.fields, ["number", "cvv"]);
        assert_eq!(entry.items[0].id.as_deref(), Some(item.item.as_str()));
        assert_eq!(entry.items[0].title, format!("Visa •••• 4242 · {origin}"));
        assert!(
            !serde_json::to_string(&entry)
                .unwrap()
                .contains("4242424242")
        );
        let caller = draft(&fill, CallerClass::Caller).unwrap();
        assert!(caller.recorded(&filled("identity")));
        let items = Command::FormItems {
            origin,
            kinds: vec![FormKind::Card],
        };
        assert!(draft(&items, CallerClass::BrowserHost).is_none());
        assert!(draft(&items, CallerClass::Caller).is_some());
    }

    /// The entry is written before the reply: a client that never reads
    /// it, and the daemon cancelling the connection as it stops, lose
    /// nothing.
    #[tokio::test]
    async fn an_entry_is_kept_when_its_reply_never_goes() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        // A reply too big for the socket's buffers waits on a reader.
        let big = "x".repeat(4 << 20);
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut line = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            command: Command::ItemNew {
                vault: None,
                kind: "note".into(),
                name: Some("big".into()),
                fields: vec![FieldInput {
                    name: "notes".into(),
                    kind: None,
                    value: big.clone(),
                }],
                favorite: false,
                tags: Vec::new(),
            },
        })
        .unwrap();
        line.push(b'\n');
        let handled = tokio::spawn(daemon.clone().handle(server, MAX_LINE));
        client.write_all(&line).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        handled.await.unwrap().unwrap();
        let before = stored(&daemon).len();

        let (server, client) = UnixStream::pair().unwrap();
        let mut line = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            command: Command::ItemGet {
                vault: None,
                query: vec!["big".into()],
                otp: false,
                ssh_private: false,
                files: Vec::new(),
                deleted: false,
            },
        })
        .unwrap();
        line.push(b'\n');
        let (mut read, mut write) = client.into_split();
        write.write_all(&line).await.unwrap();
        let handled = tokio::spawn(daemon.clone().handle(server, MAX_LINE));
        // The reply has started, and stalls on a client that reads no more.
        let mut first = [0u8; 1];
        read.read_exact(&mut first).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!handled.is_finished(), "the reply should be waiting");
        handled.abort();
        assert!(handled.await.unwrap_err().is_cancelled());

        let entries = stored(&daemon);
        assert_eq!(entries.len(), before + 1);
        assert_eq!(entries[0].command, "item-get");
        assert_eq!(entries[0].items[0].title, "big");
        drop((read, write));
    }

    /// Past its limit, a caller's repeated reads come back as one entry
    /// naming the item and saying how many, once its window ends, or as the
    /// daemon locks. The first past the limit is still an entry of its own.
    #[tokio::test]
    async fn a_flood_of_reads_folds_into_one_entry_naming_the_item() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        let before = stored(&daemon).len();
        for _ in 0..ledger::PER_ANCHOR + 40 {
            let read = ask(&daemon, get()).await;
            assert!(matches!(read, Message::Ok { .. }), "{read:?}");
        }
        // The setup's own requests count against the same anchor.
        let listed = stored(&daemon).len() - before;
        assert_eq!(listed + before, ledger::PER_ANCHOR as usize + 1);
        daemon.lock().await;
        daemon
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        let entries = stored(&daemon);
        assert_eq!(entries[0].command, "item-get");
        assert_eq!(entries[0].items, entries[1].items);
        assert!(entries[0].items[0].id.is_some());
        assert_eq!(entries[0].fields, entries[1].fields);
        assert_eq!(
            entries[0].more as usize,
            ledger::PER_ANCHOR as usize + 40 - listed
        );
        assert_eq!(entries.len(), ledger::PER_ANCHOR as usize + 2);
    }

    /// Past its limit, a caller's look-ups fold into one entry saying how
    /// many.
    #[tokio::test]
    async fn a_flood_of_look_ups_folds_into_one_entry() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        let before = stored(&daemon).len();
        let list = || Command::ItemList {
            vault: None,
            query: Vec::new(),
            kind: None,
            deleted: false,
            tags: Vec::new(),
            favorites: false,
        };
        for _ in 0..ledger::PER_ANCHOR + 40 {
            let listed = ask(&daemon, list()).await;
            assert!(matches!(listed, Message::Ok { .. }), "{listed:?}");
        }
        let listed = stored(&daemon).len() - before;
        assert_eq!(listed + before, ledger::PER_ANCHOR as usize);
        daemon.lock().await;
        daemon
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        let entries = stored(&daemon);
        assert_eq!(entries[0].command, ledger::PAST_LIMIT);
        assert_eq!(
            entries[0].more as usize,
            ledger::PER_ANCHOR as usize + 40 - listed
        );
    }

    /// A list is clamped to `MAX_LIMIT` entries, and pages back by id.
    #[tokio::test]
    async fn lists_are_clamped_and_paged() {
        let dir = tempfile::tempdir().unwrap();
        let daemon = set_up(dir.path()).await;
        let rows: Vec<(u64, Vec<u8>)> = (0..MAX_LIMIT as u64 + 10)
            .map(|i| {
                let mut entry = reported(
                    caller::nobody(),
                    session::now(),
                    AppAction::Copy,
                    None,
                    format!("i{i}"),
                    "github".into(),
                    "password".into(),
                );
                entry.time = session::now();
                (entry.time, serde_json::to_vec(&entry).unwrap())
            })
            .collect();
        daemon
            .with(|s| {
                let rows = rows.iter().map(|(t, b)| (*t, b.as_slice()));
                Ok(s.store.activity_append(rows, 0, BUDGET)?)
            })
            .unwrap();
        let Reply::Activity { entries } = daemon.activity_list(None, Some(u32::MAX), None).unwrap()
        else {
            panic!("expected activity");
        };
        assert_eq!(entries.len(), MAX_LIMIT as usize);
        let last = entries.last().unwrap().id;
        let Reply::Activity { entries: older } = daemon
            .activity_list(None, Some(u32::MAX), Some(last))
            .unwrap()
        else {
            panic!("expected activity");
        };
        assert!(older.iter().all(|e| e.id < last));
        assert_eq!(older.len(), 12, "the 10 more, then the setup's 2");
    }
}
