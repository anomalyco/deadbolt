//! The Activity list (`docs/agent-control.md`, "Lock, limits, activity"): an
//! entry for each caller request and for the app's own reveals and copies,
//! naming items and fields, never values. Entries are sealed in `store.redb`
//! on this device; those made while locked wait in memory until an unlock.
//! [`ledger`] keeps all of it in budget.

mod ledger;

use std::sync::Arc;

use anyhow::Result;
use deadbolt_client::peer::Peer;
use deadbolt_store::{Budget, Dropped};
use tracing::warn;

pub use ledger::Ledger;

use super::{Agent, Conversation, caller, fail, session};
use crate::client::code;
use crate::protocol::{
    ActivityEntry, ActivityItem, AppAction, CallerClass, CallerInfo, Command, ErrorCode, Fill,
    Outcome, Reply, Request, Tier,
};

/// How long entries are kept.
pub const KEEP_SECS: u64 = 90 * 24 * 60 * 60;
/// What the store keeps, at most; past it the oldest entries go, counted.
const BUDGET: Budget = Budget {
    rows: 100_000,
    bytes: 64 << 20,
};
const DEFAULT_LIMIT: u32 = 500;
/// The most entries one `ActivityList` returns.
const MAX_LIMIT: u32 = 1_000;

/// The tier and protocol name of every command, so a new one doesn't
/// compile until it has both.
pub fn describe(command: &Command) -> (Tier, &'static str) {
    use Command as C;
    use Tier as T;
    match command {
        C::Status => (T::Always, "status"),
        C::Stop => (T::Always, "stop"),
        C::Setup { .. } => (T::Never, "setup"),
        C::Unlock { .. } => (T::Never, "unlock"),
        C::UnlockBiometric { .. } => (T::Never, "unlock-biometric"),
        C::TouchIdSet { .. } => (T::Never, "touch-id-set"),
        C::Lock => (T::Always, "lock"),
        C::Watch { .. } => (T::Look, "watch"),
        C::AppActivate { .. } => (T::Always, "app-activate"),
        C::VaultCreate { .. } => (T::Never, "vault-create"),
        C::VaultList => (T::Look, "vault-list"),
        C::VaultRename { .. } => (T::Never, "vault-rename"),
        C::VaultDefault { .. } => (T::Never, "vault-default"),
        C::Devices { .. } => (T::Look, "devices"),
        C::DeviceRemove { .. } => (T::Never, "device-remove"),
        C::Sync { .. } => (T::Always, "sync"),
        C::Join { .. } => (T::Never, "join"),
        C::Pair { .. } => (T::Never, "pair"),
        C::ItemNew { .. } => (T::Add, "item-new"),
        C::ItemGet { .. } => (T::Read, "item-get"),
        C::ItemCode { .. } => (T::Read, "item-code"),
        C::ItemList { .. } => (T::Look, "item-list"),
        // Adding a field or editing a plain one will be Add (build order 6).
        C::ItemSet { .. } => (T::Write, "item-set"),
        C::ItemUnset { .. } => (T::Write, "item-unset"),
        C::ItemRemove { .. } => (T::Never, "item-remove"),
        C::Import { .. } => (T::Never, "import"),
        C::Generate { .. } => (T::Always, "generate"),
        C::SyncOnePassword { .. } => (T::Never, "sync-one-password"),
        C::SiteLogins { .. } => (T::Browser, "site-logins"),
        C::SiteFill { .. } => (T::Browser, "site-fill"),
        C::SiteGenerateCheck { .. } => (T::Browser, "site-generate-check"),
        C::SiteGenerate { .. } => (T::Browser, "site-generate"),
        C::SiteGenerateKeep { .. } => (T::Browser, "site-generate-keep"),
        C::SiteGenerateDrop { .. } => (T::Browser, "site-generate-drop"),
        C::SiteCheck { .. } => (T::Browser, "site-check"),
        C::SiteSave { .. } => (T::Browser, "site-save"),
        C::PasskeyList { .. } => (T::Browser, "passkey-list"),
        C::PasskeyCreate { .. } => (T::Browser, "passkey-create"),
        C::PasskeyGet { .. } => (T::Browser, "passkey-get"),
        // Sends never touch the vault: the client sealed what it shares.
        C::SendCreate { .. } => (T::Always, "send-create"),
        C::SendList => (T::Always, "send-list"),
        C::SendShow { .. } => (T::Always, "send-show"),
        C::SendRevoke { .. } => (T::Always, "send-revoke"),
        C::SendWait { .. } => (T::Always, "send-wait"),
        C::ActivityList { .. } => (T::Look, "activity-list"),
        C::ActivityReport { .. } => (T::Always, "activity-report"),
    }
}

/// An entry being written: what the request named, before it ran.
pub struct Draft {
    tier: Tier,
    command: &'static str,
    items: Vec<ActivityItem>,
    fields: Vec<String>,
}

fn named(vault: &Option<String>, query: &[String]) -> Vec<ActivityItem> {
    if query.is_empty() {
        return Vec::new();
    }
    vec![ActivityItem {
        vault: vault.clone(),
        id: None,
        title: query.join(" "),
    }]
}

fn login(vault: &str, item: &str, title: &str) -> Vec<ActivityItem> {
    vec![ActivityItem {
        vault: Some(vault.into()),
        id: Some(item.into()),
        title: title.into(),
    }]
}

fn fill_name(fill: &Fill) -> String {
    match fill {
        Fill::Username => "username",
        Fill::Password => "password",
        Fill::Totp => "otp",
    }
    .into()
}

/// The draft of an entry for `command` from a `class` peer, or `None` when
/// it isn't recorded: the app's own requests (it reports its reveals and
/// copies), a caller's `status` and `watch` (every command starts with a
/// status) and `app-activate` (every `deadbolt app`), and the browser host's look-ups, which come with every page
/// (and its generator checks and drops, asked before anyone chose a
/// password).
/// Reading Activity is never an entry, so a client that reads it on every
/// change can't feed itself.
pub fn draft(command: &Command, class: CallerClass) -> Option<Draft> {
    if matches!(command, Command::ActivityList { .. }) {
        return None;
    }
    let recorded = match class {
        CallerClass::App => false,
        CallerClass::BrowserHost => matches!(
            command,
            Command::SiteFill { .. }
                | Command::SiteGenerate { .. }
                | Command::SiteGenerateKeep { .. }
                | Command::SiteSave { .. }
                | Command::PasskeyCreate { .. }
                | Command::PasskeyGet { .. }
        ),
        CallerClass::Caller => !matches!(
            command,
            Command::Status | Command::Watch { .. } | Command::AppActivate { .. }
        ),
    };
    if !recorded {
        return None;
    }
    let (tier, name) = describe(command);
    let (items, fields) = match command {
        Command::ItemNew {
            vault,
            name,
            fields,
            ..
        } => (
            named(vault, name.as_slice()),
            fields.iter().map(|f| f.name.clone()).collect(),
        ),
        Command::ItemGet { vault, query, .. }
        | Command::ItemList { vault, query, .. }
        | Command::ItemRemove { vault, query } => (named(vault, query), Vec::new()),
        Command::ItemCode { vault, query } => (named(vault, query), vec!["otp".into()]),
        Command::ItemSet {
            vault,
            query,
            fields,
            unset,
            ..
        } => (
            named(vault, query),
            fields
                .iter()
                .map(|f| f.name.clone())
                .chain(unset.iter().cloned())
                .collect(),
        ),
        Command::ItemUnset {
            vault,
            query,
            field,
        } => (named(vault, query), vec![field.clone()]),
        Command::SiteFill {
            origin,
            login: target,
            want,
        } => (
            login(&target.vault, &target.item, origin),
            want.iter().map(fill_name).collect(),
        ),
        Command::SiteSave {
            login: target,
            title,
            ..
        } => (
            target
                .as_ref()
                .map(|t| login(&t.vault, &t.item, title))
                .unwrap_or_else(|| named(&None, std::slice::from_ref(title))),
            vec!["username".into(), "password".into()],
        ),
        Command::PasskeyGet {
            origin, passkey, ..
        } => (login(&passkey.vault, &passkey.item, origin), Vec::new()),
        Command::PasskeyCreate { origin, .. } => {
            (named(&None, std::slice::from_ref(origin)), Vec::new())
        }
        // The page, and that a password was made for it: never the password
        // or its id.
        Command::SiteGenerate { origin, .. }
        | Command::SiteGenerateKeep { origin, .. }
        | Command::SiteGenerateCheck { origin, .. }
        | Command::SiteGenerateDrop { origin, .. } => (
            named(&None, std::slice::from_ref(origin)),
            vec!["password".into()],
        ),
        _ => (Vec::new(), Vec::new()),
    };
    Some(Draft {
        tier,
        command: name,
        items,
        fields,
    })
}

impl Draft {
    /// The entry, with what the reply says about the item it found.
    pub fn finish(
        mut self,
        caller: CallerInfo,
        time: u64,
        result: &Result<Reply>,
    ) -> ActivityEntry {
        let outcome = match result {
            Ok(reply) => {
                self.learn(reply);
                Outcome::Allowed
            }
            Err(error) if code(error) == Some(ErrorCode::Locked) => Outcome::Locked,
            Err(_) => Outcome::Failed,
        };
        ActivityEntry {
            id: 0,
            time,
            caller,
            tier: self.tier,
            command: self.command.into(),
            items: self.items,
            fields: self.fields,
            outcome,
            more: 0,
        }
    }

    fn learn(&mut self, reply: &Reply) {
        let vault = self.items.first().and_then(|i| i.vault.clone());
        match reply {
            Reply::Item { item } => {
                self.items = vec![ActivityItem {
                    vault,
                    id: Some(item.id.clone()),
                    title: item.label.clone(),
                }];
                if self.command == "item-get" {
                    self.fields = item
                        .fields
                        .iter()
                        .filter(|f| !f.value.is_empty())
                        .map(|f| f.name.clone())
                        .collect();
                }
            }
            Reply::SiteSaved { login: saved, .. } => {
                let title = self
                    .items
                    .first()
                    .map(|i| i.title.clone())
                    .unwrap_or_default();
                self.items = login(&saved.vault, &saved.item, &title);
            }
            Reply::PasskeyCreated { passkey, .. } => {
                let title = self
                    .items
                    .first()
                    .map(|i| i.title.clone())
                    .unwrap_or_default();
                self.items = login(&passkey.vault, &passkey.item, &title);
            }
            _ => {}
        }
    }
}

/// The entry for something the app showed or copied.
pub fn reported(
    caller: CallerInfo,
    time: u64,
    action: AppAction,
    vault: Option<String>,
    item: String,
    title: String,
    field: String,
) -> ActivityEntry {
    let (tier, command) = match action {
        AppAction::Reveal => (Tier::Read, "reveal"),
        AppAction::Copy => (Tier::Read, "copy"),
    };
    ActivityEntry {
        id: 0,
        time,
        caller,
        tier,
        command: command.into(),
        items: vec![ActivityItem {
            vault,
            id: Some(item),
            title,
        }],
        fields: vec![field],
        outcome: Outcome::Allowed,
        more: 0,
    }
}

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

impl Agent {
    /// Answers `request` from `peer`, with its Activity entry if it gets
    /// one, to record before the reply goes.
    pub(super) async fn answer(
        self: Arc<Self>,
        peer: std::io::Result<Peer>,
        request: Request,
        conv: &Conversation,
    ) -> (Result<Reply>, Option<ActivityEntry>) {
        let agent = self.clone();
        let claimed = request.claimed;
        let mut caller = tokio::task::spawn_blocking(move || agent.callers.identify(peer, claimed))
            .await
            .unwrap_or_else(|_| caller::nobody());
        ledger::bound_caller(&mut caller);
        let draft = draft(&request.command, caller.class);
        let mut result = match request.command {
            command @ Command::ActivityReport { .. } => self.report(&caller, command),
            command => self.dispatch(command, conv).await,
        };
        if let Ok(Reply::Status(status)) = &mut result {
            status.caller = caller.clone();
        }
        let entry = draft.map(|draft| draft.finish(caller, session::now(), &result));
        (result, entry)
    }

    /// Records `entry`: stored now if unlocked, else held until an unlock.
    pub(super) fn record(&self, entry: ActivityEntry) {
        let session = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let mut ledger = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        let due = ledger.admit(entry);
        self.keep(session.as_ref().map(|s| &s.store), &mut ledger, due);
    }

    /// Stores what was held while locked, if unlocked, with the folds of
    /// callers past their limit whose window has ended, or all of them
    /// (`all`, as the agent locks or stops).
    pub(super) fn settle_activity(&self, all: bool) {
        let session = self.session.lock().unwrap_or_else(|e| e.into_inner());
        let mut ledger = self.activity.lock().unwrap_or_else(|e| e.into_inner());
        let due = ledger.due(session::now(), all);
        self.keep(session.as_ref().map(|s| &s.store), &mut ledger, due);
    }

    fn keep(
        &self,
        store: Option<&deadbolt_store::Unlocked>,
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
        let rows: Result<Vec<(u64, Vec<u8>)>, _> = entries
            .iter()
            .map(|e| serde_json::to_vec(e).map(|bytes| (e.time, bytes)))
            .collect();
        let stored = rows.map_err(anyhow::Error::from).and_then(|rows| {
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
        let mut entries = page
            .rows
            .into_iter()
            .map(|row| {
                let mut entry: ActivityEntry = serde_json::from_slice(&row.bytes)?;
                entry.id = row.id;
                Ok(entry)
            })
            .collect::<Result<Vec<_>>>()?;
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use zeroize::Zeroizing;

    use super::super::tests::test_paths;
    use super::*;
    use crate::protocol::{FieldInput, MAX_LINE, Message, PROTOCOL_VERSION, Request, SiteField};

    const SECRET: &str = "correct-horse-battery-staple";

    async fn ask(agent: &Arc<Agent>, command: Command) -> Message {
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut line = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            claimed: None,
            command,
        })
        .unwrap();
        line.push(b'\n');
        client.write_all(&line).await.unwrap();
        agent.clone().handle(server, MAX_LINE).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    fn get() -> Command {
        Command::ItemGet {
            vault: None,
            query: vec!["github".into()],
            otp: false,
        }
    }

    async fn set_up(dir: &std::path::Path) -> Arc<Agent> {
        let agent = Agent::new(test_paths(dir), true, deadbolt_store::KdfParams::DEFAULT);
        agent
            .setup(Zeroizing::new("test".into()), "laptop".into())
            .await
            .unwrap();
        let vault = ask(
            &agent,
            Command::VaultCreate {
                name: "personal".into(),
            },
        )
        .await;
        assert!(matches!(vault, Message::Ok { .. }), "{vault:?}");
        let made = ask(
            &agent,
            Command::ItemNew {
                vault: None,
                kind: "login".into(),
                name: Some("github".into()),
                fields: vec![
                    FieldInput {
                        name: "username".into(),
                        kind: None,
                        value: "kit".into(),
                    },
                    FieldInput {
                        name: "password".into(),
                        kind: None,
                        value: SECRET.into(),
                    },
                ],
            },
        )
        .await;
        assert!(matches!(made, Message::Ok { .. }), "{made:?}");
        agent
    }

    fn stored(agent: &Agent) -> Vec<ActivityEntry> {
        match agent.activity_list(None, None, None).unwrap() {
            Reply::Activity { entries } => entries,
            other => panic!("expected activity, got {other:?}"),
        }
    }

    /// Entries name what was asked for and touched; the values themselves,
    /// written or read, never reach the store.
    #[tokio::test]
    async fn activity_never_stores_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let agent = set_up(dir.path()).await;
        let read = ask(&agent, get()).await;
        let Message::Ok {
            reply: Reply::Item { item },
        } = read
        else {
            panic!("expected the item, got {read:?}");
        };
        assert!(item.fields.iter().any(|f| f.value == SECRET));

        let rows = agent
            .with(|s| Ok(s.store.activity_list(0, None, 100)?))
            .unwrap()
            .rows;
        assert_eq!(rows.len(), 3);
        for row in &rows {
            let text = String::from_utf8_lossy(&row.bytes);
            assert!(!text.contains(SECRET), "a value was stored: {text}");
            assert!(!text.contains("\"kit\""), "a value was stored: {text}");
        }
        let entries = stored(&agent);
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
        let agent = set_up(dir.path()).await;
        let origin = "https://signup.example.com".to_string();
        let generate = Command::SiteGenerate {
            origin: origin.clone(),
            field: SiteField::default(),
        };
        let made = ask(&agent, generate.clone()).await;
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
        let kept = ask(&agent, keep.clone()).await;
        assert!(matches!(kept, Message::Ok { .. }), "{kept:?}");

        // As the browser host: the same commands, with the replies they got.
        for (command, result) in [(&generate, Ok(reply)), (&keep, Ok(Reply::Done))] {
            let draft = draft(command, CallerClass::BrowserHost).expect("recorded");
            agent.record(draft.finish(caller::nobody(), session::now(), &result));
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

        let rows = agent
            .with(|s| Ok(s.store.activity_list(0, None, 100)?))
            .unwrap()
            .rows;
        for row in &rows {
            let text = String::from_utf8_lossy(&row.bytes);
            assert!(!text.contains(&password), "the password was stored: {text}");
            assert!(!text.contains(&id), "its id was stored: {text}");
        }
        let entries = stored(&agent);
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
        let agent = set_up(dir.path()).await;
        agent.lock().await;
        let refused = ask(&agent, get()).await;
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
        assert_eq!(agent.activity.lock().unwrap().held_len(), 1);

        agent
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        assert!(agent.activity.lock().unwrap().held_len() == 0);
        let entries = stored(&agent);
        assert_eq!(entries[0].command, "item-get");
        assert_eq!(entries[0].outcome, Outcome::Locked);
        assert_eq!(entries[0].items[0].title, "github");

        agent.lock().await;
        agent
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        assert_eq!(stored(&agent).len(), entries.len(), "stored once");
    }

    /// The app's own requests aren't entries, and only the app may report.
    #[tokio::test]
    async fn the_app_reports_and_callers_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let agent = set_up(dir.path()).await;
        let report = Command::ActivityReport {
            action: AppAction::Copy,
            vault: None,
            item: "i1".into(),
            title: "github".into(),
            field: "password".into(),
        };
        let caller = agent
            .callers
            .identify(Err(std::io::ErrorKind::Other.into()), None);
        assert!(agent.report(&caller, report.clone()).is_err());
        let mut app = caller;
        app.class = CallerClass::App;
        assert!(draft(&get(), CallerClass::App).is_none());
        agent.report(&app, report).unwrap();
        let entries = stored(&agent);
        assert_eq!(entries[0].command, "copy");
        assert_eq!(entries[0].fields, ["password"]);
    }

    /// A client reading Activity on every change (the app, a caller's
    /// dashboard) adds no entries, so it can't wake itself again.
    #[tokio::test]
    async fn reading_activity_is_never_an_entry() {
        let dir = tempfile::tempdir().unwrap();
        let agent = set_up(dir.path()).await;
        let before = stored(&agent);
        let changes = agent.watchers.subscribe(false);
        for _ in 0..5 {
            let list = Command::ActivityList {
                since: None,
                limit: None,
                before: None,
            };
            let read = ask(&agent, list).await;
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
        assert_eq!(stored(&agent), before);
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

    /// The entry is written before the reply: a client that never reads
    /// it, and the agent cancelling the connection as it stops, lose
    /// nothing.
    #[tokio::test]
    async fn an_entry_is_kept_when_its_reply_never_goes() {
        let dir = tempfile::tempdir().unwrap();
        let agent = set_up(dir.path()).await;
        // A reply too big for the socket's buffers waits on a reader.
        let big = "x".repeat(4 << 20);
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut line = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            claimed: None,
            command: Command::ItemNew {
                vault: None,
                kind: "note".into(),
                name: Some("big".into()),
                fields: vec![FieldInput {
                    name: "notes".into(),
                    kind: None,
                    value: big.clone(),
                }],
            },
        })
        .unwrap();
        line.push(b'\n');
        let handled = tokio::spawn(agent.clone().handle(server, MAX_LINE));
        client.write_all(&line).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        handled.await.unwrap().unwrap();
        let before = stored(&agent).len();

        let (server, client) = UnixStream::pair().unwrap();
        let mut line = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            claimed: None,
            command: Command::ItemGet {
                vault: None,
                query: vec!["big".into()],
                otp: false,
            },
        })
        .unwrap();
        line.push(b'\n');
        let (mut read, mut write) = client.into_split();
        write.write_all(&line).await.unwrap();
        let handled = tokio::spawn(agent.clone().handle(server, MAX_LINE));
        // The reply has started, and stalls on a client that reads no more.
        let mut first = [0u8; 1];
        read.read_exact(&mut first).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!handled.is_finished(), "the reply should be waiting");
        handled.abort();
        assert!(handled.await.unwrap_err().is_cancelled());

        let entries = stored(&agent);
        assert_eq!(entries.len(), before + 1);
        assert_eq!(entries[0].command, "item-get");
        assert_eq!(entries[0].items[0].title, "big");
        drop((read, write));
    }

    /// Past its limit, a caller's requests come back as one entry saying
    /// how many, once its window ends, or as the agent locks.
    #[tokio::test]
    async fn a_flood_of_requests_folds_into_one_entry() {
        let dir = tempfile::tempdir().unwrap();
        let agent = set_up(dir.path()).await;
        let before = stored(&agent).len();
        for _ in 0..ledger::PER_ANCHOR + 40 {
            let read = ask(&agent, get()).await;
            assert!(matches!(read, Message::Ok { .. }), "{read:?}");
        }
        // The setup's own requests count against the same anchor.
        let listed = stored(&agent).len() - before;
        assert_eq!(listed + before, ledger::PER_ANCHOR as usize);
        agent.lock().await;
        agent
            .unlock(Zeroizing::new("test".into()), None)
            .await
            .unwrap();
        let entries = stored(&agent);
        assert_eq!(entries[0].command, ledger::PAST_LIMIT);
        assert_eq!(
            entries[0].more as usize,
            ledger::PER_ANCHOR as usize + 40 - listed
        );
        assert_eq!(entries.len(), ledger::PER_ANCHOR as usize + 1);
    }

    /// A list is clamped to `MAX_LIMIT` entries, and pages back by id.
    #[tokio::test]
    async fn lists_are_clamped_and_paged() {
        let dir = tempfile::tempdir().unwrap();
        let agent = set_up(dir.path()).await;
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
        agent
            .with(|s| {
                let rows = rows.iter().map(|(t, b)| (*t, b.as_slice()));
                Ok(s.store.activity_append(rows, 0, BUDGET)?)
            })
            .unwrap();
        let Reply::Activity { entries } = agent.activity_list(None, Some(u32::MAX), None).unwrap()
        else {
            panic!("expected activity");
        };
        assert_eq!(entries.len(), MAX_LIMIT as usize);
        let last = entries.last().unwrap().id;
        let Reply::Activity { entries: older } = agent
            .activity_list(None, Some(u32::MAX), Some(last))
            .unwrap()
        else {
            panic!("expected activity");
        };
        assert!(older.iter().all(|e| e.id < last));
        assert_eq!(older.len(), 12, "the 10 more, then the setup's 2");
    }
}
