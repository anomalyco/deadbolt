//! The Activity list (`docs/design.md`, "Callers"): the entry each caller
//! request makes, and each of the app's own reveals and copies, naming items
//! and fields, never values. [`ledger`] keeps all of it in budget; the host
//! stores the entries.

pub mod ledger;

use anyhow::Result;
use deadbolt_proto::daemon::{
    ActivityEntry, ActivityItem, AppAction, CallerClass, CallerInfo, Command, ErrorCode, Fill,
    FormKind, Outcome, Purpose, Reference, Reply, Tier,
};

pub use ledger::Ledger;

/// How long entries are kept.
pub const KEEP_SECS: u64 = 90 * 24 * 60 * 60;

/// The tier of every command, so a new one doesn't compile until it has one.
pub fn tier(command: &Command) -> Tier {
    use Command as C;
    match command {
        C::Status
        | C::Stop
        | C::Lock
        | C::AppActivate { .. }
        | C::RemoteSync { .. }
        | C::Sync { .. }
        | C::Generate { .. }
        // Sends never touch the vault: the client sealed what it shares.
        | C::SendCreate { .. }
        | C::SendList
        | C::SendShow { .. }
        | C::SendRevoke { .. }
        | C::SendWait { .. }
        | C::ActivityReport { .. }
        | C::SshGenerate { .. }
        | C::SshInspect { .. }
        | C::RunTaint
        | C::RunUntaint { .. } => Tier::Always,
        C::Setup { .. }
        | C::Unlock { .. }
        | C::UnlockBiometric { .. }
        | C::TouchIdSet { .. }
        | C::VaultCreate { .. }
        | C::VaultRename { .. }
        | C::VaultDefault { .. }
        | C::DeviceRemove { .. }
        | C::DeviceRemoveStolen { .. }
        | C::VaultConfirmReinstated { .. }
        | C::RecoveryRotate { .. }
        | C::RemoteSet { .. }
        | C::RemoteRemove { .. }
        | C::Recover { .. }
        | C::Join { .. }
        | C::Pair { .. }
        | C::ItemRemove { .. }
        | C::Import { .. }
        | C::BreachChecksSet { .. } => Tier::Never,
        C::Watch { .. }
        | C::VaultList
        | C::Devices { .. }
        | C::VaultStatus { .. }
        | C::RemoteShow { .. }
        | C::ItemList { .. }
        | C::TagList { .. }
        | C::ActivityList { .. }
        | C::Health { .. } => Tier::Look,
        C::ItemNew { .. } => Tier::Add,
        C::ItemGet { .. } | C::ItemCode { .. } => Tier::Read,
        // Adding a field or editing a plain one will be Add (build order 6).
        C::ItemSet { .. }
        | C::ItemUnset { .. }
        // A restored login fills on its sites again.
        | C::ItemRestore { .. }
        | C::HealthIgnore { .. } => Tier::Write,
        C::SiteLogins { .. }
        | C::SiteFill { .. }
        | C::SiteGenerateCheck { .. }
        | C::SiteGenerate { .. }
        | C::SiteGenerateKeep { .. }
        | C::SiteGenerateDrop { .. }
        | C::SiteCheck { .. }
        | C::SiteSave { .. }
        | C::SiteLink { .. }
        | C::SiteRecipe { .. }
        | C::FormItems { .. }
        | C::FormFill { .. }
        | C::PasskeyList { .. }
        | C::PasskeyCreate { .. }
        | C::PasskeyGet { .. }
        | C::AutofillStatus
        | C::AutofillIdentities
        | C::AutofillList { .. }
        | C::AutofillFill { .. }
        | C::AutofillPasskeyGet { .. }
        | C::AutofillPasskeyCreate { .. } => Tier::Browser,
        C::Resolve { purpose, .. } => match purpose {
            Purpose::Run | Purpose::Inject => Tier::Use,
            Purpose::Read => Tier::Read,
        },
    }
}

/// The command an entry names: its wire name, a resolve's with its purpose.
pub fn entry_name(command: &Command) -> &'static str {
    match command {
        Command::Resolve { purpose, .. } => match purpose {
            Purpose::Run => "resolve-run",
            Purpose::Inject => "resolve-inject",
            Purpose::Read => "resolve-read",
        },
        command => command.name(),
    }
}

/// An entry being written: what the request named, before it ran.
pub struct Draft {
    tier: Tier,
    command: &'static str,
    items: Vec<ActivityItem>,
    fields: Vec<String>,
    /// The browser filling a form: an entry only for a card, not for an
    /// identity's address and contact details.
    cards_only: bool,
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

/// One item, named by text, in no vault: a page or a name a request gave.
fn titled(title: &str) -> Vec<ActivityItem> {
    vec![ActivityItem {
        vault: None,
        id: None,
        title: title.into(),
    }]
}

fn login(vault: &str, item: &str, title: &str) -> Vec<ActivityItem> {
    vec![ActivityItem {
        vault: Some(vault.into()),
        id: Some(item.into()),
        title: title.into(),
    }]
}

/// Adds `value` to `list` unless it is already there.
fn push_once<T: PartialEq>(list: &mut Vec<T>, value: T) {
    if !list.contains(&value) {
        list.push(value);
    }
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
/// copies); the `status` every command starts with and the `watch` and
/// `app-activate` that follow from it; the browser host's look-ups, which
/// come with every page (and its generator checks and drops, asked before
/// anyone chose a password, and its form look-ups); and its form fills from
/// an identity (a card fill is an entry; see [`Draft::recorded`]).
///
/// Anything else the browser host asks is recorded as a caller's would be:
/// its class rests on arguments a process can rewrite, so it never hides a
/// request. Reading Activity is never an entry, so a client that reads it on
/// every change can't feed itself.
pub fn draft(command: &Command, class: CallerClass) -> Option<Draft> {
    if matches!(command, Command::ActivityList { .. }) {
        return None;
    }
    // Secrets for commands are entries from anyone.
    let daemon = matches!(command, Command::Resolve { .. });
    // What a class asks without it being a request of its own.
    let quiet = match class {
        CallerClass::App => true,
        CallerClass::BrowserHost => matches!(
            command,
            Command::Status
                | Command::Watch { .. }
                | Command::AppActivate { .. }
                | Command::SiteLogins { .. }
                | Command::SiteCheck { .. }
                | Command::FormItems { .. }
                | Command::PasskeyList { .. }
                | Command::SiteGenerateCheck { .. }
                | Command::SiteGenerateDrop { .. }
        ),
        CallerClass::AutoFill => matches!(
            command,
            Command::Status
                | Command::Watch { .. }
                | Command::AppActivate { .. }
                | Command::AutofillStatus
                | Command::AutofillIdentities
                | Command::AutofillList { .. }
        ),
        CallerClass::Caller => matches!(
            command,
            Command::Status | Command::Watch { .. } | Command::AppActivate { .. }
        ),
    };
    if quiet && !daemon {
        return None;
    }
    let (tier, name) = (tier(command), entry_name(command));
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
        | Command::ItemRemove { vault, query }
        | Command::ItemRestore { vault, query } => (named(vault, query), Vec::new()),
        Command::ItemCode { vault, query } => (named(vault, query), vec!["otp".into()]),
        Command::ItemSet {
            vault,
            query,
            fields,
            unset,
            favorite,
            add_tags,
            remove_tags,
            ..
        } => {
            let mut names: Vec<String> = fields
                .iter()
                .map(|f| f.name.clone())
                .chain(unset.iter().cloned())
                .collect();
            if favorite.is_some() {
                names.push("favorite".into());
            }
            if !add_tags.is_empty() || !remove_tags.is_empty() {
                names.push("tags".into());
            }
            (named(vault, query), names)
        }
        Command::ItemUnset {
            vault,
            query,
            field,
        } => (named(vault, query), vec![field.clone()]),
        Command::HealthIgnore {
            vault, query, kind, ..
        } => (named(vault, query), vec![kind.as_str().into()]),
        // The page or app the browser host looked at, and the login it filled:
        // the login's, under that page.
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
                .unwrap_or_else(|| titled(title)),
            vec!["username".into(), "password".into()],
        ),
        // The new login, then the provider login it signs in with.
        Command::SiteLink {
            title,
            provider,
            account,
            ..
        } => (
            titled(title)
                .into_iter()
                .chain(login(&account.vault, &account.item, provider))
                .collect(),
            vec!["sign-in-with".into()],
        ),
        // The login a form was taught to (or forgotten from), under its page.
        Command::SiteRecipe {
            origin,
            login: target,
            ..
        } => (
            login(&target.vault, &target.item, origin),
            vec![deadbolt_core::site_recipe::RECIPE_FIELD.into()],
        ),
        Command::PasskeyGet {
            origin, passkey, ..
        } => (login(&passkey.vault, &passkey.item, origin), Vec::new()),
        Command::FormItems { origin, .. } | Command::PasskeyCreate { origin, .. } => {
            (titled(origin), Vec::new())
        }
        Command::FormFill {
            origin,
            item,
            fields,
        } => (login(&item.vault, &item.item, origin), fields.clone()),
        Command::AutofillFill {
            service,
            login: target,
            want,
            ..
        } => {
            let page = service
                .as_ref()
                .map_or("unassociated app", |s| s.identifier.as_str());
            (
                login(&target.vault, &target.item, page),
                want.iter().map(fill_name).collect(),
            )
        }
        Command::AutofillPasskeyGet { rp_id, passkey, .. } => (
            login(&passkey.vault, &passkey.item, rp_id),
            vec!["passkey".into()],
        ),
        Command::AutofillPasskeyCreate { rp_id, .. } => (titled(rp_id), vec!["passkey".into()]),
        // The items and fields named, as given; the reply names what was
        // found. Never a value.
        Command::Resolve { refs, .. } => {
            let mut items: Vec<ActivityItem> = Vec::new();
            let mut fields: Vec<String> = Vec::new();
            for reference in refs {
                let Ok(reference) = Reference::parse(reference) else {
                    continue;
                };
                let item = ActivityItem {
                    vault: reference.vault.clone(),
                    id: None,
                    title: reference.item.clone(),
                };
                push_once(&mut items, item);
                push_once(&mut fields, reference.field);
            }
            (items, fields)
        }
        // The page, and that a password was made for it: never the password
        // or its id.
        Command::SiteGenerate { origin, .. }
        | Command::SiteGenerateKeep { origin, .. }
        | Command::SiteGenerateCheck { origin, .. }
        | Command::SiteGenerateDrop { origin, .. } => (titled(origin), vec!["password".into()]),
        _ => (Vec::new(), Vec::new()),
    };
    Some(Draft {
        tier,
        command: name,
        items,
        fields,
        cards_only: class == CallerClass::BrowserHost
            && matches!(command, Command::FormFill { .. }),
    })
}

impl Draft {
    /// Whether the request, answered with `result`, is an entry: all are
    /// but the browser's form fills from an identity.
    pub fn recorded(&self, result: &Result<Reply>) -> bool {
        !(self.cards_only
            && matches!(result, Ok(Reply::FormFill { kind, .. }) if *kind != FormKind::Card))
    }

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
            Err(error) => match crate::code(error) {
                Some(ErrorCode::Locked) => Outcome::Locked,
                Some(ErrorCode::Forbidden | ErrorCode::RateLimited) => Outcome::Refused,
                _ => Outcome::Failed,
            },
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
                // The saved login takes the first place; any login it names (a link's account) stays.
                let rest = self.items.split_off(self.items.len().min(1));
                self.items = login(&saved.vault, &saved.item, &title);
                self.items.extend(rest);
            }
            // Which card, on which page: "Visa •••• 4242 · https://shop.com".
            Reply::FormFill { title, .. } => {
                if let Some(item) = self.items.first_mut() {
                    item.title = format!("{title} · {}", item.title);
                }
            }
            Reply::Secrets { secrets } => {
                self.items.clear();
                self.fields.clear();
                for secret in secrets {
                    let item = ActivityItem {
                        vault: Some(secret.vault.clone()),
                        id: Some(secret.item.clone()),
                        title: secret.title.clone(),
                    };
                    push_once(&mut self.items, item);
                    push_once(&mut self.fields, secret.field.clone());
                }
            }
            Reply::PasskeyCreated { passkey, .. }
            | Reply::AutofillPasskeyCreated { passkey, .. } => {
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
