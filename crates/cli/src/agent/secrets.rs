//! Secrets for commands (`docs/agent-control.md`, "Use, don't read"):
//! `resolve` finds the fields secret references name, for `deadbolt run`,
//! `inject` and `read`, and the standing grants that let AI callers use
//! them without asking.
//!
//! Callers that don't look like an AI get what they name while the vault
//! is unlocked, as with `deadbolt get`. A caller that does (an AI host
//! among its parents, or a claimed OpenCode session) needs a live grant
//! covering every item, field and purpose for `run` and `inject`, and Touch
//! ID each time for `read`, which no grant covers. Ancestry is a hint (an AI
//! can start a terminal outside its tree), so this keeps honest AIs on the
//! safe path; it doesn't stop a determined one.
//!
//! Grants live in this device's encrypted store, never in a vault, as the
//! agent sign-in grants do (`grants.rs`), and name items by id, so a rename
//! keeps them.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::totp::Totp;
use deadbolt_core::{FieldType, Item, VaultId};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::items::{self, Listing, label};
use super::session::{self, Loaded, get_json, set_json};
use super::{Agent, Conversation, ErrorCode, caller, fail};
use crate::browser::host::Bucket;
use crate::client::AgentError;
use crate::items::line;
use crate::protocol::{
    CallerClass, CallerInfo, Command, Purpose, Reference, Reply, ResolvedSecret, Secret,
    SecretGrantInfo, Verify,
};

const META_GRANTS: &str = "cli/secret-grants";
/// The most grants kept, so a store can't fill up with them.
const MAX_GRANTS: usize = 256;
/// The most references one `resolve` names.
const MAX_REFS: usize = 256;
/// What one AI caller (by anchor) may resolve: a burst of 20, then one a
/// second. That bounds what it learns about items by trying names, and
/// how often a `read` can raise Touch ID.
const AI_RATE: (u32, Duration) = (20, Duration::from_secs(1));
/// What all AI callers together may resolve, so making up a claimed
/// session per request doesn't help.
const ALL_AI_RATE: (u32, Duration) = (60, Duration::from_millis(500));
/// The most anchors' limits kept.
const MAX_RATES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Grant {
    id: String,
    /// The vault's id.
    vault: String,
    vault_name: String,
    /// The item's id.
    item: String,
    title: String,
    /// Every field when empty.
    fields: Vec<String>,
    purposes: Vec<Purpose>,
    created: u64,
    expires_at: Option<u64>,
}

impl Grant {
    fn live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|at| now < at)
    }

    fn covers(&self, found: &Found, purpose: Purpose, now: u64) -> bool {
        self.live(now)
            && self.vault == found.vault_id
            && self.item == found.secret.item
            && self.purposes.contains(&purpose)
            && (self.fields.is_empty() || self.fields.contains(&found.secret.field))
    }

    fn info(&self, now: u64) -> SecretGrantInfo {
        SecretGrantInfo {
            id: self.id.clone(),
            vault: self.vault_name.clone(),
            item: self.item.clone(),
            title: self.title.clone(),
            fields: self.fields.clone(),
            purposes: self.purposes.clone(),
            created: self.created,
            expires_at: self.expires_at,
            expired: !self.live(now),
        }
    }
}

fn grants(s: &Loaded) -> Result<Vec<Grant>> {
    Ok(get_json(&s.store, META_GRANTS)?.unwrap_or_default())
}

/// One reference, found: the vault's id beside what the caller gets.
pub struct Found {
    vault_id: String,
    ssh_secret: bool,
    pub secret: ResolvedSecret,
}

/// The one item in `vault` that `query` names: its title (any case), its
/// whole id or an id prefix of at least 4 characters. None or several is
/// an error, listing the candidates by short id.
fn item(s: &Loaded, vault: VaultId, query: &str) -> Result<Item> {
    let listing = Listing::new(s.vault(&vault));
    let lower = query.trim().to_lowercase();
    let hex = lower.len() >= 4 && lower.bytes().all(|b| b.is_ascii_hexdigit());
    let found: Vec<&Item> = listing
        .items
        .iter()
        .filter(|item| {
            label(item).to_lowercase() == lower || (hex && item.id.to_string().starts_with(&lower))
        })
        .collect();
    let vault_name = s.vault(&vault).name();
    match found.as_slice() {
        [item] => Ok((*item).clone()),
        [] => Err(fail(
            ErrorCode::NotFound,
            format!("no item titled {query:?} (or with that id) in vault {vault_name}"),
        )),
        many => {
            let mut lines: Vec<String> = many
                .iter()
                .map(|item| line(&listing.info(item, false, false)))
                .collect();
            lines.sort();
            Err(fail(
                ErrorCode::Failed,
                format!(
                    "{query:?} names {} items in vault {vault_name}; use its short id instead:\n{}",
                    many.len(),
                    lines.join("\n")
                ),
            ))
        }
    }
}

/// The value `reference` names at `now`: a one-time password field gives
/// its current code, never its secret.
pub fn find(s: &Loaded, reference: &Reference, now: Duration) -> Result<Found> {
    let vault = s.resolve(reference.vault.as_deref())?;
    let item = item(s, vault, &reference.item)?;
    let title = label(&item);
    let field = item
        .fields
        .get(&reference.field)
        .filter(|_| !super::passkeys::private(&item, &reference.field));
    let Some(field) = field else {
        let names: Vec<&str> = item
            .fields
            .keys()
            .map(String::as_str)
            .filter(|name| !super::passkeys::private(&item, name))
            .collect();
        return Err(fail(
            ErrorCode::NotFound,
            format!(
                "{title} has no field {:?}; its fields are {}",
                reference.field,
                names.join(", ")
            ),
        ));
    };
    let value = match field.kind {
        FieldType::Otp => {
            let totp = Totp::parse(&field.value)
                .map_err(|e| anyhow!("the one-time password of {title} is invalid: {e}"))?;
            Zeroizing::new(totp.code(now.as_secs()))
        }
        _ => Zeroizing::new(field.value.clone()),
    };
    if value.is_empty() {
        bail!("{title} › {} is empty", reference.field);
    }
    Ok(Found {
        vault_id: vault.to_string(),
        ssh_secret: item.kind == "ssh"
            && matches!(reference.field.as_str(), "private-key" | "passphrase"),
        secret: ResolvedSecret {
            vault: s.vault(&vault).name().into(),
            item: item.id.to_string(),
            title,
            field: reference.field.clone(),
            value: Secret::new(value.as_str()),
            file: field.kind == FieldType::File,
        },
    })
}

/// What `secret-grant-set` asks for.
pub struct NewGrants<'a> {
    pub vault: Option<&'a str>,
    pub items: &'a [String],
    pub fields: &'a [String],
    pub purposes: &'a [Purpose],
    pub expires_at: Option<u64>,
}

/// Sets one grant per item, replacing an item's earlier grant.
pub fn set_grants(s: &Loaded, new: NewGrants, now: u64) -> Result<Vec<SecretGrantInfo>> {
    if new.items.is_empty() {
        bail!("name at least one item");
    }
    let mut purposes: Vec<Purpose> = Vec::new();
    for purpose in new.purposes {
        if *purpose == Purpose::Read {
            bail!("no grant covers reading a value: an AI needs Touch ID for each read");
        }
        if !purposes.contains(purpose) {
            purposes.push(*purpose);
        }
    }
    if purposes.is_empty() {
        bail!("a grant needs a purpose: run, inject or both");
    }
    let mut fields: Vec<String> = Vec::new();
    for field in new.fields {
        let field = field.trim();
        if field.is_empty() {
            bail!("a field name can't be empty");
        }
        if !fields.iter().any(|f| f == field) {
            fields.push(field.to_string());
        }
    }
    if new.expires_at.is_some_and(|at| at <= now) {
        bail!("that expiry has passed already");
    }
    let vault = s.resolve(new.vault)?;
    let vault_name = s.vault(&vault).name().to_string();
    let mut all = grants(s)?;
    let mut made = Vec::new();
    for query in new.items {
        let item = item(s, vault, query)?;
        let (vault_id, item_id) = (vault.to_string(), item.id.to_string());
        let id = match all
            .iter()
            .find(|g| g.vault == vault_id && g.item == item_id)
        {
            Some(old) => old.id.clone(),
            None => super::grants::random_hex::<8>()?,
        };
        all.retain(|g| !(g.vault == vault_id && g.item == item_id));
        if all.len() >= MAX_GRANTS {
            bail!("{MAX_GRANTS} secret grants exist already; revoke some first");
        }
        let grant = Grant {
            id,
            vault: vault_id,
            vault_name: vault_name.clone(),
            item: item_id,
            title: label(&item),
            fields: fields.clone(),
            purposes: purposes.clone(),
            created: now,
            expires_at: new.expires_at,
        };
        made.push(grant.info(now));
        all.push(grant);
    }
    set_json(&s.store, META_GRANTS, &all)?;
    Ok(made)
}

pub fn list_grants(s: &Loaded, now: u64) -> Result<Vec<SecretGrantInfo>> {
    Ok(grants(s)?.iter().map(|g| g.info(now)).collect())
}

/// Removes a grant by id (or a unique prefix of at least 4 characters).
pub fn remove_grant(s: &Loaded, id: &str) -> Result<()> {
    let mut all = grants(s)?;
    let id = super::grants::pick(all.iter().map(|g| g.id.as_str()), id, "grant")?;
    all.retain(|g| g.id != id);
    set_json(&s.store, META_GRANTS, &all)?;
    Ok(())
}

/// Which of `found` no live grant covers for `purpose`.
fn uncovered<'a>(
    s: &Loaded,
    found: &'a [Found],
    purpose: Purpose,
    now: u64,
) -> Result<Vec<&'a Found>> {
    let all = grants(s)?;
    Ok(found
        .iter()
        .filter(|f| !all.iter().any(|g| g.covers(f, purpose, now)))
        .collect())
}

/// What an AI may never do: the Never tier (docs/agent-control.md,
/// "Tiers"), and the browser's fills and saves, which are the browser
/// host's alone (any same-user process can send them, so an AI is refused
/// them here until browser pairing). `None` for anything else.
fn refused(command: &Command) -> Option<&'static str> {
    Some(match command {
        Command::SiteFill { .. } => "fill a site's login",
        Command::SiteSave { login: Some(_), .. } => "change a saved login",
        Command::FormFill { .. } => "fill a form",
        Command::PasskeyGet { .. } => "sign in with a passkey",
        Command::PasskeyCreate { .. } => "save a passkey",
        Command::Setup { .. } => "set Deadbolt up",
        Command::Unlock { .. } | Command::UnlockBiometric { .. } => "unlock Deadbolt",
        Command::TouchIdSet { .. } => "turn Touch ID unlock on or off",
        Command::VaultCreate { .. } => "create a vault",
        Command::VaultRename { .. } => "rename a vault",
        Command::VaultDefault { .. } => "change the default vault",
        Command::DeviceRemove { .. } => "remove a device",
        Command::Join { .. } => "join a vault",
        Command::Pair { .. } => "approve a device",
        Command::ItemRemove { .. } => "delete an item",
        Command::Import { .. } => "import items",
        Command::SyncOnePassword { .. } => "sync from 1Password",
        Command::SshAgentSet { .. } => "turn the SSH agent on or off",
        _ => return None,
    })
}

/// "personal › GitHub › token".
fn named(found: &Found) -> String {
    format!(
        "{} › {} › {}",
        found.secret.vault, found.secret.title, found.secret.field
    )
}

/// The reference that names `found`, by vault and title.
fn reference_of(found: &Found) -> String {
    format!(
        "deadbolt://{}/{}/{}",
        found.secret.vault, found.secret.title, found.secret.field
    )
}

fn not_granted(missing: &[&Found], purpose: Purpose) -> anyhow::Error {
    let names: Vec<String> = missing.iter().map(|f| named(f)).collect();
    let mut items: Vec<String> = missing
        .iter()
        .map(|f| format!("'{}'", f.secret.title.replace('\'', "'\\''")))
        .collect();
    items.dedup();
    let mut fields: Vec<&str> = missing.iter().map(|f| f.secret.field.as_str()).collect();
    fields.sort_unstable();
    fields.dedup();
    let vault = &missing[0].secret.vault;
    AgentError {
        code: ErrorCode::NotGranted,
        message: format!(
            "AI agents aren't allowed to {} {}: run `deadbolt agents allow-secrets --vault {vault} {} --fields {} --purpose {}` yourself to allow it",
            if purpose == Purpose::Run {
                "run commands with"
            } else {
                "inject"
            },
            names.join(", "),
            items.join(" "),
            fields.join(","),
            purpose.as_str()
        ),
        grant: None,
        passkeys: None,
    }
    .into()
}

impl Agent {
    /// Takes one of an AI caller's `resolve`s against its rate limits.
    fn ai_rate(&self, caller: &CallerInfo) -> Result<()> {
        let now = std::time::Instant::now();
        let mut rates = self.resolve_rates.lock().unwrap_or_else(|e| e.into_inner());
        if rates.len() >= MAX_RATES {
            rates.clear();
        }
        let mine = rates
            .entry(super::activity::anchor(caller))
            .or_insert_with(|| Bucket::new(AI_RATE, now))
            .take(now);
        let all = mine
            && rates
                .entry("*".into())
                .or_insert_with(|| Bucket::new(ALL_AI_RATE, now))
                .take(now);
        if !all {
            return Err(fail(
                ErrorCode::RateLimited,
                "too many references resolved by AI agents; try again shortly",
            ));
        }
        Ok(())
    }

    /// The stop-gap for a caller that looks like an AI (#111), until
    /// `policy::decide` (docs/agent-control.md, build order 3): a value it
    /// would be shown (`item-get`, `item-code`) asks for Touch ID every
    /// time, as `resolve … read` does, and the Never tier and the browser's
    /// fills and saves are refused. Other callers, the app, the browser host
    /// and AutoFill pass unchanged, and so do agent clients' sign-ins
    /// (`agent-fill` and the rest), which their token authenticates.
    pub(super) async fn ai_gate(
        &self,
        caller: &CallerInfo,
        command: &Command,
        conv: &Conversation,
    ) -> Result<()> {
        if caller.class != CallerClass::Caller || !caller::is_ai(caller) {
            return Ok(());
        }
        let (vault, query, deleted, what) = match command {
            Command::ItemGet {
                vault,
                query,
                deleted,
                ..
            } => (vault, query, *deleted, ""),
            Command::ItemCode { vault, query } => (vault, query, false, "the one-time code of "),
            command => {
                return match refused(command) {
                    Some(what) => Err(fail(
                        ErrorCode::Forbidden,
                        format!(
                            "an AI agent can't {what}. {}.",
                            caller::not_from_here(caller)
                        ),
                    )),
                    None => Ok(()),
                };
            }
        };
        self.ai_rate(caller)?;
        // Locked, or a query that finds nothing, fails before anyone is
        // asked anything.
        let item = self.with(|s| items::named(s, vault.as_deref(), query, deleted))?;
        let reason = format!("show {what}{item} to an AI agent");
        self.ai_touch_id(caller, conv, &reason).await
    }

    /// Touch ID for an AI's read, raised by the agent with its own
    /// `reason`. Off, not set up, cancelled or denied, the read is
    /// `forbidden`, saying why and where to go instead.
    async fn ai_touch_id(
        &self,
        caller: &CallerInfo,
        conv: &Conversation,
        reason: &str,
    ) -> Result<()> {
        if !self.can_verify() {
            return Err(fail(
                ErrorCode::Forbidden,
                format!(
                    "an AI agent can see a value only with Touch ID each time, which is off or not set up here: use `deadbolt run` or `deadbolt inject` with a grant instead. {}.",
                    caller::not_from_here(caller)
                ),
            ));
        }
        // Waiting on the finger mustn't let the idle lock fire.
        let _busy = self.busy();
        match self.verify_user(conv, Verify::Required, reason).await {
            Ok(_) => Ok(()),
            // Locked while waiting, say, stays what it is.
            Err(error) if error.downcast_ref::<AgentError>().is_some() => Err(error),
            Err(error) => Err(fail(
                ErrorCode::Forbidden,
                format!("{error:#}: the value wasn't shown to the AI agent"),
            )),
        }
    }

    /// Answers `resolve`: the values `refs` name, if `caller` may have them
    /// for `purpose`.
    pub(super) async fn resolve(
        &self,
        caller: &CallerInfo,
        refs: &[String],
        purpose: Purpose,
        conv: &Conversation,
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
        let ai = caller::is_ai(caller);
        if ai {
            self.ai_rate(caller)?;
        }
        let lookup = |s: &Loaded| -> Result<Vec<Found>> {
            let now = crate::config::wall_clock();
            parsed.iter().map(|r| find(s, r, now)).collect()
        };
        // Locked, or a reference that names nothing, fails before anyone
        // is asked anything.
        let mut found = self.with(|s| lookup(s))?;
        // A file goes only into a file `inject` writes; an environment
        // variable or a printed value is text.
        if purpose != Purpose::Inject
            && let Some(file) = found.iter().find(|f| f.secret.file)
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
        if purpose != Purpose::Read
            && let Some(ssh) = found.iter().find(|f| f.ssh_secret)
        {
            return Err(fail(
                ErrorCode::Forbidden,
                format!(
                    "{} stays in Deadbolt: use Deadbolt's SSH agent (`deadbolt ssh on`) instead",
                    named(ssh)
                ),
            ));
        }
        if ai {
            match purpose {
                Purpose::Read => {
                    let names: Vec<String> = found.iter().map(named).collect();
                    let reason = format!("show {} to an AI agent", names.join(", "));
                    self.ai_touch_id(caller, conv, &reason).await?;
                    // A one-time code may have moved on during the prompt.
                    found = self.with(|s| lookup(s))?;
                }
                Purpose::Run | Purpose::Inject => {
                    let now = session::now();
                    self.with(|s| {
                        let missing = uncovered(s, &found, purpose, now)?;
                        if missing.is_empty() {
                            Ok(())
                        } else {
                            Err(not_granted(&missing, purpose))
                        }
                    })?;
                }
            }
        }
        Ok(Reply::Secrets {
            secrets: found.into_iter().map(|f| f.secret).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use super::super::biometric;
    use crate::protocol::FieldInput;

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
        error.downcast_ref::<AgentError>().map(|e| e.code)
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
        assert_eq!(found.secret.value.expose(), "ghp_1");
        assert_eq!(
            (found.secret.vault.as_str(), found.secret.title.as_str()),
            ("personal", "GitHub")
        );
        assert_eq!(found.secret.item, github);
        let by_id = format!("deadbolt://{}/password", &github[..6]);
        assert_eq!(
            find(&s, &r(&by_id), at).unwrap().secret.value.expose(),
            "hunter2"
        );
        // A one-time password gives its current code.
        let otp = find(&s, &r("deadbolt://GitHub/otp"), at).unwrap();
        let expected = Totp::parse(OTP).unwrap().code(NOW);
        assert_eq!(otp.secret.value.expose(), expected);

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

    #[test]
    fn grants_cover_items_fields_and_purposes_until_revoked_or_expired() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        new(
            &mut s,
            "login",
            "GitHub",
            &[("password", "pw"), ("token", "t")],
        );
        new(&mut s, "login", "Stripe", &[("password", "sk")]);
        let at = Duration::from_secs(NOW);
        let token = find(&s, &r("deadbolt://GitHub/token"), at).unwrap();
        let password = find(&s, &r("deadbolt://GitHub/password"), at).unwrap();
        let stripe = find(&s, &r("deadbolt://Stripe/password"), at).unwrap();
        let all = [token, password, stripe];
        let uncovered_names = |purpose, now| -> Vec<String> {
            uncovered(&s, &all, purpose, now)
                .unwrap()
                .iter()
                .map(|f| named(f))
                .collect()
        };
        assert_eq!(uncovered_names(Purpose::Run, NOW).len(), 3);

        let items = ["github".to_string()];
        let fields = ["token".to_string()];
        let made = set_grants(
            &s,
            NewGrants {
                vault: None,
                items: &items,
                fields: &fields,
                purposes: &[Purpose::Run],
                expires_at: Some(NOW + 60),
            },
            NOW,
        )
        .unwrap();
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].title, "GitHub");
        assert_eq!(
            uncovered_names(Purpose::Run, NOW),
            [
                "personal › GitHub › password",
                "personal › Stripe › password"
            ]
        );
        // Not for inject, and not once expired.
        assert_eq!(uncovered_names(Purpose::Inject, NOW).len(), 3);
        assert_eq!(uncovered_names(Purpose::Run, NOW + 60).len(), 3);
        assert!(list_grants(&s, NOW + 60).unwrap()[0].expired);

        // Every field, both purposes; setting the item again replaces it.
        let both = set_grants(
            &s,
            NewGrants {
                vault: Some("personal"),
                items: &items,
                fields: &[],
                purposes: &[Purpose::Run, Purpose::Inject],
                expires_at: None,
            },
            NOW,
        )
        .unwrap();
        assert_eq!(both[0].id, made[0].id);
        assert_eq!(list_grants(&s, NOW).unwrap().len(), 1);
        assert_eq!(uncovered_names(Purpose::Inject, NOW).len(), 1);

        // Never read, never nothing, never an unknown item.
        let read = NewGrants {
            vault: None,
            items: &items,
            fields: &[],
            purposes: &[Purpose::Read],
            expires_at: None,
        };
        assert!(set_grants(&s, read, NOW).is_err());
        let unknown = ["Nope".to_string()];
        let missing = NewGrants {
            vault: None,
            items: &unknown,
            fields: &[],
            purposes: &[Purpose::Run],
            expires_at: None,
        };
        assert_eq!(
            code(&set_grants(&s, missing, NOW).unwrap_err()),
            Some(ErrorCode::NotFound)
        );

        remove_grant(&s, &both[0].id[..5]).unwrap();
        assert_eq!(uncovered_names(Purpose::Run, NOW).len(), 3);
        assert!(remove_grant(&s, &both[0].id).is_err());
    }

    /// An AI caller is limited by anchor; anyone else isn't.
    #[tokio::test]
    async fn ai_callers_are_rate_limited() {
        let dir = tempfile::tempdir().unwrap();
        let agent = Agent::new(
            super::super::tests::test_paths(dir.path()),
            true,
            deadbolt_store::KdfParams::DEFAULT,
        );
        agent
            .setup(Zeroizing::new("test".into()), "laptop".into())
            .await
            .unwrap();
        agent
            .with(|s| {
                s.create_vault("personal")?;
                new(s, "login", "GitHub", &[("token", "t0k3n")]);
                Ok(())
            })
            .unwrap();
        let (conv, _client, _closed) = super::super::tests::conversation();
        let refs = ["deadbolt://GitHub/token".to_string()];
        let mut ai = CallerInfo::unverified("zsh › deadbolt");
        ai.claimed = Some(crate::protocol::Claim {
            caller: None,
            opencode_session: Some("ses_1".into()),
        });
        for _ in 0..20 {
            let error = agent
                .resolve(&ai, &refs, Purpose::Run, &conv)
                .await
                .unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::NotGranted));
        }
        let error = agent
            .resolve(&ai, &refs, Purpose::Run, &conv)
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::RateLimited));
        let person = CallerInfo::unverified("zsh › deadbolt");
        for _ in 0..30 {
            assert!(
                agent
                    .resolve(&person, &refs, Purpose::Read, &conv)
                    .await
                    .is_ok()
            );
        }
    }

    /// A caller under OpenCode, by its parents.
    fn under_opencode(class: CallerClass) -> CallerInfo {
        let mut info = CallerInfo::unverified("OpenCode › zsh › deadbolt");
        info.class = class;
        info.ancestry = vec![crate::protocol::Ancestor {
            pid: 7,
            name: "opencode".into(),
            path: Some("/opt/bin/opencode".into()),
        }];
        info
    }

    /// The browser's fills and saves are refused to an AI caller, saying
    /// why and where to go; the real browser host (macOS: by signature) and
    /// an agent client's sign-ins (by token) are not this gate's to refuse.
    #[tokio::test]
    async fn the_gate_refuses_an_ai_the_browsers_fills_and_saves() {
        use crate::protocol::{ClientAuth, Fill, LoginRef, PagePassword};
        let f = super::super::passkeys::tests::agent::unlocked().await;
        let (conv, _closed) = super::super::passkeys::tests::agent::conversation();
        let login = LoginRef {
            vault: "personal".into(),
            item: "0000".into(),
        };
        let origin = || "https://github.com".to_string();
        let save = |login: Option<LoginRef>| Command::SiteSave {
            origin: origin(),
            login,
            title: "GitHub".into(),
            url: origin(),
            username: "kit".into(),
            password: PagePassword::Typed(Secret::new("pwned-pwned")),
        };
        let refused = [
            Command::SiteFill {
                origin: origin(),
                login: login.clone(),
                want: vec![Fill::Password],
            },
            save(Some(login.clone())),
            Command::FormFill {
                origin: origin(),
                item: login.clone(),
                fields: vec!["number".into()],
            },
            Command::PasskeyGet {
                origin: origin(),
                rp_id: None,
                passkey: login.clone(),
                challenge: "AAAA".into(),
                verify: Verify::Preferred,
            },
            Command::PasskeyCreate {
                origin: origin(),
                rp_id: None,
                challenge: "AAAA".into(),
                user_id: "AAAA".into(),
                user_name: "kit".into(),
                user_display_name: String::new(),
                exclude: Vec::new(),
                verify: Verify::Preferred,
            },
        ];
        let ai = under_opencode(CallerClass::Caller);
        for command in &refused {
            let error = f.agent.ai_gate(&ai, command, &conv).await.unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Forbidden), "{command:?}");
            let message = error.to_string();
            assert!(
                message.contains("This shell runs under OpenCode (OpenCode › zsh › deadbolt)")
                    && message.contains("see `deadbolt debug whoami`"),
                "{message}"
            );
        }
        let open = [
            save(None),
            Command::SiteLogins { origin: origin() },
            Command::AgentFill {
                client: ClientAuth {
                    id: "c".into(),
                    token: Secret::new("t"),
                },
                origin: origin(),
                login: login.clone(),
                want: vec![Fill::Password],
            },
        ];
        for command in &open {
            assert!(
                f.agent.ai_gate(&ai, command, &conv).await.is_ok(),
                "{command:?}"
            );
        }
        let host = under_opencode(CallerClass::BrowserHost);
        let person = CallerInfo::unverified("zsh › deadbolt");
        for command in &refused {
            assert!(f.agent.ai_gate(&host, command, &conv).await.is_ok());
            assert!(f.agent.ai_gate(&person, command, &conv).await.is_ok());
        }
    }

    /// Touch ID cancelled or denied refuses an AI's read (exit 4, refused
    /// in Activity), from the gate and from `resolve … read` alike.
    #[tokio::test]
    async fn a_cancelled_touch_id_refuses_an_ais_read() {
        let f = super::super::passkeys::tests::agent::unlocked().await;
        let (conv, _closed) = super::super::passkeys::tests::agent::conversation();
        f.agent
            .with(|s| {
                new(s, "login", "GitHub", &[("token", "t0k3n")]);
                Ok(())
            })
            .unwrap();
        let ai = under_opencode(CallerClass::Caller);
        let get = Command::ItemGet {
            vault: None,
            query: vec!["GitHub".into()],
            otp: false,
            ssh_private: false,
            files: Vec::new(),
            deleted: false,
        };
        let refs = ["deadbolt://GitHub/token".to_string()];
        // Cancelled, and refused (a lockout, say).
        for cancelled in [true, false] {
            *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                Err(if cancelled {
                    biometric::UnlockError::Cancelled
                } else {
                    biometric::UnlockError::Unavailable("biometry is locked out".into())
                })
            }));
            let error = f.agent.ai_gate(&ai, &get, &conv).await.unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Forbidden), "{error:#}");
            let error = f
                .agent
                .resolve(&ai, &refs, Purpose::Read, &conv)
                .await
                .unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Forbidden), "{error:#}");
            assert!(!format!("{error:#}").contains("t0k3n"));
        }
        // A finger lets it through.
        let key = f.key;
        *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| Ok(Zeroizing::new(key))));
        assert!(f.agent.ai_gate(&ai, &get, &conv).await.is_ok());
    }

    #[test]
    fn not_granted_says_what_to_allow_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        new(&mut s, "login", "Kit's API", &[("token", "sekrit")]);
        let found = [find(
            &s,
            &r("deadbolt://Kit's API/token"),
            Duration::from_secs(NOW),
        )
        .unwrap()];
        let missing: Vec<&Found> = found.iter().collect();
        let error = not_granted(&missing, Purpose::Inject);
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));
        let message = error.to_string();
        assert!(
            message.contains(
                "allow-secrets --vault personal 'Kit'\\''s API' --fields token --purpose inject"
            ),
            "{message}"
        );
        assert!(!message.contains("sekrit"));
    }
}
