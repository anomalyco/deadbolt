//! Mirrors 1Password into a vault with the 1Password CLI (`op`), for
//! `Command::SyncOnePassword`. 1Password is the source of truth: items new
//! there are added, changed ones are updated (only the fields that differ),
//! and ones deleted or archived there are deleted here, but only if the
//! mirror added them. An item already here is taken over rather than added
//! again only when it is plainly the same one (see [`apply`]), and keeps
//! the fields only it has.
//!
//! The daemon runs `op` itself, in the user's session where the 1Password
//! app's CLI integration works, and outside the session lock: [`known`]
//! reads what the mirror holds, [`fetch`] asks 1Password only for what
//! changed, and [`apply`] plans and writes under the lock. Values never
//! reach argv, a file or a log: `op` prints items on a pipe, ids go back to
//! it on stdin, and reports hold only titles and field names.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::{CREATE_BATCH_BYTES, Change, DataOp, Field, Item, ItemId, Source, VaultId};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

use super::items::label;
use super::session::Loaded;
use crate::config;
use crate::import::onepassword::source_key;
use crate::import::op::{self, Mapped, Mapping};
use crate::import::{Imported, MirrorVersion, Origin, digest};
use crate::protocol::{MirrorAction, MirrorItem, MirrorReport};

const NOT_SIGNED_IN: &str = "1Password: not signed in. Sign in to the 1Password app and turn on \
     Settings › Developer › Integrate with 1Password CLI";
const LOCKED: &str = "1Password is locked: unlock the 1Password app, then sync again";
const NOT_ALLOWED: &str = "1Password did not allow access (its prompt was dismissed or timed out): sync again and approve it";
const NO_APP: &str = "cannot reach the 1Password app: open it and turn on \
     Settings › Developer › Integrate with 1Password CLI";
const TIMED_OUT: &str =
    "1Password did not answer in time: sync again, and approve its prompt within 2 minutes";
const RACED: &str = "changed here during the sync; it syncs next time";

/// How long one `op` call may take: time to approve 1Password's prompt.
const OP_TIMEOUT: Duration = Duration::from_secs(120);
/// How much longer fetching items may take, per item.
const OP_PER_ITEM: Duration = Duration::from_millis(100);

/// Where Homebrew puts `op`, for a daemon started without it on `PATH`.
const HOMEBREW: [&str; 2] = ["/opt/homebrew/bin", "/usr/local/bin"];

/// The 1Password CLI.
pub struct Op {
    program: PathBuf,
    account: Option<String>,
    timeout: Duration,
}

impl Op {
    /// `DEADBOLT_OP` if set, else `op` on `PATH` or where Homebrew puts it.
    pub fn find() -> Self {
        let program = match config::env("DEADBOLT_OP") {
            Ok(program) if !program.is_empty() => program.into(),
            _ => config::env("PATH")
                .unwrap_or_default()
                .split(':')
                .filter(|dir| !dir.is_empty())
                .chain(HOMEBREW)
                .map(|dir| PathBuf::from(dir).join("op"))
                .find(|path| path.is_file())
                .unwrap_or_else(|| "op".into()),
        };
        Self::at(program)
    }

    pub fn at(program: PathBuf) -> Self {
        Self {
            program,
            account: None,
            timeout: OP_TIMEOUT,
        }
    }

    /// Runs `op` with `args`, `--account` and `--format json`, with `input`
    /// on stdin, and parses what it prints: JSON values one after another,
    /// lists flattened. It gets the timeout plus `extra` to finish, and is
    /// killed if it doesn't, or if the future is dropped.
    async fn json(
        &self,
        args: &[&str],
        input: Option<&[u8]>,
        extra: Duration,
    ) -> Result<Vec<Value>> {
        let mut command = Command::new(&self.program);
        command.args(args);
        if let Some(account) = &self.account {
            command.args(["--account", account]);
        }
        command
            .args(["--format", "json"])
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|e| match e.kind() {
            ErrorKind::NotFound => anyhow!(
                "the 1Password CLI (op) is not installed: `brew install 1password-cli`, \
                 or set DEADBOLT_OP to its path"
            ),
            _ => anyhow!("running {}: {e}", self.program.display()),
        })?;
        let stdin = child.stdin.take();
        // Write stdin alongside: `op` may print before reading it all.
        let write = async move {
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                // `op` quitting early closes the pipe; its error says why.
                if let Err(error) = stdin.write_all(input).await {
                    tracing::debug!("writing to op: {error}");
                }
            }
        };
        let run = async {
            let ((), output) = tokio::join!(write, child.wait_with_output());
            output
        };
        let output = tokio::time::timeout(self.timeout + extra, run)
            .await
            .map_err(|_| anyhow!(TIMED_OUT))??;
        let stdout = Zeroizing::new(output.stdout);
        if !output.status.success() {
            return Err(failure(&String::from_utf8_lossy(&output.stderr)));
        }
        let mut values = Vec::new();
        for value in serde_json::Deserializer::from_slice(&stdout).into_iter::<Value>() {
            // Only the position: serde's message could quote a value.
            let value = value.map_err(|e| {
                anyhow!(
                    "the 1Password CLI printed something that is not JSON (line {} column {})",
                    e.line(),
                    e.column()
                )
            })?;
            match value {
                Value::Array(list) => values.extend(list),
                value => values.push(value),
            }
        }
        Ok(values)
    }
}

/// A failed `op`'s error, as a sentence that says what to do. `op` puts no
/// values on stderr; even so only its first line is kept.
fn failure(stderr: &str) -> anyhow::Error {
    let said = stderr
        .lines()
        .map(without_prefix)
        .find(|l| !l.is_empty())
        .unwrap_or("it gave no reason");
    let lower = stderr.to_lowercase();
    let any = |words: &[&str]| words.iter().any(|w| lower.contains(w));
    let hint = if any(&["dismissed", "denied", "authorization timeout", "timed out"]) {
        NOT_ALLOWED
    } else if any(&["locked"]) {
        LOCKED
    } else if any(&[
        "not currently signed in",
        "not signed in",
        "no accounts configured",
        "op signin",
    ]) {
        NOT_SIGNED_IN
    } else if any(&[
        "connect to 1password",
        "connecting to desktop app",
        "desktop app",
    ]) {
        NO_APP
    } else {
        let said: String = said.chars().take(200).collect();
        return anyhow!("the 1Password CLI failed: {said}");
    };
    anyhow!("{hint}")
}

/// A line of `op` stderr without its `[ERROR] 2024/03/09 16:00:00 ` start.
fn without_prefix(line: &str) -> &str {
    let mut line = line.trim();
    if line.starts_with('[')
        && let Some((_, rest)) = line.split_once("] ")
    {
        line = rest;
    }
    let stamp = |s: &str| {
        s.len() >= 20
            && s.bytes().take(19).enumerate().all(|(i, b)| match i {
                4 | 7 => b == b'/',
                10 => b == b' ',
                13 | 16 => b == b':',
                _ => b.is_ascii_digit(),
            })
    };
    if stamp(line) {
        line = line[19..].trim_start();
    }
    line
}

fn str_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// A sign-in address without its scheme or trailing slash.
fn host(address: &str) -> &str {
    address.trim_start_matches("https://").trim_end_matches('/')
}

/// The 1Password account mirrored: its id, and the user's id in it, which
/// a .1pux records instead.
#[derive(Clone)]
pub struct Account {
    id: String,
    user: Option<String>,
}

impl Account {
    fn is(&self, id: &str) -> bool {
        self.id == id || self.user.as_deref() == Some(id)
    }
}

/// The account to mirror: the one `wanted` names (by id, sign-in address,
/// email or shorthand), else the only one, else the only one `mirrored`,
/// else the only one whose export was `imported`.
async fn account(
    op: &Op,
    wanted: Option<&str>,
    mirrored: &BTreeSet<String>,
    imported: &BTreeSet<String>,
) -> Result<Account> {
    let accounts = op.json(&["account", "list"], None, Duration::ZERO).await?;
    let named = |a: &Value, ids: &BTreeSet<String>| {
        ["account_uuid", "user_uuid"]
            .into_iter()
            .filter_map(|k| str_of(a, k))
            .any(|id| ids.contains(id))
    };
    let found: Vec<&Value> = match wanted {
        Some(wanted) => {
            let wanted = host(wanted);
            accounts
                .iter()
                .filter(|a| {
                    ["account_uuid", "user_uuid", "url", "email", "shorthand"]
                        .into_iter()
                        .filter_map(|k| str_of(a, k))
                        .any(|n| host(n).eq_ignore_ascii_case(wanted))
                })
                .collect()
        }
        None => {
            let here = |ids| -> Vec<&Value> { accounts.iter().filter(|a| named(a, ids)).collect() };
            let mut here = here(mirrored);
            if here.is_empty() {
                here = accounts.iter().filter(|a| named(a, imported)).collect();
            }
            if here.len() == 1 {
                here
            } else {
                accounts.iter().collect()
            }
        }
    };
    match (found.as_slice(), wanted) {
        ([one], _) => Ok(Account {
            id: str_of(one, "account_uuid")
                .context("the 1Password CLI listed an account without an id")?
                .into(),
            user: str_of(one, "user_uuid").map(String::from),
        }),
        ([], Some(wanted)) => bail!("no 1Password account matches {wanted:?}"),
        ([], None) => bail!(NOT_SIGNED_IN),
        (many, _) => {
            let names: Vec<String> = many.iter().map(|a| account_name(a)).collect();
            bail!(
                "{} 1Password accounts: choose one with --account ({})",
                many.len(),
                names.join(", ")
            )
        }
    }
}

/// An account as `--account` takes it: its shorthand, else its email and
/// sign-in address.
fn account_name(account: &Value) -> String {
    if let Some(shorthand) = str_of(account, "shorthand").filter(|s| !s.is_empty()) {
        return shorthand.into();
    }
    match (str_of(account, "email"), str_of(account, "url")) {
        (Some(email), Some(url)) => format!("{email} on {}", host(url)),
        (Some(email), None) => email.into(),
        (None, Some(url)) => host(url).into(),
        (None, None) => str_of(account, "account_uuid").unwrap_or("?").into(),
    }
}

/// The ids of the 1Password vaults named, or `None` for every vault.
async fn vaults(op: &Op, names: &[String]) -> Result<Option<BTreeSet<String>>> {
    if names.is_empty() {
        return Ok(None);
    }
    let vaults = op.json(&["vault", "list"], None, Duration::ZERO).await?;
    let find = |want: &dyn Fn(&Value) -> bool| vaults.iter().find(|v| want(v));
    names
        .iter()
        .map(|name| {
            find(&|v| str_of(v, "id") == Some(name))
                .or_else(|| find(&|v| str_of(v, "name") == Some(name)))
                .or_else(|| {
                    find(&|v| str_of(v, "name").is_some_and(|n| n.eq_ignore_ascii_case(name)))
                })
                .and_then(|v| str_of(v, "id"))
                .map(String::from)
                .ok_or_else(|| anyhow!("no 1Password vault named {name:?}"))
        })
        .collect::<Result<_>>()
        .map(Some)
}

/// What an item's 1Password source says.
struct Copy<'a> {
    account: &'a str,
    vault: &'a str,
    id: &'a str,
    version: MirrorVersion,
}

/// What `item` is a copy of, if a 1Password item. A version this build
/// cannot read counts as adopted and changed: updated, never deleted.
fn copy(item: &Item) -> Option<Copy<'_>> {
    let source = item.source.as_ref()?;
    let (account, vault, id) = source_key(&source.id)?;
    let version = MirrorVersion::parse(&source.version).unwrap_or(MirrorVersion {
        updated: i64::MIN,
        digest: String::new(),
        origin: Origin::Adopted,
        fields: BTreeSet::new(),
        tags: BTreeSet::new(),
    });
    Some(Copy {
        account,
        vault,
        id,
        version,
    })
}

fn item_digest(item: &Item) -> String {
    digest(
        &item.kind,
        item.name.as_deref(),
        &item.fields,
        item.favorite,
        &item.tags,
    )
}

/// A 1Password item: the account (or, for an import, the user) and its id.
type Key = (String, String);

fn key(account: &str, id: &str) -> Key {
    (account.to_string(), id.to_string())
}

/// The items that are copies of 1Password items, by 1Password item, with
/// their digests: what [`apply`] checks did not change during a fetch.
type Copies = HashMap<Key, BTreeSet<(ItemId, String)>>;

fn copies(items: &[Item]) -> Copies {
    let mut copies: Copies = HashMap::new();
    for item in items {
        if let Some(c) = copy(item) {
            copies
                .entry(key(c.account, c.id))
                .or_default()
                .insert((item.id, item_digest(item)));
        }
    }
    copies
}

/// What the vault held before the fetch, so only what changed is fetched,
/// and [`apply`] can tell what changed here meanwhile.
pub struct Known {
    vault: VaultId,
    /// The accounts mirrored here.
    mirrored: BTreeSet<String>,
    /// The users whose exports were imported here: each names its account.
    imported: BTreeSet<String>,
    /// By 1Password item, one mirrored by one copy that is unchanged since
    /// it was written: the vault and 1Password time then.
    fresh: HashMap<Key, (String, i64)>,
    copies: Copies,
}

pub fn known(s: &Loaded, vault: Option<&str>) -> Result<Known> {
    let id = s.resolve(vault)?;
    let items = s.vault(&id).items();
    let mut mirrored = BTreeSet::new();
    let mut imported = BTreeSet::new();
    let mut fresh = HashMap::new();
    let mut mirrors: HashMap<Key, usize> = HashMap::new();
    for item in &items {
        let Some(c) = copy(item) else {
            continue;
        };
        if !c.version.mirrored() {
            imported.insert(c.account.to_string());
            continue;
        }
        mirrored.insert(c.account.to_string());
        *mirrors.entry(key(c.account, c.id)).or_default() += 1;
        if c.version.digest == item_digest(item) {
            fresh.insert(key(c.account, c.id), (c.vault.into(), c.version.updated));
        }
    }
    // Two copies: fetch it, so `apply` can settle them.
    fresh.retain(|key, _| mirrors.get(key) == Some(&1));
    Ok(Known {
        vault: id,
        mirrored,
        imported,
        fresh,
        copies: copies(&items),
    })
}

/// What 1Password has: every item listed, and the full items that changed.
pub struct Fetched {
    account: Account,
    /// The vaults mirrored; `None` for all of them.
    vaults: Option<BTreeSet<String>>,
    /// Every item, in every vault.
    listed: Vec<Value>,
    requested: BTreeSet<String>,
    items: HashMap<String, Value>,
}

/// Asks 1Password for its items: the account list, the vault list if
/// `vaults` names some, the item list, then in one call every item that
/// is new or changed on either side. Dropping it kills `op`.
pub async fn fetch(
    op: Op,
    account: Option<&str>,
    vaults: &[String],
    known: &Known,
) -> Result<Fetched> {
    let account = self::account(&op, account, &known.mirrored, &known.imported).await?;
    let op = Op {
        account: Some(account.id.clone()),
        ..op
    };
    let vaults = self::vaults(&op, vaults).await?;
    let listed = op.json(&["item", "list"], None, Duration::ZERO).await?;
    let (wanted, requested) = wanted(&listed, &account, vaults.as_ref(), known);
    let mut items = HashMap::new();
    if !wanted.is_empty() {
        // The list entries hold ids, titles and URLs, never values.
        let input = serde_json::to_vec(&wanted)?;
        let extra = OP_PER_ITEM.saturating_mul(u32::try_from(wanted.len()).unwrap_or(u32::MAX));
        for item in op.json(&["item", "get", "-"], Some(&input), extra).await? {
            if let Some((_, id, _)) = op::identity(&item)
                && requested.contains(&id)
            {
                items.insert(id, item);
            }
        }
    }
    Ok(Fetched {
        account,
        vaults,
        listed,
        requested,
        items,
    })
}

/// The listed items to fetch: those in the vaults mirrored, except ones
/// whose mirror is unchanged here and as of the same 1Password time and
/// vault.
fn wanted<'a>(
    listed: &'a [Value],
    account: &Account,
    vaults: Option<&BTreeSet<String>>,
    known: &Known,
) -> (Vec<&'a Value>, BTreeSet<String>) {
    let mut requested = BTreeSet::new();
    let wanted = listed
        .iter()
        .filter(|item| {
            let Some((vault, id, updated)) = op::identity(item) else {
                return false;
            };
            if !vaults.is_none_or(|v| v.contains(&vault))
                || !str_of(item, "category").is_some_and(op::mirrored)
            {
                return false;
            }
            let fresh = known
                .fresh
                .get(&key(&account.id, &id))
                .is_some_and(|(v, at)| *v == vault && *at == updated);
            !fresh && requested.insert(id)
        })
        .collect();
    (wanted, requested)
}

/// A login's username and URL, if it has both: what makes an item here
/// plainly the same as one in 1Password whose other fields differ.
fn login(kind: &str, fields: &BTreeMap<String, Field>) -> Option<(String, String)> {
    let value = |name: &str| {
        fields
            .get(name)
            .map(|f| f.value.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    (kind == "login")
        .then(|| Some((value("username")?, value("url")?)))
        .flatten()
}

/// What a sync will write, and its report.
#[derive(Default)]
struct Plan {
    unchanged: usize,
    items: Vec<MirrorItem>,
    edits: Vec<DataOp>,
    creates: Vec<DataOp>,
}

impl Plan {
    fn note(&mut self, action: MirrorAction, title: impl Into<String>, reason: Option<String>) {
        self.items.push(MirrorItem {
            action,
            title: title.into(),
            reason,
        });
    }

    fn add(&mut self, mapped: Mapped, account: &str, reason: Option<String>) {
        let source = mapped.source(account, Origin::Sync, mapped.item.digest());
        let title = title(&mapped.item);
        let Imported {
            kind,
            name,
            fields,
            favorite,
            tags,
            ..
        } = mapped.item;
        self.creates.push(DataOp::create_with(
            kind,
            name,
            fields,
            Some(source),
            favorite,
            tags,
        ));
        self.note(MirrorAction::Add, title, reason);
    }

    /// Brings a mirror up to date with `mapped`, writing only what differs.
    fn update(&mut self, item: &Item, origin: Origin, mapped: Mapped, account: &str) {
        if item.kind == mapped.item.kind {
            self.write(item, origin, MirrorAction::Update, mapped, account);
        } else if origin == Origin::Sync {
            // An item's type is fixed: replace the mirror's own copy.
            self.edits
                .push(DataOp::delete(item.id, crate::config::now()));
            self.add(mapped, account, Some("type".into()));
            if let Some(added) = self.items.last_mut() {
                added.action = MirrorAction::Update;
            }
        } else {
            let reason = "its type changed in 1Password".to_string();
            self.note(MirrorAction::Skip, title(&mapped.item), Some(reason));
        }
    }

    /// Takes over an item made here or imported: 1Password's values win,
    /// and fields only it has here are kept.
    fn adopt(&mut self, item: &Item, mapped: Mapped, account: &str) {
        if item.kind == mapped.item.kind {
            self.write(item, Origin::Adopted, MirrorAction::Adopt, mapped, account);
        } else {
            let reason = "a different type here".to_string();
            self.note(MirrorAction::Skip, title(&mapped.item), Some(reason));
        }
    }

    fn write(
        &mut self,
        item: &Item,
        origin: Origin,
        action: MirrorAction,
        mapped: Mapped,
        account: &str,
    ) {
        let old = item
            .source
            .as_ref()
            .and_then(|s| MirrorVersion::parse(&s.version));
        // Of the fields 1Password lacks, a mirror the sync added loses them
        // all; one taken over only those 1Password wrote before.
        let (from_fields, from_tags) = match origin {
            Origin::Sync => (None, None),
            _ => {
                let adopted = old.as_ref().filter(|v| v.origin == Origin::Adopted);
                (
                    Some(adopted.map(|v| v.fields.clone()).unwrap_or_default()),
                    Some(adopted.map(|v| v.tags.clone()).unwrap_or_default()),
                )
            }
        };
        let (ops, changed, fields, tags) =
            diff(item, &mapped.item, from_fields.as_ref(), from_tags.as_ref());
        let digest = digest(
            &item.kind,
            mapped.item.name.as_deref(),
            &fields,
            mapped.item.favorite,
            &tags,
        );
        let source = mapped.source(account, origin, digest);
        // The same but for 1Password's time.
        let new = MirrorVersion::parse(&source.version);
        let same = item.source.as_ref().is_some_and(|s| s.id == source.id)
            && old.zip(new).is_some_and(|(old, new)| {
                MirrorVersion {
                    updated: new.updated,
                    ..old
                } == new
            });
        if action == MirrorAction::Update && ops.is_empty() && same {
            // Same content: leave even a newer 1Password time unwritten.
            self.unchanged += 1;
            return;
        }
        self.edits.extend(ops);
        self.edits.push(DataOp::source(item.id, Some(source)));
        let reason = match (action, changed.is_empty()) {
            (_, true) => None,
            (MirrorAction::Adopt, false) => {
                Some(format!("takes over, changes: {}", changed.join(", ")))
            }
            (_, false) => Some(changed.join(", ")),
        };
        self.note(action, title(&mapped.item), reason);
    }
}

fn title(item: &Imported) -> String {
    item.name.clone().unwrap_or_else(|| item.kind.to_string())
}

/// The ops that make `item` hold what `to` does, the names changed, and
/// the fields and tags after. Of the fields and tags `to` lacks, those in
/// `from_fields` / `from_tags` go, or with `None` all of them.
fn diff(
    item: &Item,
    to: &Imported,
    from_fields: Option<&BTreeSet<String>>,
    from_tags: Option<&BTreeSet<String>>,
) -> (
    Vec<DataOp>,
    Vec<String>,
    BTreeMap<String, Field>,
    BTreeSet<String>,
) {
    let mut ops = Vec::new();
    let mut changed = Vec::new();
    let mut fields = item.fields.clone();
    if item.name != to.name {
        ops.push(DataOp::name(item.id, to.name.clone()));
        changed.push("title".to_string());
    }
    for (name, field) in &to.fields {
        if item.fields.get(name) != Some(field) {
            ops.push(DataOp::set(item.id, name.clone(), field.clone()));
            changed.push(name.clone());
            fields.insert(name.clone(), field.clone());
        }
    }
    let gone = |name: &String| from_fields.is_none_or(|from| from.contains(name));
    for name in item.fields.keys().filter(|n| !to.fields.contains_key(*n)) {
        if gone(name) {
            ops.push(DataOp::remove(item.id, name.clone()));
            changed.push(name.clone());
            fields.remove(name);
        }
    }
    if item.favorite != to.favorite {
        ops.push(DataOp::favorite(item.id, to.favorite));
        changed.push("favorite".to_string());
    }
    let mut tags = item.tags.clone();
    let mut tags_changed = false;
    for t in &to.tags {
        if !tags.contains(t) {
            let folded = deadbolt_core::tag::fold_tag(t);
            tags.retain(|e| deadbolt_core::tag::fold_tag(e) != folded);
            tags.insert(t.clone());
            ops.push(DataOp::tag_add(item.id, t.clone()));
            tags_changed = true;
        }
    }
    let tag_gone = |folded: &str| from_tags.is_none_or(|from| from.contains(folded));
    for existing in &item.tags {
        let folded = deadbolt_core::tag::fold_tag(existing);
        let in_to = to
            .tags
            .iter()
            .any(|t| deadbolt_core::tag::fold_tag(t) == folded);
        if !in_to && tag_gone(&folded) {
            tags.remove(existing);
            ops.push(DataOp::tag_remove(item.id, existing.clone()));
            tags_changed = true;
        }
    }
    if tags_changed {
        changed.push("tags".to_string());
    }
    (ops, changed, fields, tags)
}

/// Edits in entries of about [`CREATE_BATCH_BYTES`] of values each.
fn batches(ops: Vec<DataOp>) -> Vec<Vec<DataOp>> {
    let mut out: Vec<Vec<DataOp>> = Vec::new();
    let mut size = 0;
    for op in ops {
        let bytes = 64
            + match &op {
                DataOp::Edit {
                    change: Change::Set { field, value },
                    ..
                } => field.len() + value.value.len(),
                _ => 0,
            };
        match out.last_mut() {
            Some(batch) if size + bytes <= CREATE_BATCH_BYTES => batch.push(op),
            _ => {
                out.push(vec![op]);
                size = 0;
            }
        }
        size += bytes;
    }
    out
}

/// Plans the sync against the vault as it is now, and with `write` writes
/// it: all of it or, on an error, none. An item that changed here since
/// `known` was read is left for the next sync.
///
/// An item new in 1Password is matched with one here: first an import of
/// the same 1Password item, then one that is a copy of nothing with the
/// same content, then such a login with the same username and URL, if it
/// is the only login with them here and in the vaults mirrored. A match is
/// taken over; otherwise the item is added, beside any item with the same
/// name.
pub fn apply(s: &mut Loaded, known: &Known, fetched: Fetched, write: bool) -> Result<MirrorReport> {
    let vault = known.vault;
    let items = s
        .held(&vault)
        .context("the vault was left during the sync")?
        .items();
    let Fetched {
        account,
        vaults,
        listed,
        requested,
        items: mut full,
    } = fetched;
    let in_scope = |vault: &str| vaults.as_ref().is_none_or(|v| v.contains(vault));
    let now = copies(&items);
    // A copy of the item, or of the user's export of it, changed meanwhile.
    let raced = |id: &str| {
        [Some(&account.id), account.user.as_ref()]
            .into_iter()
            .flatten()
            .map(|a| key(a, id))
            .any(|k| known.copies.get(&k) != now.get(&k))
    };
    let mut plan = Plan::default();

    // This account's mirrors and imports, by 1Password item id.
    let mut mirrors: BTreeMap<&str, Vec<(&Item, Copy)>> = BTreeMap::new();
    let mut imports: BTreeMap<&str, Vec<&Item>> = BTreeMap::new();
    for item in &items {
        let Some(c) = copy(item) else {
            continue;
        };
        if !account.is(c.account) {
            continue;
        }
        if c.version.mirrored() {
            mirrors.entry(c.id).or_default().push((item, c));
        } else {
            imports.entry(c.id).or_default().push(item);
        }
    }

    // Two mirrors of one item (two devices synced at once): an adopted one
    // is kept; another the sync added is deleted, another adopted released.
    for (id, copies) in &mut mirrors {
        if copies.len() < 2 || raced(id) || !copies.iter().all(|(_, c)| in_scope(c.vault)) {
            continue;
        }
        copies.sort_by_key(|(item, c)| (c.version.origin == Origin::Sync, item.id));
        for (item, c) in copies.drain(1..) {
            let reason = Some("a second copy".to_string());
            if c.version.origin == Origin::Sync {
                plan.edits
                    .push(DataOp::delete(item.id, crate::config::now()));
                plan.note(MirrorAction::Delete, label(item), reason);
            } else {
                plan.edits.push(DataOp::source(item.id, None));
                plan.note(MirrorAction::Release, label(item), reason);
            }
        }
    }

    // Every login's username and URL, here and in the 1Password vaults
    // mirrored: a pair matched only when it is the one on each side.
    let mut logins_here: HashMap<(String, String), usize> = HashMap::new();
    for item in &items {
        if let Some(login) = login(&item.kind, &item.fields) {
            *logins_here.entry(login).or_default() += 1;
        }
    }
    let mut logins_there: HashMap<(String, String), usize> = HashMap::new();
    for entry in &listed {
        let Some((vault, id, _)) = op::identity(entry) else {
            continue;
        };
        if !in_scope(&vault) || !str_of(entry, "category").is_some_and(op::mirrored) {
            continue;
        }
        // Unfetched, it is as its mirror holds it.
        let login = match full.get(&id) {
            Some(raw) => Mapping::default()
                .item(raw)
                .ok()
                .and_then(|m| login(m.item.kind, &m.item.fields)),
            None => mirrors
                .get(id.as_str())
                .and_then(|c| c.first())
                .and_then(|(i, _)| login(&i.kind, &i.fields)),
        };
        if let Some(login) = login {
            *logins_there.entry(login).or_default() += 1;
        }
    }

    let mut mapping = Mapping::default();
    let mut seen = BTreeSet::new();
    let mut scoped = 0;
    let mut taken = BTreeSet::new();
    let mut pending = Vec::new();
    for entry in &listed {
        if let Some(id) = str_of(entry, "id") {
            seen.insert(id.to_string());
        }
        if entry
            .get("vault")
            .and_then(|v| str_of(v, "id"))
            .is_some_and(|v| !in_scope(v))
        {
            continue;
        }
        scoped += 1;
        let listed_title = str_of(entry, "title").unwrap_or("untitled").to_string();
        let Some((_, id, _)) = op::identity(entry) else {
            plan.note(
                MirrorAction::Skip,
                listed_title,
                Some("item without an id".into()),
            );
            continue;
        };
        let category = str_of(entry, "category").unwrap_or_default();
        if !op::mirrored(category) {
            let reason = op::not_mirrored(category).to_string();
            plan.note(MirrorAction::Skip, listed_title, Some(reason));
            continue;
        }
        if raced(&id) {
            plan.note(MirrorAction::Skip, listed_title, Some(RACED.into()));
            continue;
        }
        let Some(item) = full.remove(&id) else {
            if requested.contains(&id) {
                let reason = "1Password did not return it".to_string();
                plan.note(MirrorAction::Skip, listed_title, Some(reason));
            } else {
                plan.unchanged += 1;
            }
            continue;
        };
        let mapped = match mapping.item(&item) {
            Ok(mapped) => mapped,
            Err(reason) => {
                plan.note(MirrorAction::Skip, listed_title, Some(reason.into()));
                continue;
            }
        };
        drop(item);
        if let Some((existing, c)) = mirrors.get(id.as_str()).and_then(|c| c.first()) {
            plan.update(existing, c.version.origin, mapped, &account.id);
        } else if let Some(import) = imports.get(id.as_str()).and_then(|c| c.first()) {
            taken.insert(import.id);
            plan.adopt(import, mapped, &account.id);
        } else {
            pending.push(mapped);
        }
    }

    // New in 1Password: what here could be the same item, being a copy of
    // none. An import is only ever the item it was exported from.
    let mut pool: Vec<(&Item, String)> = items
        .iter()
        .filter(|i| i.source.is_none() && !taken.contains(&i.id))
        .map(|i| (i, item_digest(i)))
        .collect();
    pending.sort_by(|a, b| a.id.cmp(&b.id));
    let mut rest = Vec::new();
    for mapped in pending {
        let digest = mapped.item.digest();
        match pool.iter().position(|(_, d)| *d == digest) {
            Some(at) => {
                let (item, _) = pool.remove(at);
                plan.adopt(item, mapped, &account.id);
            }
            None => rest.push(mapped),
        }
    }
    for mapped in rest {
        if let Some(key) = login(mapped.item.kind, &mapped.item.fields) {
            let candidates: Vec<usize> = (0..pool.len())
                .filter(|&at| login(&pool[at].0.kind, &pool[at].0.fields).as_ref() == Some(&key))
                .collect();
            let here = logins_here.get(&key).copied().unwrap_or(0);
            let there = logins_there.get(&key).copied().unwrap_or(1);
            let reason = match (candidates.as_slice(), here, there) {
                ([], ..) => None,
                ([at], 1, 1) => {
                    let (item, _) = pool.remove(*at);
                    plan.adopt(item, mapped, &account.id);
                    continue;
                }
                (_, 1, n) => Some(format!(
                    "{n} 1Password items have this username and URL; added beside the one here"
                )),
                (_, n, _) => Some(format!(
                    "added beside {n} items with the same username and URL"
                )),
            };
            if reason.is_some() {
                plan.add(mapped, &account.id, reason);
                continue;
            }
        }
        let same_name = pool
            .iter()
            .filter(|(i, _)| i.kind == mapped.item.kind && i.name == mapped.item.name)
            .count();
        let reason = match same_name {
            0 => None,
            1 => Some("added beside an item with the same name".to_string()),
            n => Some(format!("added beside {n} items with the same name")),
        };
        plan.add(mapped, &account.id, reason);
    }

    // Gone from 1Password (deleted or archived), in the vaults mirrored:
    // deleted if the sync added it, else kept and released.
    let mut gone = 0;
    for (id, copies) in &mirrors {
        let Some((item, c)) = copies.first() else {
            continue;
        };
        if seen.contains(*id) || !in_scope(c.vault) {
            continue;
        }
        if raced(id) {
            plan.note(MirrorAction::Skip, label(item), Some(RACED.into()));
            continue;
        }
        gone += 1;
        if c.version.origin == Origin::Sync {
            plan.edits
                .push(DataOp::delete(item.id, crate::config::now()));
            plan.note(MirrorAction::Delete, label(item), None);
        } else {
            plan.edits.push(DataOp::source(item.id, None));
            let reason = "deleted in 1Password; kept, as the sync did not add it";
            plan.note(MirrorAction::Release, label(item), Some(reason.into()));
        }
    }
    if scoped == 0 && gone > 0 {
        let items = if gone == 1 { "item" } else { "items" };
        bail!("1Password listed no items: leaving the {gone} mirrored {items} alone");
    }

    let report = mapping.report();
    plan.items
        .sort_by(|a, b| (a.action, &a.title).cmp(&(b.action, &b.title)));
    let Plan {
        unchanged,
        items: done,
        edits,
        creates,
    } = plan;
    if write && !(edits.is_empty() && creates.is_empty()) {
        s.update(vault, |v, secret| {
            for batch in batches(edits) {
                v.write(secret, batch)?;
            }
            if !creates.is_empty() {
                v.create_items(secret, creates)?;
            }
            Ok(())
        })?;
    }
    Ok(MirrorReport {
        applied: write,
        unchanged,
        items: done,
        warnings: report.warnings,
        dropped: report.dropped,
    })
}

/// The app an item is mirrored from, for the UI; `None` for an import
/// that only records where it came from.
pub fn source_app(source: Option<&Source>) -> Option<String> {
    let source = source?;
    source_key(&source.id)?;
    MirrorVersion::parse(&source.version)
        .is_none_or(|v| v.mirrored())
        .then(|| "1Password".to_string())
}

#[cfg(test)]
pub(super) mod tests;
