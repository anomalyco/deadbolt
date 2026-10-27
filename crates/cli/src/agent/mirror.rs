//! Mirrors 1Password into a vault with the 1Password CLI (`op`), for
//! `Command::SyncOnePassword`. 1Password is the source of truth: items new
//! there are added, changed ones are updated (only the fields that differ),
//! and ones deleted or archived there are deleted here, but only if the
//! mirror added them. An item already here is taken over rather than added
//! again only when it is plainly the same one (see [`apply`]), and keeps
//! the fields only it has.
//!
//! The agent runs `op` itself, in the user's session where the 1Password
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

/// Where Homebrew puts `op`, for an agent started without it on `PATH`.
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
    });
    Some(Copy {
        account,
        vault,
        id,
        version,
    })
}

fn item_digest(item: &Item) -> String {
    digest(&item.kind, item.name.as_deref(), &item.fields)
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
            kind, name, fields, ..
        } = mapped.item;
        self.creates
            .push(DataOp::create_mirror(kind, name, fields, source));
        self.note(MirrorAction::Add, title, reason);
    }

    /// Brings a mirror up to date with `mapped`, writing only what differs.
    fn update(&mut self, item: &Item, origin: Origin, mapped: Mapped, account: &str) {
        if item.kind == mapped.item.kind {
            self.write(item, origin, MirrorAction::Update, mapped, account);
        } else if origin == Origin::Sync {
            // An item's type is fixed: replace the mirror's own copy.
            self.edits.push(DataOp::delete(item.id));
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
        let from_op = match origin {
            Origin::Sync => None,
            _ => Some(
                old.as_ref()
                    .filter(|v| v.origin == Origin::Adopted)
                    .map(|v| v.fields.clone())
                    .unwrap_or_default(),
            ),
        };
        let (ops, changed, fields) = diff(item, &mapped.item, from_op.as_ref());
        let digest = digest(&item.kind, mapped.item.name.as_deref(), &fields);
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
/// the fields after. Of the fields `to` lacks, those in `from_op` go, or
/// with `None` all of them.
fn diff(
    item: &Item,
    to: &Imported,
    from_op: Option<&BTreeSet<String>>,
) -> (Vec<DataOp>, Vec<String>, BTreeMap<String, Field>) {
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
    let gone = |name: &String| from_op.is_none_or(|from| from.contains(name));
    for name in item.fields.keys().filter(|n| !to.fields.contains_key(*n)) {
        if gone(name) {
            ops.push(DataOp::remove(item.id, name.clone()));
            changed.push(name.clone());
            fields.remove(name);
        }
    }
    (ops, changed, fields)
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
                plan.edits.push(DataOp::delete(item.id));
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
            plan.edits.push(DataOp::delete(item.id));
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
pub(super) mod tests {
    use deadbolt_core::{Entry, Hash, Payload};
    use serde_json::json;

    use super::*;
    use crate::import::onepassword::tests::USER;
    use crate::import::op::tests::items as op_items;
    use crate::protocol::FieldInput;

    const ACCOUNT: &str = "AAAABBBBCCCCDDDDEEEEFFFFGG";
    const PRIVATE: &str = "v1v1v1v1v1v1v1v1v1v1v1v1v1";
    const SHARED: &str = "v2v2v2v2v2v2v2v2v2v2v2v2v2";

    /// Every value in the fixture worth leaking.
    const SECRETS: [&str; 10] = [
        "op-github-pw",
        "op-recovery-111",
        "op-note-secret",
        "op-wifi-pw",
        "4242",
        "op-api-key",
        "op-ssh-pass",
        "op-license-pw",
        "op-account-12345678",
        "JBSWY3DPEHPK3PXP",
    ];

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

    fn account() -> Account {
        Account {
            id: ACCOUNT.into(),
            user: Some(USER.into()),
        }
    }

    /// What `known` reads, then what `fetch` gets from an `op` holding
    /// `items`, mirroring `vaults` only.
    fn fetched(s: &Loaded, items: &[Value], vaults: Option<&[&str]>) -> (Known, Fetched) {
        fetched_from(s, items, vaults, account())
    }

    fn fetched_from(
        s: &Loaded,
        items: &[Value],
        vaults: Option<&[&str]>,
        account: Account,
    ) -> (Known, Fetched) {
        let known = known(s, None).unwrap();
        let vaults: Option<BTreeSet<String>> =
            vaults.map(|v| v.iter().map(|v| v.to_string()).collect());
        // `op item list` gives no fields, sections or files.
        let listed: Vec<Value> = items
            .iter()
            .map(|i| {
                let mut i = i.clone();
                for key in ["fields", "sections", "files"] {
                    i.as_object_mut().unwrap().remove(key);
                }
                i
            })
            .collect();
        let (_, requested) = wanted(&listed, &account, vaults.as_ref(), &known);
        let items = items
            .iter()
            .filter_map(|i| {
                let (_, id, _) = op::identity(i)?;
                requested.contains(&id).then(|| (id, i.clone()))
            })
            .collect();
        let fetched = Fetched {
            account,
            vaults,
            listed,
            requested,
            items,
        };
        (known, fetched)
    }

    /// The ids of the items a sync would fetch.
    fn requested(s: &Loaded, items: &[Value]) -> Vec<String> {
        let (_, fetched) = fetched(s, items, None);
        fetched.requested.into_iter().collect()
    }

    fn checked(report: MirrorReport) -> MirrorReport {
        let text = format!("{report:?}\n{}", report.lines().join("\n"));
        for secret in SECRETS {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        report
    }

    fn sync(s: &mut Loaded, items: &[Value]) -> MirrorReport {
        sync_vaults(s, items, None)
    }

    fn sync_vaults(s: &mut Loaded, items: &[Value], vaults: Option<&[&str]>) -> MirrorReport {
        let (known, fetched) = fetched(s, items, vaults);
        checked(apply(s, &known, fetched, true).unwrap())
    }

    fn entries(s: &Loaded) -> Vec<Hash> {
        let vault = s.resolve(None).unwrap();
        s.vault(&vault).entries().iter().map(|e| e.hash()).collect()
    }

    /// The data ops of the entries written since `before`.
    fn written(s: &Loaded, before: &[Hash]) -> Vec<DataOp> {
        let vault = s.resolve(None).unwrap();
        s.vault(&vault)
            .entries()
            .into_iter()
            .filter(|e| !before.contains(&e.hash()))
            .flat_map(|e: &Entry| match e.payload() {
                Payload::Data(ops) => ops.clone(),
                _ => vec![],
            })
            .collect()
    }

    fn items(s: &Loaded) -> Vec<Item> {
        let vault = s.resolve(None).unwrap();
        s.vault(&vault).items()
    }

    fn named(s: &Loaded, name: &str) -> Vec<Item> {
        items(s)
            .into_iter()
            .filter(|i| i.name.as_deref() == Some(name))
            .collect()
    }

    fn version(item: &Item) -> MirrorVersion {
        MirrorVersion::parse(&item.source.as_ref().unwrap().version).unwrap()
    }

    fn actions(report: &MirrorReport) -> Vec<(MirrorAction, &str, Option<&str>)> {
        report
            .items
            .iter()
            .map(|i| (i.action, i.title.as_str(), i.reason.as_deref()))
            .collect()
    }

    fn titled<'a>(items: &'a mut [Value], title: &str) -> &'a mut Value {
        items.iter_mut().find(|i| i["title"] == title).unwrap()
    }

    fn input(name: &str, value: &str) -> FieldInput {
        FieldInput {
            name: name.into(),
            kind: None,
            value: value.into(),
        }
    }

    fn create(s: &mut Loaded, kind: &str, name: &str, fields: &[(&str, &str)]) {
        let fields = fields.iter().map(|(n, v)| input(n, v)).collect();
        super::super::items::create(s, None, kind, Some(name.into()), fields).unwrap();
    }

    fn set(s: &mut Loaded, name: &str, field: &str, value: &str) {
        let words = vec![name.to_string()];
        super::super::items::set(s, None, &words, vec![input(field, value)], None, &[]).unwrap();
    }

    /// The test export, imported the way it was before imports recorded
    /// where items came from.
    fn import_without_sources(s: &mut Loaded) {
        let (mut items, report) =
            crate::import::parse(crate::import::onepassword::tests::EXPORT).unwrap();
        for item in &mut items {
            item.source = None;
        }
        super::super::items::import(s, None, (items, report), true).unwrap();
    }

    fn import(s: &mut Loaded) {
        let parsed = crate::import::parse(crate::import::onepassword::tests::EXPORT).unwrap();
        super::super::items::import(s, None, parsed, true).unwrap();
    }

    const SKIPPED: [(MirrorAction, &str, Option<&str>); 3] = [
        (
            MirrorAction::Skip,
            "Deploy key",
            Some("SSH key without a private key"),
        ),
        (MirrorAction::Skip, "Future", Some("item of unknown type")),
        (MirrorAction::Skip, "Scan", Some("document")),
    ];

    const BESIDE: &str = "added beside an item with the same name";

    #[test]
    fn adds_everything_then_writes_nothing_until_something_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let op = op_items();
        let report = sync(&mut s, &op);
        assert_eq!(report.count(MirrorAction::Add), 11);
        assert_eq!(&actions(&report)[11..], SKIPPED);
        assert_eq!(report.summary(), "11 added");
        assert!(
            report.dropped.iter().any(|t| t.one == "attachment"),
            "{:?}",
            report.dropped
        );
        let github = &named(&s, "GitHub")[0];
        let source = github.source.as_ref().unwrap();
        assert_eq!(
            source.id,
            format!("1password/{ACCOUNT}/{PRIVATE}/item1item1item1item1item1a")
        );
        assert_eq!(version(github).origin, Origin::Sync);
        assert_eq!(
            source_app(github.source.as_ref()).as_deref(),
            Some("1Password")
        );
        assert!(
            !github
                .fields
                .values()
                .any(|f| f.value.contains("1password/"))
        );

        // Unchanged on both sides: nothing fetched (but the SSH key that
        // could not be mirrored), nothing written.
        let before = entries(&s);
        assert_eq!(requested(&s, &op), ["item9"]);
        let report = sync(&mut s, &op);
        assert_eq!(report.unchanged, 11);
        assert!(!report.changed());
        assert_eq!(entries(&s), before);
        assert_eq!(report.lines()[0], "Up to date (11 unchanged, 3 skipped)");
    }

    #[test]
    fn a_change_writes_only_the_fields_that_differ() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let mut op = op_items();
        sync(&mut s, &op);
        let github = titled(&mut op, "GitHub");
        github["fields"][1]["value"] = json!("op-github-pw-2");
        github["updated_at"] = json!("2024-04-01T00:00:00Z");
        let before = entries(&s);
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[0],
            (MirrorAction::Update, "GitHub", Some("password"))
        );
        assert_eq!(report.unchanged, 10);
        let ops = written(&s, &before);
        assert_eq!(ops.len(), 2, "the password and the source");
        assert!(
            matches!(&ops[0], DataOp::Edit { change: Change::Set { field, .. }, .. } if field == "password")
        );
        assert!(matches!(
            &ops[1],
            DataOp::Edit {
                change: Change::Source(Some(_)),
                ..
            }
        ));
        let github = &named(&s, "GitHub")[0];
        assert_eq!(github.fields["password"].value, "op-github-pw-2");
        assert_eq!(version(github).updated, 1_711_929_600);

        // Same content, newer time (a passkey changed): nothing written.
        titled(&mut op, "GitHub")["updated_at"] = json!("2024-05-01T00:00:00Z");
        let before = entries(&s);
        let report = sync(&mut s, &op);
        assert!(!report.changed());
        assert_eq!(entries(&s), before);
    }

    #[test]
    fn one_password_wins_over_edits_made_here() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let op = op_items();
        sync(&mut s, &op);
        set(&mut s, "A note", "notes", "mine");
        assert_eq!(requested(&s, &op), ["item3item3item3item3item3a", "item9"]);
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[0],
            (MirrorAction::Update, "A note", Some("notes"))
        );
        assert_eq!(
            named(&s, "A note")[0].fields["notes"].value,
            "op-note-secret"
        );
    }

    #[test]
    fn deletes_only_what_the_mirror_added() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let mut op = op_items();
        sync(&mut s, &op);
        create(&mut s, "login", "Mine", &[("password", "kit-pw")]);
        op.retain(|i| i["title"] != "A note" && i["title"] != "Visa");
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[..2],
            [
                (MirrorAction::Delete, "A note", None),
                (MirrorAction::Delete, "Visa", None)
            ]
        );
        assert!(named(&s, "A note").is_empty());
        assert_eq!(named(&s, "Mine").len(), 1);

        // Nothing listed at all is more likely a mistake than a wipe.
        let before = entries(&s);
        let (known, fetched) = fetched(&s, &[], None);
        let error = apply(&mut s, &known, fetched, true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "1Password listed no items: leaving the 9 mirrored items alone"
        );
        assert_eq!(entries(&s), before);
    }

    #[test]
    fn takes_over_the_same_content_and_adds_the_rest_beside() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        import_without_sources(&mut s);
        create(&mut s, "login", "Mine", &[("password", "kit-pw")]);
        let count = items(&s).len();
        let mut op = op_items();
        let report = sync(&mut s, &op);
        // `op` gives the card's and the identity's addresses as one line,
        // so those two are not plainly the same as the imported ones: they
        // are added, and the imports left as they were.
        assert_eq!(report.count(MirrorAction::Adopt), 9, "{report:?}");
        assert_eq!(
            actions(&report)[..2],
            [
                (MirrorAction::Add, "Me", Some(BESIDE)),
                (MirrorAction::Add, "Visa", Some(BESIDE)),
            ]
        );
        assert!(
            report
                .items
                .iter()
                .all(|i| i.action != MirrorAction::Adopt || i.reason.is_none())
        );
        assert_eq!(items(&s).len(), count + 2);
        let me = named(&s, "Me");
        assert_eq!(me.len(), 2);
        let mine = me.iter().find(|i| i.source.is_none()).unwrap();
        assert!(mine.fields["address"].value.contains('\n'));
        assert!(named(&s, "Mine")[0].source.is_none());
        let report = sync(&mut s, &op);
        assert_eq!(report.unchanged, 11);

        // Deleted in 1Password: kept, and no longer mirrored.
        op.retain(|i| i["title"] != "A note");
        let report = sync(&mut s, &op);
        assert_eq!(report.count(MirrorAction::Release), 1);
        let note = &named(&s, "A note")[0];
        assert!(note.source.is_none());
        assert!(!note.deleted);
    }

    #[test]
    fn a_login_with_the_same_username_and_url_is_taken_over_keeping_its_own_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        create(
            &mut s,
            "login",
            "GitHub (work)",
            &[
                ("username", "dax@example.com"),
                ("password", "mine"),
                ("url", "https://github.com/login"),
                ("pin", "2468"),
            ],
        );
        let before = entries(&s);
        let (known, fetched_) = fetched(&s, &op_items(), None);
        let dry = checked(apply(&mut s, &known, fetched_, false).unwrap());
        assert_eq!(entries(&s), before);
        let (_, title, reason) = actions(&dry)
            .into_iter()
            .find(|(a, ..)| *a == MirrorAction::Adopt)
            .unwrap();
        assert_eq!(title, "GitHub");
        let reason = reason.unwrap();
        assert!(
            reason.starts_with("takes over, changes: title, "),
            "{reason}"
        );
        assert!(
            reason.contains("password") && !reason.contains("pin"),
            "{reason}"
        );
        assert!(
            dry.lines()
                .iter()
                .any(|l| l.starts_with("  adopt   GitHub (takes over, changes: "))
        );

        let report = sync(&mut s, &op_items());
        assert_eq!(dry.items, report.items);
        let github = &named(&s, "GitHub")[0];
        assert_eq!(github.fields["password"].value, "op-github-pw");
        assert_eq!(github.fields["pin"].value, "2468");
        assert_eq!(version(github).origin, Origin::Adopted);
        assert!(named(&s, "GitHub (work)").is_empty());

        // Later changes keep it too.
        let mut op = op_items();
        let item = titled(&mut op, "GitHub");
        item["fields"][1]["value"] = json!("op-github-pw-2");
        item["updated_at"] = json!("2024-04-01T00:00:00Z");
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[0],
            (MirrorAction::Update, "GitHub", Some("password"))
        );
        assert_eq!(named(&s, "GitHub")[0].fields["pin"].value, "2468");
        // And it is fresh: written as it now is, with its own field.
        assert_eq!(requested(&s, &op), ["item9"]);

        // A field deleted in 1Password goes; one added here since stays.
        set(&mut s, "GitHub", "door", "1357");
        let item = titled(&mut op, "GitHub");
        item["fields"]
            .as_array_mut()
            .unwrap()
            .retain(|f| f["id"] != "notesPlain");
        item["updated_at"] = json!("2024-05-01T00:00:00Z");
        assert!(named(&s, "GitHub")[0].fields.contains_key("notes"));
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[0],
            (MirrorAction::Update, "GitHub", Some("notes"))
        );
        let github = &named(&s, "GitHub")[0];
        assert!(!github.fields.contains_key("notes"));
        assert_eq!(github.fields["pin"].value, "2468");
        assert_eq!(github.fields["door"].value, "1357");
        assert!(!version(github).fields.contains("door"));
        assert_eq!(requested(&s, &op), ["item9"]);
    }

    #[test]
    fn a_login_matched_here_already_makes_another_with_its_username_and_url_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let mut op = op_items();
        sync(&mut s, &op);
        create(
            &mut s,
            "login",
            "GitHub (work)",
            &[
                ("username", "dax@example.com"),
                ("password", "mine"),
                ("url", "https://github.com/login"),
            ],
        );
        let mut twin = titled(&mut op, "GitHub").clone();
        twin["id"] = json!("twin1twin1twin1twin1twin1a");
        twin["title"] = json!("GitHub 2");
        twin["fields"][1]["value"] = json!("op-github-pw-2");
        op.push(twin);
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[0],
            (
                MirrorAction::Add,
                "GitHub 2",
                Some("added beside 2 items with the same username and URL")
            ),
            "{report:?}"
        );
        assert_eq!(report.count(MirrorAction::Adopt), 0);
        let mine = &named(&s, "GitHub (work)")[0];
        assert!(mine.source.is_none());
        assert_eq!(mine.fields["password"].value, "mine");
    }

    #[test]
    fn an_import_is_never_taken_over_by_another_item() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        import(&mut s);
        let imported: Vec<Item> = items(&s);
        // The same items, from another account: none is the one exported.
        let other = Account {
            id: "OTHEROTHEROTHEROTHEROTHERO".into(),
            user: Some("U2".into()),
        };
        let (known, fetched) = fetched_from(&s, &op_items(), None, other);
        let report = checked(apply(&mut s, &known, fetched, true).unwrap());
        assert_eq!(report.count(MirrorAction::Adopt), 0, "{report:?}");
        assert_eq!(report.count(MirrorAction::Add), 11);
        for item in imported {
            let now = items(&s).into_iter().find(|i| i.id == item.id).unwrap();
            assert_eq!(now.source, item.source);
            assert_eq!(now.fields, item.fields);
        }
    }

    #[test]
    fn mirrors_of_two_accounts_are_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let op = op_items();
        sync(&mut s, &op);
        let other = Account {
            id: "OTHEROTHEROTHEROTHEROTHERO".into(),
            user: None,
        };
        let (known, theirs) = fetched_from(&s, &op, None, other.clone());
        checked(apply(&mut s, &known, theirs, true).unwrap());
        // Each is fresh in its own account.
        assert_eq!(requested(&s, &op), ["item9"]);
        let (_, theirs) = fetched_from(&s, &op, None, other);
        assert_eq!(theirs.requested.into_iter().collect::<Vec<_>>(), ["item9"]);

        // An edit to the other account's copy during a sync of this one
        // holds up nothing.
        let mut changed = op.clone();
        let github = titled(&mut changed, "GitHub");
        github["fields"][1]["value"] = json!("op-github-pw-2");
        github["updated_at"] = json!("2024-04-01T00:00:00Z");
        let (known, fetched) = fetched(&s, &changed, None);
        let theirs = named(&s, "GitHub")
            .into_iter()
            .find(|i| i.source.as_ref().unwrap().id.contains("OTHER"))
            .unwrap();
        let mut field = theirs.fields["password"].clone();
        field.value = "theirs".into();
        let vault = s.resolve(None).unwrap();
        s.update(vault, |v, secret| {
            v.write(secret, vec![DataOp::set(theirs.id, "password", field)])?;
            Ok(())
        })
        .unwrap();
        let report = checked(apply(&mut s, &known, fetched, true).unwrap());
        assert_eq!(
            actions(&report)[0],
            (MirrorAction::Update, "GitHub", Some("password")),
            "{report:?}"
        );
    }

    #[test]
    fn an_item_that_only_shares_a_name_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        create(&mut s, "note", "A note", &[("notes", "mine")]);
        // A login without a URL is no stronger.
        create(
            &mut s,
            "login",
            "GitHub",
            &[("username", "dax@example.com"), ("password", "mine")],
        );
        let report = sync(&mut s, &op_items());
        assert_eq!(report.count(MirrorAction::Adopt), 0, "{report:?}");
        assert!(actions(&report).contains(&(MirrorAction::Add, "A note", Some(BESIDE))));
        assert!(actions(&report).contains(&(MirrorAction::Add, "GitHub", Some(BESIDE))));
        for name in ["A note", "GitHub"] {
            let both = named(&s, name);
            assert_eq!(both.len(), 2);
            let mine = both.iter().find(|i| i.source.is_none()).unwrap();
            assert!(mine.fields.values().any(|f| f.value == "mine"));
        }
    }

    #[test]
    fn an_import_is_taken_over_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        import(&mut s);
        // A .1pux import only records where it came from.
        let github = &named(&s, "GitHub")[0];
        assert_eq!(version(github).origin, Origin::Import);
        assert_eq!(source_app(github.source.as_ref()), None);
        let count = items(&s).len();

        let op = op_items();
        let report = sync(&mut s, &op);
        assert_eq!(report.count(MirrorAction::Adopt), 11, "{report:?}");
        assert_eq!(report.count(MirrorAction::Add), 0);
        // It names the user, `op` the account: the same item all the same,
        // so even the two whose addresses `op` gives differently.
        let changed: Vec<_> = actions(&report)
            .into_iter()
            .filter(|(_, _, reason)| reason.is_some_and(|r| r.starts_with("takes over")))
            .collect();
        assert_eq!(
            changed,
            [
                (
                    MirrorAction::Adopt,
                    "Me",
                    Some("takes over, changes: address")
                ),
                (
                    MirrorAction::Adopt,
                    "Visa",
                    Some("takes over, changes: address")
                ),
            ]
        );
        assert_eq!(items(&s).len(), count);
        let github = &named(&s, "GitHub")[0];
        assert_eq!(
            github.source.as_ref().unwrap().id,
            format!("1password/{ACCOUNT}/{PRIVATE}/item1item1item1item1item1a")
        );
        assert_eq!(version(github).origin, Origin::Adopted);
        assert_eq!(
            source_app(github.source.as_ref()).as_deref(),
            Some("1Password")
        );
        // The export's "Old key" is gone from 1Password; never mirrored, it
        // is left as it was.
        let old = &named(&s, "Old key")[0];
        assert_eq!(version(old).origin, Origin::Import);

        let before = entries(&s);
        assert_eq!(requested(&s, &op), ["item9"]);
        let report = sync(&mut s, &op);
        assert_eq!(report.unchanged, 11);
        assert_eq!(&actions(&report), &SKIPPED);
        assert_eq!(entries(&s), before);
    }

    #[test]
    fn ambiguity_is_reported_from_the_side_it_is_on() {
        let github = |password: &'static str| {
            [
                ("username", "dax@example.com"),
                ("password", password),
                ("url", "https://github.com/login"),
            ]
        };
        // Two here.
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        for password in ["one", "two"] {
            create(&mut s, "login", "GitHub", &github(password));
        }
        let report = sync(&mut s, &op_items());
        assert!(
            actions(&report).contains(&(
                MirrorAction::Add,
                "GitHub",
                Some("added beside 2 items with the same username and URL")
            )),
            "{report:?}"
        );
        assert_eq!(report.count(MirrorAction::Add), 11);
        let mine: Vec<_> = named(&s, "GitHub")
            .into_iter()
            .filter(|i| i.source.is_none())
            .collect();
        assert_eq!(mine.len(), 2);

        // Two in 1Password.
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        create(&mut s, "login", "GitHub", &github("one"));
        let mut op = op_items();
        let mut twin = titled(&mut op, "GitHub").clone();
        twin["id"] = json!("twin1twin1twin1twin1twin1a");
        op.push(twin);
        let report = sync(&mut s, &op);
        let reason = "2 1Password items have this username and URL; added beside the one here";
        assert_eq!(
            actions(&report)
                .iter()
                .filter(|a| **a == (MirrorAction::Add, "GitHub", Some(reason)))
                .count(),
            2,
            "{report:?}"
        );
        assert_eq!(named(&s, "GitHub").len(), 3);
    }

    #[test]
    fn the_same_content_settles_a_tie_and_the_rest_are_added() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        import_without_sources(&mut s);
        let mut op = op_items();
        let mut twin = titled(&mut op, "GitHub").clone();
        twin["id"] = json!("twin1twin1twin1twin1twin1a");
        twin["fields"][1]["value"] = json!("op-github-pw-2");
        op.push(twin);
        let report = sync(&mut s, &op);
        assert_eq!(report.count(MirrorAction::Adopt), 9, "{report:?}");
        assert!(actions(&report).contains(&(MirrorAction::Adopt, "GitHub", None)));
        assert!(actions(&report).contains(&(MirrorAction::Add, "GitHub", None)));
        let github = named(&s, "GitHub");
        assert_eq!(github.len(), 2);
        assert!(github.iter().all(|i| i.source.is_some()));
        let passwords: BTreeSet<_> = github
            .iter()
            .map(|i| i.fields["password"].value.as_str())
            .collect();
        assert_eq!(
            passwords,
            BTreeSet::from(["op-github-pw", "op-github-pw-2"])
        );
    }

    #[test]
    fn a_move_between_vaults_keeps_the_one_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let mut op = op_items();
        sync(&mut s, &op);
        let id = named(&s, "GitHub")[0].id;
        titled(&mut op, "GitHub")["vault"] = json!({ "id": SHARED, "name": "Shared" });

        // A sync of the vault it left only leaves it alone.
        let report = sync_vaults(&mut s, &op, Some(&[PRIVATE]));
        assert!(!report.changed(), "{report:?}");

        let report = sync(&mut s, &op);
        assert_eq!(actions(&report)[0], (MirrorAction::Update, "GitHub", None));
        assert_eq!(report.count(MirrorAction::Update), 1);
        let github = named(&s, "GitHub");
        assert_eq!(github.len(), 1);
        assert_eq!(github[0].id, id);
        assert_eq!(
            github[0].source.as_ref().unwrap().id,
            format!("1password/{ACCOUNT}/{SHARED}/item1item1item1item1item1a")
        );
        assert_eq!(requested(&s, &op), ["item9"]);
    }

    #[test]
    fn an_item_changed_during_the_fetch_is_left_for_next_time() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let mut op = op_items();
        sync(&mut s, &op);
        let github = titled(&mut op, "GitHub");
        github["fields"][1]["value"] = json!("op-github-pw-2");
        github["updated_at"] = json!("2024-04-01T00:00:00Z");
        let (known, fetched) = fetched(&s, &op, None);
        assert!(fetched.items.contains_key("item1item1item1item1item1a"));
        assert!(!fetched.items.contains_key("item3item3item3item3item3a"));

        // Meanwhile, here: one is edited and another deleted.
        set(&mut s, "GitHub", "notes", "mine");
        let words = vec!["A note".to_string()];
        super::super::items::remove(&mut s, None, &words).unwrap();
        let report = checked(apply(&mut s, &known, fetched, true).unwrap());
        let raced: Vec<_> = actions(&report)
            .into_iter()
            .filter(|(.., reason)| *reason == Some(RACED))
            .collect();
        assert_eq!(
            raced,
            [
                (MirrorAction::Skip, "A note", Some(RACED)),
                (MirrorAction::Skip, "GitHub", Some(RACED)),
            ]
        );
        assert!(!report.changed());
        assert_eq!(report.unchanged, 9);
        assert_eq!(named(&s, "GitHub")[0].fields["notes"].value, "mine");
        assert!(named(&s, "A note").is_empty());

        // The next sync fetches both again; 1Password wins.
        let report = sync(&mut s, &op);
        assert_eq!(report.count(MirrorAction::Update), 1, "{report:?}");
        assert_eq!(report.count(MirrorAction::Add), 1);
        assert_eq!(
            named(&s, "GitHub")[0].fields["password"].value,
            "op-github-pw-2"
        );
    }

    /// Writes a copy of `name`'s source on a new item with its content.
    fn duplicate(s: &mut Loaded, name: &str, origin: Origin) {
        let item = named(s, name).remove(0);
        let mut source = item.source.clone().unwrap();
        let mut version = MirrorVersion::parse(&source.version).unwrap();
        version.origin = origin;
        if origin == Origin::Adopted {
            version.fields = item.fields.keys().cloned().collect();
        }
        source.version = version.to_string();
        let vault = s.resolve(None).unwrap();
        s.update(vault, |v, secret| {
            v.write(secret, vec![DataOp::source(item.id, Some(source.clone()))])?;
            let copy =
                DataOp::create_mirror(&item.kind, item.name.clone(), item.fields.clone(), source);
            v.create_items(secret, vec![copy])?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn second_copies_are_settled_only_in_the_vaults_mirrored() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let op = op_items();
        sync(&mut s, &op);
        duplicate(&mut s, "GitHub", Origin::Sync);
        let report = sync_vaults(&mut s, &op, Some(&[SHARED]));
        assert!(!report.changed(), "{report:?}");
        assert_eq!(named(&s, "GitHub").len(), 2);
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[0],
            (MirrorAction::Delete, "GitHub", Some("a second copy"))
        );
        assert_eq!(named(&s, "GitHub").len(), 1);

        // Two adopted copies: one is released, not deleted.
        duplicate(&mut s, "GitHub", Origin::Adopted);
        let report = sync(&mut s, &op);
        assert_eq!(
            actions(&report)[0],
            (MirrorAction::Release, "GitHub", Some("a second copy"))
        );
        let github = named(&s, "GitHub");
        assert_eq!(github.len(), 2);
        assert_eq!(github.iter().filter(|i| i.source.is_none()).count(), 1);
    }

    #[test]
    fn a_dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let mut op = op_items();
        let before = entries(&s);
        let (known, fetched_) = fetched(&s, &op, None);
        let dry = apply(&mut s, &known, fetched_, false).unwrap();
        assert!(!dry.applied);
        assert_eq!(entries(&s), before);
        assert_eq!(dry.summary(), "11 would add");
        let real = sync(&mut s, &op);
        assert_eq!(dry.items, real.items);

        op.retain(|i| i["title"] != "Visa");
        let before = entries(&s);
        let (known, fetched_) = fetched(&s, &op, None);
        let dry = apply(&mut s, &known, fetched_, false).unwrap();
        assert_eq!(dry.lines()[1], "  delete  Visa");
        assert_eq!(entries(&s), before);
    }

    #[test]
    fn vaults_left_out_are_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let op = op_items();
        sync(&mut s, &op);
        let report = sync_vaults(&mut s, &op, Some(&[PRIVATE]));
        assert!(!report.changed(), "{report:?}");
        assert_eq!(report.unchanged, 3);
        assert_eq!(named(&s, "Visa").len(), 1);
    }

    /// A fake `op` in `dir` that runs `script` for any arguments.
    fn fake_op(dir: &std::path::Path, script: &str) -> Op {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("op");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Op::at(path)
    }

    #[tokio::test]
    async fn chooses_the_account_already_mirrored() {
        let dir = tempfile::tempdir().unwrap();
        let accounts = json!([
            { "url": "https://my.1password.com/", "email": "dax@example.com", "user_uuid": USER, "account_uuid": ACCOUNT },
            { "url": "team.1password.com", "email": "dax@example.com", "user_uuid": "U2", "account_uuid": "A2" },
        ]);
        std::fs::write(dir.path().join("accounts.json"), accounts.to_string()).unwrap();
        let op = fake_op(dir.path(), r#"cat "$(dirname "$0")/accounts.json""#);
        let none = BTreeSet::new();
        let set = |ids: &[&str]| ids.iter().map(|id| id.to_string()).collect::<BTreeSet<_>>();
        let error = super::account(&op, None, &none, &none).await.err().unwrap();
        assert_eq!(
            error.to_string(),
            "2 1Password accounts: choose one with --account \
             (dax@example.com on my.1password.com, dax@example.com on team.1password.com)"
        );
        let chosen = super::account(&op, Some("my.1password.com"), &none, &none)
            .await
            .unwrap();
        assert_eq!(chosen.id, ACCOUNT);
        let chosen = super::account(&op, Some("https://team.1password.com/"), &none, &none)
            .await
            .unwrap();
        assert_eq!(chosen.id, "A2");
        // A vault mirroring one, or holding its import, names it.
        for (mirrored, imported) in [
            (set(&[ACCOUNT]), none.clone()),
            (none.clone(), set(&[USER])),
            // Mirrors outrank an import from another account.
            (set(&[ACCOUNT]), set(&["U2"])),
        ] {
            let chosen = super::account(&op, None, &mirrored, &imported)
                .await
                .unwrap();
            assert_eq!(
                (chosen.id.as_str(), chosen.user.as_deref()),
                (ACCOUNT, Some(USER))
            );
        }
        let error = super::account(&op, None, &none, &set(&[USER, "U2"])).await;
        assert!(error.is_err());
    }

    #[tokio::test]
    async fn a_stuck_op_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("pid");
        let script = format!("echo $$ > '{}'\nexec sleep 30", pid.display());
        let mut op = fake_op(dir.path(), &script);
        op.timeout = Duration::from_millis(300);
        let started = std::time::Instant::now();
        let error = op
            .json(&["item", "list"], None, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), TIMED_OUT);
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid = std::fs::read_to_string(&pid).unwrap();
        assert!(gone(pid.trim()).await, "op {pid} still running");
    }

    /// Whether process `pid` has exited, within a few seconds.
    pub(crate) async fn gone(pid: &str) -> bool {
        for _ in 0..100 {
            let alive = std::process::Command::new("kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success();
            if !alive {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[test]
    fn op_errors_say_what_to_do() {
        let cases = [
            (
                "[ERROR] 2024/03/09 16:00:00 You are not currently signed in. Please run `op signin --help` for instructions",
                NOT_SIGNED_IN,
            ),
            (
                "[ERROR] 2024/03/09 16:00:00 authorization prompt dismissed, please try again",
                NOT_ALLOWED,
            ),
            ("[ERROR] 2024/03/09 16:00:00 1Password is locked", LOCKED),
            (
                "[ERROR] 2024/03/09 16:00:00 error initializing client: connecting to desktop app: cannot connect",
                NO_APP,
            ),
        ];
        for (stderr, hint) in cases {
            assert_eq!(failure(stderr).to_string(), hint, "{stderr}");
        }
        assert_eq!(
            failure("[ERROR] 2024/03/09 16:00:00 \"Nope\" isn't a vault in this account.\nmore")
                .to_string(),
            "the 1Password CLI failed: \"Nope\" isn't a vault in this account."
        );
        assert_eq!(
            failure("").to_string(),
            "the 1Password CLI failed: it gave no reason"
        );
    }
}
