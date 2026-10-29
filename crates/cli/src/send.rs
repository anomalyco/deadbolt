//! `deadbolt send` and `deadbolt sends`: one-time links to files, secrets and
//! vault items, served live by the agent (see `docs/proposals/send.md`).
//!
//! The client builds and seals the bundle; the agent gets only the sealed
//! bytes and the access secret, never the content key, which goes straight
//! into the link.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgMatches, Args, FromArgMatches, Subcommand};
use data_encoding::{BASE64, HEXLOWER};
use deadbolt_net::{QrStyle, render_qr};
use deadbolt_send::{
    Bundle, Entry, Group, LINK_BASE, MAX_SEALED_LEN, Node, SendTicket, SenderAddr, random_secret,
    seal,
};
use zeroize::Zeroizing;

use crate::client;
use crate::config;
use crate::paths::Paths;
use crate::prompt;
use crate::protocol::{
    Command, FieldInfo, ItemInfo, Reply, Secret, SendInfo, SendState, SenderInfo,
};

/// Exit code of `send --wait` when the link expired unopened.
pub const EXIT_EXPIRED: u8 = 4;
/// Exit code of `send --wait` when the link was revoked.
pub const EXIT_REVOKED: u8 = 5;

/// `deadbolt send`'s flags, plus where each input sat on the command line:
/// inputs go into the bundle in that order, and each `--field` belongs to
/// the nearest `--item` before it.
pub struct SendArgs {
    raw: Raw,
    inputs_at: Vec<usize>,
    items_at: Vec<usize>,
    fields_at: Vec<usize>,
}

#[derive(Args)]
struct Raw {
    /// Files and folders to send, or `-` for stdin. Each must exist; a
    /// name is never looked up in the vault (use --item). Without any
    /// input, asks for a secret (hidden).
    #[arg(value_name = "PATH")]
    inputs: Vec<String>,
    /// A vault item to send, by its exact name or ID; repeat for more.
    #[arg(long = "item", value_name = "NAME|ID")]
    items: Vec<String>,
    /// Send only this field of the nearest --item before it.
    #[arg(short, long = "field", value_name = "NAME")]
    fields: Vec<String>,
    /// A title the receiver sees.
    #[arg(long)]
    title: Option<String>,
    /// A note the receiver sees above everything (not hidden).
    #[arg(long)]
    note: Option<String>,
    /// Hide files and stdin behind "reveal" too (secrets, secret item
    /// fields and key-like files such as *.pem, *.key and .env always are).
    #[arg(long)]
    sensitive: bool,
    /// How many times the link may be opened.
    #[arg(long, default_value_t = 1)]
    opens: u32,
    /// How long the link works: 30s, 15m, 1h, 24h, 7d (at most 7 days).
    #[arg(long, default_value = "1h")]
    ttl: String,
    /// Also print the link as a QR code (to stderr).
    #[arg(long)]
    qr: bool,
    /// Print `{"id", "link", "expires"}` instead of the link (needs --yes).
    #[arg(long)]
    json: bool,
    /// Create the link without showing what will be sent and asking first.
    /// Needed by scripts: without a terminal, send fails rather than wait.
    #[arg(short, long)]
    yes: bool,
    /// Wait until the link is picked up (exit 0), expires (exit 4) or is
    /// revoked (exit 5).
    #[arg(long)]
    wait: bool,
}

impl FromArgMatches for SendArgs {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let at = |id: &str| {
            matches
                .indices_of(id)
                .map(Iterator::collect)
                .unwrap_or_default()
        };
        Ok(Self {
            raw: Raw::from_arg_matches(matches)?,
            inputs_at: at("inputs"),
            items_at: at("items"),
            fields_at: at("fields"),
        })
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl Args for SendArgs {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        Raw::augment_args(cmd)
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Raw::augment_args_for_update(cmd)
    }
}

#[derive(Args)]
pub struct SendsArgs {
    #[command(subcommand)]
    command: Option<SendsCommand>,
}

#[derive(Subcommand)]
enum SendsCommand {
    /// List sends: id, state, opens, expiry and what was sent.
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Show one send: its state and when it was opened.
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Stop a link working.
    Revoke { id: String },
}

/// One thing to send, as given on the command line.
#[derive(Debug, PartialEq)]
enum Source {
    Stdin,
    Path(PathBuf),
    Item {
        query: String,
        field: Option<String>,
    },
}

impl SendArgs {
    /// The inputs in command-line order, each `--field` bound to the
    /// nearest `--item` before it. Paths must exist.
    fn sources(&self) -> Result<Vec<Source>> {
        let raw = &self.raw;
        let mut sources: Vec<(usize, Source)> = Vec::new();
        for (arg, &at) in raw.inputs.iter().zip(&self.inputs_at) {
            let source = match arg.as_str() {
                "-" => Source::Stdin,
                path if Path::new(path).exists() => Source::Path(PathBuf::from(path)),
                path => bail!("{path}: no such file"),
            };
            sources.push((at, source));
        }
        for (query, &at) in raw.items.iter().zip(&self.items_at) {
            let query = query.clone();
            sources.push((at, Source::Item { query, field: None }));
        }
        sources.sort_by_key(|(at, _)| *at);
        for (name, &at) in raw.fields.iter().zip(&self.fields_at) {
            let item = sources
                .iter_mut()
                .rev()
                .find(|(item_at, s)| *item_at < at && matches!(s, Source::Item { .. }));
            let Some((_, Source::Item { query, field })) = item else {
                bail!("--field {name:?} must follow the --item it belongs to");
            };
            if let Some(first) = field {
                bail!(
                    "--item {query:?} has two fields ({first:?} and {name:?}); repeat --item for each"
                );
            }
            *field = Some(name.clone());
        }
        Ok(sources.into_iter().map(|(_, s)| s).collect())
    }
}

/// How `send` asks before creating the link.
#[derive(Debug, PartialEq)]
enum Ask {
    /// `--yes`: don't.
    Skip,
    /// On stdin, a terminal.
    Stdin,
    /// On `/dev/tty`: stdin carries what is sent.
    Tty,
}

/// Asking needs a terminal on stdout and stderr, and one to read the answer
/// from: stdin, or `/dev/tty` when stdin is what's being sent.
fn ask(yes: bool, json: bool, reads_stdin: bool, stdin_tty: bool, out_tty: bool) -> Result<Ask> {
    if yes {
        return Ok(Ask::Skip);
    }
    if json {
        bail!("--json needs --yes (no prompt possible)");
    }
    if !out_tty || !(stdin_tty || reads_stdin) {
        bail!("no terminal to confirm on: pass --yes to create the link without asking");
    }
    Ok(if reads_stdin { Ask::Tty } else { Ask::Stdin })
}

/// What a part of the bundle is, for the preview.
#[derive(Clone, Copy)]
enum Kind {
    File,
    Folder,
    Item,
    Field,
    Secret,
    Stdin,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Folder => "folder",
            Kind::Item => "item",
            Kind::Field => "field",
            Kind::Secret => "secret",
            Kind::Stdin => "stdin",
        }
    }
}

struct Part {
    kind: Kind,
    node: Node,
}

pub async fn send(
    paths: &Paths,
    args: SendArgs,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<ExitCode> {
    let sources = args.sources()?;
    let args = args.raw;
    let ttl = match config::parse_timeout(&args.ttl)? {
        Some(ttl) if ttl.as_secs() > 0 => ttl,
        _ => bail!("--ttl must be a duration, such as 15m, 1h or 24h"),
    };
    if args.opens == 0 {
        bail!("--opens must be at least 1");
    }
    let stdin_used = sources.iter().filter(|s| **s == Source::Stdin).count();
    if stdin_used > 1 {
        bail!("`-` (stdin) can only be sent once");
    }
    if stdin_used == 1 && from_stdin {
        bail!("--passphrase-stdin cannot be used when sending stdin");
    }
    let ask = ask(
        args.yes,
        args.json,
        stdin_used == 1,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal() && std::io::stderr().is_terminal(),
    )?;
    let mut tty =
        match ask {
            Ask::Tty => Some(prompt::tty().context(
                "no terminal to confirm on: pass --yes to create the link without asking",
            )?),
            Ask::Skip | Ask::Stdin => None,
        };
    if sources.is_empty() && !prompt::interactive() {
        bail!("nothing to send: pass files, `-` for stdin, or --item NAME");
    }

    client::ensure_running(paths).await?;
    let mut parts = Vec::new();
    if sources.is_empty() {
        let value = prompt::ask_value("secret to send", true)?;
        if value.is_empty() {
            bail!("nothing to send");
        }
        parts.push(Part {
            kind: Kind::Secret,
            node: Node::Entry(Entry::text("secret", value.as_str(), true)),
        });
    }
    let mut walk = Walk::new(MAX_SEALED_LEN);
    for source in &sources {
        let part = match source {
            Source::Stdin => Part {
                kind: Kind::Stdin,
                node: stdin_entry(args.sensitive)?,
            },
            Source::Path(path) => {
                let node = walk.node(path, args.sensitive)?;
                let kind = match node {
                    Node::Group(_) => Kind::Folder,
                    Node::Entry(_) => Kind::File,
                };
                Part { kind, node }
            }
            Source::Item { query, field } => {
                let item = find_item(paths, query, vault.clone(), from_stdin).await?;
                Part {
                    kind: if field.is_some() {
                        Kind::Field
                    } else {
                        Kind::Item
                    },
                    node: item_node(&item, field.as_deref())?,
                }
            }
        };
        parts.push(part);
    }

    if ask != Ask::Skip {
        eprint!(
            "{}",
            preview(
                &parts,
                args.opens,
                ttl.as_secs(),
                args.title.as_deref(),
                args.note.as_deref()
            )
        );
        let question = "Create link?";
        let confirmed = match tty.as_mut() {
            Some(tty) => prompt::confirm_from(question, tty)?,
            None => prompt::confirm(question)?,
        };
        if !confirmed {
            eprintln!("not sent");
            return Ok(ExitCode::FAILURE);
        }
    }

    let names: Vec<String> = parts.iter().map(|p| node_name(&p.node)).collect();
    let entries: Vec<Node> = parts.into_iter().map(|p| p.node).collect();

    let bundle = Bundle {
        title: args.title.clone(),
        note: args.note.clone(),
        entries,
    };
    let plaintext = bundle.encode();
    drop(bundle);
    // Sealing adds 16 bytes per 64 KiB chunk and a 15-byte prefix.
    if plaintext.len() + plaintext.len() / 4096 + 64 > MAX_SEALED_LEN {
        bail!(
            "too large to send: {} bytes, at most about {} MB",
            plaintext.len(),
            MAX_SEALED_LEN / 1024 / 1024
        );
    }
    let key = random_secret()?;
    let secret = random_secret()?;
    let sealed = seal(&key, &plaintext)?;
    drop(plaintext);

    let label = args.title.clone().unwrap_or_else(|| label(&names));
    let command = Command::SendCreate {
        secret: Secret::new(HEXLOWER.encode(secret.as_ref())),
        sealed: BASE64.encode(&sealed),
        opens: args.opens,
        ttl_secs: ttl.as_secs(),
        label,
    };
    let Reply::SendCreated { send, sender } = client::call(paths, command, no_events).await? else {
        bail!("unexpected reply");
    };
    let ticket = SendTicket::new(sender_addr(&sender)?, secret, key);
    let link = Zeroizing::new(ticket.link_at(&link_base()));
    if sender.relay_url.is_none() {
        eprintln!(
            "warning: no relay reachable, so this link won't open in a browser; check the network and send again"
        );
    }
    if args.qr
        && let Ok(qr) = render_qr(&link, QrStyle::LightOnDark)
    {
        eprintln!("{qr}");
    }
    if args.json {
        println!(
            "{}",
            serde_json::json!({ "id": send.id, "link": *link, "expires": send.expires })
        );
    } else {
        println!("{}", *link);
    }
    eprintln!(
        "send {}: {}, {}, expires {}. Served live from this computer: it ends if the deadbolt agent stops.",
        send.id,
        send.label,
        opens(send.opens),
        until(send.expires)
    );
    if !args.wait {
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("waiting for it to be opened...");
    let Reply::Send { send } =
        client::call(paths, Command::SendWait { id: send.id }, no_events).await?
    else {
        bail!("unexpected reply");
    };
    Ok(match send.state {
        SendState::PickedUp => {
            eprintln!("picked up {}", opened_at(&send));
            ExitCode::SUCCESS
        }
        SendState::Expired => {
            eprintln!("expired{}", opened_suffix(&send));
            ExitCode::from(EXIT_EXPIRED)
        }
        SendState::Revoked => {
            eprintln!("revoked{}", opened_suffix(&send));
            ExitCode::from(EXIT_REVOKED)
        }
        SendState::Open => bail!("the send is still open"),
    })
}

pub async fn sends(paths: &Paths, args: SendsArgs) -> Result<()> {
    client::ensure_running(paths).await?;
    match args.command.unwrap_or(SendsCommand::Ls { json: false }) {
        SendsCommand::Ls { json } => {
            let Reply::Sends { sends } = client::call(paths, Command::SendList, no_events).await?
            else {
                bail!("unexpected reply");
            };
            if json {
                println!("{}", serde_json::to_string(&sends)?);
                return Ok(());
            }
            if sends.is_empty() {
                eprintln!("no sends (they end when the deadbolt agent stops)");
            }
            for send in &sends {
                println!(
                    "{}\t{}\t{}/{} opened\t{}\t{}",
                    send.id,
                    send.state,
                    send.opened.len(),
                    send.opens,
                    expiry(send),
                    send.label
                );
            }
        }
        SendsCommand::Show { id, json } => {
            let Reply::Send { send } =
                client::call(paths, Command::SendShow { id }, no_events).await?
            else {
                bail!("unexpected reply");
            };
            if json {
                println!("{}", serde_json::to_string(&send)?);
                return Ok(());
            }
            println!("id\t{}", send.id);
            println!("what\t{}", send.label);
            println!("state\t{}", send.state);
            println!("opens\t{} of {}", send.opened.len(), send.opens);
            for at in &send.opened {
                println!("opened\t{}", crate::ago(*at));
            }
            if let Some(at) = send.revoked {
                println!("revoked\t{}", crate::ago(at));
            }
            println!("created\t{}", crate::ago(send.created));
            println!("expires\t{}", expiry(&send));
            println!("size\t{} bytes sealed", send.size);
        }
        SendsCommand::Revoke { id } => {
            let Reply::Send { send } =
                client::call(paths, Command::SendRevoke { id }, no_events).await?
            else {
                bail!("unexpected reply");
            };
            match send.state {
                SendState::Revoked => println!("revoked {}", send.id),
                state => println!("{} was already {state}", send.id),
            }
        }
    }
    Ok(())
}

fn no_events(event: crate::protocol::Event) -> Result<Option<crate::protocol::Answer>> {
    Err(anyhow!("unexpected event {event:?}"))
}

/// The receive page links point to: `DEADBOLT_SEND_URL` (a local or
/// self-hosted copy of the site's `/r`), else deadbolt.pw.
fn link_base() -> String {
    config::env("DEADBOLT_SEND_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| LINK_BASE.to_string())
}

fn sender_addr(sender: &SenderInfo) -> Result<SenderAddr> {
    let bytes = HEXLOWER
        .decode(sender.id.as_bytes())
        .context("the agent's send endpoint id is not hex")?;
    let id = bytes
        .try_into()
        .map_err(|_| anyhow!("the agent's send endpoint id is not 32 bytes"))?;
    Ok(SenderAddr {
        id,
        relay_url: sender.relay_url.clone(),
        direct_addrs: sender
            .direct_addrs
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect(),
    })
}

/// The item whose ID (full or short) or name is exactly `query`. Close
/// names are suggested, never picked.
async fn find_item(
    paths: &Paths,
    query: &str,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<ItemInfo> {
    let command = Command::ItemList {
        vault: vault.clone(),
        query: Vec::new(),
        kind: None,
    };
    let Reply::Items { items } = crate::request(paths, command, from_stdin).await? else {
        bail!("unexpected reply");
    };
    let id = exact_item(&items, query)?;
    let command = Command::ItemGet {
        vault,
        query: vec![id],
        otp: true,
        files: false,
    };
    let Reply::Item { item } = crate::request(paths, command, from_stdin).await? else {
        bail!("unexpected reply");
    };
    Ok(item)
}

/// The ID of the one item with ID or name `query`.
fn exact_item(items: &[ItemInfo], query: &str) -> Result<String> {
    if let Some(item) = items.iter().find(|i| i.id == query || i.short == query) {
        return Ok(item.id.clone());
    }
    let named: Vec<&ItemInfo> = items.iter().filter(|i| i.label == query).collect();
    match named.as_slice() {
        [item] => Ok(item.id.clone()),
        [] => {
            let similar = similar_names(items, query);
            if similar.is_empty() {
                bail!("no item named {query:?}");
            }
            let similar: Vec<String> = similar.iter().map(|n| format!("{n:?}")).collect();
            bail!(
                "no item named {query:?}. Did you mean: {}?",
                similar.join(", ")
            )
        }
        many => {
            let lines: Vec<String> = many.iter().map(|i| crate::items::line(i)).collect();
            bail!(
                "{} items are named {query:?}; pass the ID of one to --item:\n{}",
                many.len(),
                lines.join("\n")
            )
        }
    }
}

/// Up to five item names close to `query`: the same ignoring case,
/// containing it or contained in it, or a few typos away.
fn similar_names(items: &[ItemInfo], query: &str) -> Vec<String> {
    let query = query.to_lowercase();
    let typos = (query.chars().count() / 3).max(1);
    let mut scored: Vec<(usize, &str)> = items
        .iter()
        .filter_map(|item| {
            let name = item.label.to_lowercase();
            let contains = query.chars().count() >= 3
                && name.chars().count() >= 3
                && (name.contains(&query) || query.contains(&name));
            let score = if contains {
                name.chars().count().abs_diff(query.chars().count())
            } else {
                match edit_distance(&name, &query) {
                    d if d <= typos => d,
                    _ => return None,
                }
            };
            Some((score, item.label.as_str()))
        })
        .collect();
    scored.sort();
    let mut names: Vec<String> = Vec::new();
    for (_, name) in scored {
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names.truncate(5);
    names
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (above + 1)
                .min(row[j] + 1)
                .min(diagonal + usize::from(ca != *cb));
            diagonal = above;
        }
    }
    row[b.len()]
}

/// What `send` asks about before creating the link:
///
/// ```text
/// About to send (single use, expires in 1h):
///   file  opencodejr.pem  1.7 KB  sensitive
/// ```
fn preview(
    parts: &[Part],
    opens: u32,
    ttl_secs: u64,
    title: Option<&str>,
    note: Option<&str>,
) -> String {
    let uses = match opens {
        1 => "single use".to_string(),
        n => format!("opens {n} times"),
    };
    let mut rows: Vec<[String; 4]> = Vec::new();
    if let Some(title) = title {
        rows.push(["title".into(), title.into(), String::new(), String::new()]);
    }
    if let Some(note) = note {
        rows.push(["note".into(), note.into(), String::new(), String::new()]);
    }
    for part in parts {
        let (count, bytes, sensitive) = leaves(&part.node);
        let size = match part.kind {
            Kind::Item => plural(count, "field"),
            Kind::Folder => format!("{}, {}", plural(count, "file"), size(bytes)),
            _ => size(bytes),
        };
        let sensitive = match sensitive {
            0 => String::new(),
            n if n == count => "sensitive".into(),
            n => format!("{n} sensitive"),
        };
        rows.push([
            part.kind.as_str().into(),
            node_name(&part.node),
            size,
            sensitive,
        ]);
    }
    let width = |col: usize| {
        rows.iter()
            .map(|r| r[col].chars().count())
            .max()
            .unwrap_or(0)
    };
    let widths = [width(0), width(1), width(2)];
    let mut out = format!(
        "About to send ({uses}, expires in {}):\n",
        duration(ttl_secs)
    );
    for row in &rows {
        let mut line = format!(
            "  {:w0$}  {:w1$}  {:w2$}  {}",
            row[0],
            row[1],
            row[2],
            row[3],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2]
        );
        line.truncate(line.trim_end().len());
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Entries under `node`: how many, their bytes, and how many are sensitive.
fn leaves(node: &Node) -> (usize, usize, usize) {
    match node {
        Node::Entry(e) => (1, e.data.len(), usize::from(e.sensitive)),
        Node::Group(g) => g
            .entries
            .iter()
            .map(leaves)
            .fold((0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2)),
    }
}

fn plural(n: usize, noun: &str) -> String {
    match n {
        1 => format!("1 {noun}"),
        n => format!("{n} {noun}s"),
    }
}

/// `512 B`, `1.7 KB`, `3.2 MB`.
fn size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < KB * KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{:.1} MB", b / KB / KB)
    }
}

/// `30s`, `15m`, `1h`, `7d`, in the largest unit that divides it.
fn duration(secs: u64) -> String {
    match secs {
        s if s % 86400 == 0 => format!("{}d", s / 86400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// Key and secret files, sent hidden behind "reveal" like typed secrets.
fn looks_secret(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
    matches!(
        ext,
        "pem" | "key" | "p12" | "pfx" | "jks" | "keystore" | "kdbx" | "env"
    ) || name == ".env"
        || name.starts_with(".env.")
        || (name.starts_with("id_") && ext != "pub")
}

/// Fields of type secret and otp stay hidden; the others show.
fn field_entry(field: &FieldInfo) -> Entry {
    Entry::text(
        field.name.clone(),
        field.value.clone(),
        matches!(field.kind.as_str(), "secret" | "otp"),
    )
}

fn item_node(item: &ItemInfo, field: Option<&str>) -> Result<Node> {
    let fields = item.fields.iter().filter(|f| !f.value.is_empty());
    match field {
        Some(name) => {
            let field = item
                .fields
                .iter()
                .find(|f| f.name == name && !f.value.is_empty())
                .ok_or_else(|| anyhow!("{} has no field {name:?}", item.label))?;
            let mut entry = field_entry(field);
            entry.name = format!("{} {}", item.label, field.name);
            Ok(Node::Entry(entry))
        }
        None => Ok(Node::Group(Group {
            name: Some(item.label.clone()),
            entries: fields.map(|f| Node::Entry(field_entry(f))).collect(),
        })),
    }
}

fn stdin_entry(sensitive: bool) -> Result<Node> {
    let mut data = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut data)
        .context("reading stdin")?;
    if data.is_empty() {
        bail!("stdin is empty");
    }
    let entry = match String::from_utf8(data) {
        // Text: a secret, without the newline `echo` adds.
        Ok(text) if text.len() <= 4096 => {
            let value = text
                .strip_suffix('\n')
                .map(|t| t.strip_suffix('\r').unwrap_or(t))
                .unwrap_or(&text);
            let entry = Entry::text("secret", value, true);
            drop(Zeroizing::new(text));
            entry
        }
        Ok(text) => Entry {
            name: "stdin.txt".into(),
            data: text.into_bytes(),
            mime: Some("text/plain".into()),
            sensitive,
        },
        Err(e) => Entry {
            name: "stdin".into(),
            data: e.into_bytes(),
            mime: Some("application/octet-stream".into()),
            sensitive,
        },
    };
    Ok(Node::Entry(entry))
}

/// Reads files and folders for one send: never more than a bundle holds
/// ([`MAX_SEALED_LEN`]), and never a folder inside itself through a link.
struct Walk {
    /// What's left for contents and names, counted as the bundle encodes
    /// them (at least), so nothing the bundle could hold is turned away.
    left: u64,
    /// The folders being read, outermost first, by device and inode.
    open: Vec<(u64, u64)>,
}

fn too_large(path: &Path) -> anyhow::Error {
    anyhow!(
        "too large to send: {} goes past about {} MB",
        path.display(),
        MAX_SEALED_LEN / 1024 / 1024
    )
}

/// What the bundle spends on an entry and a group besides its name and data.
const ENTRY_COST: u64 = 15;
const GROUP_COST: u64 = 10;

impl Walk {
    fn new(limit: usize) -> Self {
        Walk {
            left: limit as u64,
            open: Vec::new(),
        }
    }

    fn spend(&mut self, path: &Path, n: u64) -> Result<()> {
        self.left = self.left.checked_sub(n).ok_or_else(|| too_large(path))?;
        Ok(())
    }

    /// A file as an entry, a folder as a group of its files and folders.
    fn node(&mut self, path: &Path, sensitive: bool) -> Result<Node> {
        use std::os::unix::fs::MetadataExt;

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .or_else(|| {
                std::fs::canonicalize(path)
                    .ok()?
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "files".into());
        let meta =
            std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if meta.is_dir() {
            self.spend(path, GROUP_COST + name.len() as u64)?;
            self.open.push((meta.dev(), meta.ino()));
            let entries = self.children(path, sensitive);
            self.open.pop();
            return Ok(Node::Group(Group {
                name: Some(name),
                entries: entries?,
            }));
        }
        if !meta.is_file() {
            bail!("{} is not a file or folder", path.display());
        }
        if meta.len() > MAX_SEALED_LEN as u64 {
            bail!("{} is too large to send", path.display());
        }
        let room = self.left.saturating_sub(ENTRY_COST + name.len() as u64);
        if meta.len() > room {
            return Err(too_large(path));
        }
        // At most one byte past the room, should the file grow meanwhile.
        let mut data = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(room.saturating_add(1)).read_to_end(&mut data))
            .with_context(|| format!("reading {}", path.display()))?;
        self.spend(path, ENTRY_COST + name.len() as u64 + data.len() as u64)?;
        let mime = mime(&name, &data);
        let sensitive = sensitive || looks_secret(&name);
        Ok(Node::Entry(Entry {
            name,
            data,
            mime: Some(mime.into()),
            sensitive,
        }))
    }

    fn children(&mut self, path: &Path, sensitive: bool) -> Result<Vec<Node>> {
        use std::os::unix::fs::MetadataExt;

        let mut children: Vec<_> = std::fs::read_dir(path)
            .with_context(|| format!("reading {}", path.display()))?
            .collect::<Result<_, _>>()
            .with_context(|| format!("reading {}", path.display()))?;
        children.sort_by_key(|c| c.file_name());
        let mut entries = Vec::new();
        for child in children {
            let kind = child.file_type()?;
            let child_path = child.path();
            // Symlinks are followed, except back into a folder being read;
            // sockets, fifos and devices are skipped.
            let target = if kind.is_symlink() {
                std::fs::metadata(&child_path).ok()
            } else {
                Some(child.metadata()?)
            };
            match target {
                Some(m) if m.is_dir() && self.open.contains(&(m.dev(), m.ino())) => {
                    eprintln!(
                        "skipping {}: it links back to a folder it's in",
                        child_path.display()
                    )
                }
                Some(m) if m.is_dir() || m.is_file() => {
                    entries.push(self.node(&child_path, sensitive)?)
                }
                _ => eprintln!("skipping {}", child_path.display()),
            }
        }
        Ok(entries)
    }
}

/// The media type from the content's magic bytes, else the extension, else
/// text for UTF-8 and octets otherwise.
pub fn mime(name: &str, data: &[u8]) -> &'static str {
    const MAGIC: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"%PDF-", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b", "application/gzip"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    ];
    if let Some((_, mime)) = MAGIC.iter().find(|(magic, _)| data.starts_with(magic)) {
        return mime;
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return "image/webp";
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let by_ext = match ext.as_str() {
        "svg" => Some("image/svg+xml"),
        "json" => Some("application/json"),
        "html" | "htm" => Some("text/html"),
        "csv" => Some("text/csv"),
        "md" => Some("text/markdown"),
        "txt" | "env" | "pem" | "key" | "pub" | "toml" | "yaml" | "yml" | "ini" | "conf" => {
            Some("text/plain")
        }
        "tar" => Some("application/x-tar"),
        "mp4" => Some("video/mp4"),
        "mp3" => Some("audio/mpeg"),
        _ => None,
    };
    by_ext.unwrap_or(if std::str::from_utf8(data).is_ok() {
        "text/plain"
    } else {
        "application/octet-stream"
    })
}

fn node_name(node: &Node) -> String {
    match node {
        Node::Entry(e) => e.name.clone(),
        Node::Group(g) => g.name.clone().unwrap_or_else(|| "group".into()),
    }
}

/// `a`, `a, b`, `a, b, c`, `a, b +2 more`.
fn label(names: &[String]) -> String {
    match names {
        [] => "nothing".into(),
        [a] => a.clone(),
        [a, b] => format!("{a}, {b}"),
        [a, b, c] => format!("{a}, {b}, {c}"),
        [a, b, rest @ ..] => format!("{a}, {b} +{} more", rest.len()),
    }
}

fn opens(n: u32) -> String {
    if n == 1 {
        "opens once".into()
    } else {
        format!("opens {n} times")
    }
}

/// `in 59m`, or how long ago for the past.
fn until(unix: u64) -> String {
    let now = config::now();
    if unix <= now {
        return crate::ago(unix);
    }
    let secs = unix - now;
    let minutes = secs.div_ceil(60);
    match secs {
        0..60 => format!("in {secs}s"),
        _ if minutes < 60 => format!("in {minutes}m"),
        _ if minutes < 24 * 60 => match minutes % 60 {
            0 => format!("in {}h", minutes / 60),
            m => format!("in {}h{m:02}m", minutes / 60),
        },
        _ => format!("in {}d{}h", secs / 86400, secs % 86400 / 3600),
    }
}

fn expiry(send: &SendInfo) -> String {
    let now = config::now();
    match send.state {
        SendState::Open => format!("expires {}", until(send.expires)),
        _ if send.expires > now => format!("would expire {}", until(send.expires)),
        _ => format!("expired {}", crate::ago(send.expires)),
    }
}

fn opened_at(send: &SendInfo) -> String {
    match send.opened.last() {
        Some(at) => crate::ago(*at),
        None => String::new(),
    }
}

fn opened_suffix(send: &SendInfo) -> String {
    match send.opened.len() {
        0 => " without being opened".into(),
        n => format!(" after {n} of {} opens", send.opens),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        send: SendArgs,
    }

    fn sources(args: &[&str]) -> Result<Vec<Source>> {
        use clap::Parser;
        let cli = Cli::try_parse_from(std::iter::once("send").chain(args.iter().copied()))?;
        cli.send.sources()
    }

    fn item(query: &str, field: Option<&str>) -> Source {
        Source::Item {
            query: query.into(),
            field: field.map(String::from),
        }
    }

    #[test]
    fn missing_paths_are_errors_not_searches() {
        let err = sources(&["./prod.env.typo"]).unwrap_err();
        assert_eq!(err.to_string(), "./prod.env.typo: no such file");
    }

    #[test]
    fn fields_bind_to_the_item_before_them() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.pem");
        std::fs::write(&key, "k").unwrap();
        let key = key.to_str().unwrap();
        assert_eq!(
            sources(&[
                "--item", "A", key, "--field", "x", "--item", "B", "-", "--item", "C", "-f", "y",
            ])
            .unwrap(),
            [
                item("A", Some("x")),
                Source::Path(key.into()),
                item("B", None),
                Source::Stdin,
                item("C", Some("y")),
            ]
        );
        let err = sources(&["--field", "x", "--item", "A"]).unwrap_err();
        assert!(err.to_string().contains("must follow the --item"), "{err}");
        let err = sources(&["--item", "A", "--field", "x", "--field", "y"]).unwrap_err();
        assert!(err.to_string().contains("has two fields"), "{err}");
    }

    #[test]
    fn asking_needs_a_terminal_or_yes() {
        // yes, json, reads_stdin, stdin_tty, out_tty
        assert_eq!(ask(true, true, false, false, false).unwrap(), Ask::Skip);
        assert_eq!(ask(false, false, false, true, true).unwrap(), Ask::Stdin);
        // Stdin is the payload: the answer comes from /dev/tty.
        assert_eq!(ask(false, false, true, false, true).unwrap(), Ask::Tty);
        assert_eq!(ask(false, false, true, true, true).unwrap(), Ask::Tty);
        let err = ask(false, true, false, true, true).unwrap_err();
        assert_eq!(err.to_string(), "--json needs --yes (no prompt possible)");
        for (reads_stdin, stdin_tty, out_tty) in [(false, false, true), (false, true, false)] {
            let err = ask(false, false, reads_stdin, stdin_tty, out_tty).unwrap_err();
            assert!(err.to_string().contains("pass --yes"), "{err}");
        }
    }

    fn info(id: &str, label: &str) -> ItemInfo {
        ItemInfo {
            id: id.into(),
            short: id[..4].into(),
            kind: "login".into(),
            label: label.into(),
            detail: None,
            fields: Vec::new(),
            source: None,
        }
    }

    #[test]
    fn items_match_exactly_and_only_suggest() {
        let items = [
            info("aaaa1111", "Stripe"),
            info("bbbb2222", "Stripe (test)"),
            info("cccc3333", "GitHub"),
            info("dddd4444", "Twin"),
            info("eeee5555", "Twin"),
        ];
        assert_eq!(exact_item(&items, "Stripe").unwrap(), "aaaa1111");
        assert_eq!(exact_item(&items, "cccc3333").unwrap(), "cccc3333");
        assert_eq!(exact_item(&items, "bbbb").unwrap(), "bbbb2222");
        let err = exact_item(&items, "stripe").unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"no item named "stripe". Did you mean: "Stripe", "Stripe (test)"?"#
        );
        let err = exact_item(&items, "Githbu").unwrap_err();
        assert!(
            err.to_string().ends_with(r#"Did you mean: "GitHub"?"#),
            "{err}"
        );
        let err = exact_item(&items, "zzz").unwrap_err();
        assert_eq!(err.to_string(), r#"no item named "zzz""#);
        let err = exact_item(&items, "Twin").unwrap_err().to_string();
        assert!(err.starts_with(r#"2 items are named "Twin""#), "{err}");
        assert!(
            err.contains("dddd\tTwin") && err.contains("eeee\tTwin"),
            "{err}"
        );
    }

    #[test]
    fn preview_lists_every_part() {
        let file = Entry {
            name: "opencodejr.pem".into(),
            data: vec![b'k'; 1741],
            mime: None,
            sensitive: looks_secret("opencodejr.pem"),
        };
        let folder = Group {
            name: Some("certs".into()),
            entries: vec![
                Node::Entry(Entry::text("a.crt", "x".repeat(10), false)),
                Node::Entry(Entry::text("b.crt", "y".repeat(20), false)),
            ],
        };
        let stripe = Group {
            name: Some("Stripe".into()),
            entries: vec![
                Node::Entry(Entry::text("username", "dax", false)),
                Node::Entry(Entry::text("secret-key", "sk_live", true)),
            ],
        };
        let part = |kind, node| Part { kind, node };
        let parts = [
            part(Kind::File, Node::Entry(file)),
            part(Kind::Folder, Node::Group(folder)),
            part(Kind::Item, Node::Group(stripe)),
            part(
                Kind::Field,
                Node::Entry(Entry::text("Stripe secret-key", "sk_live", true)),
            ),
            part(Kind::Stdin, Node::Entry(Entry::text("secret", "tok", true))),
        ];
        assert_eq!(
            preview(&parts, 1, 3600, None, Some("App ID 5497873")),
            [
                "About to send (single use, expires in 1h):",
                "  note    App ID 5497873",
                "  file    opencodejr.pem     1.7 KB         sensitive",
                "  folder  certs              2 files, 30 B",
                "  item    Stripe             2 fields       1 sensitive",
                "  field   Stripe secret-key  7 B            sensitive",
                "  stdin   secret             3 B            sensitive",
                "",
            ]
            .join("\n")
        );
        assert!(
            preview(&parts[..1], 3, 900, None, None)
                .starts_with("About to send (opens 3 times, expires in 15m):\n")
        );
    }

    fn names(node: &Node) -> Vec<String> {
        match node {
            Node::Entry(e) => vec![e.name.clone()],
            Node::Group(g) => g
                .entries
                .iter()
                .flat_map(|n| {
                    let inner = names(n);
                    let prefix = node_name(n);
                    match n {
                        Node::Entry(_) => inner,
                        Node::Group(_) => {
                            inner.into_iter().map(|i| format!("{prefix}/{i}")).collect()
                        }
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn folder_links_are_followed_but_never_back_into_themselves() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("a/deeper")).unwrap();
        std::fs::create_dir(dir.path().join("shared")).unwrap();
        std::fs::write(root.join("a/x.txt"), "x").unwrap();
        std::fs::write(dir.path().join("shared/s.txt"), "s").unwrap();
        std::os::unix::fs::symlink(&root, root.join("a/deeper/up")).unwrap();
        std::os::unix::fs::symlink("..", root.join("a/parent")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("shared"), root.join("one")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("shared"), root.join("two")).unwrap();
        let node = Walk::new(MAX_SEALED_LEN).node(&root, false).unwrap();
        assert_eq!(names(&node), ["a/x.txt", "one/s.txt", "two/s.txt"]);
    }

    #[test]
    fn a_folder_stops_at_what_a_bundle_holds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), [0u8; 40]).unwrap();
        std::fs::write(dir.path().join("b"), [0u8; 40]).unwrap();
        let name = dir.path().file_name().unwrap().len() as u64;
        let exact = GROUP_COST + name + 2 * (ENTRY_COST + 1 + 40);
        let fits = Walk::new(exact as usize).node(dir.path(), false).unwrap();
        assert_eq!(names(&fits), ["a", "b"]);
        let error = Walk::new(exact as usize - 1)
            .node(dir.path(), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("too large to send"), "{error}");
        assert!(error.ends_with("/b goes past about 32 MB"), "{error}");
        // What the walk counts is never more than the bundle encodes.
        let bundle = Bundle {
            title: None,
            note: None,
            entries: vec![fits],
        };
        assert!(exact <= bundle.encode().len() as u64);
    }

    #[test]
    fn key_files_are_sensitive() {
        for name in [
            "a.pem",
            "tls.KEY",
            ".env",
            ".env.local",
            "prod.env",
            "id_ed25519",
        ] {
            assert!(looks_secret(name), "{name}");
        }
        for name in ["id_ed25519.pub", "report.pdf", "envoy.yaml"] {
            assert!(!looks_secret(name), "{name}");
        }
    }

    #[test]
    fn mime_sniffing() {
        assert_eq!(mime("x", b"\x89PNG\r\n\x1a\nrest"), "image/png");
        assert_eq!(mime("doc.pdf", b"%PDF-1.7"), "application/pdf");
        assert_eq!(mime("a.json", b"{}"), "application/json");
        assert_eq!(mime("notes", b"hello"), "text/plain");
        assert_eq!(
            mime("blob", &[0xff, 0xfe, 0x00]),
            "application/octet-stream"
        );
    }

    #[test]
    fn labels() {
        let names: Vec<String> = ["a", "b", "c", "d", "e"].map(String::from).into();
        assert_eq!(label(&names[..1]), "a");
        assert_eq!(label(&names[..3]), "a, b, c");
        assert_eq!(label(&names), "a, b +3 more");
    }

    #[test]
    fn items_keep_their_secret_fields_hidden() {
        let field = |name: &str, kind: &str, value: &str| FieldInfo {
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
        };
        let item = ItemInfo {
            id: "abcd".into(),
            short: "abcd".into(),
            kind: "login".into(),
            label: "GitHub".into(),
            detail: None,
            fields: vec![
                field("username", "text", "dax"),
                field("password", "secret", "hunter2"),
                field("otp", "otp", "JBSWY3DPEHPK3PXP"),
                field("notes", "note", ""),
            ],
            source: None,
        };
        let Node::Group(group) = item_node(&item, None).unwrap() else {
            panic!("expected a group");
        };
        assert_eq!(group.name.as_deref(), Some("GitHub"));
        let flags: Vec<(String, bool)> = group
            .entries
            .iter()
            .map(|n| match n {
                Node::Entry(e) => (e.name.clone(), e.sensitive),
                Node::Group(_) => panic!("nested"),
            })
            .collect();
        assert_eq!(
            flags,
            [
                ("username".into(), false),
                ("password".into(), true),
                ("otp".into(), true)
            ]
        );
        let Node::Entry(one) = item_node(&item, Some("password")).unwrap() else {
            panic!("expected an entry");
        };
        assert_eq!(
            (one.name.as_str(), one.sensitive),
            ("GitHub password", true)
        );
        assert_eq!(one.data, b"hunter2");
        assert!(item_node(&item, Some("notes")).is_err());
    }
}
