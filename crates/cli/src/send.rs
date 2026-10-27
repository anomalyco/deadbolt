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
use clap::{Args, Subcommand};
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
    Command, ErrorCode, FieldInfo, ItemInfo, Reply, Secret, SendInfo, SendState, SenderInfo,
};

/// Exit code of `send --wait` when the link expired unopened.
pub const EXIT_EXPIRED: u8 = 4;
/// Exit code of `send --wait` when the link was revoked.
pub const EXIT_REVOKED: u8 = 5;

#[derive(Args)]
pub struct SendArgs {
    /// Files, folders, `-` for stdin, or vault items (search words or an id
    /// prefix, quoted as one argument). An argument that names an existing
    /// path is a file; anything else is looked up in the vault. Without any,
    /// asks for a secret (hidden), or reads piped stdin.
    #[arg(value_name = "PATH|ITEM")]
    inputs: Vec<String>,
    /// Send this vault item even if a file of the same name exists; repeat
    /// for more.
    #[arg(long = "item", value_name = "QUERY")]
    items: Vec<String>,
    /// Send only this field of each item.
    #[arg(short, long)]
    field: Option<String>,
    /// A title the receiver sees.
    #[arg(long)]
    title: Option<String>,
    /// A note the receiver sees above everything (not hidden).
    #[arg(long)]
    note: Option<String>,
    /// Hide files and stdin behind "reveal" too (secrets and secret item
    /// fields always are).
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
    /// Print `{"id", "link", "expires"}` instead of the link.
    #[arg(long)]
    json: bool,
    /// Wait until the link is picked up (exit 0), expires (exit 4) or is
    /// revoked (exit 5).
    #[arg(long)]
    wait: bool,
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

pub async fn send(
    paths: &Paths,
    args: SendArgs,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<ExitCode> {
    let ttl = match config::parse_timeout(&args.ttl)? {
        Some(ttl) if ttl.as_secs() > 0 => ttl,
        _ => bail!("--ttl must be a duration, such as 15m, 1h or 24h"),
    };
    if args.opens == 0 {
        bail!("--opens must be at least 1");
    }
    let stdin_used = args.inputs.iter().filter(|i| *i == "-").count();
    if stdin_used > 1 {
        bail!("`-` (stdin) can only be sent once");
    }
    if stdin_used == 1 && from_stdin {
        bail!("--passphrase-stdin cannot be used when sending stdin");
    }
    let mut inputs: Vec<Input> = args
        .inputs
        .iter()
        .map(|arg| match arg.as_str() {
            "-" => Input::Stdin,
            path if Path::new(path).exists() => Input::Path(PathBuf::from(path)),
            query => Input::Item(query.to_string()),
        })
        .chain(args.items.iter().cloned().map(Input::Item))
        .collect();
    if inputs.is_empty() {
        if prompt::interactive() {
            inputs.push(Input::Prompt);
        } else if !std::io::stdin().is_terminal() && !from_stdin {
            inputs.push(Input::Stdin);
        } else {
            bail!("nothing to send: pass files, `-` for stdin, or a vault item");
        }
    }
    if args.field.is_some() && !inputs.iter().any(|i| matches!(i, Input::Item(_))) {
        bail!("--field applies to vault items");
    }

    client::ensure_running(paths).await?;
    let mut entries = Vec::new();
    let mut names = Vec::new();
    for input in &inputs {
        let node = match input {
            Input::Prompt => {
                let value = prompt::ask_value("secret to send", true)?;
                if value.is_empty() {
                    bail!("nothing to send");
                }
                Node::Entry(Entry::text("secret", value.as_str(), true))
            }
            Input::Stdin => stdin_entry(args.sensitive)?,
            Input::Path(path) => path_node(path, args.sensitive)?,
            Input::Item(query) => {
                if Path::new(query).exists() {
                    // Only via --item: say why it isn't the file.
                    eprintln!("note: sending vault item {query:?}, not the file of that name");
                }
                let item = get_item(paths, query, vault.clone(), from_stdin).await?;
                item_node(&item, args.field.as_deref())?
            }
        };
        names.push(node_name(&node));
        entries.push(node);
    }
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

enum Input {
    Prompt,
    Stdin,
    Path(PathBuf),
    Item(String),
}

fn no_events(event: crate::protocol::Event) -> Result<Option<bool>> {
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

async fn get_item(
    paths: &Paths,
    query: &str,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<ItemInfo> {
    let command = Command::ItemGet {
        vault,
        query: query.split_whitespace().map(String::from).collect(),
        otp: true,
    };
    match crate::request(paths, command, from_stdin).await {
        Ok(Reply::Item { item }) => Ok(item),
        Ok(_) => bail!("unexpected reply"),
        Err(error) if client::code(&error) == Some(ErrorCode::NotFound) => {
            bail!("no file or vault item matches {query:?}")
        }
        Err(error) => Err(error),
    }
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

/// A file as an entry, a folder as a group of its files and folders.
fn path_node(path: &Path, sensitive: bool) -> Result<Node> {
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
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if meta.is_dir() {
        let mut children: Vec<_> = std::fs::read_dir(path)
            .with_context(|| format!("reading {}", path.display()))?
            .collect::<Result<_, _>>()
            .with_context(|| format!("reading {}", path.display()))?;
        children.sort_by_key(|c| c.file_name());
        let mut entries = Vec::new();
        for child in children {
            let kind = child.file_type()?;
            let child_path = child.path();
            // Symlinks are followed; sockets, fifos and devices are skipped.
            let target = if kind.is_symlink() {
                std::fs::metadata(&child_path).ok()
            } else {
                Some(child.metadata()?)
            };
            match target {
                Some(m) if m.is_dir() || m.is_file() => {
                    entries.push(path_node(&child_path, sensitive)?)
                }
                _ => eprintln!("skipping {}", child_path.display()),
            }
        }
        return Ok(Node::Group(Group {
            name: Some(name),
            entries,
        }));
    }
    if !meta.is_file() {
        bail!("{} is not a file or folder", path.display());
    }
    if meta.len() > MAX_SEALED_LEN as u64 {
        bail!("{} is too large to send", path.display());
    }
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mime = mime(&name, &data);
    Ok(Node::Entry(Entry {
        name,
        data,
        mime: Some(mime.into()),
        sensitive,
    }))
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
    match secs {
        0..60 => format!("in {secs}s"),
        60..3600 => format!("in {}m", secs.div_ceil(60)),
        3600..86400 => format!("in {}h{:02}m", secs / 3600, secs % 3600 / 60),
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
