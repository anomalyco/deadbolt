//! `deadbolt receive`: opens a Deadbolt Send link from a terminal, through the
//! same [`deadbolt_send::receive`] the browser page uses. Nothing is looked up
//! in the vault and no daemon is needed: the link carries everything.

use std::io::{IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::Args;
use deadbolt_send::{
    Bundle, Entry, Network, Node, Progress, SendTicket, receive, receiver_endpoint,
};

use crate::config;

#[derive(Args)]
pub struct ReceiveArgs {
    /// The link, or only the part after `#`.
    #[arg(value_name = "LINK", allow_hyphen_values = true)]
    link: String,
    /// Directory to write files to (default: the current directory).
    #[arg(long, value_name = "DIR", default_value = ".")]
    output: PathBuf,
    /// Write over files that already exist.
    #[arg(long)]
    force: bool,
    /// Print one JSON object: title, note, values and files.
    #[arg(long)]
    json: bool,
}

pub async fn run(args: ReceiveArgs) -> Result<ExitCode> {
    let ticket: SendTicket = args.link.parse()?;
    let network = if config::test_env("DEADBOLT_NET").as_deref() == Some("local") {
        Network::Local
    } else {
        Network::Relays
    };
    let endpoint = receiver_endpoint(network)
        .await
        .context("starting the receive endpoint")?;
    let progress = !args.json && std::io::stderr().is_terminal();
    let result = receive(&endpoint, &ticket, |step| {
        if !progress {
            return;
        }
        match step {
            Progress::Connecting => eprintln!("connecting to the sender..."),
            Progress::Proving => eprintln!("opening the link..."),
            Progress::Downloading { received: 0, total } => {
                eprintln!("downloading {total} bytes...");
            }
            Progress::Downloading { .. } => {}
            Progress::Decrypting => eprintln!("decrypting..."),
        }
    })
    .await;
    endpoint.close().await;
    let bundle = result?;

    if let Some(title) = bundle.title.as_deref().filter(|t| !t.is_empty()) {
        eprintln!("title\t{title}");
    }
    if let Some(note) = bundle.note.as_deref().filter(|n| !n.is_empty()) {
        eprintln!("note\t{note}");
    }

    let received = Received::plan(&bundle, &args.output)?;
    received.prepare(args.force)?;
    received.write(args.force)?;
    if args.json {
        received.print_json(&bundle)?;
    } else {
        received.print_values()?;
        for file in &received.files {
            eprintln!("wrote\t{}", file.path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

struct Value {
    name: String,
    value: String,
    sensitive: bool,
}

struct File<'a> {
    /// The name in the bundle, groups included (`certs/a.pem`).
    name: String,
    path: PathBuf,
    data: &'a [u8],
}

struct Received<'a> {
    values: Vec<Value>,
    files: Vec<File<'a>>,
}

impl<'a> Received<'a> {
    /// Sorts a bundle's entries into values for stdout and files for the
    /// output directory, checking every name on the way. Nothing is written.
    fn plan(bundle: &'a Bundle, output: &Path) -> Result<Self> {
        let mut received = Self {
            values: Vec::new(),
            files: Vec::new(),
        };
        received.add(&bundle.entries, output, "")?;
        Ok(received)
    }

    fn add(&mut self, nodes: &'a [Node], dir: &Path, prefix: &str) -> Result<()> {
        for node in nodes {
            match node {
                Node::Entry(entry) => {
                    if let Some(value) = text_value(entry) {
                        self.values.push(Value {
                            name: join(prefix, &entry.name),
                            value: value.to_owned(),
                            sensitive: entry.sensitive,
                        });
                    } else {
                        self.files.push(File {
                            name: join(prefix, &entry.name),
                            path: dir.join(component(&entry.name)?),
                            data: &entry.data,
                        });
                    }
                }
                Node::Group(group) => {
                    let name = group.name.as_deref().filter(|name| !name.is_empty());
                    let (dir, prefix) = match name {
                        Some(name) if group.entries.iter().any(has_file) => {
                            (dir.join(component(name)?), join(prefix, name))
                        }
                        Some(name) => (dir.to_path_buf(), join(prefix, name)),
                        None => (dir.to_path_buf(), prefix.to_owned()),
                    };
                    self.add(&group.entries, &dir, &prefix)?;
                }
            }
        }
        Ok(())
    }

    /// Fails before anything is written if one file would land on another.
    fn prepare(&self, force: bool) -> Result<()> {
        if force {
            return Ok(());
        }
        for file in &self.files {
            if std::fs::symlink_metadata(&file.path).is_ok() {
                bail!(
                    "{} already exists (pass --force to overwrite)",
                    file.path.display()
                );
            }
        }
        Ok(())
    }

    fn write(&self, force: bool) -> Result<()> {
        for file in &self.files {
            if let Some(parent) = file.path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true);
            if force {
                options.create(true).truncate(true);
            } else {
                options.create_new(true);
            }
            let mut handle = options
                .open(&file.path)
                .with_context(|| format!("writing {}", file.path.display()))?;
            handle
                .write_all(file.data)
                .with_context(|| format!("writing {}", file.path.display()))?;
        }
        Ok(())
    }

    fn print_values(&self) -> Result<()> {
        let mut out = std::io::stdout().lock();
        match self.values.as_slice() {
            [value] => {
                out.write_all(value.value.as_bytes())?;
                if !value.value.ends_with('\n') {
                    out.write_all(b"\n")?;
                }
            }
            values => {
                for value in values {
                    writeln!(out, "{}\t{}", value.name, value.value)?;
                }
            }
        }
        out.flush().context("writing to stdout")?;
        Ok(())
    }

    fn print_json(&self, bundle: &Bundle) -> Result<()> {
        let json = serde_json::json!({
            "title": bundle.title.as_deref(),
            "note": bundle.note.as_deref(),
            "values": self
                .values
                .iter()
                .map(|value| serde_json::json!({
                    "name": value.name,
                    "value": value.value,
                    "sensitive": value.sensitive,
                }))
                .collect::<Vec<_>>(),
            "files": self
                .files
                .iter()
                .map(|file| serde_json::json!({
                    "name": file.name,
                    "path": file.path.display().to_string(),
                    "bytes": file.data.len(),
                }))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&json)?);
        Ok(())
    }
}

/// A short piece of text the browser receive page would show as a value: a
/// `text/*` (or untyped) entry, valid UTF-8, at most 4 KB, with no file
/// extension in its name.
fn text_value(entry: &Entry) -> Option<&str> {
    let textual = entry
        .mime
        .as_deref()
        .is_none_or(|mime| mime.is_empty() || mime.starts_with("text/"));
    if !textual {
        return None;
    }
    let value = std::str::from_utf8(&entry.data).ok()?;
    let has_extension = entry.name.rsplit_once('.').is_some_and(|(_, ext)| {
        (1..=8).contains(&ext.len()) && ext.bytes().all(|b| b.is_ascii_alphanumeric())
    });
    (!has_extension && value.len() <= 4096).then_some(value)
}

fn has_file(node: &Node) -> bool {
    match node {
        Node::Entry(entry) => text_value(entry).is_none(),
        Node::Group(group) => group.entries.iter().any(has_file),
    }
}

/// One plain path component: no separators, no `.` or `..`.
fn component(name: &str) -> Result<PathBuf> {
    let mut parts = Path::new(name).components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(part)), None) => Ok(part.into()),
        _ => bail!("refusing to write {name:?}: it isn't a plain file name"),
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadbolt_send::Group;

    fn plan<'a>(bundle: &'a Bundle, output: &Path) -> Result<Received<'a>> {
        Received::plan(bundle, output)
    }

    fn bundle(entries: Vec<Node>) -> Bundle {
        Bundle {
            title: None,
            note: None,
            entries,
        }
    }

    fn file(name: &str) -> Node {
        Node::Entry(Entry {
            name: name.into(),
            data: b"x".to_vec(),
            mime: Some("application/octet-stream".into()),
            sensitive: false,
        })
    }

    #[test]
    fn values_and_files_are_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = bundle(vec![
            Node::Entry(Entry::text("secret", "tok_123", true)),
            Node::Entry(Entry::text("report.txt", "quarterly", false)),
            Node::Group(Group {
                name: Some("Stripe".into()),
                entries: vec![Node::Entry(Entry::text("password", "sk_live", true))],
            }),
        ]);
        let received = plan(&bundle, dir.path()).unwrap();
        let values: Vec<_> = received
            .values
            .iter()
            .map(|value| (value.name.as_str(), value.value.as_str(), value.sensitive))
            .collect();
        assert_eq!(
            values,
            [
                ("secret", "tok_123", true),
                ("Stripe/password", "sk_live", true)
            ]
        );
        assert_eq!(received.files[0].name, "report.txt");
        assert_eq!(received.files[0].path, dir.path().join("report.txt"));
        assert_eq!(received.files[0].data, b"quarterly");
    }

    #[test]
    fn names_may_not_leave_the_output_directory() {
        for name in ["../evil", "a/b", "/etc/passwd", "..", "."] {
            let dir = tempfile::tempdir().unwrap();
            let bundle = bundle(vec![file(name)]);
            let err = plan(&bundle, dir.path()).err().unwrap();
            assert!(err.to_string().contains("isn't a plain file name"), "{err}");
        }
        let dir = tempfile::tempdir().unwrap();
        let bundle = bundle(vec![Node::Group(Group {
            name: Some("..".into()),
            entries: vec![file("x")],
        })]);
        let err = plan(&bundle, dir.path()).err().unwrap();
        assert!(err.to_string().contains("isn't a plain file name"), "{err}");
    }

    #[test]
    fn files_are_not_written_over_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.txt");
        std::fs::write(&path, "old").unwrap();
        // A text file with an extension is a file, not a value.
        let bundle = bundle(vec![Node::Entry(Entry::text("a.txt", "new", false))]);
        let bundle = plan(&bundle, dir.path()).unwrap();
        assert_eq!(bundle.values.len(), 0);
        let err = bundle.prepare(false).unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");
        bundle.prepare(true).unwrap();
        bundle.write(true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }
}
