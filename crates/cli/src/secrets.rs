//! `deadbolt run`, `inject` and `read` (`docs/agent-control.md`, "Use,
//! don't read"): secret references (`deadbolt://[vault/]item/field`)
//! resolved by the daemon, into a command's environment, a 0600 file, or
//! printed. The daemon decides who may have them; this side never logs,
//! echoes or passes a value on argv.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::signal::unix::{SignalKind, signal};
use zeroize::Zeroizing;

use crate::paths::Paths;
use crate::protocol::{Command, Purpose, Reference, Reply, ResolvedSecret, SCHEME};
use crate::{client, request};

/// What a masked value becomes in a command's output.
pub const CONCEALED: &[u8] = b"<concealed by deadbolt>";
/// Values shorter than this aren't masked: replacing every "a" or "42" in
/// the output would wreck it and hide nothing worth hiding.
const MIN_MASKED: usize = 3;

#[derive(Args)]
pub struct RunArgs {
    /// Set NAME to the value REF names (deadbolt://[vault/]item/field);
    /// repeat for more.
    #[arg(long = "env", value_name = "NAME=REF")]
    env: Vec<String>,
    /// Read NAME=VALUE lines from FILE (`#` comments, `export`, quotes):
    /// values that are references are resolved, others set as they are.
    #[arg(long, value_name = "FILE")]
    env_file: Vec<PathBuf>,
    /// Don't conceal the values in the command's output. Masking makes the
    /// command's stdout and stderr pipes, so it sees no terminal (no
    /// colors or full-screen UIs, and its pager may change); --no-mask
    /// leaves them on the terminal.
    #[arg(long)]
    no_mask: bool,
    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<OsString>,
}

#[derive(Args)]
pub struct InjectArgs {
    /// The template, with `{{ deadbolt://… }}` where values go (default:
    /// stdin).
    #[arg(short = 'i', long = "in-file", value_name = "FILE")]
    input: Option<PathBuf>,
    /// Where to write (default: stdout, which counts as reading the values,
    /// so AI agents need Touch ID). Written 0600, replacing it only if
    /// `deadbolt inject` wrote it and it hasn't changed since.
    #[arg(short = 'o', long = "out-file", value_name = "FILE")]
    output: Option<PathBuf>,
    /// Replace the output file whoever wrote it.
    #[arg(short, long)]
    force: bool,
}

#[derive(Args)]
pub struct ReadArgs {
    /// deadbolt://[vault/]item/field
    reference: String,
    /// Don't print a newline after the value.
    #[arg(short, long)]
    no_newline: bool,
}

/// An environment variable's value: a reference to resolve, or as given.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EnvValue {
    Reference(String),
    Literal(Zeroizing<String>),
}

impl EnvValue {
    fn of(value: &str) -> Result<Self> {
        if value.trim_start().starts_with(SCHEME) {
            Reference::parse(value).map_err(|e| anyhow!(e))?;
            Ok(Self::Reference(value.trim().to_string()))
        } else {
            Ok(Self::Literal(Zeroizing::new(value.to_string())))
        }
    }
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains(['=', '\0']) || name.chars().any(char::is_whitespace) {
        bail!("{name:?} isn't an environment variable name");
    }
    Ok(())
}

/// The `NAME=VALUE` lines of an env file, values unquoted. Errors name the
/// line, never its value.
fn env_file(text: &str, file: &Path) -> Result<Vec<(String, EnvValue)>> {
    let mut vars = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            bail!("{}:{}: not NAME=VALUE", file.display(), n + 1);
        };
        let name = name.trim();
        check_name(name).with_context(|| format!("{}:{}", file.display(), n + 1))?;
        let value = value.trim();
        let value = match value.as_bytes() {
            [q @ (b'"' | b'\''), .., last] if last == q && value.len() >= 2 => {
                &value[1..value.len() - 1]
            }
            _ => value,
        };
        let value = EnvValue::of(value).with_context(|| format!("{}:{}", file.display(), n + 1))?;
        vars.push((name.to_string(), value));
    }
    Ok(vars)
}

/// The command's environment changes, later ones winning: inherited
/// variables whose value is a reference, then `--env-file`s, then `--env`.
fn environment(args: &RunArgs) -> Result<IndexMap<String, EnvValue>> {
    let mut vars: IndexMap<String, EnvValue> = IndexMap::new();
    for (name, value) in std::env::vars_os() {
        let (Some(name), Some(value)) = (name.to_str(), value.to_str()) else {
            continue;
        };
        if value.trim_start().starts_with(SCHEME) {
            let value =
                EnvValue::of(value).with_context(|| format!("the environment variable {name}"))?;
            vars.insert(name.to_string(), value);
        }
    }
    for file in &args.env_file {
        let text = Zeroizing::new(
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
        );
        for (name, value) in env_file(&text, file)? {
            vars.insert(name, value);
        }
    }
    for pair in &args.env {
        let Some((name, value)) = pair.split_once('=') else {
            bail!("--env takes NAME=deadbolt://vault/item/field");
        };
        check_name(name)?;
        // Never echo a value that isn't a reference: it may be a secret.
        if !value.trim_start().starts_with(SCHEME) {
            bail!("--env {name}: the value isn't a deadbolt:// reference");
        }
        let reference = Reference::parse(value).map_err(|e| anyhow!("--env {name}: {e}"))?;
        vars.insert(name.to_string(), EnvValue::Reference(reference.to_string()));
    }
    Ok(vars)
}

/// The values `refs` name, from the daemon, by reference.
async fn resolve(
    paths: &Paths,
    refs: Vec<String>,
    purpose: Purpose,
    from_stdin: bool,
) -> Result<HashMap<String, ResolvedSecret>> {
    for reference in &refs {
        Reference::parse(reference).map_err(|e| anyhow!(e))?;
    }
    if refs.is_empty() {
        return Ok(HashMap::new());
    }
    client::ensure_running(paths).await?;
    let command = Command::Resolve {
        refs: refs.clone(),
        purpose,
    };
    let Reply::Secrets { secrets } = request(paths, command, from_stdin).await? else {
        bail!("unexpected reply");
    };
    if secrets.len() != refs.len() {
        bail!(
            "the daemon answered {} of {} references",
            secrets.len(),
            refs.len()
        );
    }
    Ok(refs.into_iter().zip(secrets).collect())
}

/// Replaces secret values in a stream with [`CONCEALED`], as they pass:
/// each value, its URL encoding and its base64. A value split across reads
/// is held back until the next read says whether it completes, so output
/// flows unless its tail could be the start of a value.
pub struct Masker {
    /// Longest first.
    patterns: Vec<Zeroizing<Vec<u8>>>,
    held: Zeroizing<Vec<u8>>,
}

fn url_encoded(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl Masker {
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for value in values {
            if value.len() < MIN_MASKED {
                continue;
            }
            let forms = [
                value.to_string(),
                url_encoded(value),
                data_encoding::BASE64_NOPAD.encode(value.as_bytes()),
            ];
            for form in forms {
                let form = Zeroizing::new(form.into_bytes());
                if !patterns.contains(&form) {
                    patterns.push(form);
                }
            }
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
        Masker {
            patterns,
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// What of `chunk` (after what was held) can be written now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);
        self.scan(false)
    }

    /// Whether output is held back, waiting for the next read.
    pub fn holding(&self) -> bool {
        !self.held.is_empty()
    }

    /// The rest, at the end of the stream (or after a quiet spell).
    pub fn finish(&mut self) -> Vec<u8> {
        self.scan(true)
    }

    fn scan(&mut self, end: bool) -> Vec<u8> {
        let buf = std::mem::replace(&mut self.held, Zeroizing::new(Vec::new()));
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < buf.len() {
            let rest = &buf[i..];
            // A value that may go on in the next read: wait for it, so a
            // shorter value inside it can't leave the rest showing.
            if !end
                && self
                    .patterns
                    .iter()
                    .any(|p| p.len() > rest.len() && p.starts_with(rest))
            {
                self.held.extend_from_slice(rest);
                break;
            }
            match self.patterns.iter().find(|p| rest.starts_with(p)) {
                Some(p) => {
                    out.extend_from_slice(CONCEALED);
                    i += p.len();
                }
                None => {
                    out.push(buf[i]);
                    i += 1;
                }
            }
        }
        out
    }
}

/// How long held-back output waits for the rest of a value before it goes
/// out as it is: a prompt ending in what could start a value mustn't stall.
const QUIET: std::time::Duration = std::time::Duration::from_millis(100);

/// Copies `from` to `to`, masked, flushing as it goes.
async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    mut masker: Option<Masker>,
) -> std::io::Result<()> {
    let mut buf = Zeroizing::new(vec![0u8; 16 * 1024]);
    loop {
        let holding = masker.as_ref().is_some_and(Masker::holding);
        let n = if holding {
            match tokio::time::timeout(QUIET, from.read(&mut buf)).await {
                Ok(read) => read?,
                Err(_) => {
                    // Quiet: write what was held. A value written in pieces
                    // further apart than this may show.
                    if let Some(m) = &mut masker {
                        to.write_all(&m.finish()).await?;
                        to.flush().await?;
                    }
                    continue;
                }
            }
        } else {
            from.read(&mut buf).await?
        };
        let out = match (&mut masker, n) {
            (Some(m), 0) => m.finish(),
            (Some(m), n) => m.push(&buf[..n]),
            (None, 0) => Vec::new(),
            (None, n) => buf[..n].to_vec(),
        };
        to.write_all(&out).await?;
        to.flush().await?;
        if n == 0 {
            return Ok(());
        }
    }
}

/// `deadbolt run`: resolves the references, runs the command with them in
/// its environment and exits with its code (128 + the signal if one ended
/// it).
pub async fn run(paths: &Paths, args: RunArgs, from_stdin: bool) -> Result<ExitCode> {
    let vars = environment(&args)?;
    let mut refs: Vec<String> = Vec::new();
    for value in vars.values() {
        if let EnvValue::Reference(r) = value
            && !refs.contains(r)
        {
            refs.push(r.clone());
        }
    }
    let values = resolve(paths, refs, Purpose::Run, from_stdin).await?;
    let (program, rest) = args
        .command
        .split_first()
        .context("name a command to run after --")?;
    let mut command = tokio::process::Command::new(program);
    command.args(rest).stdin(Stdio::inherit());
    for (name, value) in &vars {
        match value {
            EnvValue::Reference(r) => {
                command.env(name, values[r].value.expose());
            }
            EnvValue::Literal(value) => {
                command.env(name, value.as_str());
            }
        }
    }
    let mask = !args.no_mask;
    let masker = || mask.then(|| Masker::new(values.values().map(|s| s.value.expose())));
    if mask {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("running {}", program.to_string_lossy()))?;
    drop(command);
    let out = child
        .stdout
        .take()
        .map(|from| tokio::spawn(pump(from, tokio::io::stdout(), masker())));
    let err = child
        .stderr
        .take()
        .map(|from| tokio::spawn(pump(from, tokio::io::stderr(), masker())));
    drop(values);

    // Signals go on to the command. From a terminal, Ctrl-C and Ctrl-\
    // already reached it (it shares our process group): sending them again
    // would make it see two.
    let terminal = std::io::stdin().is_terminal();
    let mut forwarding = Vec::new();
    if let Some(pid) = child
        .id()
        .and_then(|pid| rustix::process::Pid::from_raw(pid as i32))
    {
        use rustix::process::Signal;
        for (kind, sig, from_terminal) in [
            (SignalKind::terminate(), Signal::TERM, false),
            (SignalKind::hangup(), Signal::HUP, false),
            (SignalKind::user_defined1(), Signal::USR1, false),
            (SignalKind::user_defined2(), Signal::USR2, false),
            (SignalKind::interrupt(), Signal::INT, true),
            (SignalKind::quit(), Signal::QUIT, true),
        ] {
            let mut stream = signal(kind)?;
            let skip = terminal && from_terminal;
            forwarding.push(AbortOnDrop(tokio::spawn(async move {
                while stream.recv().await.is_some() {
                    if !skip && let Err(error) = rustix::process::kill_process(pid, sig) {
                        // It has exited, and is about to be reaped.
                        tracing::debug!("forwarding a signal: {error}");
                    }
                }
            })));
        }
    }
    let status = child.wait().await?;
    drop(forwarding);
    for task in [out, err].into_iter().flatten() {
        drop(task.await);
    }
    let code = match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(signal)) => 128 + signal,
        (None, None) => 1,
    };
    Ok(ExitCode::from(code.clamp(0, 255) as u8))
}

/// Aborts a task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A template, split at its `{{ deadbolt://… }}` references.
#[derive(Debug, PartialEq, Eq)]
enum Part<'a> {
    Text(&'a str),
    Reference(String),
}

fn template(text: &str) -> Result<Vec<Part<'_>>> {
    let mut parts = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let inner = &rest[start + 2..];
        let Some(end) = inner.find("}}") else {
            if inner.trim_start().starts_with(SCHEME) {
                bail!("a {{{{ deadbolt://… reference isn't closed with }}}}");
            }
            break;
        };
        let content = inner[..end].trim();
        if content.starts_with(SCHEME) {
            let reference = Reference::parse(content).map_err(|e| anyhow!(e))?;
            parts.push(Part::Text(&rest[..start]));
            parts.push(Part::Reference(reference.to_string()));
        } else if content.contains(SCHEME) {
            bail!(
                "a {{{{ … }}}} holds a deadbolt:// reference beside other text; a reference must be all of it: {{{{ deadbolt://vault/item/field }}}}"
            );
        } else {
            // Another templating language's: left as it is.
            parts.push(Part::Text(&rest[..start + 2 + end + 2]));
        }
        rest = &inner[end + 2..];
    }
    parts.push(Part::Text(rest));
    parts.retain(|p| *p != Part::Text(""));
    Ok(parts)
}

/// A file `deadbolt inject` wrote, as it left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Written {
    path: PathBuf,
    dev: u64,
    ino: u64,
    len: u64,
    mtime_ns: i128,
}

impl Written {
    fn of(path: &Path, meta: &std::fs::Metadata) -> Self {
        Written {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        }
    }
}

/// The most files remembered.
const MAX_WRITTEN: usize = 256;

/// Where `deadbolt inject` remembers what it wrote: no values, only each
/// file's identity, size and time.
fn written_list(paths: &Paths) -> PathBuf {
    paths.data.join("injected.json")
}

fn read_written(paths: &Paths) -> Vec<Written> {
    let list = written_list(paths);
    let read = std::fs::read(&list)
        .map_err(|e| (e.kind() != std::io::ErrorKind::NotFound).then(|| e.to_string()))
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| Some(e.to_string())));
    match read {
        Ok(written) => written,
        Err(None) => Vec::new(),
        Err(Some(error)) => {
            eprintln!(
                "warning: {} is unreadable ({error}); existing outputs count as not written by inject: delete it, or pass --force",
                list.display()
            );
            Vec::new()
        }
    }
}

/// The output path, its directory resolved, so one file has one name.
fn canonical_output(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("{} isn't a file name", path.display()))?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let dir = dir
        .canonicalize()
        .with_context(|| format!("finding {}", dir.display()))?;
    Ok(dir.join(name))
}

/// Writes `text` to `out`, 0600, replacing a file only if inject wrote it
/// (and it is unchanged since) or with `force`.
fn write_output(paths: &Paths, out: &Path, text: &[u8], force: bool) -> Result<()> {
    let path = canonical_output(out)?;
    let mut written = read_written(paths);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            let ours = written.contains(&Written::of(&path, &meta));
            if !force && !ours {
                bail!(
                    "{} exists and wasn't written by `deadbolt inject` (or changed since): pass --force to replace it",
                    out.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("checking {}", out.display())),
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".deadbolt-inject")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(dir)
        .with_context(|| format!("writing in {}", dir.display()))?;
    file.write_all(text)?;
    file.as_file().sync_all()?;
    file.persist(&path)
        .map_err(|e| e.error)
        .with_context(|| format!("writing {}", out.display()))?;
    let meta = std::fs::symlink_metadata(&path)?;
    written.retain(|w| w.path != path);
    written.push(Written::of(&path, &meta));
    let excess = written.len().saturating_sub(MAX_WRITTEN);
    written.drain(..excess);
    let list = written_list(paths);
    if let Some(dir) = list.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut record = tempfile::Builder::new()
        .prefix(".injected")
        .tempfile_in(list.parent().unwrap_or(Path::new(".")))?;
    record.write_all(&serde_json::to_vec(&written)?)?;
    record.persist(&list).map_err(|e| e.error)?;
    Ok(())
}

/// `deadbolt inject`: the template with each reference's value in place.
pub async fn inject(paths: &Paths, args: InjectArgs, from_stdin: bool) -> Result<()> {
    let text = Zeroizing::new(match &args.input {
        Some(file) if file.as_os_str() != "-" => {
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?
        }
        _ => {
            if std::io::stdin().is_terminal() {
                bail!("pass the template with -i, or pipe it on stdin");
            }
            if from_stdin {
                bail!("--passphrase-stdin cannot be used when the template comes from stdin");
            }
            std::io::read_to_string(std::io::stdin().lock())?
        }
    });
    let parts = template(&text)?;
    let mut refs: Vec<String> = Vec::new();
    for part in &parts {
        if let Part::Reference(r) = part
            && !refs.contains(r)
        {
            refs.push(r.clone());
        }
    }
    // Written to stdout, the values go to whoever runs this: that's a read,
    // which an AI can't do on an inject grant.
    let to_stdout = args.output.as_ref().is_none_or(|f| f.as_os_str() == "-");
    let purpose = if to_stdout {
        Purpose::Read
    } else {
        Purpose::Inject
    };
    let values = resolve(paths, refs, purpose, from_stdin).await?;
    // A file field is written out whole and decoded, so it must be all of
    // the template (whitespace around it aside).
    if let Some(file) = values.values().find(|v| v.file) {
        let alone: Vec<&Part> = parts
            .iter()
            .filter(|p| !matches!(p, Part::Text(t) if t.trim().is_empty()))
            .collect();
        let [Part::Reference(r)] = alone.as_slice() else {
            bail!(
                "{} › {} is a file: a template can hold it only as its one reference, {{{{ deadbolt://… }}}} and nothing else",
                file.title,
                file.field
            );
        };
        let bytes = deadbolt_client::file::contents(values[r].value.expose())?;
        match &args.output {
            Some(path) if path.as_os_str() != "-" => {
                write_output(paths, path, &bytes, args.force)?;
            }
            _ => bail!("a file is written only to -o FILE"),
        }
        return Ok(());
    }
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for part in &parts {
        match part {
            Part::Text(text) => out.push_str(text),
            Part::Reference(r) => out.push_str(values[r].value.expose()),
        }
    }
    match &args.output {
        Some(file) if file.as_os_str() != "-" => {
            write_output(paths, file, out.as_bytes(), args.force)?;
        }
        _ => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(out.as_bytes())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// `deadbolt read`: prints one value.
pub async fn read(paths: &Paths, args: ReadArgs, from_stdin: bool) -> Result<()> {
    let reference = Reference::parse(&args.reference)
        .map_err(|e| anyhow!(e))?
        .to_string();
    let values = resolve(paths, vec![reference.clone()], Purpose::Read, from_stdin).await?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(values[&reference].value.expose().as_bytes())?;
    if !args.no_newline {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(values: &[&str], chunks: &[&str]) -> String {
        let mut masker = Masker::new(values.iter().copied());
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(masker.push(chunk.as_bytes()));
        }
        out.extend(masker.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn values_are_concealed_even_split_across_reads() {
        let c = "<concealed by deadbolt>";
        assert_eq!(masked(&["hunter2"], &["pw=hunter2\n"]), format!("pw={c}\n"));
        // Split at every point, and byte by byte.
        let text = "a hunter2 b hunter2";
        for at in 0..text.len() {
            let (one, two) = text.split_at(at);
            assert_eq!(
                masked(&["hunter2"], &[one, two]),
                format!("a {c} b {c}"),
                "split at {at}"
            );
        }
        let bytes: Vec<String> = text.chars().map(String::from).collect();
        let bytes: Vec<&str> = bytes.iter().map(String::as_str).collect();
        assert_eq!(masked(&["hunter2"], &bytes), format!("a {c} b {c}"));
        // A value inside a longer one doesn't leave the rest showing.
        assert_eq!(
            masked(&["abc", "abcdef"], &["x abc", "def y"]),
            format!("x {c} y")
        );
        assert_eq!(
            masked(&["abc", "abcdef"], &["x abc", "xy"]),
            format!("x {c}xy")
        );
        // A prefix that never completes comes out at the end.
        assert_eq!(masked(&["hunter2"], &["hunt"]), "hunt");
        // URL-encoded and base64 forms, and short values left alone.
        assert_eq!(
            masked(&["p@ss word"], &["u=p%40ss%20word"]),
            format!("u={c}")
        );
        assert_eq!(masked(&["hunter2"], &["aHVudGVyMg=="]), format!("{c}=="));
        assert_eq!(masked(&["42"], &["42 is 42"]), "42 is 42");
        // Output that can't be a value's start flows straight through.
        let mut masker = Masker::new(["hunter2"]);
        assert_eq!(masker.push(b"ready> "), b"ready> ");
    }

    /// Held-back output goes out after a quiet spell, so a prompt ending
    /// in what could start a value doesn't stall.
    #[tokio::test]
    async fn held_output_flushes_when_the_command_goes_quiet() {
        let (mut child, from) = tokio::io::duplex(64);
        let (to, mut seen) = tokio::io::duplex(64);
        let pumping = tokio::spawn(pump(from, to, Some(Masker::new(["hunter2"]))));
        child.write_all(b"password? hunt").await.unwrap();
        let mut got = vec![0u8; 64];
        let mut text = Vec::new();
        while text.len() < b"password? hunt".len() {
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), seen.read(&mut got))
                .await
                .expect("held output never flushed")
                .unwrap();
            text.extend_from_slice(&got[..n]);
        }
        assert_eq!(text, b"password? hunt");
        drop(child);
        pumping.await.unwrap().unwrap();
    }

    #[test]
    fn env_files_and_templates_parse_without_echoing_values() {
        let file = Path::new(".env.tpl");
        let vars = env_file(
            "# comment\n\nexport TOKEN=deadbolt://personal/GitHub/token\nPLAIN = 'x y'\nQ=\"deadbolt://a/b\"\n",
            file,
        )
        .unwrap();
        assert_eq!(
            vars,
            [
                (
                    "TOKEN".to_string(),
                    EnvValue::Reference("deadbolt://personal/GitHub/token".into())
                ),
                (
                    "PLAIN".to_string(),
                    EnvValue::Literal(Zeroizing::new("x y".into()))
                ),
                (
                    "Q".to_string(),
                    EnvValue::Reference("deadbolt://a/b".into())
                ),
            ]
        );
        let error = env_file("A=1\nsecret-without-equals\n", file).unwrap_err();
        assert_eq!(error.to_string(), ".env.tpl:2: not NAME=VALUE");
        assert!(env_file("A=deadbolt://only-item\n", file).is_err());

        let parts = template(
            "a: {{ deadbolt://GitHub/token }}\nb: {{deadbolt://work/x%2Fy/k}} {{ other }}",
        )
        .unwrap();
        assert_eq!(
            parts,
            [
                Part::Text("a: "),
                Part::Reference("deadbolt://GitHub/token".into()),
                Part::Text("\nb: "),
                Part::Reference("deadbolt://work/x%2Fy/k".into()),
                Part::Text(" {{ other }}"),
            ]
        );
        assert!(template("{{ deadbolt://GitHub/token").is_err());
        assert!(template("{{ deadbolt://GitHub }}").is_err());
        assert!(template("{{ other {{ deadbolt://x/y }}").is_err());
        assert_eq!(
            template("{{ unclosed").unwrap(),
            [Part::Text("{{ unclosed")]
        );
    }
}
