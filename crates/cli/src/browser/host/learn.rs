//! Learning-mode session log files written and read by the native messaging host.

use std::time::Duration;

use serde_json::Value;

use super::protocol::{Body, Code, Refusal};
use crate::paths::Paths;

/// The most one learning session's log grows to; past it lines are refused.
const MAX_LEARN_LOG: u64 = 4 * 1024 * 1024;
/// How many session logs are kept, and for how long; a new session prunes the rest, oldest first.
pub(super) const MAX_LEARN_LOGS: usize = 10;
const LEARN_LOG_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The most of a log one `learn-read` answers: escaped, well under `MAX_REPLY`.
pub(super) const LEARN_READ: u64 = 256 * 1024;

/// it: it names the log file, so nothing else gets near the path.
pub(super) fn learn_session(session: &str) -> bool {
    session.len() == 36
        && session.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit() && !b.is_ascii_uppercase(),
        })
}

/// Appends `line` to the session's log, `<learn dir>/<session>.jsonl`, both
/// readable by this user only. Works locked: it touches no vault. A new
/// session's log first prunes the old ones (see `prune_learn_logs`).
pub(super) fn learn(
    paths: &Paths,
    session: &str,
    line: &serde_json::Map<String, Value>,
) -> Result<(), Refusal> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if !learn_session(session) {
        return Err(Refusal::bad("session is a lowercase UUID"));
    }
    let failed = |what: &str, error: std::io::Error| Refusal {
        code: Code::Failed,
        message: format!("couldn't {what} the learning log: {error}"),
    };
    let dir = paths.learn_dir();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| failed("create", e))?;
    // Also when it was there already, with looser permissions.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| failed("create", e))?;
    let path = dir.join(format!("{session}.jsonl"));
    let mut bytes = serde_json::to_vec(line).map_err(|_| Refusal::bad("line is not JSON"))?;
    bytes.push(b'\n');
    let existing = std::fs::metadata(&path).ok();
    if existing.is_none() {
        let now = std::time::UNIX_EPOCH + Duration::from_secs(crate::config::now());
        prune_learn_logs(&dir, now);
    }
    let size = existing.map(|m| m.len()).unwrap_or(0);
    if size + bytes.len() as u64 > MAX_LEARN_LOG {
        return Err(Refusal::bad(format!(
            "a learning log is at most {MAX_LEARN_LOG} bytes"
        )));
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(&bytes))
        .map_err(|e| failed("write", e))
}

/// Up to `LEARN_READ` bytes of a session's log from `offset`, whole lines
/// only (a line is far smaller), and where the next part starts, if any.
pub(super) fn learn_read(paths: &Paths, session: &str, offset: u64) -> Result<Body, Refusal> {
    use std::io::{Read, Seek};

    if !learn_session(session) {
        return Err(Refusal::bad("session is a lowercase UUID"));
    }
    let path = paths.learn_dir().join(format!("{session}.jsonl"));
    let Ok(mut file) = std::fs::File::open(path) else {
        return Err(Refusal {
            code: Code::NotFound,
            message: "no such learning log".into(),
        });
    };
    let mut bytes = Vec::new();
    file.seek(std::io::SeekFrom::Start(offset))
        .and_then(|_| file.take(LEARN_READ + 1).read_to_end(&mut bytes))
        .map_err(|_| Refusal::bad("couldn't read the learning log"))?;
    let mut next = None;
    if bytes.len() as u64 > LEARN_READ {
        let end = bytes[..LEARN_READ as usize]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(LEARN_READ as usize, |i| i + 1);
        bytes.truncate(end);
        next = Some(offset + end as u64);
    }
    let text = String::from_utf8(bytes).map_err(|_| Refusal::bad("the learning log isn't text"))?;
    Ok(Body::LearnText { text, next })
}

/// Before a new session's log: removes the logs older than `LEARN_LOG_AGE`,
/// then the oldest until the new one makes `MAX_LEARN_LOGS`. Best effort: a
/// log that can't be read or removed is left.
pub(super) fn prune_learn_logs(dir: &std::path::Path, now: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut logs: Vec<(std::time::SystemTime, std::path::PathBuf)> = entries
        .filter_map(|e| {
            let e = e.ok()?;
            let path = e.path();
            let meta = e.metadata().ok()?;
            let modified = meta.modified().ok()?;
            (meta.is_file() && path.extension().is_some_and(|x| x == "jsonl"))
                .then_some((modified, path))
        })
        .collect();
    logs.sort();
    let excess = (logs.len() + 1).saturating_sub(MAX_LEARN_LOGS);
    for (i, (modified, path)) in logs.iter().enumerate() {
        let old = now.duration_since(*modified).unwrap_or_default() > LEARN_LOG_AGE;
        if i < excess || old {
            std::fs::remove_file(path).ok();
        }
    }
}
