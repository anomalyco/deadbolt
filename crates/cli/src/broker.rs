//! `deadbolt broker`: one `deadbolt run`'s reverse proxy (docs/broker.md).
//!
//! `deadbolt run --broker` starts it with an empty environment (no
//! `LD_PRELOAD`, no `DYLD_*`, nothing of the caller's), in its own process
//! group, and writes its config, real secrets included, to its stdin
//! (`--fd 0`). The broker hardens itself before reading a byte (no core
//! dumps, not dumpable on Linux, no debugger on macOS in release builds),
//! reads the config, drops the pipe, binds `127.0.0.1:0`, prints
//! `{"port":N}` and serves until the run's process is gone or it is told
//! to stop. The secrets never touch argv, an environment or a disk.
//!
//! The command gets placeholders (`db_ph_<32 hex>`) and
//! `http://127.0.0.1:<port>/<alias>`: a placeholder is worthless off the
//! machine and after the run, and on it only a process in the run's tree
//! can use it, because every connection's client is looked up by its socket
//! (`deadbolt_os::net`) before a byte of it is read.

mod aws;
mod config;
mod hygiene;
pub mod launch;
mod proxy;
mod redact;
#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use deadbolt_os::mem::{HardeningOptions, harden_process};
use deadbolt_os::net::{LoopbackConnection, owner_in_subtree_confirmed};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use zeroize::Zeroizing;

use config::BrokerConfig;
use proxy::Broker;

use crate::daemon::taint::{OsProcesses, ProcessFacts, Start};

/// `deadbolt broker`, which `main` hands over before anything else runs.
pub const COMMAND: &str = "broker";
/// The largest config frame read.
const MAX_FRAME: u64 = 1 << 20;
/// How often the broker checks that its run is still there.
const ROOT_POLL: Duration = Duration::from_millis(250);

/// The run's process: who may connect.
#[derive(Debug, Clone)]
pub struct Lineage {
    pub root_pid: u32,
    pub root_start: Option<(u64, u64)>,
}

impl Lineage {
    /// Whether the run's process is still the one that started the broker.
    pub fn root_alive(&self) -> bool {
        self.root_alive_in(&OsProcesses)
    }

    /// Whether the client end of `connection` is held by the run's process
    /// or one of its descendants. The owner the tree walk found is named by
    /// `(pid, start)`, its ancestry is walked back to the run by start time,
    /// and only then is it asked again whether it holds the socket: a pid
    /// that exited and was reused while this looked is never let in.
    pub fn allows(&self, connection: LoopbackConnection) -> bool {
        self.allows_with(&OsProcesses, |root, confirm| {
            owner_in_subtree_confirmed(root, connection, confirm)
        })
    }

    /// `find` is [`owner_in_subtree_confirmed`] for one connection: the
    /// owner, once it passes the check it's given and still holds the socket.
    fn allows_with(
        &self,
        facts: &impl ProcessFacts,
        find: impl FnOnce(u32, &mut dyn FnMut(u32) -> bool) -> Option<u32>,
    ) -> bool {
        if !self.root_alive_in(facts) {
            return false;
        }
        let mut owner_start = None;
        let owner = find(self.root_pid, &mut |owner| {
            let Some(start) = facts.facts(owner).map(|f| f.start) else {
                return false;
            };
            owner_start = Some(start);
            self.descends(facts, owner, start)
        });
        owner
            .zip(owner_start)
            .is_some_and(|(owner, start)| facts.facts(owner).is_some_and(|f| f.start == start))
            && self.root_alive_in(facts)
    }

    fn root_alive_in(&self, facts: &impl ProcessFacts) -> bool {
        let found = facts.facts(self.root_pid);
        match self.root_start {
            Some(start) => found.is_some_and(|found| found.start == start),
            None => found.is_some(),
        }
    }

    /// Whether `(pid, start)` is the run's process or descends from it, each
    /// parent started no later than its child.
    fn descends(&self, facts: &impl ProcessFacts, mut pid: u32, mut start: Start) -> bool {
        for _ in 0..deadbolt_os::net::MAX_SUBTREE {
            if pid == self.root_pid {
                return self.root_start.is_none_or(|root| root == start);
            }
            let Some(me) = facts.facts(pid).filter(|f| f.start == start) else {
                return false;
            };
            if me.ppid <= 1 || me.ppid == pid {
                return false;
            }
            let Some(parent) = facts.facts(me.ppid) else {
                return false;
            };
            if parent.start > start {
                return false;
            }
            pid = me.ppid;
            start = parent.start;
        }
        false
    }
}

/// `deadbolt broker [--fd N]`.
pub fn run(args: &[OsString]) -> ExitCode {
    // First, before a secret is in memory.
    let hardening = harden_process(HardeningOptions {
        deny_debugger: !cfg!(any(debug_assertions, test)),
    });
    for (protection, outcome) in hardening.failures() {
        eprintln!("deadbolt broker: {protection}: {outcome}");
    }
    match start(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("deadbolt broker: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn fd_arg(args: &[OsString]) -> Result<u32> {
    let args: Vec<&str> = args
        .iter()
        .map(|a| a.to_str().context("arguments must be text"))
        .collect::<Result<_>>()?;
    let fd = match args.as_slice() {
        [] => "0",
        ["--fd", fd] => fd,
        [one] if one.starts_with("--fd=") => &one[5..],
        _ => bail!("usage: deadbolt broker [--fd N]"),
    };
    fd.parse().context("--fd takes a file descriptor number")
}

/// The config frame from fd `fd`, read to its end. Stdin is then pointed
/// at /dev/null, closing the pipe; another fd stays open, drained.
fn read_frame(fd: u32) -> Result<Zeroizing<Vec<u8>>> {
    let mut frame = Zeroizing::new(Vec::with_capacity(64 * 1024));
    // A File reads unbuffered: no copy of the secrets is left in a buffer
    // (`std::io::stdin()` would keep one in its own).
    let file = if fd == 0 {
        use std::os::fd::AsFd;
        std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned()?)
    } else {
        open_fd(fd)?
    };
    file.take(MAX_FRAME + 1)
        .read_to_end(&mut frame)
        .context("reading the config")?;
    if fd == 0 {
        let null = std::fs::File::open("/dev/null")?;
        rustix::stdio::dup2_stdin(&null)?;
    }
    if frame.len() as u64 > MAX_FRAME {
        bail!("the config is over {MAX_FRAME} bytes");
    }
    Ok(frame)
}

/// Fd `fd` as a file: `/dev/fd`, or `/proc/self/fd` on a Linux without it.
fn open_fd(fd: u32) -> Result<std::fs::File> {
    let dev = std::path::PathBuf::from(format!("/dev/fd/{fd}"));
    let path = if cfg!(target_os = "linux") && !dev.exists() {
        std::path::PathBuf::from(format!("/proc/self/fd/{fd}"))
    } else {
        dev
    };
    std::fs::File::open(&path).with_context(|| format!("opening fd {fd}"))
}

fn start(args: &[OsString]) -> Result<()> {
    let fd = fd_arg(args)?;
    let frame = read_frame(fd)?;
    let config: BrokerConfig = serde_json::from_slice(&frame).context("the config isn't valid")?;
    drop(frame);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let (broker, listener) = bind(config).await?;
        let port = listener.local_addr()?.port();
        {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{}", serde_json::json!({ "port": port }))?;
            stdout.flush()?;
        }
        let lineage = broker.lineage().cloned();
        let mut terminate = signal(SignalKind::terminate())?;
        let mut hangup = signal(SignalKind::hangup())?;
        tokio::select! {
            served = broker.serve(listener) => served.context("serving")?,
            () = root_gone(lineage) => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {}
        }
        Ok(())
    })
}

/// Binds `127.0.0.1:0` for `config`.
pub async fn bind(config: BrokerConfig) -> Result<(Arc<Broker>, TcpListener)> {
    let broker = Arc::new(Broker::new(config)?);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("listening on 127.0.0.1")?;
    Ok((broker, listener))
}

/// Returns once the run's process is gone; never without one.
async fn root_gone(lineage: Option<Lineage>) {
    let Some(lineage) = lineage else {
        return std::future::pending().await;
    };
    while lineage.root_alive() {
        tokio::time::sleep(ROOT_POLL).await;
    }
}
