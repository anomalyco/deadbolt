//! Taint: the processes `deadbolt run` started, and everything they start.
//!
//! `deadbolt run` registers itself here after it has resolved its own
//! secrets and before it spawns the command, so the command is a
//! descendant of a registered process from its first instruction: no
//! window between spawn and registration. On every control connection
//! while a run is registered, the daemon walks the caller's ancestry by
//! `(pid, start time)`; a caller descended from a run is pinned to the
//! run's capability (none, by default) and gets nothing ambient: no item,
//! no secret, no unlock, no prompt. `deadbolt run` ends its entry with the
//! run id, which never reaches the command (neither its environment nor its
//! arguments); an entry whose process is gone is dropped as it's found.
//!
//! Start times guard pid reuse both ways: an entry names its process by
//! `(pid, start)`, so a recycled pid is not the run, and a parent started
//! after its child is not its parent (the real one exited and its pid was
//! reused), which ends the walk.
//!
//! What escapes: a process that outlives its run (`nohup`, a double fork
//! that reparents to launchd or init) is no longer anyone's descendant once
//! the run ends, or once it's reparented. The socket's other checks still
//! apply to it.

use std::collections::HashSet;
use std::time::Instant;

use anyhow::{Result, bail};
use deadbolt_client::peer::Peer;
use deadbolt_engine::cap::{CapCheck, CapId, UseScope};
use subtle::ConstantTimeEq;

use super::{Daemon, fail};
use crate::protocol::{Command, ErrorCode, Reply, Secret};

/// What a process inside a run hears.
pub const DENIED: &str = "process is running inside deadbolt run and cannot access daemon secrets";

/// A process's start time: seconds and microseconds since the epoch on
/// macOS, clock ticks after boot (and 0) on Linux.
pub type Start = (u64, u64);

/// The most ancestors walked before giving up.
const MAX_HOPS: usize = 64;
/// The most runs registered at once.
const MAX_RUNS: usize = 4096;

/// What the walk reads of a process: its parent and when it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub ppid: u32,
    pub start: Start,
}

/// Reads [`Facts`] by pid; the OS in the daemon, a table in tests.
pub trait ProcessFacts {
    fn facts(&self, pid: u32) -> Option<Facts>;
}

/// The running system's processes.
pub struct OsProcesses;

impl ProcessFacts for OsProcesses {
    #[cfg(target_os = "macos")]
    fn facts(&self, pid: u32) -> Option<Facts> {
        use deadbolt_os::process::{ZOMBIE, bsd_info, kinfo_proc};
        if let Some(info) = bsd_info(pid) {
            return (info.status != ZOMBIE).then_some(Facts {
                ppid: info.ppid,
                start: info.start,
            });
        }
        // Other users' processes (launchd, login, sshd) answer only here.
        let info = kinfo_proc(pid)?;
        (info.stat != ZOMBIE && u32::try_from(info.pid).ok() == Some(pid)).then_some(Facts {
            ppid: u32::try_from(info.ppid).ok()?,
            start: info.start,
        })
    }

    #[cfg(target_os = "linux")]
    fn facts(&self, pid: u32) -> Option<Facts> {
        // `stat` finds the name's end with `rfind(')')`, so a name holding
        // spaces or parentheses can't shift the fields after it.
        let stat = deadbolt_client::peer::linux::stat(pid)?;
        Some(Facts {
            ppid: stat.ppid,
            start: (stat.start_ticks, 0),
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn facts(&self, _pid: u32) -> Option<Facts> {
        None
    }
}

/// One `deadbolt run`, by the process that registered.
#[derive(Debug)]
pub struct TaintEntry {
    pub run_id: [u8; 16],
    pub root_pid: u32,
    pub root_start: Start,
    /// What its processes may do: `None`, nothing.
    pub cap_id: Option<CapId>,
    pub created_at: Instant,
}

/// Where a caller stands.
#[derive(Debug)]
pub enum Taint<'a> {
    /// Not descended from any run.
    Clean,
    /// Descended from this run (or its process itself).
    Run(&'a TaintEntry),
    /// Its facts couldn't be read, or its ancestry didn't end: treated as
    /// tainted while a run is registered.
    Unknown,
}

/// The runs registered now.
#[derive(Debug, Default)]
pub struct TaintTable {
    entries: Vec<TaintEntry>,
}

impl TaintTable {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Registers the process `(pid, start)` and every process it starts;
    /// the run id ends it.
    pub fn register(&mut self, pid: u32, start: Start, cap_id: Option<CapId>) -> Result<[u8; 16]> {
        if self.entries.len() >= MAX_RUNS {
            bail!("too many runs are registered");
        }
        let mut run_id = [0u8; 16];
        getrandom::fill(&mut run_id).map_err(|e| anyhow::anyhow!("drawing a run id: {e}"))?;
        self.entries.push(TaintEntry {
            run_id,
            root_pid: pid,
            root_start: start,
            cap_id,
            created_at: Instant::now(),
        });
        Ok(run_id)
    }

    /// Ends the run `run_id` names, comparing it with every entry in
    /// constant time, and returns it.
    pub fn unregister(&mut self, run_id: &[u8; 16]) -> Option<TaintEntry> {
        let mut found = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if bool::from(entry.run_id.ct_eq(run_id)) {
                found = Some(index);
            }
        }
        found.map(|i| self.entries.swap_remove(i))
    }

    /// Drops the runs whose process is gone (exited, or its pid reused).
    pub fn prune(&mut self, facts: &impl ProcessFacts) {
        self.entries.retain(|entry| {
            facts
                .facts(entry.root_pid)
                .is_some_and(|f| f.start == entry.root_start)
        });
    }

    fn entry(&self, pid: u32, start: Start) -> Option<&TaintEntry> {
        self.entries
            .iter()
            .find(|e| e.root_pid == pid && e.root_start == start)
    }

    /// The run `(caller_pid, caller_start)` or one of its ancestors is, if
    /// any.
    pub fn check_ancestry(
        &self,
        facts: &impl ProcessFacts,
        caller_pid: u32,
        caller_start: Start,
    ) -> Taint<'_> {
        if self.entries.is_empty() {
            return Taint::Clean;
        }
        let Some(mut me) = facts.facts(caller_pid).filter(|f| f.start == caller_start) else {
            return Taint::Unknown;
        };
        let mut pid = caller_pid;
        let mut seen = HashSet::from([pid]);
        for _ in 0..MAX_HOPS {
            if let Some(entry) = self.entry(pid, me.start) {
                return Taint::Run(entry);
            }
            if pid <= 1 || me.ppid == 0 {
                return Taint::Clean;
            }
            if !seen.insert(me.ppid) {
                return Taint::Unknown;
            }
            let Some(parent) = facts.facts(me.ppid) else {
                // Exited between reads, or out of sight: the walk ends.
                return Taint::Clean;
            };
            if parent.start > me.start {
                // The pid is someone new's; the real parent is gone.
                return Taint::Clean;
            }
            pid = me.ppid;
            me = parent;
        }
        Taint::Unknown
    }
}

/// The caller's start time, from the kernel's word for it (`peer`), or
/// `None` if it has exited. On macOS the audit token must still name a
/// live process after the read, so the start time read is that process's.
pub fn caller_start(
    peer: &deadbolt_client::peer::Peer,
    facts: &impl ProcessFacts,
) -> Option<Start> {
    let start = facts.facts(peer.pid)?.start;
    #[cfg(target_os = "macos")]
    {
        if !peer
            .token
            .as_ref()
            .is_some_and(deadbolt_client::peer::live_token)
        {
            return None;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if peer.pid_version != Some(start.0) {
            return None;
        }
    }
    Some(start)
}

/// What `command` needs of a run's capability, if a capability can allow
/// it at all.
fn needs(command: &Command) -> Option<CapCheck> {
    Some(match command {
        Command::VaultList | Command::ItemList { .. } | Command::TagList { .. } => CapCheck::Meta,
        Command::Resolve { refs, .. } => CapCheck::Reveal { refs: refs.clone() },
        Command::SiteFill { origin, .. } => CapCheck::Use(UseScope::Fill {
            origin: origin.clone(),
        }),
        _ => return None,
    })
}

impl Daemon {
    /// Answers `run-taint` and `run-untaint`, and refuses what a process
    /// inside a run asks beyond its run's capability. `None` lets the
    /// request through. Costs nothing while no run is registered.
    pub(super) fn screen(&self, peer: Option<&Peer>, command: &Command) -> Option<Result<Reply>> {
        let mut taints = self.taints.lock().unwrap_or_else(|e| e.into_inner());
        if let Command::RunUntaint { run } = command {
            let ended = deadbolt_engine::unhex::<16>(run.expose())
                .ok()
                .and_then(|run| taints.unregister(&run));
            return Some(match ended {
                Some(entry) => {
                    tracing::debug!(lasted = ?entry.created_at.elapsed(), "a run ended");
                    Ok(Reply::Done)
                }
                None => Err(fail(ErrorCode::NotFound, "no such run")),
            });
        }
        let taint_run = matches!(command, Command::RunTaint);
        if taints.is_empty() && !taint_run {
            return None;
        }
        taints.prune(&OsProcesses);
        let caller = peer.and_then(|p| Some((p.pid, caller_start(p, &OsProcesses)?)));
        let cap = match caller {
            _ if taints.is_empty() => None,
            Some((pid, start)) => match taints.check_ancestry(&OsProcesses, pid, start) {
                Taint::Clean => None,
                Taint::Run(entry) => Some(entry.cap_id.clone()),
                Taint::Unknown => Some(None),
            },
            None => Some(None),
        };
        match (cap, command) {
            (None, Command::RunTaint) => {
                let Some((pid, start)) = caller else {
                    return Some(Err(fail(
                        ErrorCode::Failed,
                        "can't read the calling process",
                    )));
                };
                Some(
                    taints
                        .register(pid, start, None)
                        .map(|run| Reply::RunTainted {
                            run: Secret::new(deadbolt_engine::hex(&run)),
                        }),
                )
            }
            (None, _) | (Some(_), Command::Status) => None,
            (Some(Some(cap)), command) => {
                drop(taints);
                let Some(check) = needs(command) else {
                    return Some(Err(fail(ErrorCode::Forbidden, DENIED)));
                };
                let allowed = self.with(|s| {
                    s.engine
                        .authorize_cap(&cap, &check)
                        .map_err(|e| fail(ErrorCode::Forbidden, format!("{DENIED}: {e}")))
                });
                allowed.err().map(Err)
            }
            (Some(None), _) => Some(Err(fail(ErrorCode::Forbidden, DENIED))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Processes by pid: `(ppid, start)`.
    struct Table(HashMap<u32, Facts>);

    impl Table {
        fn new(rows: &[(u32, u32, u64)]) -> Self {
            Self(
                rows.iter()
                    .map(|&(pid, ppid, start)| {
                        (
                            pid,
                            Facts {
                                ppid,
                                start: (start, 0),
                            },
                        )
                    })
                    .collect(),
            )
        }
    }

    impl ProcessFacts for Table {
        fn facts(&self, pid: u32) -> Option<Facts> {
            self.0.get(&pid).copied()
        }
    }

    fn tainted(table: &TaintTable, facts: &Table, pid: u32) -> bool {
        let start = facts.facts(pid).unwrap().start;
        !matches!(table.check_ancestry(facts, pid, start), Taint::Clean)
    }

    /// init 1 <- shell 10 <- run 20 <- child 30 <- grandchild 40 ... and a
    /// sibling shell 11.
    fn tree() -> Table {
        let mut rows = vec![
            (1, 0, 1),
            (10, 1, 10),
            (11, 1, 11),
            (20, 10, 20),
            (30, 20, 30),
            (40, 30, 40),
        ];
        // A chain 40 deep under the grandchild.
        rows.extend((41..80).map(|pid| (pid, pid - 1, u64::from(pid))));
        Table::new(&rows)
    }

    #[test]
    fn a_run_taints_itself_and_every_descendant_but_not_its_parents() {
        let facts = tree();
        let mut table = TaintTable::default();
        assert!(!tainted(&table, &facts, 79));
        table.register(20, (20, 0), None).unwrap();
        for pid in [20, 30, 40, 41, 79] {
            assert!(tainted(&table, &facts, pid), "{pid}");
        }
        for pid in [1, 10, 11] {
            assert!(!tainted(&table, &facts, pid), "{pid}");
        }
    }

    #[test]
    fn ends_with_its_run_id_and_never_another() {
        let facts = tree();
        let mut table = TaintTable::default();
        let run = table.register(20, (20, 0), None).unwrap();
        let mut wrong = run;
        wrong[0] ^= 1;
        assert!(table.unregister(&wrong).is_none());
        assert!(tainted(&table, &facts, 30));
        assert_eq!(table.unregister(&run).unwrap().root_pid, 20);
        assert!(table.is_empty());
        assert!(!tainted(&table, &facts, 30));
    }

    #[test]
    fn a_recycled_pid_is_neither_the_run_nor_its_descendant() {
        let mut table = TaintTable::default();
        table.register(20, (20, 0), None).unwrap();
        // Pid 20 now belongs to a process started later: not the run.
        let reused = Table::new(&[(1, 0, 1), (10, 1, 10), (20, 10, 500), (30, 20, 501)]);
        assert!(!tainted(&table, &reused, 20));
        assert!(!tainted(&table, &reused, 30));
        // And pruning drops the stale entry.
        table.prune(&reused);
        assert!(table.is_empty());
    }

    #[test]
    fn a_parent_younger_than_its_child_ends_the_walk() {
        let mut table = TaintTable::default();
        table.register(20, (20, 0), None).unwrap();
        // 30's parent exited; pid 20 went to a newer process (a run).
        let facts = Table::new(&[(1, 0, 1), (20, 1, 20), (30, 20, 15)]);
        assert!(!tainted(&table, &facts, 30));
    }

    #[test]
    fn a_caller_that_is_gone_or_misnamed_is_unknown() {
        let facts = tree();
        let mut table = TaintTable::default();
        table.register(20, (20, 0), None).unwrap();
        assert!(matches!(
            table.check_ancestry(&facts, 999, (1, 0)),
            Taint::Unknown
        ));
        assert!(matches!(
            table.check_ancestry(&facts, 30, (31, 0)),
            Taint::Unknown
        ));
    }

    #[test]
    fn cycles_and_endless_chains_are_unknown() {
        let mut table = TaintTable::default();
        table.register(5, (5, 0), None).unwrap();
        let cycle = Table::new(&[(100, 101, 10), (101, 100, 10)]);
        assert!(matches!(
            table.check_ancestry(&cycle, 100, (10, 0)),
            Taint::Unknown
        ));
        let rows: Vec<(u32, u32, u64)> = (2..200).map(|pid| (pid, pid - 1, 1)).collect();
        let deep = Table::new(&rows);
        assert!(matches!(
            table.check_ancestry(&deep, 199, (1, 0)),
            Taint::Unknown
        ));
    }

    #[test]
    fn dead_runs_are_pruned_and_live_ones_kept() {
        let facts = tree();
        let mut table = TaintTable::default();
        table.register(20, (20, 0), None).unwrap();
        table.register(777, (777, 0), None).unwrap();
        table.prune(&facts);
        assert_eq!(table.entries.len(), 1);
        assert!(tainted(&table, &facts, 30));
    }

    #[test]
    fn this_process_reads_its_own_facts() {
        let me = std::process::id();
        let facts = OsProcesses.facts(me).unwrap();
        assert_eq!(facts.ppid, std::os::unix::process::parent_id());
        let mut table = TaintTable::default();
        let parent = OsProcesses.facts(facts.ppid).unwrap();
        table.register(facts.ppid, parent.start, None).unwrap();
        assert!(matches!(
            table.check_ancestry(&OsProcesses, me, facts.start),
            Taint::Run(_)
        ));
    }
}
