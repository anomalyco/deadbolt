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

use std::ops::ControlFlow;
use std::time::Instant;

use anyhow::{Result, bail};
use deadbolt_client::peer::Peer;
use deadbolt_client::peer::ancestry::{
    self, AncestorStep, OsProcesses, ProcessFacts, Start, WalkEnd,
};
use deadbolt_engine::cap::{CapCheck, CapId, UseScope};
use subtle::ConstantTimeEq;

use super::{Daemon, fail};
use crate::protocol::{Command, ErrorCode, Reply, Secret};

/// What a process inside a run hears.
pub const DENIED: &str = "process is running inside deadbolt run and cannot access daemon secrets";

/// The most ancestors walked before giving up.
const MAX_HOPS: usize = 64;
/// The most runs registered at once.
const MAX_RUNS: usize = 4096;

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

/// Why a run wasn't ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unregister {
    NoSuchRun,
    /// The id is a run's, but the caller isn't its process.
    NotItsProcess,
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
    /// constant time, and returns it. Only the run's own process, `caller`
    /// by `(pid, start)`, may end it: the id alone, leaked to another
    /// process, isn't enough.
    pub fn unregister(
        &mut self,
        run_id: &[u8; 16],
        caller: Option<(u32, Start)>,
    ) -> Result<TaintEntry, Unregister> {
        let mut found = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if bool::from(entry.run_id.ct_eq(run_id)) {
                found = Some(index);
            }
        }
        let index = found.ok_or(Unregister::NoSuchRun)?;
        let entry = &self.entries[index];
        if caller != Some((entry.root_pid, entry.root_start)) {
            return Err(Unregister::NotItsProcess);
        }
        Ok(self.entries.swap_remove(index))
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
        match ancestry::walk_from(
            facts,
            caller_pid,
            caller_start,
            MAX_HOPS,
            |step| match step {
                AncestorStep::Visible { pid, start } => match self.entry(pid, start) {
                    Some(entry) => ControlFlow::Break(entry),
                    None => ControlFlow::Continue(()),
                },
                AncestorStep::Hidden { .. } => ControlFlow::Continue(()),
            },
        ) {
            ControlFlow::Break(entry) => Taint::Run(entry),
            // init, a proven `hidepid` system boundary, or a reused parent pid
            // ends the walk clean. An unreadable parent other than init proves
            // nothing: unknown, not clean.
            ControlFlow::Continue(
                WalkEnd::Root
                | WalkEnd::SystemBoundary
                | WalkEnd::NoParent
                | WalkEnd::PidReused
                | WalkEnd::Unreadable { pid: 1 },
            ) => Taint::Clean,
            ControlFlow::Continue(
                WalkEnd::StartMismatch
                | WalkEnd::Unreadable { .. }
                | WalkEnd::Cycle
                | WalkEnd::HopLimit,
            ) => Taint::Unknown,
        }
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

impl Daemon {
    /// `status` for a process inside a run: whether a daemon of which
    /// protocol is there and unlocked, so its client can tell, and none of
    /// the vaults, devices or peers.
    fn status_for_run(&self) -> crate::protocol::Status {
        let mut status = self.status();
        status.device = None;
        status.vaults = Vec::new();
        status.peers = 0;
        status.peers_online = 0;
        status.home = String::new();
        status
    }
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
            let caller = peer.and_then(|p| Some((p.pid, caller_start(p, &OsProcesses)?)));
            let ended = deadbolt_engine::unhex::<16>(run.expose())
                .map_err(|_| Unregister::NoSuchRun)
                .and_then(|run| taints.unregister(&run, caller));
            return Some(match ended {
                Ok(entry) => {
                    tracing::debug!(lasted = ?entry.created_at.elapsed(), "a run ended");
                    Ok(Reply::Done)
                }
                Err(Unregister::NotItsProcess) => Err(fail(
                    ErrorCode::Forbidden,
                    "only the run's own process may end it",
                )),
                Err(Unregister::NoSuchRun) => Err(fail(ErrorCode::NotFound, "no such run")),
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
            (None, _) => None,
            (Some(_), Command::Status) => {
                drop(taints);
                Some(Ok(Reply::Status(Box::new(self.status_for_run()))))
            }
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
mod screen_tests;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use deadbolt_client::peer::ancestry::{Facts, Hidden};

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
        let root = Some((20, (20, 0)));
        assert_eq!(
            table.unregister(&wrong, root).unwrap_err(),
            Unregister::NoSuchRun
        );
        assert!(tainted(&table, &facts, 30));
        assert_eq!(table.unregister(&run, root).unwrap().root_pid, 20);
        assert!(table.is_empty());
        assert!(!tainted(&table, &facts, 30));
    }

    /// The run id is the run's process's to use: another process that learned
    /// it (its child, a reused pid, nobody the daemon could read) can't end
    /// the run and leave its descendants untainted.
    #[test]
    fn only_the_runs_own_process_ends_it() {
        let facts = tree();
        let mut table = TaintTable::default();
        let run = table.register(20, (20, 0), None).unwrap();
        for caller in [Some((30, (30, 0))), Some((20, (500, 0))), None] {
            assert_eq!(
                table.unregister(&run, caller).unwrap_err(),
                Unregister::NotItsProcess,
                "{caller:?}"
            );
            assert!(tainted(&table, &facts, 30));
        }
        assert!(table.unregister(&run, Some((20, (20, 0)))).is_ok());
        assert!(table.is_empty());
    }

    /// A parent that can't be read and isn't init is no proof the walk ended:
    /// on Linux a thread-group leader that exited while its threads run is a
    /// zombie that `/proc` once read as gone, and a run's child could hide
    /// behind it.
    #[test]
    fn an_unreadable_parent_other_than_init_is_unknown() {
        let mut table = TaintTable::default();
        table.register(20, (20, 0), None).unwrap();
        // 30's parent 25 (a zombie leader under the run) reads as nothing.
        let facts = Table::new(&[(1, 0, 1), (20, 1, 20), (30, 25, 30)]);
        assert!(matches!(
            table.check_ancestry(&facts, 30, (30, 0)),
            Taint::Unknown
        ));
        // Reparented to init, a missing pid 1 still ends the walk clean.
        let orphan = Table::new(&[(20, 10, 20), (30, 1, 30)]);
        assert!(matches!(
            table.check_ancestry(&orphan, 30, (30, 0)),
            Taint::Clean
        ));
    }

    /// `hidepid`: a hidden parent the OS proves is the system's ends the
    /// walk; one a visible process started is walked through.
    #[test]
    fn a_hidden_parent_is_walked_through_or_ends_at_the_system() {
        struct Hiding(Table, Option<Hidden>);
        impl ProcessFacts for Hiding {
            fn facts(&self, pid: u32) -> Option<Facts> {
                self.0.facts(pid)
            }
            fn hidden(&self, parent: u32, child: u32, start: Start) -> Option<Hidden> {
                (parent == 25 && child == 30 && start == (30, 0)).then_some(self.1?)
            }
        }
        let mut table = TaintTable::default();
        table.register(20, (20, 0), None).unwrap();
        let rows = || Table::new(&[(1, 0, 1), (20, 1, 20), (30, 25, 30)]);
        let through = Hiding(rows(), Some(Hidden::VisibleParent(20)));
        assert!(matches!(
            table.check_ancestry(&through, 30, (30, 0)),
            Taint::Run(_)
        ));
        let system = Hiding(rows(), Some(Hidden::SystemBoundary));
        assert!(matches!(
            table.check_ancestry(&system, 30, (30, 0)),
            Taint::Clean
        ));
        let unproven = Hiding(rows(), None);
        assert!(matches!(
            table.check_ancestry(&unproven, 30, (30, 0)),
            Taint::Unknown
        ));
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
