//! Canonical upward process-ancestry walk.
//!
//! Shared by caller identification (`peer`), `deadbolt run` taint screening
//! (`daemon::taint`), and `deadbolt broker` lineage checks (`broker`). Walking
//! upward through one implementation keeps cycle protection, hop bounds,
//! monotonic start-time checks (pid-reuse detection), and Linux `hidepid`
//! handling identical everywhere.

use std::cell::RefCell;
use std::collections::HashSet;
use std::ops::ControlFlow;

use deadbolt_proto::daemon::Ancestor;

/// A process's start time: `(seconds, microseconds)` since the epoch on
/// macOS, `(clock ticks after boot, 0)` on Linux.
pub type Start = (u64, u64);

/// What the upward walk reads of a process: its parent and when it started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub ppid: u32,
    pub start: Start,
}

/// A parent whose facts can't be read, as Linux's `hidepid` explains it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hidden {
    /// Hidden, and no visible process started it: the walk has reached the
    /// system's processes.
    SystemBoundary,
    /// Hidden, started by this visible process, where the walk goes on.
    VisibleParent(u32),
}

/// Reads process [`Facts`] by pid; [`OsProcesses`] on a live machine, a
/// table in tests.
pub trait ProcessFacts {
    fn facts(&self, pid: u32) -> Option<Facts>;

    /// Why `parent`, whose facts didn't read, is out of sight while its
    /// child `(child, child_start)` still names it: `None` unless that's
    /// proven (Linux's `hidepid`).
    fn hidden(&self, _parent: u32, _child: u32, _child_start: Start) -> Option<Hidden> {
        None
    }
}

/// The running system's processes.
#[derive(Debug, Clone, Copy, Default)]
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
        // A thread-group leader that exited while its other threads run is
        // a zombie, still alive: `stat` reads it through them.
        let stat = super::linux::stat(pid)?;
        Some(Facts {
            ppid: stat.ppid,
            start: (stat.start_ticks, 0),
        })
    }

    #[cfg(target_os = "linux")]
    fn hidden(&self, parent: u32, child: u32, child_start: Start) -> Option<Hidden> {
        super::linux::hidden_parent(parent, child, child_start.0)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn facts(&self, _pid: u32) -> Option<Facts> {
        None
    }
}

/// One process visited during an upward walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AncestorStep {
    /// A visible process whose facts were read and whose start time is no
    /// later than its child's.
    Visible { pid: u32, start: Start },
    /// A hidden parent (`hidepid`) that has a visible ancestor above it;
    /// the walk continues from that visible ancestor next.
    Hidden { pid: u32 },
}

/// Why an upward walk stopped without the visitor short-circuiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkEnd {
    /// Reached init/launchd (pid 1).
    Root,
    /// Reached a proven `hidepid` system boundary.
    SystemBoundary,
    /// A process other than pid 1 reported `ppid == 0`.
    NoParent,
    /// A parent's start time was later than its child's: the real parent
    /// exited and its pid was reused.
    PidReused,
    /// The starting process's own facts couldn't be read or didn't match
    /// its expected start time.
    StartMismatch,
    /// `pid`'s facts couldn't be read and weren't proven hidden by the OS.
    Unreadable { pid: u32 },
    /// The parent chain looped back to an already-visited pid.
    Cycle,
    /// Reached `max_hops` before finding a root.
    HopLimit,
}

/// Walks upward from `(pid, start)`, verifying `facts.facts(pid)` matches
/// `start`, visiting `(pid, start)` first and then each ancestor up to
/// `max_hops` hops.
pub fn walk_from<B>(
    facts: &impl ProcessFacts,
    pid: u32,
    start: Start,
    max_hops: usize,
    mut visit: impl FnMut(AncestorStep) -> ControlFlow<B>,
) -> ControlFlow<B, WalkEnd> {
    let Some(me) = facts.facts(pid).filter(|f| f.start == start) else {
        return ControlFlow::Continue(WalkEnd::StartMismatch);
    };
    if let ControlFlow::Break(found) = visit(AncestorStep::Visible {
        pid,
        start: me.start,
    }) {
        return ControlFlow::Break(found);
    }
    walk_ancestors(facts, pid, me.ppid, me.start, max_hops, visit)
}

/// Walks the ancestors of `pid` (whose parent is `ppid`, born at `start`),
/// nearest first, up to `max_hops` hops.
///
/// Guards against cycles (tracking every visited pid in a set), pid reuse
/// (requiring each visible parent to have started no later than the last
/// visible child), and Linux `hidepid` boundaries.
pub fn walk_ancestors<B>(
    facts: &impl ProcessFacts,
    pid: u32,
    ppid: u32,
    start: Start,
    max_hops: usize,
    mut visit: impl FnMut(AncestorStep) -> ControlFlow<B>,
) -> ControlFlow<B, WalkEnd> {
    if pid == 1 {
        return ControlFlow::Continue(WalkEnd::Root);
    }
    let mut seen = HashSet::from([pid]);
    let mut child = pid;
    let mut child_start = start;
    let mut next = ppid;
    let mut via_hidden = false;
    let mut hops = 0usize;

    loop {
        if next == 0 {
            return ControlFlow::Continue(WalkEnd::NoParent);
        }
        if hops >= max_hops {
            return ControlFlow::Continue(WalkEnd::HopLimit);
        }
        if !seen.insert(next) {
            return ControlFlow::Continue(WalkEnd::Cycle);
        }
        hops += 1;

        let Some(parent) = facts.facts(next) else {
            if via_hidden {
                return ControlFlow::Continue(WalkEnd::Unreadable { pid: next });
            }
            match facts.hidden(next, child, child_start) {
                None => return ControlFlow::Continue(WalkEnd::Unreadable { pid: next }),
                Some(Hidden::SystemBoundary) => {
                    return ControlFlow::Continue(WalkEnd::SystemBoundary);
                }
                Some(Hidden::VisibleParent(visible)) => {
                    if let ControlFlow::Break(found) = visit(AncestorStep::Hidden { pid: next }) {
                        return ControlFlow::Break(found);
                    }
                    // The visible grandparent must not be younger than the last
                    // visible child. Keep `child` and `child_start` unchanged.
                    next = visible;
                    via_hidden = true;
                    continue;
                }
            }
        };

        if parent.start > child_start {
            return ControlFlow::Continue(WalkEnd::PidReused);
        }
        if let ControlFlow::Break(found) = visit(AncestorStep::Visible {
            pid: next,
            start: parent.start,
        }) {
            return ControlFlow::Break(found);
        }
        if next == 1 {
            return ControlFlow::Continue(WalkEnd::Root);
        }
        child = next;
        child_start = parent.start;
        next = parent.ppid;
        via_hidden = false;
    }
}

/// Collects `pid`'s ancestors (starting from `ppid`, child born at `start`),
/// nearest first, up to `max_hops`, and whether the chain reached init/launchd
/// or a proven `hidepid` system boundary.
pub fn collect_ancestry(
    pid: u32,
    ppid: u32,
    start: Start,
    max_hops: usize,
    lookup: impl FnMut(u32) -> Option<(Ancestor, Facts)>,
    hidden: impl FnMut(u32, u32, Start) -> Option<Hidden>,
) -> (Vec<Ancestor>, bool) {
    struct Adapter<L, H> {
        lookup: RefCell<L>,
        hidden: RefCell<H>,
        last: RefCell<Option<(u32, Ancestor)>>,
    }

    impl<L, H> ProcessFacts for Adapter<L, H>
    where
        L: FnMut(u32) -> Option<(Ancestor, Facts)>,
        H: FnMut(u32, u32, Start) -> Option<Hidden>,
    {
        fn facts(&self, pid: u32) -> Option<Facts> {
            let (ancestor, facts) = (self.lookup.borrow_mut())(pid)?;
            *self.last.borrow_mut() = Some((pid, ancestor));
            Some(facts)
        }

        fn hidden(&self, parent: u32, child: u32, child_start: Start) -> Option<Hidden> {
            (self.hidden.borrow_mut())(parent, child, child_start)
        }
    }

    let adapter = Adapter {
        lookup: RefCell::new(lookup),
        hidden: RefCell::new(hidden),
        last: RefCell::new(None),
    };
    let mut ancestry = Vec::new();
    let end = walk_ancestors(&adapter, pid, ppid, start, max_hops, |step| {
        match step {
            AncestorStep::Visible { pid, .. } => {
                if let Some((cached_pid, entry)) = adapter.last.borrow_mut().take()
                    && cached_pid == pid
                {
                    ancestry.push(entry);
                }
            }
            AncestorStep::Hidden { pid } => {
                ancestry.push(Ancestor {
                    pid,
                    name: "(hidden)".into(),
                    path: None,
                });
            }
        }
        ControlFlow::<()>::Continue(())
    });
    (
        ancestry,
        matches!(
            end,
            ControlFlow::Continue(WalkEnd::Root | WalkEnd::SystemBoundary)
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Table {
        rows: HashMap<u32, Facts>,
        hidden: HashMap<(u32, u32, Start), Hidden>,
    }

    impl Table {
        fn new(rows: &[(u32, u32, Start)]) -> Self {
            Self {
                rows: rows
                    .iter()
                    .map(|&(pid, ppid, start)| (pid, Facts { ppid, start }))
                    .collect(),
                hidden: HashMap::new(),
            }
        }

        fn with_hidden(
            mut self,
            parent: u32,
            child: u32,
            child_start: Start,
            kind: Hidden,
        ) -> Self {
            self.hidden.insert((parent, child, child_start), kind);
            self
        }
    }

    impl ProcessFacts for Table {
        fn facts(&self, pid: u32) -> Option<Facts> {
            self.rows.get(&pid).copied()
        }

        fn hidden(&self, parent: u32, child: u32, child_start: Start) -> Option<Hidden> {
            self.hidden.get(&(parent, child, child_start)).copied()
        }
    }

    #[test]
    fn walks_to_root_and_checks_start_monotonicity() {
        let table = Table::new(&[
            (1, 0, (1, 0)),
            (2, 1, (2, 0)),
            (3, 2, (3, 0)),
            (4, 3, (4, 0)),
        ]);
        let mut visited = Vec::new();
        let end = walk_from(&table, 4, (4, 0), 64, |step| {
            visited.push(step);
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::Root));
        assert_eq!(
            visited,
            [
                AncestorStep::Visible {
                    pid: 4,
                    start: (4, 0)
                },
                AncestorStep::Visible {
                    pid: 3,
                    start: (3, 0)
                },
                AncestorStep::Visible {
                    pid: 2,
                    start: (2, 0)
                },
                AncestorStep::Visible {
                    pid: 1,
                    start: (1, 0)
                },
            ]
        );

        // Same second, later microsecond: parent is younger -> PidReused.
        let younger = Table::new(&[(1, 0, (1, 0)), (3, 1, (4, 1)), (4, 3, (4, 0))]);
        let end = walk_from(&younger, 4, (4, 0), 64, |_| ControlFlow::<()>::Continue(()));
        assert_eq!(end, ControlFlow::Continue(WalkEnd::PidReused));

        // Mismatched starting process.
        let end = walk_from(&table, 4, (99, 0), 64, |_| ControlFlow::<()>::Continue(()));
        assert_eq!(end, ControlFlow::Continue(WalkEnd::StartMismatch));
    }

    #[test]
    fn detects_cycles_and_hop_limits() {
        let cycle = Table::new(&[(10, 11, (1, 0)), (11, 10, (1, 0))]);
        let mut hops = 0;
        let end = walk_from(&cycle, 10, (1, 0), 4096, |_| {
            hops += 1;
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::Cycle));
        assert_eq!(hops, 2);

        let self_loop = Table::new(&[(10, 10, (1, 0))]);
        let end = walk_from(&self_loop, 10, (1, 0), 64, |_| {
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::Cycle));

        let rows: Vec<_> = (1..=20).map(|p| (p, p - 1, (u64::from(p), 0))).collect();
        let deep = Table::new(&rows);
        let end = walk_from(&deep, 20, (20, 0), 5, |_| ControlFlow::<()>::Continue(()));
        assert_eq!(end, ControlFlow::Continue(WalkEnd::HopLimit));
    }

    #[test]
    fn handles_hidepid_visible_parent_and_system_boundary() {
        let through = Table::new(&[(1, 0, (1, 0)), (20, 1, (20, 0)), (30, 25, (30, 0))])
            .with_hidden(25, 30, (30, 0), Hidden::VisibleParent(20));
        let mut visited = Vec::new();
        let end = walk_from(&through, 30, (30, 0), 64, |step| {
            visited.push(step);
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::Root));
        assert_eq!(
            visited,
            [
                AncestorStep::Visible {
                    pid: 30,
                    start: (30, 0)
                },
                AncestorStep::Hidden { pid: 25 },
                AncestorStep::Visible {
                    pid: 20,
                    start: (20, 0)
                },
                AncestorStep::Visible {
                    pid: 1,
                    start: (1, 0)
                },
            ]
        );

        // A visible grandparent younger than the last visible child is pid reuse.
        let younger_grand = Table::new(&[(1, 0, (1, 0)), (20, 1, (99, 0)), (30, 25, (30, 0))])
            .with_hidden(25, 30, (30, 0), Hidden::VisibleParent(20));
        let end = walk_from(&younger_grand, 30, (30, 0), 64, |_| {
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::PidReused));

        // A cycle through a hidden parent stops immediately.
        let hidden_cycle = Table::new(&[(30, 25, (30, 0))]).with_hidden(
            25,
            30,
            (30, 0),
            Hidden::VisibleParent(30),
        );
        let end = walk_from(&hidden_cycle, 30, (30, 0), 64, |_| {
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::Cycle));

        // System boundary ends cleanly.
        let boundary =
            Table::new(&[(30, 25, (30, 0))]).with_hidden(25, 30, (30, 0), Hidden::SystemBoundary);
        let end = walk_from(&boundary, 30, (30, 0), 64, |_| {
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::SystemBoundary));

        // Unproven missing parent is Unreadable.
        let missing = Table::new(&[(30, 25, (30, 0))]);
        let end = walk_from(&missing, 30, (30, 0), 64, |_| {
            ControlFlow::<()>::Continue(())
        });
        assert_eq!(end, ControlFlow::Continue(WalkEnd::Unreadable { pid: 25 }));
    }

    #[test]
    fn os_processes_walks_this_process_to_root() {
        let me = std::process::id();
        let facts = OsProcesses.facts(me).unwrap();
        assert_eq!(facts.ppid, std::os::unix::process::parent_id());
        let end = walk_from(&OsProcesses, me, facts.start, 1024, |_| {
            ControlFlow::<()>::Continue(())
        });
        assert!(
            matches!(
                end,
                ControlFlow::Continue(WalkEnd::Root | WalkEnd::SystemBoundary)
            ),
            "{end:?}"
        );
    }
}
