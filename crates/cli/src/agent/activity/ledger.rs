//! What keeps Activity in budget: every string and list in an entry has a
//! cap, each anchor and all anchors together a rate past which their entries
//! fold into one, and the entries held while locked a count and a size past
//! which they fold too. A folded entry says how many it stands for (`more`),
//! so nothing goes silently.
//!
//! Past a rate, requests that read, change or remove (the Read, Write and
//! Never tiers) never fold into one that drops what they named: the first
//! of each kind stays an entry of its own, and only exact repeats of it
//! (same caller, command, items, fields and outcome) fold, into an entry
//! that names them too.

use std::collections::HashMap;

use crate::protocol::{ActivityEntry, CallerInfo, Claim, Tier};

/// The longest string an entry keeps, in bytes, cut marker included.
pub const MAX_TEXT: usize = 256;
const CUT: &str = "…(cut)";
/// The most items, fields or parents an entry keeps.
pub const MAX_LIST: usize = 16;

/// Entries an anchor may add per window; past it they fold into one.
pub const PER_ANCHOR: u32 = 60;
pub const WINDOW_SECS: u64 = 60;
/// Anchors tracked at once; past it new ones share one window.
const MAX_ANCHORS: usize = 256;
/// Entries all anchors together may add per window; past it they fold, so a
/// caller that makes up a new anchor (a claimed session) for each request
/// can't push the rest of the table out of the store's budget.
pub const ALL_ANCHORS: u32 = 300;
/// Kinds of sensitive request whose repeats are folded at once; past it
/// each is an entry of its own.
const MAX_KINDS: usize = 256;

/// Entries held while locked, by count and by size; past either they fold.
pub const MAX_HELD: usize = 1_000;
pub const MAX_HELD_BYTES: usize = 1 << 20;

pub const PAST_LIMIT: &str = "more-past-limit";
pub const WHILE_LOCKED: &str = "more-while-locked";
pub const PAST_BUDGET: &str = "more-past-budget";

/// Cuts `text` to [`MAX_TEXT`] bytes, marking that it was cut.
pub fn cut(text: &mut String) {
    if text.len() <= MAX_TEXT {
        return;
    }
    let mut end = MAX_TEXT - CUT.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str(CUT);
}

fn cut_opt(text: &mut Option<String>) {
    if let Some(text) = text {
        cut(text);
    }
}

pub fn bound_claim(claim: &mut Claim) {
    cut_opt(&mut claim.caller);
    cut_opt(&mut claim.opencode_session);
}

/// Caps every string and list of `caller`, its claim included.
pub fn bound_caller(caller: &mut CallerInfo) {
    cut(&mut caller.label);
    cut_opt(&mut caller.program);
    cut_opt(&mut caller.tty);
    if let Some(signature) = &mut caller.signature {
        cut_opt(&mut signature.signing_id);
        cut_opt(&mut signature.team_id);
        cut_opt(&mut signature.cdhash);
    }
    caller.ancestry.truncate(MAX_LIST);
    for parent in &mut caller.ancestry {
        cut(&mut parent.name);
        cut_opt(&mut parent.path);
    }
    if let Some(claim) = &mut caller.claimed {
        bound_claim(claim);
    }
}

/// Caps every string and list of `entry`.
pub fn bound(entry: &mut ActivityEntry) {
    bound_caller(&mut entry.caller);
    cut(&mut entry.command);
    entry.items.truncate(MAX_LIST);
    for item in &mut entry.items {
        cut_opt(&mut item.vault);
        cut_opt(&mut item.id);
        cut(&mut item.title);
    }
    entry.fields.truncate(MAX_LIST);
    for field in &mut entry.fields {
        cut(field);
    }
    cut_opt(&mut entry.client);
}

/// What a grant would be tied to (`docs/agent-control.md`): the terminal
/// and its session's start, else who it looks like and the session it
/// claims. Only for limits: nothing here is trusted.
pub fn anchor(caller: &CallerInfo) -> String {
    match &caller.tty {
        Some(tty) => format!("tty {tty} {:?}", caller.session_started),
        None => {
            let claimed = caller.claimed.as_ref();
            let session = claimed.and_then(|c| c.opencode_session.as_deref());
            format!("{} {session:?}", caller.label)
        }
    }
}

/// Entries not listed one by one, the first standing for the rest.
struct Fold {
    first: ActivityEntry,
    count: u64,
    labels: Vec<String>,
}

impl Fold {
    fn new(first: ActivityEntry) -> Fold {
        Fold {
            labels: vec![first.caller.label.clone()],
            first,
            count: 1,
        }
    }

    fn add(&mut self, entry: &ActivityEntry) {
        self.count += 1;
        if self.labels.len() < 3 && !self.labels.contains(&entry.caller.label) {
            self.labels.push(entry.caller.label.clone());
        }
    }

    /// One entry for them all: "N more requests …, by A, B".
    fn entry(self, command: &str) -> ActivityEntry {
        let mut entry = self.first;
        entry.caller.label = self.labels.join(", ");
        cut(&mut entry.caller.label);
        entry.command = command.into();
        entry.items.clear();
        entry.fields.clear();
        entry.more = self.count;
        entry
    }

    /// One entry for repeats of one request, naming what it named: "N more
    /// item-get personal/GitHub password".
    fn repeats(self) -> ActivityEntry {
        let mut entry = self.first;
        entry.more = self.count;
        entry
    }
}

/// Whether requests of `tier` read, change or remove something, so their
/// entries always say what. Agent sign-ins hand values to a client.
fn sensitive(tier: Tier) -> bool {
    matches!(tier, Tier::Read | Tier::Write | Tier::Never | Tier::Agent)
}

/// What makes two entries repeats of one request: everything they name.
fn kind(entry: &ActivityEntry) -> String {
    serde_json::to_string(&(
        &entry.caller.label,
        &entry.command,
        entry.tier,
        entry.outcome,
        &entry.items,
        &entry.fields,
        &entry.client,
    ))
    .unwrap_or_default()
}

struct Window {
    start: u64,
    count: u32,
    fold: Option<Fold>,
}

/// Activity the agent holds in memory.
#[derive(Default)]
pub struct Ledger {
    /// Entries recorded while locked, stored on unlock.
    held: Vec<ActivityEntry>,
    held_bytes: usize,
    over: Option<Fold>,
    windows: HashMap<String, Window>,
    /// Every anchor's entries together.
    all: Option<Window>,
    /// Sensitive requests past a limit, by [`kind`]: each window's first is
    /// an entry of its own, and its repeats fold.
    kinds: HashMap<String, Window>,
}

impl Ledger {
    /// Takes `entry` (bounded) against its anchor's window and every
    /// anchor's, returning what is due now: the entry, unless it is past a
    /// limit (and, if sensitive, a repeat), and any fold whose window ended.
    pub fn admit(&mut self, mut entry: ActivityEntry) -> Vec<ActivityEntry> {
        bound(&mut entry);
        let now = entry.time;
        let mut due = self.due(now, false);
        let mut key = anchor(&entry.caller);
        if !self.windows.contains_key(&key) && self.windows.len() >= MAX_ANCHORS {
            key = String::new();
        }
        let window = self.windows.entry(key).or_insert(Window {
            start: now,
            count: 0,
            fold: None,
        });
        let all = self.all.get_or_insert(Window {
            start: now,
            count: 0,
            fold: None,
        });
        if window.count < PER_ANCHOR && all.count < ALL_ANCHORS {
            window.count += 1;
            all.count += 1;
            due.push(entry);
            return due;
        }
        if sensitive(entry.tier) {
            let kind = kind(&entry);
            match self.kinds.get_mut(&kind) {
                Some(Window {
                    fold: Some(fold), ..
                }) => fold.add(&entry),
                Some(repeat) => repeat.fold = Some(Fold::new(entry)),
                None => {
                    if self.kinds.len() < MAX_KINDS {
                        self.kinds.insert(
                            kind,
                            Window {
                                start: now,
                                count: 0,
                                fold: None,
                            },
                        );
                    }
                    due.push(entry);
                }
            }
            return due;
        }
        let over = if window.count >= PER_ANCHOR {
            window
        } else {
            all
        };
        match &mut over.fold {
            Some(fold) => fold.add(&entry),
            None => over.fold = Some(Fold::new(entry)),
        }
        due
    }

    /// The folds of windows ended by `now` (all of them if `all`), as
    /// entries, forgetting those windows.
    pub fn due(&mut self, now: u64, all: bool) -> Vec<ActivityEntry> {
        let ended = |w: &Window| all || now >= w.start.saturating_add(WINDOW_SECS);
        let mut due = Vec::new();
        self.windows.retain(|_, w| {
            if !ended(w) {
                return true;
            }
            due.extend(w.fold.take().map(|fold| fold.entry(PAST_LIMIT)));
            false
        });
        if let Some(window) = self.all.take_if(|w| ended(w)) {
            due.extend(window.fold.map(|fold| fold.entry(PAST_LIMIT)));
        }
        self.kinds.retain(|_, w| {
            if !ended(w) {
                return true;
            }
            due.extend(w.fold.take().map(Fold::repeats));
            false
        });
        due.sort_by_key(|e| e.time);
        due
    }

    /// Holds `entry` until an unlock, folding it in past the held limits.
    pub fn hold(&mut self, entry: ActivityEntry) {
        let size = serde_json::to_vec(&entry).map_or(MAX_HELD_BYTES, |b| b.len());
        let full = self.held.len() >= MAX_HELD || self.held_bytes + size > MAX_HELD_BYTES;
        match &mut self.over {
            Some(over) => over.add(&entry),
            None if full => self.over = Some(Fold::new(entry)),
            None => {
                self.held_bytes += size;
                self.held.push(entry);
            }
        }
    }

    /// Everything held, folds last, emptying it.
    pub fn take_held(&mut self) -> Vec<ActivityEntry> {
        self.held_bytes = 0;
        let mut held = std::mem::take(&mut self.held);
        held.extend(self.over.take().map(|over| over.entry(WHILE_LOCKED)));
        held
    }

    /// Puts back what [`Ledger::take_held`] gave, when it couldn't be stored.
    pub fn restore_held(&mut self, entries: Vec<ActivityEntry>) {
        for entry in entries {
            self.hold(entry);
        }
    }

    #[cfg(test)]
    pub fn held_len(&self) -> usize {
        self.held.len() + usize::from(self.over.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ActivityItem, Ancestor, Outcome, Tier};

    fn entry(time: u64, label: &str) -> ActivityEntry {
        let mut caller = CallerInfo::unverified(label);
        caller.tty = Some("/dev/ttys001".into());
        ActivityEntry {
            id: 0,
            time,
            caller,
            tier: Tier::Read,
            command: "item-get".into(),
            items: vec![ActivityItem {
                vault: None,
                id: None,
                title: "github".into(),
            }],
            fields: vec!["password".into()],
            outcome: Outcome::Allowed,
            more: 0,
            client: None,
        }
    }

    /// Whatever a caller claims or names, an entry keeps at most
    /// `MAX_TEXT` bytes of each string, marked as cut, and `MAX_LIST` of
    /// each list.
    #[test]
    fn entries_have_bounded_strings_and_lists() {
        let long = "é".repeat(10_000);
        let mut e = entry(1, &long);
        e.caller.claimed = Some(Claim {
            caller: Some(long.clone()),
            opencode_session: Some(long.clone()),
        });
        e.caller.program = Some(long.clone());
        e.caller.ancestry = (0..100)
            .map(|pid| Ancestor {
                pid,
                name: long.clone(),
                path: Some(long.clone()),
            })
            .collect();
        e.items = (0..100)
            .map(|_| ActivityItem {
                vault: Some(long.clone()),
                id: Some(long.clone()),
                title: long.clone(),
            })
            .collect();
        e.fields = vec![long.clone(); 100];
        bound(&mut e);

        let claim = e.caller.claimed.as_ref().unwrap();
        let mut texts = vec![
            &e.caller.label,
            claim.caller.as_ref().unwrap(),
            claim.opencode_session.as_ref().unwrap(),
            e.caller.program.as_ref().unwrap(),
            &e.items[0].title,
            e.items[0].vault.as_ref().unwrap(),
            &e.fields[0],
            &e.caller.ancestry[0].name,
        ];
        texts.push(e.caller.ancestry[0].path.as_ref().unwrap());
        for text in texts {
            assert!(text.len() <= MAX_TEXT, "{} bytes", text.len());
            assert!(text.ends_with(CUT));
        }
        assert_eq!(e.items.len(), MAX_LIST);
        assert_eq!(e.fields.len(), MAX_LIST);
        assert_eq!(e.caller.ancestry.len(), MAX_LIST);
        assert!(serde_json::to_vec(&e).unwrap().len() < 32 * 1024);

        let mut short = "github".to_string();
        cut(&mut short);
        assert_eq!(short, "github");
    }

    fn look(time: u64, label: &str) -> ActivityEntry {
        ActivityEntry {
            tier: Tier::Look,
            command: "item-list".into(),
            fields: Vec::new(),
            ..entry(time, label)
        }
    }

    /// Past `PER_ANCHOR` in a window, an anchor's entries fold into one
    /// that says how many it stands for, due when the window ends.
    #[test]
    fn an_anchor_past_its_limit_folds_into_one_entry() {
        let mut ledger = Ledger::default();
        let mut due = Vec::new();
        for _ in 0..PER_ANCHOR + 25 {
            due.extend(ledger.admit(look(100, "zsh › deadbolt")));
        }
        assert_eq!(due.len(), PER_ANCHOR as usize);
        // Another terminal has its own window.
        let mut other = look(100, "zsh › deadbolt");
        other.caller.tty = Some("/dev/ttys002".into());
        assert_eq!(ledger.admit(other).len(), 1);
        assert!(ledger.due(100 + WINDOW_SECS - 1, false).is_empty());

        let folded = ledger.due(100 + WINDOW_SECS, false);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].command, PAST_LIMIT);
        assert_eq!(folded[0].more, 25);
        assert_eq!(folded[0].caller.label, "zsh › deadbolt");
        assert!(folded[0].items.is_empty());
        // A new window starts afresh.
        assert_eq!(ledger.admit(look(200, "zsh › deadbolt")).len(), 1);
    }

    /// Past the limit, a read, a change or a removal keeps what it named:
    /// each kind's first is an entry of its own, at once, and only exact
    /// repeats fold, into an entry naming the same items and fields.
    #[test]
    fn agent_fills_past_the_limit_keep_their_login_and_client() {
        let mut ledger = Ledger::default();
        for _ in 0..PER_ANCHOR {
            assert_eq!(ledger.admit(look(100, "node")).len(), 1);
        }
        let fill = |client: &str| ActivityEntry {
            tier: Tier::Agent,
            command: "agent-fill".into(),
            items: vec![ActivityItem {
                vault: Some("v1".into()),
                id: Some("i1".into()),
                title: "GitHub (https://github.com)".into(),
            }],
            client: Some(client.into()),
            ..entry(101, "node")
        };
        let due = ledger.admit(fill("browse"));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].client.as_deref(), Some("browse"));
        assert_eq!(due[0].items[0].id.as_deref(), Some("i1"));
        assert!(ledger.admit(fill("browse")).is_empty());
        // Another client's fill of the same login is no repeat of it.
        assert_eq!(ledger.admit(fill("other")).len(), 1);
        let folded = ledger.due(101 + WINDOW_SECS, false);
        let repeat = folded.iter().find(|e| e.command == "agent-fill").unwrap();
        assert_eq!((repeat.more, repeat.client.as_deref()), (1, Some("browse")));
        assert_eq!(repeat.items[0].id.as_deref(), Some("i1"));
    }

    #[test]
    fn sensitive_entries_past_the_limit_keep_their_items() {
        let mut ledger = Ledger::default();
        for _ in 0..PER_ANCHOR {
            assert_eq!(ledger.admit(look(100, "zsh › deadbolt")).len(), 1);
        }
        let item = |id: &str, title: &str| ActivityItem {
            vault: Some("personal".into()),
            id: Some(id.into()),
            title: title.into(),
        };
        let get = |id: &str, title: &str| ActivityEntry {
            items: vec![item(id, title)],
            ..entry(101, "zsh › deadbolt")
        };
        let remove = ActivityEntry {
            tier: Tier::Never,
            command: "device-remove".into(),
            items: vec![item("d2", "laptop")],
            fields: Vec::new(),
            ..entry(102, "zsh › deadbolt")
        };
        let due = ledger.admit(get("i1", "GitHub"));
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].items[0].id.as_deref(), Some("i1"));
        assert_eq!(due[0].fields, ["password"]);
        for _ in 0..5 {
            assert!(ledger.admit(get("i1", "GitHub")).is_empty());
        }
        assert_eq!(ledger.admit(get("i2", "AWS")).len(), 1);
        assert_eq!(ledger.admit(remove.clone()).len(), 1);
        assert!(ledger.admit(remove).is_empty());

        let mut folded = ledger.due(102 + WINDOW_SECS, false);
        folded.sort_by_key(|e| e.command.clone());
        let named: Vec<_> = folded
            .iter()
            .map(|e| (e.command.as_str(), e.items[0].id.as_deref(), e.more))
            .collect();
        assert_eq!(
            named,
            [
                ("device-remove", Some("d2"), 1),
                ("item-get", Some("i1"), 5)
            ]
        );
        assert_eq!(folded[1].fields, ["password"]);
        assert!(folded.iter().all(|e| e.command != PAST_LIMIT));
    }

    /// A caller making up a new anchor for each request (a new claimed
    /// session) still fills only `ALL_ANCHORS` entries a window: the rest
    /// fold into one, so it can't push older entries out of the store.
    #[test]
    fn new_anchors_share_one_limit() {
        let mut ledger = Ledger::default();
        let mut due = Vec::new();
        for n in 0..ALL_ANCHORS + 1_000 {
            let mut entry = look(100, "OpenCode › zsh › deadbolt");
            entry.caller.tty = None;
            entry.caller.claimed = Some(Claim {
                caller: None,
                opencode_session: Some(format!("ses_{n}")),
            });
            due.extend(ledger.admit(entry));
        }
        assert_eq!(due.len(), ALL_ANCHORS as usize);
        let folded = ledger.due(100 + WINDOW_SECS, false);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].command, PAST_LIMIT);
        assert_eq!(folded[0].more, 1_000);
    }

    /// Held entries keep to a count and a size; past either, the rest fold
    /// into one entry naming who made them.
    #[test]
    fn held_entries_fold_past_their_limits() {
        let mut ledger = Ledger::default();
        for i in 0..MAX_HELD + 5 {
            ledger.hold(entry(i as u64, if i % 2 == 0 { "a" } else { "b" }));
        }
        let held = ledger.take_held();
        assert_eq!(held.len(), MAX_HELD + 1);
        let over = held.last().unwrap();
        assert_eq!(over.command, WHILE_LOCKED);
        assert_eq!(over.more, 5);
        assert_eq!(over.caller.label, "a, b");
        assert_eq!(ledger.held_len(), 0);

        let mut big = entry(1, "c");
        big.fields = vec!["f".repeat(MAX_TEXT); MAX_LIST];
        let size = serde_json::to_vec(&big).unwrap().len();
        for _ in 0..MAX_HELD {
            ledger.hold(big.clone());
        }
        let held = ledger.take_held();
        let kept = held.len() - 1;
        assert!(kept * size <= MAX_HELD_BYTES && (kept + 1) * size > MAX_HELD_BYTES);
        assert_eq!(held.last().unwrap().more, (MAX_HELD - kept) as u64);
    }
}
