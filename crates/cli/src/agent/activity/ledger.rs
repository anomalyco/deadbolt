//! What keeps Activity in budget: every string and list in an entry has a
//! cap, each anchor a rate past which its entries fold into one, and the
//! entries held while locked a count and a size past which they fold too.
//! A folded entry says how many it stands for (`more`), so nothing goes
//! silently.

use std::collections::HashMap;

use crate::protocol::{ActivityEntry, CallerInfo, Claim};

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
fn anchor(caller: &CallerInfo) -> String {
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
}

impl Ledger {
    /// Takes `entry` (bounded) against its anchor's window, returning what
    /// is due now: the entry, unless its anchor is past [`PER_ANCHOR`], and
    /// any window's fold that has ended.
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
        if window.count < PER_ANCHOR {
            window.count += 1;
            due.push(entry);
        } else {
            match &mut window.fold {
                Some(fold) => fold.add(&entry),
                None => window.fold = Some(Fold::new(entry)),
            }
        }
        due
    }

    /// The folds of windows ended by `now` (all of them if `all`), as
    /// entries, forgetting those windows.
    pub fn due(&mut self, now: u64, all: bool) -> Vec<ActivityEntry> {
        let ended: Vec<String> = self
            .windows
            .iter()
            .filter(|(_, w)| all || now >= w.start.saturating_add(WINDOW_SECS))
            .map(|(key, _)| key.clone())
            .collect();
        let mut due = Vec::new();
        for key in ended {
            if let Some(fold) = self.windows.remove(&key).and_then(|w| w.fold) {
                due.push(fold.entry(PAST_LIMIT));
            }
        }
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

    /// Past `PER_ANCHOR` in a window, an anchor's entries fold into one
    /// that says how many it stands for, due when the window ends.
    #[test]
    fn an_anchor_past_its_limit_folds_into_one_entry() {
        let mut ledger = Ledger::default();
        let mut due = Vec::new();
        for _ in 0..PER_ANCHOR + 25 {
            due.extend(ledger.admit(entry(100, "zsh › deadbolt")));
        }
        assert_eq!(due.len(), PER_ANCHOR as usize);
        // Another terminal has its own window.
        let mut other = entry(100, "zsh › deadbolt");
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
        assert_eq!(ledger.admit(entry(200, "zsh › deadbolt")).len(), 1);
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
