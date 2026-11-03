//! Activity, as the native daemon keeps it (`docs/agent-control.md`, "Lock,
//! limits, activity"): an entry for what a page had Deadbolt fill, save, make
//! or sign, and for what the vault page showed or copied, naming items and
//! fields, never values. Entries are sealed in the store's Activity table on
//! this device only, never in the signed log, for 90 days and within the
//! native budget; past it the oldest go, and the listing that reaches the
//! oldest kept says how many went.

use deadbolt_store::{Budget, Dropped, Unlocked};
use serde::{Deserialize, Serialize};

/// How long entries are kept, as native.
pub const KEEP_SECS: u64 = 90 * 24 * 60 * 60;
/// What the store keeps, at most, as native.
pub const BUDGET: Budget = Budget {
    rows: 100_000,
    bytes: 64 << 20,
};
/// The entries one listing returns unless asked for fewer or more: what the
/// native app's Settings shows.
pub const PAGE: usize = 50;
/// The most entries one listing returns, as native.
pub const MAX_PAGE: usize = 1_000;
/// The longest string an entry keeps, in bytes, cut marker included.
pub const MAX_TEXT: usize = 256;
const CUT: &str = "…(cut)";
/// The most items or fields an entry keeps.
pub const MAX_LIST: usize = 16;
/// The command of the entry that counts what went to stay in budget.
pub const PAST_BUDGET: &str = "more-past-budget";

/// Who asked: a page, through the inline menu or the popup's Fill
/// (`autofill`), or this browser's own vault page (`vault`).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Caller {
    Autofill,
    Vault,
    Deadbolt,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Allowed,
    Refused,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The item's reference (`vault:item`), when it's in the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub title: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Increasing; assigned when the entry is stored.
    #[serde(default)]
    pub id: u64,
    /// Unix seconds.
    pub time: u64,
    pub caller: Caller,
    /// The protocol command (`site-fill`), or `reveal`/`copy` for the vault
    /// page, as native names them.
    pub command: String,
    #[serde(default)]
    pub items: Vec<Item>,
    #[serde(default)]
    pub fields: Vec<String>,
    /// The page's origin, for what a page asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    pub outcome: Outcome,
    /// How many entries this one stands for that aren't listed: those that
    /// went to stay in budget (`more-past-budget`). 0 for an ordinary entry.
    #[serde(default)]
    pub more: u64,
}

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

/// Caps every string and list of `entry`.
pub fn bound(entry: &mut Entry) {
    cut(&mut entry.command);
    entry.items.truncate(MAX_LIST);
    for item in &mut entry.items {
        cut(&mut item.title);
        if let Some(id) = &mut item.id {
            cut(id);
        }
    }
    entry.fields.truncate(MAX_LIST);
    for field in &mut entry.fields {
        cut(field);
    }
    if let Some(site) = &mut entry.site {
        cut(site);
    }
}

/// Stores `entry` (bounded) at its time, dropping entries older than
/// [`KEEP_SECS`] before `now` and the oldest past `budget`.
pub fn record(
    store: &Unlocked,
    mut entry: Entry,
    now: u64,
    budget: Budget,
) -> deadbolt_store::Result<()> {
    bound(&mut entry);
    let bytes = serde_json::to_vec(&entry)
        .map_err(|_| deadbolt_store::Error::Corrupt("an activity entry didn't encode".into()))?;
    store.activity_append(
        [(entry.time, bytes.as_slice())],
        now.saturating_sub(KEEP_SECS),
        budget,
    )?;
    Ok(())
}

/// Entries with ids before `before`, newest first, at most `limit` (at most
/// [`MAX_PAGE`]); the page that reaches the oldest kept ends with one
/// `more-past-budget` entry when some went to stay in budget. Page back with
/// the last entry's id.
pub fn list(
    store: &Unlocked,
    before: Option<u64>,
    limit: usize,
) -> deadbolt_store::Result<Vec<Entry>> {
    let page = store.activity_list(0, before, limit.clamp(1, MAX_PAGE))?;
    let mut entries: Vec<Entry> = page
        .rows
        .into_iter()
        // A row is authenticated: one that doesn't read is from another
        // version's format, and isn't shown rather than failing the list.
        .filter_map(|row| {
            let mut entry: Entry = serde_json::from_slice(&row.bytes).ok()?;
            entry.id = row.id;
            Some(entry)
        })
        .collect();
    entries.extend(page.dropped.map(past_budget));
    Ok(entries)
}

fn past_budget(dropped: Dropped) -> Entry {
    Entry {
        id: dropped.last_id,
        time: dropped.last_time,
        caller: Caller::Deadbolt,
        command: PAST_BUDGET.into(),
        items: Vec::new(),
        fields: Vec::new(),
        site: None,
        outcome: Outcome::Allowed,
        more: dropped.count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadbolt_store::KdfParams;

    fn store() -> Unlocked {
        deadbolt_store::init_with_backend(
            redb::backends::InMemoryBackend::new(),
            b"test",
            [3; 32],
            KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
    }

    fn fill(time: u64, title: &str) -> Entry {
        Entry {
            id: 0,
            time,
            caller: Caller::Autofill,
            command: "site-fill".into(),
            items: vec![Item {
                id: Some("v:i".into()),
                title: title.into(),
            }],
            fields: vec!["username".into(), "password".into()],
            site: Some("https://github.com".into()),
            outcome: Outcome::Allowed,
            more: 0,
        }
    }

    fn titles(entries: &[Entry]) -> Vec<&str> {
        entries
            .iter()
            .map(|e| e.items.first().map_or(e.command.as_str(), |i| &i.title))
            .collect()
    }

    /// Entries list newest first, page back by id, and keep no value: only
    /// the names of the item, its fields and the page.
    #[test]
    fn entries_list_newest_first_and_page_back() {
        let store = store();
        assert!(list(&store, None, PAGE).unwrap().is_empty());
        for (time, title) in [(10, "a"), (20, "b"), (30, "c")] {
            record(&store, fill(time, title), time, BUDGET).unwrap();
        }
        let page = list(&store, None, 2).unwrap();
        assert_eq!(titles(&page), ["c", "b"]);
        assert_eq!(page[0].fields, ["username", "password"]);
        assert_eq!(page[0].site.as_deref(), Some("https://github.com"));
        let older = list(&store, Some(page[1].id), 2).unwrap();
        assert_eq!(titles(&older), ["a"]);
        // Asking for none still answers a row; asking for more is capped.
        assert_eq!(list(&store, None, 0).unwrap().len(), 1);
        assert_eq!(list(&store, None, usize::MAX).unwrap().len(), 3);
    }

    /// Entries older than 90 days go as new ones arrive.
    #[test]
    fn entries_past_ninety_days_go() {
        let store = store();
        let day = 24 * 60 * 60;
        record(&store, fill(day, "old"), day, BUDGET).unwrap();
        record(&store, fill(80 * day, "recent"), 80 * day, BUDGET).unwrap();
        assert_eq!(
            titles(&list(&store, None, PAGE).unwrap()),
            ["recent", "old"]
        );
        let now = 92 * day;
        record(&store, fill(now, "new"), now, BUDGET).unwrap();
        let kept = list(&store, None, PAGE).unwrap();
        assert_eq!(titles(&kept), ["new", "recent"]);
    }

    /// Past the budget the oldest entries go, and the listing that reaches
    /// the oldest kept says how many went.
    #[test]
    fn the_oldest_go_past_the_budget_and_are_counted() {
        let store = store();
        let three = Budget {
            rows: 3,
            bytes: 1 << 20,
        };
        for time in 1..=5 {
            record(&store, fill(time, &time.to_string()), time, three).unwrap();
        }
        let all = list(&store, None, PAGE).unwrap();
        assert_eq!(titles(&all), ["5", "4", "3", PAST_BUDGET]);
        let last = all.last().unwrap();
        assert_eq!(
            (last.more, last.time, last.caller),
            (2, 2, Caller::Deadbolt)
        );
        // Only the page reaching the oldest kept says so.
        assert_eq!(titles(&list(&store, None, 2).unwrap()), ["5", "4"]);
    }

    /// Whatever an item is called, an entry keeps at most `MAX_TEXT` bytes
    /// of each string and `MAX_LIST` of each list.
    #[test]
    fn entries_are_bounded() {
        let store = store();
        let long = "é".repeat(10_000);
        let mut entry = fill(1, &long);
        entry.fields = vec![long.clone(); 100];
        entry.items = vec![entry.items[0].clone(); 100];
        entry.site = Some(long);
        record(&store, entry, 1, BUDGET).unwrap();
        let kept = &list(&store, None, 1).unwrap()[0];
        assert_eq!((kept.items.len(), kept.fields.len()), (MAX_LIST, MAX_LIST));
        for text in [
            &kept.items[0].title,
            &kept.fields[0],
            kept.site.as_ref().unwrap(),
        ] {
            assert!(
                text.len() <= MAX_TEXT && text.ends_with(CUT),
                "{} bytes",
                text.len()
            );
        }
    }
}
