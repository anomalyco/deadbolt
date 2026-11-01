//! Recently Deleted: ⇧⌘⌫ or ⌘K open it over the vault, the keys move and
//! open an item read-only, and a restore brings it back to the vault.

use deadbolt_app::daemon::{Done, Job, Values};
use deadbolt_client::protocol::{FieldInfo, ItemInfo};
use rune::{Key, Mods};

use super::{Rig, cmd, failure, info, rig};

const NEWER: &str = "d41e070000000000000000000000000000000000000000000000000000000000";
const OLDER: &str = "6b0a930000000000000000000000000000000000000000000000000000000000";

fn shift_cmd() -> Mods {
    Mods {
        shift: true,
        ..cmd()
    }
}

fn deleted(id: &str, label: &str, at: u64) -> ItemInfo {
    ItemInfo {
        deleted_at: Some(at),
        ..info(id, "login", label)
    }
}

fn listing() -> Vec<ItemInfo> {
    vec![
        deleted(NEWER, "netflix.com", 2_000_000_000),
        deleted(OLDER, "Spare key", 1_000_000_000),
    ]
}

/// The `Trash` asks sent since the last look: their restores.
fn trash_asks(r: &Rig) -> Vec<(u64, Option<String>)> {
    r.sent()
        .into_iter()
        .filter_map(|j| match j {
            Job::Trash { seq, restore } => Some((seq, restore)),
            _ => None,
        })
        .collect()
}

/// ⇧⌘⌫, answered with `listing`.
fn open(r: &mut Rig) {
    r.press(Key::Backspace, shift_cmd());
    assert!(r.rt.state.trash.open, "⇧⌘⌫ opens Recently Deleted");
    let asks = trash_asks(r);
    assert_eq!(asks.len(), 1, "{asks:?}");
    let (seq, restore) = asks[0].clone();
    assert_eq!(restore, None, "opening restores nothing");
    r.reply(Done::Trash {
        seq,
        result: Ok((None, listing())),
    });
}

#[test]
fn recently_deleted_opens_from_its_shortcut_and_actions_and_esc_leaves() {
    let mut r = rig("vault");
    open(&mut r);
    assert!(r.shows("Recently Deleted"));
    assert!(r.shows("netflix.com") && r.shows("Spare key"));
    assert!(!r.rt.state.search.focused, "the page has the keys");

    r.tap(Key::Escape);
    assert!(!r.rt.state.trash.open, "esc leaves");
    assert!(r.rt.state.search.focused, "the keys go back to the search");

    r.command('k');
    r.press(Key::Backspace, shift_cmd());
    assert!(r.rt.state.trash.open, "⌘K's Recently deleted opens it too");
    assert!(r.rt.state.nav.palette.is_none());

    r.press(Key::Backspace, shift_cmd());
    assert!(!r.rt.state.trash.open, "⇧⌘⌫ again closes it");
}

#[test]
fn a_deleted_item_opens_read_only_and_restores_into_the_vault() {
    let mut r = rig("vault");
    open(&mut r);
    r.tap(Key::Text("j".into()));
    assert_eq!(r.rt.state.trash.row, 1, "J moves down");

    r.tap(Key::Enter);
    let (id, seq) = r
        .sent()
        .into_iter()
        .find_map(|j| match j {
            Job::TrashItem { id, seq } => Some((id, seq)),
            _ => None,
        })
        .expect("↵ asks for the item's values");
    assert_eq!(id, OLDER);
    let item = ItemInfo {
        fields: vec![
            FieldInfo {
                name: "username".into(),
                kind: "text".into(),
                value: "dax".into(),
            },
            FieldInfo {
                name: "password".into(),
                kind: "secret".into(),
                value: "hunter2-spare".into(),
            },
        ],
        ..deleted(OLDER, "Spare key", 1_000_000_000)
    };
    r.reply(Done::TrashItem {
        seq,
        result: Ok(Values::new(item)),
    });
    assert!(r.rt.state.trash.shown.is_some());
    assert!(r.shows("dax"), "its plain fields show");
    assert!(
        r.plaintext("hunter2-spare").is_empty(),
        "secrets stay masked"
    );

    r.tap(Key::Enter);
    let asks = trash_asks(&r);
    assert_eq!(asks.len(), 1, "{asks:?}");
    let (seq, restore) = asks[0].clone();
    assert_eq!(restore.as_deref(), Some(OLDER), "↵ on the item restores it");
    r.reply(Done::Trash {
        seq,
        result: Ok((
            Some(info(OLDER, "login", "Spare key")),
            vec![deleted(NEWER, "netflix.com", 2_000_000_000)],
        )),
    });
    assert!(r.rt.state.trash.shown.is_none(), "back to the list");
    assert!(r.rt.state.trash.open, "still in Recently Deleted");
    assert_eq!(r.rt.state.trash.items.len(), 1, "it leaves the list");
    assert!(r.shows("Restored Spare key. It's back in the vault on every device."));
    assert!(
        r.sent().iter().any(|j| matches!(j, Job::List { .. })),
        "the vault's list catches up"
    );
    assert_eq!(
        r.rt.state.trash.row, 0,
        "the keys stay on a row that's there"
    );
}

#[test]
fn command_r_restores_the_row_and_a_refusal_says_why() {
    let mut r = rig("vault");
    open(&mut r);
    r.command('r');
    let asks = trash_asks(&r);
    let (seq, restore) = asks[0].clone();
    assert_eq!(restore.as_deref(), Some(NEWER), "⌘R restores the newest");
    r.reply(Done::Trash {
        seq,
        result: Err(failure("no deleted item matches \"d41e\"")),
    });
    assert!(
        r.shows("Couldn't restore netflix.com: No deleted item matches \"d41e\"."),
        "{:?}",
        r.rt.state.trash.error
    );
    assert_eq!(r.rt.state.trash.items.len(), 2, "the list stays");
}

#[test]
fn locking_closes_recently_deleted_and_wipes_the_open_item() {
    let mut r = rig("vault");
    open(&mut r);
    r.tap(Key::Enter);
    let seq = r
        .sent()
        .into_iter()
        .find_map(|j| match j {
            Job::TrashItem { seq, .. } => Some(seq),
            _ => None,
        })
        .unwrap();
    r.reply(Done::TrashItem {
        seq,
        result: Ok(Values::new(deleted(NEWER, "netflix.com", 2_000_000_000))),
    });
    assert!(r.rt.state.trash.shown.is_some());
    r.command('l');
    r.reply(Done::Locked(Ok(())));
    assert!(!r.rt.state.trash.open);
    assert!(r.rt.state.trash.shown.is_none());
    assert!(r.rt.state.trash.items.is_empty());
}
