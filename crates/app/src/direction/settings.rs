//! Direction A's ⌘, Settings: a page in the item's place, as Seer's. Rows
//! are a label over a faint line with the control at the end, grouped with
//! room between groups; ↑↓ or J K move between rows, ←→, ↵ or Space change
//! one, Esc leaves. Under them, every shortcut.

use rune::{Color, El, col, el, icon, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Keybind, Kit, Switch};

use super::Look;
use super::document::PAGE_W;
use crate::model::App;

pub fn page(s: &App, k: &Kit, look: Look) -> El {
    let mut n = 0;
    let mut next = || {
        n += 1;
        n - 1
    };
    let on = |i: usize| look.row == Some(i);
    let touch = s.touch_id_available().then(|| {
        let i = next();
        setting(
            k,
            on(i),
            "Unlock with Touch ID",
            "Use your fingerprint instead of the passphrase on this Mac",
            toggle(k, s.touch_id_enabled()),
        )
    });
    let i = next();
    let clear = setting(
        k,
        on(i),
        "Clear copied secrets",
        "How long a copied password stays on the clipboard",
        stepper(k, &clear_after(s.clear_after), on(i)),
    );
    let i = next();
    let keys: Vec<String> = s.hotkey.shortcut.as_ref().map_or_else(
        || vec!["⇧".into(), "⌘".into(), "Space".into()],
        rune::Shortcut::keycaps,
    );
    let shortcut = setting(
        k,
        on(i),
        "Quick panel",
        "Search and copy from any app",
        row()
            .gap(10.0)
            .center_y()
            .children(on(i).then(|| super::hint(k, &["↵"], "Record")))
            .child(Keybind::new(&keys).build(k)),
    );
    let i = next();
    let synced = match &s.mirror.result {
        Some(Ok(done)) => done.clone(),
        Some(Err(_)) => "Last sync failed".into(),
        None => "Copies new and changed items from the 1Password app".into(),
    };
    let mirror = setting(
        k,
        on(i),
        "Sync from 1Password",
        &synced,
        button(
            k,
            if s.mirror.syncing {
                "Syncing…"
            } else {
                "Sync now"
            },
        ),
    );
    let i = next();
    let installed = s
        .installer
        .as_ref()
        .is_some_and(crate::install::Installer::installed);
    let command = setting(
        k,
        on(i),
        "deadbolt command",
        "Use your vault from Terminal and scripts",
        if installed {
            row()
                .gap(6.0)
                .center_y()
                .child(icon(k.glyph.check_small, 16.0).color(k.c.icon_muted))
                .child(
                    text("Installed")
                        .font(k.ty.text_small)
                        .color(k.c.text_muted),
                )
        } else {
            button(k, "Install…")
        },
    );
    let device = s
        .status
        .as_ref()
        .and_then(|st| st.device.as_ref())
        .and_then(|d| d.name.clone())
        .unwrap_or_default();
    let peers = s.status.as_ref().map_or(0, |st| st.peers);
    let i = next();
    let devices = setting(
        k,
        on(i),
        &format!("This Mac · {device}"),
        &match peers {
            0 => "No other devices yet".to_owned(),
            1 => "Shares Personal with 1 other device".to_owned(),
            n => format!("Shares Personal with {n} other devices"),
        },
        button(k, "Add a device…"),
    );
    let body = col()
        .key("settings-col")
        .w_full()
        .max_w(PAGE_W)
        .child(
            text("Settings")
                .font(super::document::TITLE)
                .color(k.c.text_strong)
                .pb(20.0),
        )
        .child(group(
            k,
            "Security",
            touch.into_iter().chain([clear]).collect(),
        ))
        .child(group(k, "Getting to it", vec![shortcut, command]))
        .child(group(k, "Devices", vec![devices, mirror]))
        .child(
            el().key("kb-rule")
                .w_full()
                .h(0.5)
                .mt(12.0)
                .fill(k.c.border_weak),
        )
        .child(keyboard(k));
    col()
        .key("settings")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .items_center()
        .px(40.0)
        .pb(32.0)
        .clip_rounded(0.0)
        .child(body)
}

fn group(k: &Kit, title: &str, rows: Vec<El>) -> El {
    col()
        .key(format!("group-{title}"))
        .w_full()
        .pb(24.0)
        .child(
            text(title.to_owned())
                .font(k.ty.small_medium)
                .color(k.c.text_faint)
                .pb(4.0),
        )
        .children(rows)
}

fn setting(k: &Kit, on: bool, label: &str, about: &str, control: El) -> El {
    row()
        .key(format!("set-{label}"))
        .w_full()
        .min_h(56.0)
        .ml(-14.0)
        .mr(-14.0)
        .px(14.0)
        .py(10.0)
        .gap(16.0)
        .radius(10.0)
        .continuous_corners()
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .child(
            col()
                .key("words")
                .gap(2.0)
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(
                    text(label.to_owned())
                        .font(k.ty.ui_medium)
                        .color(k.c.text_strong),
                )
                .child(
                    text(about.to_owned())
                        .font(super::FACT.lh(16.0))
                        .color(k.c.text_faint)
                        .wrap(),
                ),
        )
        .child(control)
}

fn toggle(k: &Kit, on: bool) -> El {
    Switch::new(on)
        .label("Unlock with Touch ID")
        .hide_label()
        .build(k)
        .key("switch")
}

fn button(k: &Kit, label: &str) -> El {
    Button::new(label)
        .variant(ButtonVariant::Neutral)
        .control_size(ControlSize::Regular)
        .build(k)
}

/// A value ←→ steps through, its arrows showing while the keys are on it.
fn stepper(k: &Kit, value: &str, on: bool) -> El {
    let arrow = |glyph: &str| {
        text(glyph.to_owned()).font(k.ty.small).color(if on {
            k.c.text_muted
        } else {
            Color::TRANSPARENT
        })
    };
    row()
        .key("stepper")
        .gap(10.0)
        .center_y()
        .child(arrow("←"))
        .child(
            text(value.to_owned())
                .font(k.ty.ui_medium.features("'tnum' 1"))
                .color(k.c.text_base),
        )
        .child(arrow("→"))
}

fn clear_after(secs: f64) -> String {
    match secs as u64 {
        0 => "Never".into(),
        s if s < 60 => format!("{s} s"),
        s => format!("{} min", s / 60),
    }
}

/// Every shortcut, two columns of keycaps and what they do.
fn keyboard(k: &Kit) -> El {
    const KEYS: &[(&[&str], &str)] = &[
        (&["⌘", "K"], "Search or act"),
        (&["↑", "↓"], "Move (or J K)"),
        (&["↵"], "Copy password"),
        (&["⇧", "↵"], "Copy username"),
        (&["⌥", "↵"], "Copy code"),
        (&["⇥"], "Into the fields"),
        (&["Space"], "Show a secret"),
        (&["⌘", "1–9"], "Jump to an item"),
        (&["⌘", "N"], "New item"),
        (&["⌘", "E"], "Edit"),
        (&["⌘", "⌫"], "Delete"),
        (&["⌘", "L"], "Lock"),
        (&["⌘", ","], "Settings"),
        (&["⇧", "⌘", "Space"], "Quick panel"),
        (&["⇧", "⌘", "I"], "Import"),
        (&["?"], "All shortcuts"),
    ];
    let half = KEYS.len().div_ceil(2);
    let column = |keys: &[(&[&str], &str)]| {
        keys.iter()
            .fold(col().gap(10.0).grow(1.0).w(0.0), |c, (caps, label)| {
                c.child(
                    row()
                        .w_full()
                        .center_y()
                        .child(
                            text((*label).to_owned())
                                .font(k.ty.text_small)
                                .color(k.c.text_muted)
                                .grow(1.0),
                        )
                        .child(Keybind::new(caps).build(k)),
                )
            })
    };
    col()
        .key("keyboard")
        .w_full()
        .pt(24.0)
        .gap(14.0)
        .child(
            text("Keyboard")
                .font(k.ty.small_medium)
                .color(k.c.text_faint),
        )
        .child(
            row()
                .w_full()
                .gap(40.0)
                .items_start()
                .child(column(&KEYS[..half]))
                .child(column(&KEYS[half..])),
        )
}
