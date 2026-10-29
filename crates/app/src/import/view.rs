//! Drawing the import: the drop zone, the preview and "Imported 12 from
//! 1Password".
//!
//! Motion: the pane's states (drop zone, preview, nothing new) swap with the
//! app's whole-state replacement. A drag over the window highlights the drop
//! zone at once, and labels that change in place roll. Nothing animates on
//! first paint; reduced motion keeps only the fades (Rune's runtime).

use rune::{El, col, icon, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, RollingText};

use super::{Phase, Preview, changed, details, import_label, new_items, nothing_new};
use crate::model::App;
use crate::view::theme::{IMPORT, SUBHEADING};
use crate::view::{replace, status_pill, tnum, vault_name};

/// Where each app's export is.
const SOURCES: &[(&str, &str)] = &[
    ("1Password 8", "File › Export › (account) › 1PUX"),
    ("Apple Passwords", "File › Export All Passwords…"),
    ("Bitwarden", "Tools › Export vault › .json"),
];

/// The detail pane of a vault with items, while importing.
pub fn pane(s: &App, k: &Kit) -> El {
    if let Some((preview, importing)) = s.import.preview() {
        return self::preview(s, k, preview, importing);
    }
    col()
        .key("import")
        .w_full()
        .gap(20.0)
        .transition(replace())
        .child(
            text("Import passwords")
                .key("title")
                .font(SUBHEADING)
                .color(k.c.text_strong),
        )
        .child(drop_zone(s, k))
        .children(error(s, k))
}

/// Why the last file wasn't previewed or imported, under the drop zone.
pub fn error(s: &App, k: &Kit) -> Option<El> {
    let notice = s.import.error.as_ref()?;
    Some(crate::view::banner(k, notice).key("import-error"))
}

/// Where each app's export is, and Choose File…. A file dragged over the
/// window lights it up.
pub fn drop_zone(s: &App, k: &Kit) -> El {
    let hover = s.drop_hovering();
    let title = match &s.import.phase {
        Phase::Reading { name, .. } => format!("Reading {name}…"),
        _ => "Drop an export here".to_owned(),
    };
    let mut sources = col().key("sources").w_full().gap(6.0);
    for (app, how) in SOURCES {
        sources = sources.child(
            row()
                .key(*app)
                .w_full()
                .gap(12.0)
                .child(
                    text(*app)
                        .key("app")
                        .w(124.0)
                        .font(k.ty.text_small)
                        .color(k.c.text_base),
                )
                .child(
                    text(*how)
                        .key("how")
                        .font(k.ty.text_small)
                        .color(k.c.text_muted)
                        .wrap()
                        .grow(1.0)
                        .shrink()
                        .min_w(0.0),
                ),
        );
    }
    let mut actions = row().key("actions").gap(8.0).center_y().child(
        Button::new("Choose File…")
            .variant(ButtonVariant::Neutral)
            .control_size(ControlSize::Regular)
            .disabled(s.import.busy())
            .on_press_tx(|s: &mut App, tx| s.choose_file(tx))
            .build(k)
            .key("choose"),
    );
    if s.import.open && !s.items.is_empty() {
        actions = actions.child(
            Button::new("Cancel")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Regular)
                .on_press(|s: &mut App| s.cancel_import())
                .build(k)
                .key("cancel"),
        );
    }
    col()
        .key("drop-zone")
        .w_full()
        .padding(16.0)
        .gap(14.0)
        .radius(k.radius.lg)
        .fill(if hover { k.c.layer_02 } else { k.c.layer_01 })
        .border(
            1.0,
            if hover {
                k.c.text_strong
            } else {
                k.c.border_base
            },
        )
        .child(
            row()
                .key("drop-head")
                .gap(10.0)
                .center_y()
                .child(icon(&IMPORT, 16.0).key("icon").color(if hover {
                    k.c.icon_base
                } else {
                    k.c.icon_muted
                }))
                .child(
                    RollingText::new("drop-title", title)
                        .font(k.ty.ui_medium)
                        .color(k.c.text_strong)
                        .build(k),
                ),
        )
        .child(sources)
        .child(actions)
}

/// What the export holds that's new, what's already here, and what can't
/// come across; Return imports, Escape cancels.
fn preview(s: &App, k: &Kit, p: &Preview, importing: bool) -> El {
    let report = &p.report;
    let n = p.new_items();
    let mut counts = col().key("counts").w_full().gap(4.0);
    if n > 0 {
        counts = counts.child(
            text(new_items(report))
                .key("new")
                .font(tnum(k.ty.body_medium))
                .color(k.c.text_strong),
        );
        if report.duplicates > 0 {
            counts = counts.child(
                text(format!("{} already in Deadbolt", report.duplicates))
                    .key("duplicates")
                    .font(tnum(k.ty.text_small))
                    .color(k.c.text_muted),
            );
        }
    } else {
        counts = counts.child(
            text(nothing_new(p, vault_name(s, "your vault")))
                .key("nothing-new")
                .font(k.ty.body_medium)
                .color(k.c.text_strong)
                .wrap()
                .w_full(),
        );
    }
    let lines = details(report);
    let quiet = (!lines.is_empty()).then(|| {
        let mut quiet = col().key("details").w_full().gap(2.0);
        for (i, line) in lines.into_iter().enumerate() {
            quiet = quiet.child(
                text(line)
                    .key(format!("detail-{i}"))
                    .font(tnum(k.ty.text_small))
                    .color(k.c.text_faint)
                    .wrap()
                    .w_full(),
            );
        }
        quiet
    });
    let mut buttons = row().key("buttons").gap(8.0).center_y();
    if n == 0 {
        buttons = buttons.child(
            Button::new("Done")
                .variant(ButtonVariant::Contrast)
                .control_size(ControlSize::Regular)
                .on_press(|s: &mut App| s.cancel_import())
                .build(k)
                .key("done")
                .default_button(),
        );
    } else {
        let label = if importing {
            "Importing…".to_owned()
        } else {
            import_label(n)
        };
        buttons = buttons
            .child(
                // Rolls to "Importing…", its width springing with the label.
                Button::new(label)
                    .rolling("import-label")
                    .variant(ButtonVariant::Contrast)
                    .control_size(ControlSize::Regular)
                    .disabled(importing)
                    .on_press(|s: &mut App| s.confirm_import())
                    .build(k)
                    .key("import")
                    .default_button(),
            )
            .child(
                Button::new("Cancel")
                    .variant(ButtonVariant::GhostMuted)
                    .control_size(ControlSize::Regular)
                    .disabled(importing)
                    .on_press(|s: &mut App| s.cancel_import())
                    .build(k)
                    .key("cancel"),
            );
    }
    col()
        .key(if n > 0 {
            "import-preview"
        } else {
            "import-nothing"
        })
        .w_full()
        .gap(20.0)
        .transition(replace())
        .child(
            col()
                .key("head")
                .w_full()
                .gap(4.0)
                .child(
                    text(format!("Import from {}", report.source))
                        .key("title")
                        .font(SUBHEADING)
                        .color(k.c.text_strong),
                )
                .child(
                    text(p.name.clone())
                        .key("file")
                        .font(k.ty.text_small)
                        .color(k.c.text_muted)
                        .truncate_fade(),
                ),
        )
        .children(
            p.changed
                .then(|| crate::view::banner(k, &changed(&p.name)).key("import-changed")),
        )
        .child(counts)
        .children(quiet)
        .child(buttons)
}

/// "Imported 12 from 1Password", in the copy notice's place and style.
pub fn imported(s: &App, k: &Kit) -> Option<El> {
    let (message, _) = s.import.imported.as_ref()?;
    let pill = row()
        .gap(8.0)
        .center_y()
        .child(
            icon(k.glyph.check_small, 16.0)
                .key("check")
                .color(k.c.icon_base),
        )
        .child(
            text(message.clone())
                .key("message")
                .font(k.ty.small)
                .color(k.c.text_base),
        );
    Some(status_pill(k, "imported", pill))
}
