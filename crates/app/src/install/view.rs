//! Views for the command installer: the full-screen install page, the vault's
//! one-time offer, and Settings' entry.

use rune::{El, Transition, col, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit};

use super::{Copied, Existing, InstallError, Installer, quote, temporary};
use crate::model::App;
use crate::onboarding::view::{
    CHEVRON_LEFT, PANEL_W, bar, muted, offer_card, page as centred, title,
};
use crate::view::Paged;

fn installer(s: &mut App) -> Option<&mut Installer> {
    s.installer.as_mut()
}

/// A command to run, with a Copy button that confirms in place.
fn command(i: &Installer, k: &Kit, now: f64, which: Copied) -> El {
    let (key, line, label) = match which {
        Copied::Command => ("command", i.command(), "Copy command"),
        Copied::Path => ("path-command", i.path_command(), "Copy PATH command"),
    };
    let copied = i.copied(which, now);
    col()
        .key(key)
        .w_full()
        .gap(8.0)
        .items_start()
        .child(
            text(line)
                .key("line")
                .font(k.ty.mono)
                .color(k.c.text_base)
                .wrap()
                .w_full(),
        )
        .child(
            Button::new(if copied { "Copied" } else { label })
                .variant(ButtonVariant::Neutral)
                .control_size(ControlSize::Large)
                .icon(if copied {
                    k.glyph.check_small
                } else {
                    k.glyph.copy
                })
                .on_press_tx(move |s: &mut App, tx: &mut rune::Tx| {
                    let now = s.clock;
                    if let Some(i) = installer(s) {
                        i.copy(which, now, tx);
                    }
                })
                .build(k)
                .key(if copied { "copied" } else { "copy" })
                .transition(Transition::blur_replace()),
        )
}

fn action(k: &Kit, label: &str, busy: bool, press: fn(&mut Installer)) -> El {
    Button::new(label)
        .variant(ButtonVariant::Contrast)
        .control_size(ControlSize::Large)
        .disabled(busy)
        .on_press(move |s: &mut App| {
            if let Some(i) = installer(s) {
                press(i);
            }
        })
        .build(k)
        .key("action")
}

/// The install page, in place of the vault.
pub fn page(s: &App, k: &Kit) -> Paged {
    let Some(i) = &s.installer else {
        return col().into();
    };
    let mut body = col().w_full().gap(14.0).items_start();
    let key = match &i.scan {
        None => {
            body = body
                .child(title(k, "title", "Install the deadbolt command"))
                .child(muted(k, "about", "Checking for an existing command…"));
            "checking"
        }
        Some(_) if temporary(&i.source) => {
            body = body
                .child(title(k, "title", "Install the deadbolt command"))
                .child(muted(k, "about", InstallError::Temporary.to_string()));
            "temporary"
        }
        Some(scan) if scan.installed() => {
            body = body
                .child(title(k, "title", "Command installed"))
                .child(muted(
                    k,
                    "about",
                    format!("{} links to this app.", scan.destination.display()),
                ))
                .child(muted(
                    k,
                    "undo",
                    format!("To undo: rm {}", quote(&scan.destination)),
                ));
            "installed"
        }
        Some(scan) => match &scan.found {
            Some((path, Existing::Moved(target))) => {
                body = body
                    .child(title(k, "title", "Repair the deadbolt command"))
                    .child(muted(
                        k,
                        "about",
                        format!(
                            "{} links to a Deadbolt that moved or was deleted ({}).",
                            path.display(),
                            target.display()
                        ),
                    ));
                if scan.manual {
                    body = body
                        .child(muted(
                            k,
                            "manual",
                            "Administrator access is needed. Run this in your terminal:",
                        ))
                        .child(command(i, k, s.clock, Copied::Command));
                } else {
                    let label = if i.busy {
                        "Repairing…"
                    } else {
                        "Point it at this app"
                    };
                    body = body.child(action(k, label, i.busy, Installer::apply));
                }
                "moved"
            }
            Some((path, kind)) => {
                let name = match kind {
                    Existing::Homebrew => "a Homebrew install",
                    Existing::Cargo => "a Cargo install",
                    _ => "an existing command",
                };
                let label = if i.busy { "Checking…" } else { "Check again" };
                body = body
                    .child(title(k, "title", "Install the deadbolt command"))
                    .child(muted(
                        k,
                        "about",
                        format!(
                            "Found {name} at {}. Remove it with its installer to use this app's command.",
                            path.display()
                        ),
                    ))
                    .child(
                        Button::new(label)
                            .variant(ButtonVariant::Neutral)
                            .control_size(ControlSize::Large)
                            .disabled(i.busy)
                            .on_press(|s: &mut App| {
                                if let Some(i) = installer(s) {
                                    i.refresh();
                                }
                            })
                            .build(k)
                            .key("action"),
                    );
                "existing"
            }
            None => {
                body = body
                    .child(title(k, "title", "Install the deadbolt command"))
                    .child(muted(
                        k,
                        "about",
                        "Use Deadbolt from your terminal and coding agents.",
                    ));
                if scan.manual {
                    body = body
                        .child(muted(
                            k,
                            "manual",
                            "Administrator access is needed. Run this in your terminal:",
                        ))
                        .child(command(i, k, s.clock, Copied::Command));
                } else {
                    let label = if i.busy {
                        "Installing…"
                    } else {
                        "Install command"
                    };
                    body = body
                        .child(muted(
                            k,
                            "location",
                            format!("Links {}", scan.destination.display()),
                        ))
                        .child(action(k, label, i.busy, Installer::apply));
                }
                "install"
            }
        },
    };
    if let Some(scan) = &i.scan
        && !scan.on_path
        && matches!(key, "install" | "installed")
    {
        body = body
            .child(muted(
                k,
                "path",
                "If your terminal can't find deadbolt, add this to your shell profile:",
            ))
            .child(command(i, k, s.clock, Copied::Path));
    }
    let mut panel = col()
        .key("panel")
        .w(PANEL_W)
        .gap(14.0)
        .child(body.key(key).transition(Transition::blur_replace()));
    if let Some(error) = &i.error {
        panel = panel.child(
            text(error.clone())
                .key("install-error")
                .font(k.ty.text_small)
                .color(k.c.danger.fg)
                .wrap()
                .w_full()
                .transition(Transition::opacity()),
        );
    }
    let back = bar(k, "Back", &CHEVRON_LEFT, |s| {
        if let Some(i) = installer(s) {
            i.close();
        }
    });
    centred("install-command", Some(back), panel)
}

/// The vault's one-time offer, above the copy notice.
pub fn offer(s: &App, k: &Kit) -> Option<El> {
    let i = s.installer.as_ref().filter(|i| i.offering())?;
    let moved = matches!(
        i.scan.as_ref().and_then(|s| s.found.as_ref()),
        Some((_, Existing::Moved(_)))
    );
    let (head, about, label) = if moved {
        (
            "Your deadbolt command needs repair",
            "It links to a Deadbolt that moved or was deleted.",
            "Repair…",
        )
    } else {
        (
            "Use Deadbolt from your terminal",
            "Install the deadbolt command for your shell and coding agents.",
            "Install…",
        )
    };
    Some(offer_card(
        k,
        "command-offer",
        head,
        ("about", about),
        ("open", label, App::show_installer),
        |s| {
            if let Some(i) = installer(s) {
                i.dismiss();
            }
        },
    ))
}

/// Settings' way to the install page, when the app has a command to install.
pub fn setting(s: &App, k: &Kit) -> Option<El> {
    let i = s.installer.as_ref()?;
    let label = if i.installed() {
        "Details…"
    } else {
        "Install…"
    };
    Some(
        crate::settings::button(label)
            .on_press(|s: &mut App| {
                s.close_settings();
                s.show_installer();
            })
            .build(k)
            .key("install"),
    )
}
