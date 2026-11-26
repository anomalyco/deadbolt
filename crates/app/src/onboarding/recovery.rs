//! The 24-word recovery kit, held between the vault's creation and the person
//! saying they've saved it. The daemon keeps no copy, so this step is the only
//! place the words show: they are wiped as soon as it closes.

use std::time::Duration;

use rune::{El, SecretCopy, SecretState, Shadow, TextStyle, Transition, col, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit};

use super::view::{PANEL_W, muted, page, title};
use super::worker::RecoveryKit;
use super::{COPIED_FOR, Step};
use crate::model::App;
use crate::view::{Notice, Paged, Severity, banner, tnum};

/// How long the words stay on the clipboard: long enough to paste into a
/// password manager, and cleared sooner if the step closes.
const KIT_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// The words and the vault they recover, for the save step.
#[derive(Debug, PartialEq)]
pub struct Recovery {
    pub vault: String,
    /// The vault's id, shortened for reading out.
    pub id: String,
    kit: RecoveryKit,
}

impl Recovery {
    pub fn new(vault: String, id: String, kit: RecoveryKit) -> Recovery {
        Recovery { vault, id, kit }
    }

    /// The words in order, for the grid.
    pub fn words(&self) -> Vec<&str> {
        self.kit.words()
    }

    /// The words as one string, for the clipboard.
    pub fn text(&self) -> &str {
        self.kit.as_str()
    }
}

/// A copy of the words: Rune's handle, which clears the clipboard when it
/// lapses or the step closes, and the check that confirms the copy briefly.
#[derive(Debug)]
pub struct KitCopy {
    copy: SecretCopy,
    /// Stamped on the first frame after the click, so time spent idle before
    /// it never cuts the confirmation short.
    at: Option<f64>,
    /// The check has run its time; the clipboard handle stays for its clear.
    lapsed: bool,
}

impl KitCopy {
    fn new(copy: SecretCopy) -> KitCopy {
        KitCopy {
            copy,
            at: None,
            lapsed: false,
        }
    }

    /// Whether the button should say "Copied" this frame.
    pub fn showing(&self, now: f64) -> bool {
        !self.lapsed && self.at.is_none_or(|at| now - at < COPIED_FOR)
    }

    /// Stamps the first frame and ends the check COPIED_FOR later. True when
    /// the button's label changes.
    fn poll(&mut self, now: f64, tx: &mut rune::Tx) -> bool {
        if self.lapsed {
            return false;
        }
        match self.at {
            None => {
                self.at = Some(now);
                tx.wake_after(Duration::from_secs_f64(COPIED_FOR));
                false
            }
            Some(at) if now - at >= COPIED_FOR - 1e-3 => {
                self.lapsed = true;
                true
            }
            _ => false,
        }
    }
}

impl App {
    /// The moment is over and the vault has words waiting: show them, and
    /// leave the vault unopened until they're saved.
    pub(crate) fn begin_recovery(&mut self) {
        let o = &mut self.onboarding;
        match std::mem::replace(&mut o.step, Step::Welcome) {
            Step::Done {
                vault,
                id,
                kit: Some(kit),
                ..
            } => {
                o.done_at = None;
                o.phase = 0;
                o.copied_kit = None;
                o.step = Step::Recovery(Box::new(Recovery {
                    vault,
                    id: super::short(&id).to_owned(),
                    kit,
                }));
            }
            step => o.step = step,
        }
    }

    /// Copies all 24 words, as a secret: the clipboard clears at its end, or
    /// when the step closes.
    pub fn copy_recovery(&mut self, tx: &mut rune::Tx) {
        let Step::Recovery(recovery) = &self.onboarding.step else {
            return;
        };
        let words = recovery.text().to_owned();
        self.onboarding.notice = None;
        self.onboarding.copied_kit = Some(KitCopy::new(tx.copy_secret(words, KIT_LIFETIME)));
    }

    /// "I've saved these words": wipe the words now, then open the vault.
    pub fn save_recovery(&mut self, tx: &mut rune::Tx) {
        let o = &mut self.onboarding;
        if !matches!(o.step, Step::Recovery(_)) {
            return;
        }
        // Dropping the step drops the kit, and with it the only copy of the
        // words in this process.
        o.forget_recovery();
        tx.animated();
        self.open_vault(tx);
    }

    /// A failed copy says so, and a copy taken by something else ends the
    /// check. True when either changed.
    pub(crate) fn poll_recovery(&mut self, now: f64, tx: &mut rune::Tx) -> bool {
        let o = &mut self.onboarding;
        let Some(kit) = &mut o.copied_kit else {
            return false;
        };
        let mut changed = kit.poll(now, tx);
        let state = kit.copy.state();
        let over = matches!(
            state,
            SecretState::Failed(_) | SecretState::Replaced | SecretState::Cleared
        );
        if let SecretState::Failed(error) = state {
            o.notice = Some(Notice::new(Severity::Danger, "Couldn’t copy", error));
        }
        changed |= over;
        if over {
            o.copied_kit = None;
        }
        changed
    }
}

impl super::Onboarding {
    /// Takes the copied words off the clipboard if they're still there.
    pub(super) fn forget_recovery_copy(&mut self) {
        if let Some(copied) = self.copied_kit.take() {
            copied.copy.clear_now();
        }
    }

    /// Drops a save step, a moment still holding the words, and their copy:
    /// the screen is leaving, locking, or closing, and the words must not
    /// outlive it.
    pub(super) fn forget_recovery(&mut self) {
        self.forget_recovery_copy();
        if matches!(
            self.step,
            Step::Recovery(_) | Step::Done { kit: Some(_), .. }
        ) {
            self.step = Step::Welcome;
        }
    }
}

/// The save step: what the words are for, the numbered grid, the vault's id,
/// and two actions.
pub(super) fn recovery(s: &App, k: &Kit, r: &Recovery) -> Paged {
    let copied = s
        .onboarding
        .copied_kit
        .as_ref()
        .is_some_and(|c| c.showing(s.clock));
    let about = "These 24 words are the only way to recover your vault if you \
                 lose every device. Deadbolt won’t show them again.";
    let mut panel = col()
        .key("panel")
        .w(PANEL_W)
        .gap(24.0)
        .items_start()
        .child(
            col()
                .key("head")
                .w_full()
                .gap(6.0)
                .child(
                    title(k, "title-Save your recovery kit", "Save your recovery kit")
                        .transition(Transition::blur_replace()),
                )
                .child(muted(k, "about-recovery", about).transition(Transition::blur_replace())),
        )
        .child(
            col()
                .key("save")
                .w_full()
                .gap(16.0)
                .items_start()
                .child(grid(k, &r.words()))
                .child(
                    row()
                        .key("vault-id")
                        .w_full()
                        .gap(8.0)
                        .center_y()
                        .child(text("Vault").font(k.ty.text_xsmall).color(k.c.text_faint))
                        .child(
                            text(r.vault.clone())
                                .font(k.ty.text_small)
                                .color(k.c.text_muted),
                        )
                        .child(text("·").font(k.ty.text_xsmall).color(k.c.text_faint))
                        .child(
                            text(r.id.clone())
                                .key("id")
                                .font(tnum(k.ty.mono.lh(16.0)))
                                .color(k.c.text_muted),
                        ),
                ),
        );
    if let Some(n) = &s.onboarding.notice {
        panel = panel.child(banner(k, n));
    }
    panel = panel.child(
        row()
            .key("actions")
            .w_full()
            .gap(8.0)
            .child(
                Button::new(if copied {
                    "Copied"
                } else {
                    "Copy recovery words"
                })
                .variant(ButtonVariant::Neutral)
                .control_size(ControlSize::Large)
                .icon(if copied {
                    k.glyph.check_small
                } else {
                    k.glyph.copy
                })
                .on_press_tx(|s: &mut App, tx| s.copy_recovery(tx))
                .build(k)
                .key("copy-recovery")
                // Equal halves: "Copied" never shifts its neighbour.
                .grow(1.0)
                .transition(Transition::blur_replace()),
            )
            .child(
                Button::new("I’ve saved these words")
                    .variant(ButtonVariant::Contrast)
                    .control_size(ControlSize::Large)
                    .on_press_tx(|s: &mut App, tx| s.save_recovery(tx))
                    .build(k)
                    .key("save-recovery")
                    .grow(1.0),
            ),
    );
    page("recovery", None, panel)
}

/// The words, four columns by six rows, numbered 1 to 24.
fn grid(k: &Kit, words: &[&str]) -> El {
    let mut rows = col().key("grid").w_full().gap(7.0);
    for (line, chunk) in words.chunks(4).enumerate() {
        let mut cells = row().key(format!("row-{line}")).w_full().gap(10.0);
        for (i, word) in chunk.iter().enumerate() {
            let n = line * 4 + i + 1;
            cells = cells.child(
                row()
                    .key(format!("cell-{n}"))
                    .w(84.0)
                    .gap(6.0)
                    .center_y()
                    .child(
                        text(format!("{n:>2}"))
                            .key(format!("number-{n}"))
                            .font(tnum(NUMBER))
                            .color(k.c.text_faint),
                    )
                    .child(
                        text((*word).to_owned())
                            .key(format!("word-{n}"))
                            .font(tnum(WORD))
                            .color(k.c.text_strong),
                    ),
            );
        }
        rows = rows.child(cells);
    }
    col()
        .key("kit")
        .w_full()
        .padding(14.0)
        .radius(k.radius.md)
        .fill(k.c.layer_01)
        .box_shadow(Shadow {
            spread: 0.5,
            color: k.c.border_base,
            ..Shadow::default()
        })
        .child(rows)
}

/// The words and their numbers, monospaced so a written copy reads back
/// exactly: 0 and O, l and 1, never a guess.
const WORD: TextStyle = TextStyle::new(12.5, 450.0).mono().lh(19.0);
const NUMBER: TextStyle = TextStyle::new(10.5, 500.0).mono().lh(19.0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grid_is_four_columns_of_six_numbered_rows() {
        let words: Vec<String> = (1..=24).map(|i| format!("w{i}")).collect();
        let kit = RecoveryKit::new(words.join(" "));
        let recovery = Recovery::new("personal".into(), "abcd1234".into(), kit);
        assert_eq!(recovery.words().len(), 24);
        assert_eq!(recovery.text().split(' ').count(), 24);
    }
}
