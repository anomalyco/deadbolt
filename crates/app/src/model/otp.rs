//! The shown item's one-time code. The agent computes each one; the app
//! never holds the secret.

use std::time::Duration;

use deadbolt_client::protocol::Code;
use rune::Tx;
use zeroize::Zeroizing;

use crate::agent::{Failure, Job};

use super::App;

/// The one-time code's countdown bar, in points.
pub const CODE_BAR: [f32; 2] = [40.0, 3.0];
/// How long after a code's period ends the next is asked for, so the
/// agent's clock is past the boundary too.
pub const CODE_SLACK: f64 = 0.05;

/// The shown item's one-time code. The agent computes each one; the app
/// never holds the secret. Wiped when dropped.
pub struct Otp {
    pub item: String,
    /// The field it comes from (`code_field`).
    pub field: String,
    pub code: Option<Zeroizing<String>>,
    /// Why there's no code: an otp value saved before codes were checked.
    pub error: Option<String>,
    /// When the code stops being valid, on Rune's clock.
    pub until: f64,
    /// When it stops, in unix seconds: a new value is a new period.
    valid_until: u64,
    /// Counts periods, so each period's countdown bar is a new one.
    pub turns: u64,
    /// The countdown bar's rect, emptying linearly over the rest of the period.
    pub bar: rune::Tween<[f32; 4]>,
    /// A request for the next code is out.
    pub(super) fetching: bool,
    /// Copy the next code that lands: none was current when asked.
    pub(super) copy_next: bool,
    /// A wake is set for when the next is due.
    woken: bool,
}

impl Otp {
    pub(super) fn new(item: String, field: String) -> Otp {
        let [_, h] = CODE_BAR;
        Otp {
            item,
            field,
            code: None,
            error: None,
            until: 0.0,
            valid_until: 0,
            turns: 0,
            bar: rune::Tween::linear([0.0; 4], [0.0, 0.0, 0.0, h], Duration::ZERO),
            fetching: false,
            copy_next: false,
            woken: false,
        }
    }

    /// `code` came at `now`: it shows, and its bar empties over the rest of
    /// its period.
    pub(super) fn land(&mut self, code: &Code, now: f64) {
        let period = code.period.max(1) as f64;
        let remaining = (code.remaining_ms as f64 / 1000.0).clamp(0.0, period);
        if code.valid_until != self.valid_until {
            self.valid_until = code.valid_until;
            self.turns += 1;
        }
        self.code = Some(code.code.clone());
        self.error = None;
        self.until = now + remaining;
        self.woken = false;
        let [w, h] = CODE_BAR;
        self.bar = rune::Tween::linear(
            [0.0, 0.0, w * (remaining / period) as f32, h],
            [0.0, 0.0, 0.0, h],
            Duration::from_secs_f64(remaining),
        );
    }

    /// The code, while it's valid at `now`.
    pub fn current(&self, now: f64) -> Option<&Zeroizing<String>> {
        self.code.as_ref().filter(|_| now < self.until)
    }
}

impl App {
    /// A code (or why there is none) for the shown item. Its countdown runs
    /// on the render clock; the next is asked for once this one's period
    /// ends (`tick_code`).
    pub(crate) fn on_code(&mut self, result: Result<Code, Failure>, tx: &mut Tx) {
        let now = self.clock;
        let Some(otp) = &mut self.otp else { return };
        otp.fetching = false;
        let code = match result {
            Ok(code) => code,
            Err(failure) if failure.locked() => return self.on_locked(tx),
            Err(failure) => {
                otp.code = None;
                otp.error = Some(failure.message);
                if std::mem::take(&mut otp.copy_next) {
                    self.notice = otp.error.clone();
                }
                return;
            }
        };
        otp.land(&code, now);
        // The code that just came is the one asked for, however little of
        // its period is left.
        if std::mem::take(&mut otp.copy_next) {
            let field = otp.field.clone();
            self.put_on_clipboard(field, code.code.to_string(), tx);
        }
    }

    /// `CODE_SLACK` after a code's period ends, asks for the next, waking
    /// for that moment (set from the first poll after the code came, so a
    /// scene's code wakes too). The quick panel shows no code, so it asks
    /// only when one is copied.
    pub(super) fn tick_code(&mut self, now: f64, tx: &mut Tx) {
        if self.panel.is_some() {
            return;
        }
        let Some(otp) = &mut self.otp else { return };
        if otp.fetching || otp.code.is_none() {
            return;
        }
        let due = otp.until + CODE_SLACK;
        if now < due - 1e-3 {
            if !std::mem::replace(&mut otp.woken, true) {
                tx.wake_after(Duration::from_secs_f64(due - now));
            }
            return;
        }
        otp.fetching = true;
        self.agent.send(Job::Code {
            id: otp.item.clone(),
            seq: self.seq,
        });
    }

    /// The shown item's code, or `None` after asking the agent for the next
    /// one, which is copied as it lands.
    pub(super) fn code_for_copy(&mut self) -> Option<String> {
        let now = self.clock;
        let otp = self.otp.as_mut()?;
        if let Some(code) = otp.current(now) {
            return Some(code.to_string());
        }
        if let Some(error) = &otp.error {
            self.notice = Some(error.clone());
            return None;
        }
        otp.copy_next = true;
        if !otp.fetching {
            otp.fetching = true;
            self.agent.send(Job::Code {
                id: otp.item.clone(),
                seq: self.seq,
            });
        }
        None
    }
}

/// The selected item has a one-time code ⌥⏎ can copy.
pub fn has_code(s: &App) -> bool {
    let selected = s.selected_item().map(|i| i.id.as_str());
    s.otp
        .as_ref()
        .is_some_and(|o| o.error.is_none() && Some(o.item.as_str()) == selected)
}

/// Groups a code's digits for reading: 123 456, 123 4567, 1234 5678.
pub fn group_code(code: &str) -> String {
    let at = code.len() / 2;
    match (code.get(..at), code.get(at..)) {
        (Some(a), Some(b)) if code.len() >= 6 => format!("{a} {b}"),
        _ => code.to_owned(),
    }
}
