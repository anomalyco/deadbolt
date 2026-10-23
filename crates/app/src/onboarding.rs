//! First run: create a vault on this device, or join one from another device.
//! The state and what each input and reply does to it; `onboarding/view.rs`
//! draws it and `onboarding/worker.rs` talks to the agent.
//!
//! A device can be set up (it has a key and a passphrase) and still hold no
//! vault, after a cancelled join for example. Onboarding then skips the
//! passphrase and asks only for what's left.

pub mod qr;
pub mod view;
pub mod worker;

use std::time::Duration;

use deadbolt_client::protocol::VaultInfo;
use rune::{Key, KeyEvent, TextEdit, Tx};
use zeroize::Zeroizing;

use crate::agent::{Failure, Job};
use crate::clipboard::Copied;
use crate::model::{App, Screen};
use worker::{NewDevice, Progress, Stage, Worker};

/// Shortest passphrase the form accepts.
pub const MIN_PASSPHRASE: usize = 8;
/// How long a copied command's button shows a check, in seconds.
pub const COPIED_FOR: f64 = 1.6;

/// The moment a vault is created or joined, from the bolt throwing to the vault
/// opening. See `view::bolt` for what happens when.
pub mod moment {
    /// The bolt reaches the strike.
    pub const CONTACT: f64 = 0.11;
    /// The strike starts to cool.
    pub const COOL: f64 = 0.2;
    /// It has cooled to red and fades to rest.
    pub const EMBER: f64 = 0.5;
    /// The vault opens.
    pub const OPEN: f64 = 1.5;
    pub const PHASES: [f64; 4] = [CONTACT, COOL, EMBER, OPEN];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Create,
    Join,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    Welcome,
    /// The create form.
    Create,
    /// The join form.
    Join,
    /// A request is running; `Onboarding::plan` lists its stages.
    Working(Flow),
    /// The ticket is up, waiting for the other device.
    Ticket,
    /// Comparing the confirmation code.
    Confirm {
        code: String,
        vault: String,
        inviter: String,
    },
    /// Created or joined: the moment, then the vault.
    Done {
        flow: Flow,
        vault: String,
        from: Option<String>,
    },
}

/// How serious a notice is, which sets its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Nothing went wrong: the person changed their mind, a ticket ran out.
    Neutral,
    /// Stopped for safety: the codes didn't match.
    Caution,
    /// Something failed.
    Danger,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Notice {
    pub severity: Severity,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    TooShort,
    Weak,
    Fair,
    Strong,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pairing {
    pub vault: String,
    pub inviter: String,
}

/// The pairing ticket: until it's used or expires, anyone holding it can ask
/// to join the vault, so it's wiped when dropped.
pub struct Ticket {
    pub text: Zeroizing<String>,
    pub qr: Option<qr::Matrix>,
}

pub struct Onboarding {
    pub step: Step,
    /// The stages the running request will report, in order.
    pub plan: Vec<Stage>,
    /// The stage the worker last reported, if it's in the plan.
    pub stage: Option<Stage>,
    pub device: TextEdit,
    pub vault: TextEdit,
    pub passphrase: TextEdit,
    pub repeat: TextEdit,
    /// This device already has a key and passphrase.
    pub device_ready: bool,
    /// Submit was pressed with something missing: every problem shows.
    pub attempted: bool,
    pub notice: Option<Notice>,
    pub ticket: Option<Ticket>,
    pub copied: Option<Copied>,
    /// A command copied from the empty vault's guide, and when.
    pub copied_command: Option<(&'static str, f64)>,
    /// The vault being joined and the device inviting this one, once the code shows.
    pub pairing: Option<Pairing>,
    /// When the vault was created or joined, on the app's clock.
    pub done_at: Option<f64>,
    /// How many of `moment::PHASES` have passed.
    pub phase: usize,
    pub worker: Worker,
    /// The person answered "they don't match".
    declined: bool,
    /// The person cancelled the join.
    cancelled: bool,
    /// The running request set this device up (it wasn't before).
    set_up_now: bool,
}

impl Onboarding {
    pub fn new(worker: Worker) -> Onboarding {
        Onboarding {
            step: Step::Welcome,
            plan: Vec::new(),
            stage: None,
            device: TextEdit::new(""),
            vault: TextEdit::new("personal"),
            passphrase: TextEdit::new("").secure(),
            repeat: TextEdit::new("").secure(),
            device_ready: false,
            attempted: false,
            notice: None,
            ticket: None,
            copied: None,
            copied_command: None,
            pairing: None,
            done_at: None,
            phase: 0,
            worker,
            declined: false,
            cancelled: false,
            set_up_now: false,
        }
    }

    /// Back to the welcome screen with empty fields; keeps the worker. Only
    /// through [`App::reset_onboarding`], which clears a copied ticket first.
    fn reset(&mut self, device_ready: bool) {
        let worker = std::mem::replace(&mut self.worker, Worker::offline());
        self.passphrase.clear();
        self.repeat.clear();
        *self = Onboarding {
            device_ready,
            ..Onboarding::new(worker)
        };
    }

    /// A cancelled join waits for a device setup already under way.
    pub fn stopping(&self) -> bool {
        self.cancelled && matches!(self.step, Step::Working(Flow::Join))
    }

    /// A request is running or its result is showing: status changes from
    /// elsewhere must not move the screen.
    pub fn busy(&self) -> bool {
        matches!(
            self.step,
            Step::Working(_) | Step::Ticket | Step::Confirm { .. } | Step::Done { .. }
        )
    }

    pub fn strength(&self) -> Strength {
        strength(&self.passphrase.text)
    }

    pub fn device_name(&self) -> &str {
        self.device.text.trim()
    }

    /// What's wrong with the device name, if anything.
    pub fn device_problem(&self) -> Option<&'static str> {
        self.device_name()
            .is_empty()
            .then_some("Name this device so your other devices can tell it apart.")
    }

    /// What's wrong with the vault name, if anything (the agent's rule).
    pub fn vault_problem(&self) -> Option<&'static str> {
        let name = self.vault.text.trim();
        if name.is_empty() {
            return Some("Name the vault.");
        }
        let bytes = name.as_bytes();
        let valid = bytes.len() <= 64
            && bytes[0].is_ascii_lowercase()
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        (!valid).then_some("Use a-z, 0-9, - and _, starting with a letter.")
    }

    pub fn passphrase_problem(&self) -> Option<&'static str> {
        (self.strength() == Strength::TooShort).then_some("At least 8 characters.")
    }

    /// `Some(true)` when the repeat matches, `Some(false)` when it can't
    /// (or, after submit, doesn't yet), `None` while it's still a prefix.
    pub fn repeat_matches(&self) -> Option<bool> {
        let (first, second) = (self.passphrase.text.as_str(), self.repeat.text.as_str());
        if second.is_empty() && !self.attempted {
            None
        } else if first == second {
            Some(true)
        } else if first.starts_with(second) && !self.attempted {
            None
        } else {
            Some(false)
        }
    }

    /// The new device's details, unless this device is set up already.
    fn needs_device(&self) -> bool {
        !self.device_ready
    }

    fn device_valid(&self) -> bool {
        !self.needs_device()
            || (self.device_problem().is_none()
                && self.passphrase_problem().is_none()
                && self.repeat_matches() == Some(true)
                && !self.passphrase.text.is_empty())
    }

    pub fn can_create(&self) -> bool {
        self.vault_problem().is_none() && self.device_valid()
    }

    pub fn can_join(&self) -> bool {
        self.device_valid()
    }

    fn new_device(&mut self) -> Option<NewDevice> {
        self.needs_device().then(|| NewDevice {
            name: self.device_name().to_owned(),
            passphrase: crate::model::take_secret(&mut self.passphrase),
        })
    }

    /// Focuses the first field with a problem, else the first field.
    fn focus_first(&mut self, flow: Flow) {
        self.blur();
        let device = self.needs_device();
        if flow == Flow::Create && device && self.device_problem().is_some() {
            self.device.focused = true;
        } else if flow == Flow::Create && self.vault_problem().is_some() {
            self.vault.focused = true;
        } else if device && self.device_problem().is_some() {
            self.device.focused = true;
        } else if device && (self.passphrase_problem().is_some() || self.passphrase.text.is_empty())
        {
            self.passphrase.focused = true;
        } else if device && self.repeat_matches() != Some(true) {
            self.repeat.focused = true;
        } else if flow == Flow::Create {
            self.vault.focused = true;
        }
    }

    fn blur(&mut self) {
        self.device.focused = false;
        self.vault.focused = false;
        self.passphrase.focused = false;
        self.repeat.focused = false;
    }

    /// Wipes both passphrase fields.
    pub fn forget(&mut self) {
        self.passphrase.clear();
        self.repeat.clear();
    }
}

/// A rough strength: the bits a brute-force guesser would face for a
/// password drawn at random from the characters used, discounted for
/// repetition. It flatters dictionary words, so it only ever asks for more.
pub fn strength(passphrase: &str) -> Strength {
    let len = passphrase.chars().count();
    if len < MIN_PASSPHRASE {
        return Strength::TooShort;
    }
    let has = |f: fn(&char) -> bool| passphrase.chars().any(|c| f(&c));
    let pool = [
        (has(char::is_ascii_lowercase), 26.0),
        (has(char::is_ascii_uppercase), 26.0),
        (has(char::is_ascii_digit), 10.0),
        (has(|c| c.is_ascii_punctuation()), 32.0),
        (has(|c| *c == ' '), 1.0),
        (has(|c| !c.is_ascii()), 100.0),
    ]
    .iter()
    .filter(|(present, _)| *present)
    .map(|(_, n)| n)
    .sum::<f64>();
    let mut distinct: Vec<char> = passphrase.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    let variety = (distinct.len() as f64 * 2.0 / len as f64).min(1.0);
    let bits = len as f64 * pool.max(2.0).log2() * variety;
    match bits {
        b if b < 50.0 => Strength::Weak,
        b if b < 75.0 => Strength::Fair,
        _ => Strength::Strong,
    }
}

/// What this computer calls itself: the name people gave it on macOS
/// ("Kit's Mac Studio"), else the host name without `.local`.
pub fn default_device_name() -> String {
    #[cfg(target_os = "macos")]
    if let Ok(out) = std::process::Command::new("/usr/sbin/scutil")
        .args(["--get", "ComputerName"])
        .output()
        && out.status.success()
    {
        let name = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !name.is_empty() {
            return name;
        }
    }
    let uname = rustix::system::uname();
    let host = uname.nodename().to_string_lossy();
    let host = host.trim();
    let host = host.strip_suffix(".local").unwrap_or(host);
    if host.is_empty() {
        "device".into()
    } else {
        host.into()
    }
}

impl App {
    /// Shows the welcome screen. Leaves a running request alone.
    pub(crate) fn begin_onboarding(&mut self, device_ready: bool) {
        self.show(Screen::Onboarding);
        if self.onboarding.busy() {
            self.onboarding.device_ready |= device_ready;
            return;
        }
        self.reset_onboarding(device_ready);
    }

    /// Onboarding from scratch, leaving nothing of the last attempt behind.
    fn reset_onboarding(&mut self, device_ready: bool) {
        self.forget_onboarding();
        self.onboarding.reset(device_ready);
    }

    /// Leaving onboarding (or the app): takes a copied ticket off the clipboard
    /// if it's still there, wipes the ticket and passphrases, and hangs up a join.
    pub(crate) fn forget_onboarding(&mut self) {
        self.forget_ticket();
        self.onboarding.worker.cancel();
        self.onboarding.forget();
    }

    pub fn choose(&mut self, flow: Flow) {
        let o = &mut self.onboarding;
        o.notice = None;
        o.attempted = false;
        if o.device.text.is_empty() && o.needs_device() {
            o.device = TextEdit::new(default_device_name());
        }
        o.step = match flow {
            Flow::Create => Step::Create,
            Flow::Join => Step::Join,
        };
        o.blur();
        if o.needs_device() {
            o.passphrase.focused = true;
        } else if flow == Flow::Create {
            o.vault.focused = true;
        }
    }

    pub fn onboarding_back(&mut self) {
        let o = &mut self.onboarding;
        if o.busy() {
            return;
        }
        o.forget();
        o.attempted = false;
        o.notice = None;
        o.blur();
        o.step = Step::Welcome;
    }

    pub fn submit_create(&mut self) {
        let o = &mut self.onboarding;
        if o.step != Step::Create {
            return;
        }
        if !o.can_create() {
            o.attempted = true;
            o.focus_first(Flow::Create);
            return;
        }
        o.notice = None;
        o.blur();
        o.set_up_now = false;
        o.plan = if o.needs_device() {
            vec![Stage::Protecting, Stage::CreatingVault]
        } else {
            vec![Stage::CreatingVault]
        };
        // Until the worker reports a stage the first shows as active.
        o.stage = None;
        o.step = Step::Working(Flow::Create);
        let device = o.new_device();
        o.repeat.clear();
        let vault = o.vault.text.trim().to_owned();
        o.worker.create(device, vault);
    }

    pub fn submit_join(&mut self) {
        let o = &mut self.onboarding;
        if o.step != Step::Join {
            return;
        }
        if !o.can_join() {
            o.attempted = true;
            o.focus_first(Flow::Join);
            return;
        }
        o.notice = None;
        o.blur();
        o.declined = false;
        o.cancelled = false;
        o.set_up_now = false;
        o.plan = if o.needs_device() {
            vec![Stage::Protecting, Stage::MakingTicket]
        } else {
            vec![Stage::MakingTicket]
        };
        // Until the worker reports a stage the first shows as active.
        o.stage = None;
        o.step = Step::Working(Flow::Join);
        let device = o.new_device();
        o.repeat.clear();
        o.worker.join(device);
    }

    /// The person compared the codes.
    pub fn answer_code(&mut self, matches: bool) {
        let o = &mut self.onboarding;
        if !matches!(o.step, Step::Confirm { .. }) || o.declined || o.cancelled {
            return;
        }
        if matches {
            o.plan = vec![Stage::Joining];
            o.stage = Some(Stage::Joining);
            o.step = Step::Working(Flow::Join);
        } else {
            o.declined = true;
        }
        o.worker.answer(matches);
    }

    /// Hangs up the join; the device stays set up.
    pub fn cancel_join(&mut self) {
        let o = &mut self.onboarding;
        let joining = matches!(o.step, Step::Working(Flow::Join)) && o.pairing.is_none();
        if o.cancelled || !(joining || matches!(o.step, Step::Ticket | Step::Confirm { .. })) {
            return;
        }
        o.cancelled = true;
        o.worker.cancel();
    }

    /// Copies `deadbolt pair <ticket>`, the command to run on the other device.
    pub fn copy_ticket(&mut self) {
        let Some(ticket) = &self.onboarding.ticket else {
            return;
        };
        let command = Zeroizing::new(format!("deadbolt pair {}", ticket.text.as_str()));
        match self.clipboard.copy(&command) {
            Ok(copied) => self.onboarding.copied = Some(copied),
            Err(error) => {
                self.onboarding.notice = Some(Notice {
                    severity: Severity::Danger,
                    title: "Couldn't copy".into(),
                    body: error,
                });
            }
        }
    }

    /// Copies a command from the empty vault's guide.
    pub fn copy_command(&mut self, command: &'static str, tx: &mut Tx) {
        match self.clipboard.copy(command) {
            Ok(_) => {
                self.onboarding.copied_command = Some((command, self.clock));
                tx.wake_after(Duration::from_secs_f64(COPIED_FOR));
            }
            Err(error) => self.notice = Some(format!("Couldn't copy: {error}")),
        }
    }

    /// Takes the copied ticket off the clipboard if it's still there, and
    /// wipes the ticket.
    fn forget_ticket(&mut self) {
        if let Some(copied) = self.onboarding.copied.take() {
            self.clipboard.clear(copied);
        }
        self.onboarding.ticket = None;
    }

    /// Applies the requests' progress and runs the moment. True when anything changed.
    pub fn poll_onboarding(&mut self, now: f64, tx: &mut Tx) -> bool {
        let (progress, next) = self.onboarding.worker.drain(now);
        let mut changed = !progress.is_empty();
        if self
            .onboarding
            .copied_command
            .is_some_and(|(_, at)| now - at >= COPIED_FOR - 1e-3)
        {
            self.onboarding.copied_command = None;
            changed = true;
        }
        for p in progress {
            self.on_progress(p, now);
        }
        if let Some(at) = next {
            tx.wake_after(Duration::from_secs_f64((at - now).max(0.0)));
        }
        if let Some(done) = self.onboarding.done_at {
            let age = now - done;
            if age >= moment::OPEN {
                self.open_vault(tx);
                return true;
            }
            // The view draws each phase; wake for the next.
            let phase = moment::PHASES.iter().filter(|p| age >= **p).count();
            if let Some(next) = moment::PHASES.get(phase) {
                tx.wake_after(Duration::from_secs_f64(next - age));
            }
            if phase != self.onboarding.phase {
                self.onboarding.phase = phase;
                changed = true;
            }
        }
        changed
    }

    fn on_progress(&mut self, progress: Progress, now: f64) {
        let o = &mut self.onboarding;
        match progress {
            Progress::Stage(stage) => {
                if o.plan.contains(&stage) {
                    o.stage = Some(stage);
                }
            }
            // Not inferred from `device_ready`: a status refresh may already have set it.
            Progress::DeviceReady { set_up } => {
                o.set_up_now |= set_up;
                o.device_ready = true;
            }
            // A cancel is on its way; its result will say so.
            Progress::Ticket(_) | Progress::Code { .. } if o.cancelled => {}
            Progress::Ticket(text) => {
                let qr = qr::Matrix::new(&text);
                o.ticket = Some(Ticket { text, qr });
                o.device_ready = true;
                o.step = Step::Ticket;
            }
            Progress::Code {
                code,
                vault,
                inviter,
            } => {
                self.forget_ticket();
                let inviter = inviter.name.unwrap_or_else(|| short(&inviter.id).into());
                self.onboarding.pairing = Some(Pairing {
                    vault: vault.clone(),
                    inviter: inviter.clone(),
                });
                self.onboarding.step = Step::Confirm {
                    code,
                    vault,
                    inviter,
                };
            }
            Progress::Created(result) => match result {
                Ok(vault) => self.done(Flow::Create, vault, None, now),
                Err(failure) => self.onboarding_failed(Flow::Create, failure),
            },
            Progress::Joined(result) => {
                self.forget_ticket();
                match result {
                    Ok(vault) => {
                        let from = self.onboarding.pairing.take().map(|p| p.inviter);
                        self.done(Flow::Join, vault, from, now);
                    }
                    Err(failure) => self.onboarding_failed(Flow::Join, failure),
                }
            }
        }
    }

    fn done(&mut self, flow: Flow, vault: VaultInfo, from: Option<String>, now: f64) {
        let o = &mut self.onboarding;
        o.forget();
        o.notice = None;
        o.device_ready = true;
        o.stage = None;
        o.step = Step::Done {
            flow,
            vault: vault.name,
            from,
        };
        o.done_at = Some(now);
        o.phase = 0;
    }

    fn open_vault(&mut self, tx: &mut Tx) {
        self.reset_onboarding(true);
        self.agent.send(Job::Status);
        self.list();
        self.enter_vault(tx);
    }

    fn onboarding_failed(&mut self, flow: Flow, failure: Failure) {
        let o = &mut self.onboarding;
        o.forget();
        o.stage = None;
        o.pairing = None;
        let notice = if flow == Flow::Join && o.cancelled {
            Notice {
                severity: Severity::Neutral,
                title: "Join cancelled".into(),
                body: if o.set_up_now {
                    "Nothing was shared. This device is set up now, with the passphrase you \
                     chose. Make a new ticket when you're ready."
                } else {
                    "Nothing was shared. Make a new ticket when you're ready."
                }
                .into(),
            }
        } else if flow == Flow::Join && o.declined {
            Notice {
                severity: Severity::Caution,
                title: "Stopped: the codes didn't match".into(),
                body: "Nothing was shared and the ticket no longer works. Make a new one and \
                       compare again. If you didn't start pairing on your other device, \
                       someone else may have seen the ticket."
                    .into(),
            }
        } else {
            failure_notice(flow, &failure)
        };
        o.cancelled = false;
        o.declined = false;
        o.set_up_now = false;
        o.notice = Some(notice);
        o.attempted = false;
        o.step = match flow {
            Flow::Create => Step::Create,
            Flow::Join => Step::Join,
        };
        o.blur();
        if flow == Flow::Create {
            o.vault.focused = true;
        }
        // Setup may have finished before the failure: ask whether the device is set up now.
        self.agent.send(Job::Status);
    }
}

/// What a failed request means for the person, from the agent's message.
fn failure_notice(flow: Flow, failure: &Failure) -> Notice {
    let message = failure.message.as_str();
    let (severity, title, body) = if message.contains(worker::ALREADY_SET_UP) {
        (
            Severity::Caution,
            "This device is already set up",
            "It was set up meanwhile, so the passphrase you just typed wasn't used. The \
             passphrase it was set up with is the one that unlocks it."
                .to_owned(),
        )
    } else if message.contains("not confirmed") {
        (
            Severity::Caution,
            "The other device didn't confirm",
            "Nothing was shared. Make a new ticket and compare the codes on both screens."
                .to_owned(),
        )
    } else if message.contains("expired") {
        (
            Severity::Neutral,
            "The ticket expired",
            "Tickets work for 10 minutes. Make a new one.".to_owned(),
        )
    } else if message.contains("already exists") {
        (
            Severity::Danger,
            "That name is taken",
            "This device already has a vault with that name. Pick another.".to_owned(),
        )
    } else {
        let title = match flow {
            Flow::Create => "Couldn't create the vault",
            Flow::Join => "Couldn't join",
        };
        (
            Severity::Danger,
            title,
            format!("{}. Try again.", sentence(message)),
        )
    };
    Notice {
        severity,
        title: title.into(),
        body,
    }
}

/// `message` with a capital letter and no trailing full stop.
fn sentence(message: &str) -> String {
    let message = message.trim().trim_end_matches('.');
    let mut chars = message.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => "The agent failed".into(),
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

/// Keys while onboarding, before the focused field: ⇧⌘Space opens the quick
/// panel rather than typing a space, and Escape goes back or cancels. True
/// when handled.
pub fn key(s: &mut App, ev: &KeyEvent, tx: &mut Tx) -> bool {
    if s.panel_shortcut(ev, tx) {
        return true;
    }
    if ev.key != Key::Escape {
        return false;
    }
    match s.onboarding.step {
        Step::Create | Step::Join => s.onboarding_back(),
        Step::Ticket | Step::Confirm { .. } => s.cancel_join(),
        Step::Working(Flow::Join) if s.onboarding.pairing.is_none() => s.cancel_join(),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_asks_for_more_until_it_is_long_and_varied() {
        assert_eq!(strength(""), Strength::TooShort);
        assert_eq!(strength("hunter2"), Strength::TooShort);
        assert_eq!(strength("hunter22"), Strength::Weak);
        assert_eq!(strength("aaaaaaaaaaaaaaaaaaaaaaaa"), Strength::Weak);
        assert_eq!(strength("Hunter22-x"), Strength::Fair);
        assert_eq!(strength("correct horse battery staple"), Strength::Strong);
    }

    #[test]
    fn a_device_set_up_meanwhile_is_a_caution_not_a_failure() {
        let failure = Failure {
            code: None,
            message: worker::ALREADY_SET_UP.into(),
        };
        let notice = failure_notice(Flow::Join, &failure);
        assert_eq!(notice.severity, Severity::Caution);
        assert_eq!(notice.title, "This device is already set up");
    }

    #[test]
    fn vault_names_follow_the_agents_rule() {
        let mut o = Onboarding::new(Worker::offline());
        for (name, ok) in [
            ("personal", true),
            ("work-2", true),
            ("", false),
            ("Personal", false),
            ("2fa", false),
            ("my vault", false),
        ] {
            o.vault = TextEdit::new(name);
            assert_eq!(o.vault_problem().is_none(), ok, "{name:?}");
        }
    }
}
