//! First run: create a vault on this device, or join one from another device.
//! The state and what each input and reply does to it; `onboarding/view.rs`
//! draws it and `onboarding/worker.rs` talks to the agent.
//!
//! A device can be set up (it has a key and a passphrase) and still hold no
//! vault, after a cancelled join for example. Onboarding then skips the
//! passphrase and asks only for what's left.

mod ceremony;
pub mod view;
pub mod worker;

use std::time::Duration;

use deadbolt_client::protocol::VaultInfo;
use rune::{Key, KeyEvent, SecretCopy, SecretState, TextEdit, Tx};
use zeroize::Zeroizing;

use crate::agent::{Failure, Job};
use crate::model::{App, Screen};
use crate::view::{Notice, Severity};
use worker::{NewDevice, Progress, Stage, Worker};

/// Shortest passphrase the form accepts.
pub const MIN_PASSPHRASE: usize = 8;
/// How long a copied command's button shows a check, in seconds.
pub const COPIED_FOR: f64 = 1.6;
/// How long a copied code stays on the clipboard: as long as it works.
const CODE_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// The moment a vault is created or joined, from the bolt throwing to the vault
/// opening. See `onboarding/ceremony.rs` for what happens when.
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

impl Flow {
    pub(crate) fn step(self) -> Step {
        match self {
            Flow::Create => Step::Create,
            Flow::Join => Step::Join,
        }
    }
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
    /// The code is up, waiting for the other device.
    Code,
    /// Created or joined: the moment, then the vault.
    Done {
        flow: Flow,
        vault: String,
        from: Option<String>,
    },
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
    /// The pairing code: until it's used or expires, whoever types it first
    /// pairs with this device, so it's wiped when dropped.
    pub code: Option<Zeroizing<String>>,
    /// The copied `deadbolt pair` command, while it's still on the clipboard.
    pub copied: Option<SecretCopy>,
    /// A command copied from the empty vault's guide, and when.
    pub copied_command: Option<(&'static str, Option<f64>)>,
    /// The vault joined and the device that invited this one, once paired.
    pub pairing: Option<Pairing>,
    /// When the vault was created or joined, on the app's clock.
    pub done_at: Option<f64>,
    /// How many of `moment::PHASES` have passed.
    pub phase: usize,
    pub worker: Worker,
    /// What this computer calls itself (`default_device_name`), once the
    /// lookup off the main thread lands.
    pub suggested_device: Option<String>,
    /// The person edited the device name: a late suggestion leaves it alone.
    pub device_edited: bool,
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
            code: None,
            copied: None,
            copied_command: None,
            pairing: None,
            done_at: None,
            phase: 0,
            worker,
            suggested_device: None,
            device_edited: false,
            cancelled: false,
            set_up_now: false,
        }
    }

    /// Back to the welcome screen with empty fields; keeps the worker. Only
    /// through [`App::reset_onboarding`], which clears a copied code first.
    fn reset(&mut self, device_ready: bool) {
        let worker = std::mem::replace(&mut self.worker, Worker::offline());
        *self = Onboarding {
            device_ready,
            suggested_device: self.suggested_device.take(),
            ..Onboarding::new(worker)
        };
    }

    /// Fills the device name with the suggestion, unless there's none yet,
    /// no device to name, or the person has written their own.
    fn suggest_device(&mut self) {
        if !self.needs_device()
            || self.device_edited
            || !self.device.text.is_empty()
            || !matches!(self.step, Step::Create | Step::Join)
        {
            return;
        }
        if let Some(name) = &self.suggested_device {
            let focused = self.device.focused;
            self.device = TextEdit::new(name.clone());
            self.device.focused = focused;
        }
    }

    /// A cancelled join waits for a device setup already under way.
    pub fn stopping(&self) -> bool {
        self.cancelled && matches!(self.step, Step::Working(Flow::Join))
    }

    /// A request is running or its result is showing: status changes from
    /// elsewhere must not move the screen.
    pub fn busy(&self) -> bool {
        matches!(self.step, Step::Working(_) | Step::Code | Step::Done { .. })
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
        if first == second && (!second.is_empty() || self.attempted) {
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

    pub(crate) fn can_submit(&self, flow: Flow) -> bool {
        let device_ok = !self.needs_device()
            || (self.device_problem().is_none()
                && self.passphrase_problem().is_none()
                && self.repeat_matches() == Some(true));
        device_ok && (flow != Flow::Create || self.vault_problem().is_none())
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
        if device && self.device_problem().is_some() {
            self.device.focused = true;
        } else if flow == Flow::Create && self.vault_problem().is_some() {
            self.vault.focused = true;
        } else if device && self.passphrase_problem().is_some() {
            self.passphrase.focused = true;
        } else if device && self.repeat_matches() != Some(true) {
            self.repeat.focused = true;
        } else if flow == Flow::Create {
            self.vault.focused = true;
        }
    }

    pub fn blur(&mut self) {
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
/// ("Kit's Mac Studio"), else the host name without `.local`. Runs
/// `scutil`, so only off the main thread (`Worker::name_device`).
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
        if !device_ready && self.onboarding.suggested_device.is_none() {
            self.onboarding.worker.name_device();
        }
    }

    /// Onboarding from scratch, leaving nothing of the last attempt behind.
    fn reset_onboarding(&mut self, device_ready: bool) {
        self.forget_onboarding();
        self.onboarding.reset(device_ready);
    }

    /// Leaving onboarding (or the app): takes a copied code off the clipboard
    /// if it's still there, wipes the code and passphrases, and hangs up a join.
    pub(crate) fn forget_onboarding(&mut self) {
        self.forget_code();
        self.onboarding.worker.cancel();
        self.onboarding.forget();
    }

    pub fn choose(&mut self, flow: Flow) {
        let o = &mut self.onboarding;
        o.notice = None;
        o.attempted = false;
        o.step = flow.step();
        o.suggest_device();
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

    /// Enter in a name field: submits once the passphrase is ready (or none is
    /// needed), else moves cleanly to the next passphrase field.
    pub(crate) fn advance_onboarding(&mut self, flow: Flow) {
        let o = &mut self.onboarding;
        if !o.needs_device()
            || (o.passphrase_problem().is_none() && o.repeat_matches() == Some(true))
        {
            self.submit_onboarding(flow);
        } else if o.passphrase_problem().is_none() {
            o.blur();
            o.repeat.focused = true;
        } else {
            o.blur();
            o.passphrase.focused = true;
        }
    }

    pub fn submit_create(&mut self) {
        self.submit_onboarding(Flow::Create);
    }

    pub fn submit_join(&mut self) {
        self.submit_onboarding(Flow::Join);
    }

    pub(crate) fn submit_onboarding(&mut self, flow: Flow) {
        let o = &mut self.onboarding;
        if o.step != flow.step() {
            return;
        }
        if !o.can_submit(flow) {
            o.attempted = true;
            o.focus_first(flow);
            return;
        }
        o.notice = None;
        o.blur();
        o.cancelled = false;
        o.set_up_now = false;
        let next = match flow {
            Flow::Create => Stage::CreatingVault,
            Flow::Join => Stage::MakingCode,
        };
        o.plan = if o.needs_device() {
            vec![Stage::Protecting, next]
        } else {
            vec![next]
        };
        // Until the worker reports a stage the first shows as active.
        o.stage = None;
        o.step = Step::Working(flow);
        let device = o.new_device();
        o.repeat.clear();
        match flow {
            Flow::Create => o.worker.create(device, o.vault.text.trim().to_owned()),
            Flow::Join => o.worker.join(device),
        }
    }

    /// Hangs up the join; the device stays set up.
    pub fn cancel_join(&mut self) {
        let o = &mut self.onboarding;
        let joining = matches!(o.step, Step::Working(Flow::Join)) && o.pairing.is_none();
        if o.cancelled || !(joining || o.step == Step::Code) {
            return;
        }
        o.cancelled = true;
        o.worker.cancel();
    }

    /// Copies `deadbolt pair <code>`, the command to run on the other device.
    pub fn copy_code(&mut self, tx: &mut Tx) {
        let Some(code) = &self.onboarding.code else {
            return;
        };
        let command = format!("deadbolt pair {}", code.as_str());
        self.onboarding.notice = None;
        self.onboarding.copied = Some(tx.copy_secret(command, CODE_LIFETIME));
    }

    /// Copies a command from the empty vault's guide.
    pub fn copy_command(&mut self, command: &'static str, tx: &mut Tx) {
        tx.copy(command);
        self.onboarding.copied_command = Some((command, None));
    }

    /// Takes the copied code off the clipboard if it's still there, and
    /// wipes the code.
    fn forget_code(&mut self) {
        if let Some(copied) = self.onboarding.copied.take() {
            copied.clear_now();
        }
        self.onboarding.code = None;
    }

    /// The copied code's write failed, or something else took its place
    /// on the clipboard: the button stops saying it's copied. True when so.
    fn check_code_copy(&mut self) -> bool {
        let o = &mut self.onboarding;
        match o.copied.as_ref().map(SecretCopy::state) {
            Some(SecretState::Failed(error)) => {
                o.notice = Some(Notice::new(Severity::Danger, "Couldn't copy", error));
            }
            Some(SecretState::Replaced | SecretState::Cleared) => {}
            _ => return false,
        }
        o.copied = None;
        true
    }

    /// Applies the requests' progress and runs the moment. True when anything changed.
    pub fn poll_onboarding(&mut self, now: f64, tx: &mut Tx) -> bool {
        let (progress, next) = self.onboarding.worker.drain(now);
        // The first frame after a copy stamps it: `clock` is stale after idle.
        if let Some((_, at @ None)) = &mut self.onboarding.copied_command {
            *at = Some(now);
            tx.wake_after(Duration::from_secs_f64(COPIED_FOR));
        }
        let mut changed = self.check_code_copy()
            || !progress.is_empty()
            || self
                .onboarding
                .copied_command
                .take_if(|(_, at)| at.is_some_and(|at| now - at >= COPIED_FOR - 1e-3))
                .is_some();
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
            Progress::DeviceName(name) => {
                o.suggested_device = Some(name);
                o.suggest_device();
            }
            // Not inferred from `device_ready`: a status refresh may already have set it.
            Progress::DeviceReady { set_up } => {
                o.set_up_now |= set_up;
                o.device_ready = true;
            }
            // A cancel is on its way; its result will say so.
            Progress::Code(_) | Progress::Paired { .. } if o.cancelled => {}
            Progress::Code(code) => {
                o.code = Some(code);
                o.device_ready = true;
                o.step = Step::Code;
            }
            // The vault arrives with the reply, right behind this.
            Progress::Paired { vault, inviter } => {
                self.forget_code();
                let inviter = inviter.name.unwrap_or_else(|| short(&inviter.id).into());
                self.onboarding.pairing = Some(Pairing { vault, inviter });
            }
            Progress::Created(result) => match result {
                Ok(vault) => self.done(Flow::Create, vault, None, now),
                Err(failure) => self.onboarding_failed(Flow::Create, failure),
            },
            Progress::Joined(result) => {
                self.forget_code();
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
            let body = if o.set_up_now {
                "Nothing was shared. This device is set up now, with the passphrase you \
                 chose. Make a new code when you're ready."
            } else {
                "Nothing was shared. Make a new code when you're ready."
            };
            Notice::new(Severity::Neutral, "Join cancelled", body)
        } else {
            failure_notice(flow, &failure)
        };
        o.cancelled = false;
        o.set_up_now = false;
        o.notice = Some(notice);
        o.attempted = false;
        o.step = flow.step();
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
    } else if message.contains("wrong code") {
        (
            Severity::Caution,
            "Someone tried a wrong code",
            "Nothing was shared, and that code no longer works. Make a new one. If you \
             didn't try one yourself, someone may be trying to get in."
                .to_owned(),
        )
    } else if message.contains("expired") {
        (
            Severity::Neutral,
            "The code expired",
            "Codes work for 5 minutes. Make a new one.".to_owned(),
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
        let detail = sentence(message);
        let detail = if detail.is_empty() {
            "The agent failed."
        } else {
            detail.as_str()
        };
        (Severity::Danger, title, format!("{detail} Try again."))
    };
    Notice::new(severity, title, body)
}

/// A message as a sentence: capitalised, with a full stop.
pub(crate) fn sentence(message: &str) -> String {
    let mut chars = message.trim().chars();
    let mut out: String = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => return String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
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
        Step::Code => s.cancel_join(),
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
