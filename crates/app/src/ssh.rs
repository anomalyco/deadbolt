//! SSH agent setting (`Settings › Getting to it`) and SSH key generation / file
//! import in the item form (`docs/ssh-agent.md`).

use std::path::Path;

use deadbolt_client::protocol::{SshKeyKind, Status};
use rune::{El, Transition, Tx, row, spacer, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, SegmentedControl, Switch};
use zeroize::Zeroizing;

use crate::agent::{Failure, Job};
use crate::edit::Problem;
use crate::model::{App, Screen};
use crate::onboarding::{COPIED_FOR, sentence};
use crate::view::theme::FACT;

pub struct SshGeneratedKey {
    pub private_key: Zeroizing<String>,
    pub public_key: String,
    pub fingerprint: String,
    pub comment: Option<String>,
}

pub struct Ssh {
    pub busy: bool,
    pub error: Option<String>,
    pub kind: SshKeyKind,
    copied_at: Option<f64>,
    pending_copy: bool,
}

impl Default for Ssh {
    fn default() -> Self {
        Self {
            busy: false,
            error: None,
            kind: SshKeyKind::Ed25519,
            copied_at: None,
            pending_copy: false,
        }
    }
}

impl App {
    pub fn ssh_agent_enabled(&self) -> bool {
        self.status.as_ref().is_some_and(|s| s.ssh_agent)
    }

    pub fn ssh_agent_socket(&self) -> String {
        let raw = self
            .status
            .as_ref()
            .and_then(|s| s.ssh_socket.as_deref())
            .unwrap_or("~/.deadbolt/ssh.sock");
        shorten_home(raw)
    }

    pub fn toggle_ssh_agent(&mut self) {
        if self.ssh.busy {
            return;
        }
        let next = !self.ssh_agent_enabled();
        self.ssh.error = None;
        if let Some(status) = &mut self.status {
            status.ssh_agent = next;
        }
        if self.agent.is_live() {
            self.ssh.busy = true;
            self.agent.send(Job::SshAgentSet(next));
        }
    }

    pub fn copy_ssh_config(&mut self, tx: &mut Tx) {
        let sock = self.ssh_agent_socket();
        let quoted = if sock.contains(' ') {
            format!("\"{sock}\"")
        } else {
            sock
        };
        let snippet =
            format!("Match host * exec \"test -z $SSH_CONNECTION\"\n    IdentityAgent {quoted}");
        tx.copy(snippet);
        self.ssh.pending_copy = true;
    }

    pub(crate) fn poll_ssh(&mut self, now: f64, tx: &mut Tx) -> bool {
        if self.ssh.pending_copy {
            self.ssh.pending_copy = false;
            self.ssh.copied_at = Some(now);
            tx.wake_after(std::time::Duration::from_secs_f64(COPIED_FOR));
            return true;
        }
        if let Some(at) = self.ssh.copied_at
            && now - at >= COPIED_FOR
        {
            self.ssh.copied_at = None;
            return true;
        }
        false
    }

    pub(crate) fn on_ssh_agent_set(
        &mut self,
        enabled: bool,
        result: Result<Status, (Failure, Option<Box<Status>>)>,
        tx: &mut Tx,
    ) {
        self.ssh.busy = false;
        match result {
            Ok(status) => {
                self.ssh.error = None;
                self.on_status(status, tx);
            }
            Err((failure, status)) => {
                if let Some(st) = status {
                    self.on_status(*st, tx);
                } else if let Some(st) = &mut self.status {
                    st.ssh_agent = !enabled;
                }
                if failure.locked() {
                    if self.screen != Screen::Locked {
                        self.on_locked(tx);
                    }
                } else {
                    self.ssh.error = Some(failure.message);
                }
            }
        }
    }

    pub fn set_ssh_kind(&mut self, kind: SshKeyKind) {
        if self.saving() || self.ssh.kind == kind {
            return;
        }
        self.ssh.kind = kind;
    }

    pub fn generate_ssh_key(&mut self) {
        if !self
            .edit
            .form
            .as_ref()
            .is_some_and(|f| f.kind == "ssh" && !f.saving)
        {
            return;
        }
        let seq = self.next_generation_seq();
        let Some(form) = self.edit.form.as_mut() else {
            return;
        };
        let comment = form
            .fields
            .iter()
            .find(|f| f.name == "comment")
            .map(|f| f.edit.text.trim().to_owned())
            .filter(|c| !c.is_empty());
        form.set_generating(Some(seq));
        self.agent.send(Job::SshGenerate {
            kind: self.ssh.kind,
            comment,
            seq,
        });
    }

    pub fn choose_ssh_key_file(&mut self, tx: &mut Tx) {
        if !self
            .edit
            .form
            .as_ref()
            .is_some_and(|f| f.kind == "ssh" && !f.saving)
        {
            return;
        }
        let options = rune::FileDialogOptions {
            title: "Import SSH Private Key".into(),
            ..rune::FileDialogOptions::default()
        };
        tx.open_file(options, move |s: &mut App, result, _| {
            if let Ok(Some(path)) = result {
                s.import_ssh_key_file(path);
            }
        });
    }

    pub fn import_ssh_key_file(&mut self, path: std::path::PathBuf) {
        if !self
            .edit
            .form
            .as_ref()
            .is_some_and(|f| f.kind == "ssh" && !f.saving)
        {
            return;
        }
        let seq = self.next_generation_seq();
        let Some(form) = self.edit.form.as_mut() else {
            return;
        };
        let comment = form
            .fields
            .iter()
            .find(|f| f.name == "comment")
            .map(|f| f.edit.text.trim().to_owned())
            .filter(|c| !c.is_empty());
        form.set_generating(Some(seq));
        self.agent.send(Job::SshImportFile { path, comment, seq });
    }

    pub(crate) fn on_ssh_generated(&mut self, seq: u64, result: Result<SshGeneratedKey, Failure>) {
        let Some(form) = self
            .edit
            .form
            .as_mut()
            .filter(|f| f.kind == "ssh" && f.generating_seq() == Some(seq))
        else {
            return;
        };
        form.set_generating(None);
        match result {
            Ok(mut key) => {
                if let Some(priv_input) = form.fields.iter_mut().find(|f| f.name == "private-key") {
                    priv_input.kept = false;
                    priv_input.edit.set_revealed(false);
                    priv_input
                        .edit
                        .replace_text(std::mem::take(&mut *key.private_key));
                }
                if let Some(pub_input) = form.fields.iter_mut().find(|f| f.name == "public-key") {
                    pub_input.edit.replace_text(key.public_key);
                }
                if let Some(fp_input) = form.fields.iter_mut().find(|f| f.name == "fingerprint") {
                    fp_input.edit.replace_text(key.fingerprint);
                }
                if let Some(comment) = key.comment
                    && let Some(c_input) = form.fields.iter_mut().find(|f| f.name == "comment")
                    && c_input.edit.text.trim().is_empty()
                {
                    c_input.edit.replace_text(comment);
                }
                form.generated += 1;
                form.problem = None;
                form.nudge = false;
            }
            Err(failure) => {
                form.problem = Some(Problem {
                    field: Some("private-key".into()),
                    message: sentence(&failure.message),
                });
            }
        }
    }
}

pub fn setting_about(s: &App, k: &Kit) -> El {
    if let Some(err) = &s.ssh.error {
        return text(err.clone())
            .key("ssh-agent-error")
            .font(k.ty.small_medium)
            .color(k.c.danger.fg)
            .wrap()
            .w_full()
            .transition(Transition::opacity());
    }
    let words = if s.ssh_agent_enabled() {
        format!(
            "Listening at {} · approve each use with Touch ID",
            s.ssh_agent_socket()
        )
    } else {
        "Use SSH keys in your vault for ssh and Git without ~/.ssh key files".to_owned()
    };
    text(words)
        .key("about")
        .font(FACT.lh(16.0))
        .color(k.c.text_faint)
        .wrap()
        .w_full()
}

pub fn setting_controls(s: &App, k: &Kit) -> El {
    let mut r = row().key("ssh-controls").gap(10.0).center_y();
    if s.ssh_agent_enabled() {
        let copied = s.ssh.copied_at.is_some();
        r = r.child(
            crate::settings::button(if copied { "Copied" } else { "Copy config" })
                .disabled(s.ssh.busy)
                .on_press_tx(|s: &mut App, tx| s.copy_ssh_config(tx))
                .build(k)
                .key("ssh-copy-config"),
        );
    }
    r.child(
        Switch::new(s.ssh_agent_enabled())
            .label("SSH agent")
            .hide_label()
            .disabled(s.ssh.busy)
            .on_toggle(|s: &mut App| s.toggle_ssh_agent())
            .build(k)
            .key("ssh-agent-switch"),
    )
}

/// Controls under `private-key` on an SSH item form: key type (`Ed25519`,
/// `ECDSA P-256`), **Generate key** and **Import file…**.
pub fn generator_row(s: &App, k: &Kit, saving: bool) -> El {
    let labels = ["Ed25519", "ECDSA P-256"];
    let at = match s.ssh.kind {
        SshKeyKind::Ed25519 => Some(0),
        SshKeyKind::EcdsaP256 => Some(1),
    };
    let mut seg = SegmentedControl::new(&labels, at)
        .fit()
        .on_pick(|s: &mut App, i, _| {
            let kind = if i == 1 {
                SshKeyKind::EcdsaP256
            } else {
                SshKeyKind::Ed25519
            };
            s.set_ssh_kind(kind);
        });
    if saving {
        for i in 0..labels.len() {
            seg = seg.segment_state(i, rune_kit::State::Disabled);
        }
    }
    row()
        .key("ssh-generator")
        .w_full()
        .gap(8.0)
        .center_y()
        .child(seg.build(k).key("ssh-kind"))
        .child(
            Button::new("Generate key")
                .variant(ButtonVariant::Neutral)
                .control_size(ControlSize::Large)
                .disabled(saving)
                .on_press(|s: &mut App| s.generate_ssh_key())
                .build(k)
                .key("ssh-generate"),
        )
        .child(spacer())
        .child(
            Button::new("Import file…")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Large)
                .disabled(saving)
                .on_press_tx(|s: &mut App, tx| s.choose_ssh_key_file(tx))
                .build(k)
                .key("ssh-import-file"),
        )
}

fn shorten_home(path: &str) -> String {
    let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else {
        return path.to_owned();
    };
    match Path::new(path).strip_prefix(Path::new(&home)) {
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => path.to_owned(),
    }
}
