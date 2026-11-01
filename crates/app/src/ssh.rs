//! SSH key generation and file import in the item form.

use deadbolt_client::protocol::SshKeyKind;
use rune::{El, Tx, row, spacer};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, SegmentedControl};
use zeroize::Zeroizing;

use crate::agent::{Failure, Job};
use crate::edit::Problem;
use crate::model::App;
use crate::onboarding::sentence;

pub struct SshGeneratedKey {
    pub private_key: Zeroizing<String>,
    pub public_key: String,
    pub fingerprint: String,
    pub comment: Option<String>,
}

pub struct Ssh {
    pub kind: SshKeyKind,
}

impl Default for Ssh {
    fn default() -> Self {
        Self {
            kind: SshKeyKind::Ed25519,
        }
    }
}

impl App {
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
