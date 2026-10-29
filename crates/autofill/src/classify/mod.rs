//! Classification: field types and form kinds from a [`Snapshot`], with a
//! trace of every contribution.
//!
//! Passes (spec §8.4), per frame:
//!
//! 1. [`gate`]: which fields can hold a login value at all, and their texts.
//! 2. [`fields`]: clue, autocomplete, element and input-mode scores per type.
//! 3. [`group`]: real forms, and virtual forms for runs of fields outside any.
//! 5. [`context`] (first half): neighbour adjustments such as a confirmation
//!    password after a password, then a provisional pick.
//! 4. [`forms`]: each group's kind from its text, URL and field mix.
//! 5. [`context`] (second half): roles that depend on the form's kind.
//! 10. Pick: the best type at or above [`FIELD_THRESHOLD`], ties to the
//!     earlier type in [`FieldType::ALL`].
//!
//! Pass 5 is split around pass 4 because a form's kind depends on how many
//! passwords it has, and which password is which depends on the form's kind.

mod context;
mod fields;
mod forms;
mod gate;
mod group;

use serde::Serialize;

use crate::clues::{Channel, Rules, RulesError};
use crate::snapshot::{Frame, Snapshot};

/// A field needs at least this score to get a type.
pub const FIELD_THRESHOLD: i32 = 3;
/// A form needs at least this score to get a kind.
pub const FORM_THRESHOLD: i32 = 3;

/// What a field holds. Serialised as the extension's `FieldRole`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum FieldType {
    #[serde(rename = "username")]
    Username,
    #[serde(rename = "email")]
    Email,
    #[serde(rename = "phone")]
    Phone,
    #[serde(rename = "password")]
    CurrentPassword,
    #[serde(rename = "new-password")]
    NewPassword,
    #[serde(rename = "otp")]
    OneTimeCode,
    #[serde(rename = "captcha")]
    Captcha,
}

impl FieldType {
    /// Every type, in tie-break order.
    pub const ALL: [FieldType; 7] = [
        FieldType::Username,
        FieldType::Email,
        FieldType::Phone,
        FieldType::CurrentPassword,
        FieldType::NewPassword,
        FieldType::OneTimeCode,
        FieldType::Captcha,
    ];

    /// The name rule files and the extension use.
    pub fn rule_name(self) -> &'static str {
        match self {
            FieldType::Username => "username",
            FieldType::Email => "email",
            FieldType::Phone => "phone",
            FieldType::CurrentPassword => "password",
            FieldType::NewPassword => "new-password",
            FieldType::OneTimeCode => "otp",
            FieldType::Captcha => "captcha",
        }
    }

    pub fn from_rule_name(name: &str) -> Option<FieldType> {
        FieldType::ALL.into_iter().find(|t| t.rule_name() == name)
    }

    pub fn is_identifier(self) -> bool {
        matches!(
            self,
            FieldType::Username | FieldType::Email | FieldType::Phone
        )
    }

    pub fn is_password(self) -> bool {
        matches!(self, FieldType::CurrentPassword | FieldType::NewPassword)
    }
}

/// What a form is for. Serialised as the extension's `SurfaceKind`, plus
/// `newsletter` and `none`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormKind {
    Login,
    Signup,
    ChangePassword,
    Reset,
    Mfa,
    Newsletter,
    None,
}

impl FormKind {
    /// The kinds with clue tables, in tie-break order.
    pub const SCORED: [FormKind; 6] = [
        FormKind::Login,
        FormKind::Signup,
        FormKind::ChangePassword,
        FormKind::Reset,
        FormKind::Mfa,
        FormKind::Newsletter,
    ];

    pub fn rule_name(self) -> &'static str {
        match self {
            FormKind::Login => "login",
            FormKind::Signup => "signup",
            FormKind::ChangePassword => "change-password",
            FormKind::Reset => "reset",
            FormKind::Mfa => "mfa",
            FormKind::Newsletter => "newsletter",
            FormKind::None => "none",
        }
    }

    pub fn from_rule_name(name: &str) -> Option<FormKind> {
        FormKind::SCORED
            .into_iter()
            .chain([FormKind::None])
            .find(|k| k.rule_name() == name)
    }

    /// The kinds the extension shows a surface for (its `SurfaceKind`).
    pub fn is_surface(self) -> bool {
        !matches!(self, FormKind::Newsletter | FormKind::None)
    }
}

/// One signed contribution to a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Contribution {
    /// `<table>:<phrase>` for clues, `<table>:ac=<token>` and so on for
    /// weights, `<pass>:<rule>` for coded rules.
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<Channel>,
    /// The field type or form kind it counts for.
    pub target: &'static str,
    /// The score change; 0 for a rule that sets the result directly.
    pub delta: i32,
}

/// The result for one snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub frames: Vec<FrameAnalysis>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameAnalysis {
    pub frame_ref: String,
    /// The primary group's kind when it is a surface kind: what `scanPage()` reports.
    pub kind: Option<FormKind>,
    /// The group holding the frame's most important field.
    pub primary_group: Option<usize>,
    pub groups: Vec<GroupAnalysis>,
    /// Every field that could hold a login value, in document order.
    pub fields: Vec<FieldAnalysis>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAnalysis {
    /// The `<form>`'s id, or `None` for a virtual form.
    pub form: Option<u32>,
    pub kind: FormKind,
    pub score: i32,
    /// Snapshot ids of the group's fields.
    pub fields: Vec<u32>,
    pub trace: Vec<Contribution>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldAnalysis {
    /// The field's snapshot id.
    pub id: u32,
    pub group: Option<usize>,
    pub role: Option<FieldType>,
    pub score: i32,
    pub runner_up: Option<(FieldType, i32)>,
    /// On each box of a code split into one box per character: how many boxes.
    pub split: Option<u32>,
    pub trace: Vec<Contribution>,
}

/// The engine: compiled rules, reused across snapshots.
#[derive(Debug)]
pub struct Engine {
    rules: Rules,
}

impl Engine {
    /// An engine with the rules built into the crate.
    pub fn embedded() -> Result<Engine, RulesError> {
        Ok(Engine {
            rules: Rules::embedded()?,
        })
    }

    pub fn with_rules(rules: Rules) -> Engine {
        Engine { rules }
    }

    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    /// Classifies every frame of a snapshot. Pure and deterministic.
    pub fn analyze(&self, snapshot: &Snapshot) -> Analysis {
        Analysis {
            frames: snapshot
                .frames
                .iter()
                .map(|f| self.analyze_frame(f))
                .collect(),
        }
    }

    fn analyze_frame(&self, frame: &Frame) -> FrameAnalysis {
        let rules = &self.rules;
        // Pass 1.
        let prepared: Vec<gate::Prepared> = frame
            .fields
            .iter()
            .map(|f| gate::prepare(frame, f))
            .collect();
        // Pass 2.
        let mut scored: Vec<Option<fields::Scored>> = prepared
            .iter()
            .map(|p| (p.eligible && !p.otp_box).then(|| fields::score(rules, p)))
            .collect();
        // Pass 3.
        let groups = group::group(frame, &prepared);
        // Pass 5, neighbours, then a provisional pick.
        for g in &groups {
            context::neighbours(&g.fields, &prepared, &mut scored);
        }
        let mut roles: Vec<Option<FieldType>> = scored
            .iter()
            .map(|s| s.as_ref().and_then(fields::Scored::best))
            .collect();
        // Split codes: a run of one-character boxes is one code.
        let mut split: Vec<Option<u32>> = vec![None; prepared.len()];
        for g in &groups {
            let boxes: Vec<usize> = g
                .fields
                .iter()
                .copied()
                .filter(|&i| prepared[i].otp_box)
                .collect();
            if (4..=8).contains(&boxes.len()) {
                for &i in &boxes {
                    split[i] = Some(boxes.len() as u32);
                }
            }
        }
        // Pass 4, then pass 5's kind-dependent roles.
        let mut group_out = Vec::with_capacity(groups.len());
        let mut overrides: Vec<Vec<Contribution>> = vec![Vec::new(); prepared.len()];
        for g in &groups {
            let has_split = g.fields.iter().any(|&i| split[i].is_some());
            let decided = forms::decide(rules, frame, g, &prepared, &roles, &scored, has_split);
            if let Some(kind) = decided.kind {
                context::adjust_for_kind(kind, &g.fields, &prepared, &mut roles, &mut overrides);
                if kind == FormKind::Login {
                    context::login_partner(
                        &g.fields,
                        &prepared,
                        &scored,
                        &mut roles,
                        &mut overrides,
                    );
                }
            }
            group_out.push(GroupAnalysis {
                form: g.form,
                kind: decided.kind.unwrap_or(FormKind::None),
                score: decided.score,
                fields: g.fields.iter().map(|&i| frame.fields[i].id).collect(),
                trace: decided.trace,
            });
        }

        // Primary group: the one holding the most important field, as scanPage() picks its form.
        // Judged on the settled roles, so a login whose identifier only context found still counts.
        let anchor = |want: fn(FieldType) -> bool| {
            groups
                .iter()
                .enumerate()
                .flat_map(|(gi, g)| g.fields.iter().map(move |&i| (gi, i)))
                .find(|&(_, i)| roles[i].is_some_and(want))
        };
        let primary = anchor(FieldType::is_password)
            .or_else(|| anchor(FieldType::is_identifier))
            .or_else(|| anchor(|t| t == FieldType::OneTimeCode))
            .map(|(gi, _)| gi)
            .or_else(|| {
                groups
                    .iter()
                    .position(|g| g.fields.iter().any(|&i| split[i].is_some()))
            });

        let mut group_of = vec![None; prepared.len()];
        for (gi, g) in groups.iter().enumerate() {
            for &i in &g.fields {
                group_of[i] = Some(gi);
            }
        }
        let mut field_out = Vec::new();
        for (i, p) in prepared.iter().enumerate() {
            if !p.eligible {
                continue;
            }
            let mut trace = p.gate.clone();
            let (score, runner_up) = match &scored[i] {
                Some(s) => {
                    trace.extend(s.trace.iter().cloned());
                    s.summary(roles[i])
                }
                None => (0, None),
            };
            trace.append(&mut overrides[i]);
            let role = if split[i].is_some() {
                trace.push(Contribution {
                    rule: "shape:split-code".into(),
                    channel: None,
                    target: "otp",
                    delta: 0,
                });
                Some(FieldType::OneTimeCode)
            } else {
                roles[i]
            };
            field_out.push(FieldAnalysis {
                id: frame.fields[i].id,
                group: group_of[i],
                role,
                score,
                runner_up,
                split: split[i],
                trace,
            });
        }

        FrameAnalysis {
            frame_ref: frame.frame_ref.clone(),
            kind: primary
                .map(|gi| group_out[gi].kind)
                .filter(|k| k.is_surface()),
            primary_group: primary,
            groups: group_out,
            fields: field_out,
        }
    }
}

#[cfg(test)]
mod tests;
