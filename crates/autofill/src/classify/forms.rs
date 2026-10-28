//! Pass 4: form clues. A group's kind from its text (display channel), its
//! form's id, name and action and the frame URL (code channel), and the mix of
//! fields in it (coded shape rules).

use super::fields::Scored;
use super::gate::Prepared;
use super::group::Group;
use super::{Contribution, FORM_THRESHOLD, FieldType, FormKind};
use crate::clues::{Channel, Rules, Texts};
use crate::snapshot::Frame;
use crate::text;

#[derive(Debug, Clone, Default)]
pub struct Decided {
    pub kind: Option<FormKind>,
    pub score: i32,
    pub trace: Vec<Contribution>,
}

#[derive(Debug, Default)]
struct Scores {
    scores: [i32; FormKind::SCORED.len()],
    trace: Vec<Contribution>,
}

impl Scores {
    fn add(
        &mut self,
        kind: FormKind,
        delta: i32,
        rule: impl Into<String>,
        channel: Option<Channel>,
    ) {
        if delta == 0 {
            return;
        }
        self.scores[kind as usize] += delta;
        self.trace.push(Contribution {
            rule: rule.into(),
            channel,
            target: kind.rule_name(),
            delta,
        });
    }

    fn get(&self, kind: FormKind) -> i32 {
        self.scores[kind as usize]
    }

    /// Caps a kind's score, recording the cut.
    fn cap(&mut self, kind: FormKind, max: i32, rule: &str) {
        let over = self.get(kind) - max;
        if over > 0 {
            self.add(kind, -over, rule, None);
        }
    }
}

/// The texts a group's kind is judged on.
fn texts(frame: &Frame, group: &Group) -> (String, String) {
    let mut display: Vec<&str> = vec![&frame.title];
    display.extend(frame.headings.iter().map(String::as_str));
    let mut code: Vec<&str> = vec![&frame.url];
    if let Some(form) = group
        .form
        .and_then(|id| frame.forms.iter().find(|f| f.id == id))
    {
        display.extend([form.header_text.as_str(), form.text.as_str()]);
        code.extend([
            form.action.as_str(),
            form.html_id.as_str(),
            form.name.as_str(),
        ]);
    }
    display.extend(group.buttons.iter().map(|&b| frame.fields[b].text.as_str()));
    (
        text::words(&display.join(" \n ")),
        text::code_words(&code.join(" ")),
    )
}

pub fn decide(
    rules: &Rules,
    frame: &Frame,
    group: &Group,
    prepared: &[Prepared],
    roles: &[Option<FieldType>],
    scored: &[Option<Scored>],
    has_split: bool,
) -> Decided {
    let (display, code) = texts(frame, group);
    let mut s = Scores::default();
    let mut signup_code = false;
    let (mut login_display, mut login_code) = (0, 0);
    for hit in rules.form_matcher.find(Texts {
        display: &display,
        code: &code,
    }) {
        let table = &rules.forms[hit.table];
        let clue = &table.clues[hit.clue];
        s.add(table.kind, clue.score, clue.id.as_str(), Some(hit.channel));
        signup_code |= table.kind == FormKind::Signup && hit.channel == Channel::Code;
        if table.kind == FormKind::Login {
            match hit.channel {
                Channel::Code => login_code += clue.score,
                _ => login_display += clue.score,
            }
        }
    }

    // The shape of the form.
    let count = |want: fn(FieldType) -> bool| {
        group
            .fields
            .iter()
            .filter(|&&i| roles[i].is_some_and(want))
            .count()
    };
    // A password box whose own wording says PIN or code beside another
    // password box is the second secret of a card-and-PIN login, not a
    // second password.
    let passwords: Vec<usize> = group
        .fields
        .iter()
        .copied()
        .filter(|&i| roles[i] == Some(FieldType::CurrentPassword))
        .collect();
    let pins = if passwords.len() >= 2 {
        passwords
            .iter()
            .filter(|&&i| {
                scored[i]
                    .as_ref()
                    .is_some_and(|s| s.wording(FieldType::OneTimeCode) > 0)
            })
            .count()
            .min(passwords.len() - 1)
    } else {
        0
    };
    if pins > 0 {
        s.trace.push(Contribution {
            rule: "shape:pin-is-not-a-second-password".into(),
            channel: None,
            target: "login",
            delta: 0,
        });
    }
    let pw = passwords.len() - pins;
    let npw = count(|t| t == FieldType::NewPassword);
    let ident = count(FieldType::is_identifier);
    let otp = count(|t| t == FieldType::OneTimeCode) + usize::from(has_split);
    let ac = |token: &str| {
        group
            .fields
            .iter()
            .any(|&i| prepared[i].autocomplete.iter().any(|t| t == token))
    };

    if pw == 1 && npw == 0 {
        s.add(FormKind::Login, 5, "shape:one-password", None);
    }
    if pw == 0 && npw == 0 && ident > 0 {
        s.add(FormKind::Login, 1, "shape:identifier-only", None);
    }
    if pw >= 2 {
        s.add(FormKind::Login, -3, "shape:several-passwords", None);
    }
    if npw > 0 && !ac("current-password") {
        s.add(FormKind::Login, -3, "shape:new-password", None);
    }
    if ac("webauthn") {
        s.add(FormKind::Login, 3, "shape:ac-webauthn", None);
    }
    if ac("current-password") {
        s.add(FormKind::Login, 3, "shape:ac-current-password", None);
    }
    if ac("username") && pw == 0 {
        s.add(FormKind::Login, 2, "shape:ac-username", None);
    }
    // A lone email box on a page whose URL says "login" may be a 404 page's
    // or a newsletter's: without a password or code, the URL doesn't count
    // when the wording speaks against a sign-in.
    if pw + npw == 0
        && otp == 0
        && login_code > 0
        && login_display < 0
        && !ac("username")
        && !ac("webauthn")
    {
        s.add(
            FormKind::Login,
            -login_code,
            "shape:identifier-only-url-against-wording",
            None,
        );
    }

    // With a single password box, autocomplete=new-password is a weak hint
    // (sites use it to block autofill on logins); wording has to confirm it.
    let single = pw + npw == 1;
    if npw > 0 && pw == 0 {
        s.add(
            FormKind::Signup,
            if single { 1 } else { 3 },
            "shape:new-password-only",
            None,
        );
    }
    if pw + npw >= 2 {
        s.add(FormKind::Signup, 3, "shape:several-passwords", None);
    }
    if ac("new-password") {
        s.add(
            FormKind::Signup,
            if single { 1 } else { 3 },
            "shape:ac-new-password",
            None,
        );
    }
    if single && npw == 1 {
        s.add(FormKind::Login, 2, "shape:single-new-password", None);
    }
    if pw == 1 && npw == 0 {
        s.add(FormKind::Signup, -2, "shape:one-password", None);
    }
    // A "Create account" link next to an email-first sign-in doesn't make it a sign-up.
    if pw + npw == 0 && !signup_code {
        s.cap(FormKind::Signup, 2, "shape:no-password-caps-signup");
    }

    // Shape alone is weak here (two password boxes can be password + PIN);
    // the "current / new password" wording does most of the work.
    if (pw >= 1 && npw >= 1) || pw + npw >= 3 {
        s.add(FormKind::ChangePassword, 2, "shape:current-and-new", None);
    }
    if ac("current-password") && ac("new-password") {
        s.add(
            FormKind::ChangePassword,
            4,
            "shape:ac-current-and-new",
            None,
        );
    }

    if ident > 0 && pw + npw == 0 {
        s.add(FormKind::Reset, 1, "shape:identifier-only", None);
    }
    if pw + npw > 0 {
        s.add(FormKind::Reset, -6, "shape:has-password", None);
    }

    if otp > 0 && pw == 0 {
        s.add(FormKind::Mfa, 6, "shape:code-only", None);
    }
    if otp > 0 && pw > 0 {
        s.add(FormKind::Mfa, 1, "shape:code-and-password", None);
    }

    if ident > 0 && pw + npw == 0 {
        s.add(FormKind::Newsletter, 1, "shape:identifier-only", None);
    }
    if pw + npw > 0 {
        s.add(FormKind::Newsletter, -8, "shape:has-password", None);
    }

    let mut best: Option<FormKind> = None;
    for kind in FormKind::SCORED {
        if s.get(kind) >= FORM_THRESHOLD && best.is_none_or(|b| s.get(kind) > s.get(b)) {
            best = Some(kind);
        }
    }
    let score = best.map_or_else(
        || {
            FormKind::SCORED
                .iter()
                .map(|k| s.get(*k))
                .max()
                .unwrap_or(0)
        },
        |k| s.get(k),
    );
    Decided {
        kind: best,
        score,
        trace: s.trace,
    }
}
