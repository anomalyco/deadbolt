//! Pass 5: context. Neighbour adjustments before the form is judged, and the
//! password roles that depend on the form's kind after.

use super::fields::Scored;
use super::gate::Prepared;
use super::{Contribution, FIELD_THRESHOLD, FieldType, FormKind};
use crate::snapshot::Element;

/// A password box right after another one in the same group is a
/// confirmation, unless it is really a PIN or code box (by its score or its
/// own wording).
pub fn neighbours(group: &[usize], prepared: &[Prepared], scored: &mut [Option<Scored>]) {
    let mut previous = false;
    for &i in group {
        if prepared[i].element != Element::Password {
            continue;
        }
        let Some(s) = scored[i].as_mut() else {
            continue;
        };
        if s.get(FieldType::OneTimeCode) >= FIELD_THRESHOLD || s.wording(FieldType::OneTimeCode) > 0
        {
            continue;
        }
        if previous {
            s.add(FieldType::NewPassword, 4, "context:second-password", None);
            s.add(
                FieldType::CurrentPassword,
                -4,
                "context:second-password",
                None,
            );
        }
        previous = true;
    }
}

/// Once the form's kind is known, settles which password is which.
pub fn adjust_for_kind(
    kind: FormKind,
    group: &[usize],
    prepared: &[Prepared],
    roles: &mut [Option<FieldType>],
    overrides: &mut [Vec<Contribution>],
) {
    let passwords: Vec<usize> = group
        .iter()
        .copied()
        .filter(|&i| {
            prepared[i].element == Element::Password && roles[i].is_some_and(FieldType::is_password)
        })
        .collect();
    let has = |i: usize, token: &str| prepared[i].autocomplete.iter().any(|t| t == token);
    let mut set = |roles: &mut [Option<FieldType>], i: usize, ty: FieldType, rule: &str| {
        if roles[i] != Some(ty) {
            roles[i] = Some(ty);
            overrides[i].push(Contribution {
                rule: rule.to_owned(),
                channel: None,
                target: ty.rule_name(),
                delta: 0,
            });
        }
    };
    match kind {
        FormKind::Signup => {
            for &i in &passwords {
                if !has(i, "current-password") {
                    set(
                        roles,
                        i,
                        FieldType::NewPassword,
                        "kind:signup-passwords-are-new",
                    );
                }
            }
        }
        FormKind::ChangePassword => {
            for (n, &i) in passwords.iter().enumerate() {
                if has(i, "new-password") {
                    set(
                        roles,
                        i,
                        FieldType::NewPassword,
                        "kind:change-password-autocomplete",
                    );
                } else if has(i, "current-password") {
                    set(
                        roles,
                        i,
                        FieldType::CurrentPassword,
                        "kind:change-password-autocomplete",
                    );
                } else if n == 0 {
                    set(
                        roles,
                        i,
                        FieldType::CurrentPassword,
                        "kind:change-password-first-is-current",
                    );
                } else {
                    set(
                        roles,
                        i,
                        FieldType::NewPassword,
                        "kind:change-password-rest-are-new",
                    );
                }
            }
        }
        FormKind::Login => {
            // Sites sometimes set autocomplete=new-password on a login box to block autofill.
            if let [only] = passwords[..] {
                set(
                    roles,
                    only,
                    FieldType::CurrentPassword,
                    "kind:login-single-password",
                );
            } else {
                for &i in &passwords {
                    if roles[i] == Some(FieldType::NewPassword) && !has(i, "new-password") {
                        set(roles, i, FieldType::CurrentPassword, "kind:login-password");
                    }
                }
            }
        }
        FormKind::Reset | FormKind::Mfa | FormKind::Newsletter | FormKind::None => {}
    }
}

/// In a login form with one password and no identifier, the field right
/// before the password is the identifier even when its label says little
/// (`Uživatel:`, `User code`, `Card number` on a bank login). With no
/// password, the box marked `autocomplete=username` is.
pub fn login_partner(
    group: &[usize],
    prepared: &[Prepared],
    scored: &[Option<Scored>],
    roles: &mut [Option<FieldType>],
    overrides: &mut [Vec<Contribution>],
) {
    if group
        .iter()
        .any(|&i| roles[i].is_some_and(FieldType::is_identifier))
    {
        return;
    }
    let passwords: Vec<usize> = (0..group.len())
        .filter(|&n| roles[group[n]] == Some(FieldType::CurrentPassword))
        .collect();
    let candidate = match passwords[..] {
        [at] => group[..at]
            .iter()
            .rev()
            .copied()
            .find(|&i| !prepared[i].otp_box),
        // An identifier step: the box the markup calls the username.
        [] => group.iter().copied().find(|&i| {
            prepared[i]
                .autocomplete
                .iter()
                .any(|t| t == "username" || t == "webauthn")
        }),
        _ => None,
    };
    let Some(candidate) = candidate else { return };
    if roles[candidate].is_some()
        || !matches!(
            prepared[candidate].element,
            Element::Text | Element::Email | Element::Tel | Element::Number | Element::Search
        )
    {
        return;
    }
    let Some(s) = scored[candidate].as_ref() else {
        return;
    };
    // A search box or a profile field (name, address, birthday) by its own
    // markup is something else, whatever its place. Card wording is not: bank
    // logins ask for a card number.
    let elsewhere = s.trace.iter().any(|c| {
        c.delta < 0
            && (c.rule.starts_with("non-login-autocomplete:")
                || c.rule.starts_with("not-a-login-field:search"))
    });
    if elsewhere {
        return;
    }
    let mut best = FieldType::Username;
    for ty in [FieldType::Email, FieldType::Phone] {
        if s.get(ty) > s.get(best) {
            best = ty;
        }
    }
    roles[candidate] = Some(best);
    overrides[candidate].push(Contribution {
        rule: "context:login-partner".into(),
        channel: None,
        target: best.rule_name(),
        delta: 0,
    });
}
