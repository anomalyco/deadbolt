//! Pass 1: normalise and gate. Decides which fields can hold a login value at
//! all, drops fields the site marked for password managers to ignore, and
//! builds each remaining field's display and code text.

use super::Contribution;
use crate::snapshot::{Element, Field, Frame};
use crate::text;

/// A field's facts, ready for scoring.
#[derive(Debug, Clone, Default)]
pub struct Prepared {
    /// Visible, text-like and not opted out: it can get a type.
    pub eligible: bool,
    /// A visible button with short text: its text counts for its form.
    pub button: bool,
    /// The element as scored: a text box drawn as dots counts as a password box.
    pub element: Element,
    /// Lowercase autocomplete tokens.
    pub autocomplete: Vec<String>,
    pub input_mode: String,
    pub max_len: u32,
    /// [`text::words`] of what a person reads about the field.
    pub display: String,
    /// [`text::code_words`] of its id, name, class and test ids.
    pub code: String,
    /// One box of a code split one character per box.
    pub otp_box: bool,
    pub gate: Vec<Contribution>,
}

/// Elements that can hold a username, password or code.
fn text_like(element: Element) -> bool {
    matches!(
        element,
        Element::Text
            | Element::Email
            | Element::Password
            | Element::Tel
            | Element::Number
            | Element::Url
            | Element::Search
    )
}

/// Buttons with longer text are page sections, not controls.
const MAX_BUTTON_TEXT: usize = 40;
/// Display text is cut here before it is normalised.
const MAX_DISPLAY: usize = 300;

/// Markers sites put on fields, forms or `<body>` to keep password managers
/// away. Deadbolt honours its own and the common vendor ones.
fn opted_out(hints: &[(String, String)]) -> Option<&str> {
    hints.iter().find_map(|(key, value)| {
        let value = value.to_ascii_lowercase();
        let hit = match key.as_str() {
            "data-deadbolt-ignore" | "data-1p-ignore" | "data-op-ignore" | "data-bwignore" => {
                value != "false"
            }
            "data-lpignore" => value == "true",
            "data-form-type" => value == "other",
            _ => false,
        };
        hit.then_some(key.as_str())
    })
}

fn hint<'a>(hints: &'a [(String, String)], key: &str) -> Option<&'a str> {
    hints
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

pub fn prepare(frame: &Frame, field: &Field) -> Prepared {
    let mut p = Prepared {
        element: field.element,
        ..Prepared::default()
    };
    if field.element == Element::Button {
        p.button = field.flags.visible
            && !field.text.trim().is_empty()
            && field.text.chars().count() <= MAX_BUTTON_TEXT;
        return p;
    }
    if !field.flags.visible || !text_like(field.element) {
        return p;
    }
    let form_hints = field
        .form
        .and_then(|id| frame.forms.iter().find(|f| f.id == id))
        .map(|f| f.data_hints.as_slice());
    let marker = opted_out(&field.data_hints)
        .map(|k| ("field", k))
        .or_else(|| form_hints.and_then(opted_out).map(|k| ("form", k)))
        .or_else(|| opted_out(&frame.body_hints).map(|k| ("body", k)));
    if marker.is_some() {
        return p;
    }
    p.eligible = true;

    if field.flags.masked && field.element != Element::Password {
        p.element = Element::Password;
        p.gate.push(Contribution {
            rule: "gate:text-security".into(),
            channel: None,
            target: "password",
            delta: 0,
        });
    }
    p.autocomplete = field
        .autocomplete
        .to_ascii_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    p.input_mode = field.input_mode.to_ascii_lowercase();
    p.max_len = field.max_length.unwrap_or(0);
    p.otp_box = p.max_len == 1;

    // What a person reads: labels, aria-label, placeholder and title; the
    // nearest text before the field only when it has none of those.
    let mut parts: Vec<&str> = field.labels.iter().map(String::as_str).collect();
    parts.extend([
        field.aria_label.as_str(),
        field.placeholder.as_str(),
        field.title.as_str(),
    ]);
    if parts.iter().all(|s| s.trim().is_empty()) {
        parts.push(&field.label_before);
    }
    // "you@example.com" as a placeholder means an email box.
    if field.placeholder.contains('@') {
        parts.push("email");
    }
    let display: String = parts
        .iter()
        .filter(|s| !s.trim().is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    p.display = text::words(&display.chars().take(MAX_DISPLAY).collect::<String>());

    let mut code: Vec<&str> = vec![&field.html_id, &field.name, &field.class];
    code.extend(hint(&field.data_hints, "data-testid"));
    code.extend(hint(&field.data_hints, "data-test"));
    let code: String = code
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    p.code = text::code_words(&code.chars().take(MAX_DISPLAY).collect::<String>());
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Flags;

    fn field(element: Element) -> Field {
        Field {
            element,
            flags: Flags {
                visible: true,
                ..Flags::default()
            },
            ..Field::default()
        }
    }

    #[test]
    fn ignore_markers_on_field_form_or_body() {
        let mut frame = Frame::default();
        let mut f = field(Element::Text);
        f.data_hints = vec![("data-1p-ignore".into(), "".into())];
        assert!(!prepare(&frame, &f).eligible);
        f.data_hints = vec![("data-1p-ignore".into(), "false".into())];
        assert!(prepare(&frame, &f).eligible);
        f.data_hints = vec![("data-lpignore".into(), "false".into())];
        assert!(prepare(&frame, &f).eligible);
        frame.body_hints = vec![("data-deadbolt-ignore".into(), "true".into())];
        assert!(!prepare(&frame, &f).eligible);
    }

    #[test]
    fn hidden_and_non_text_fields_are_not_eligible() {
        let frame = Frame::default();
        let mut f = field(Element::Text);
        f.flags.visible = false;
        assert!(!prepare(&frame, &f).eligible);
        assert!(!prepare(&frame, &field(Element::Select)).eligible);
        assert!(!prepare(&frame, &field(Element::Checkbox)).eligible);
    }

    #[test]
    fn masked_text_is_scored_as_a_password_box() {
        let mut f = field(Element::Text);
        f.flags.masked = true;
        assert_eq!(prepare(&Frame::default(), &f).element, Element::Password);
    }

    #[test]
    fn nearby_text_only_without_labels() {
        let mut f = field(Element::Text);
        f.label_before = "Username".into();
        assert_eq!(prepare(&Frame::default(), &f).display, " username ");
        f.placeholder = "you@example.com".into();
        assert_eq!(
            prepare(&Frame::default(), &f).display,
            " you example com email "
        );
    }
}
