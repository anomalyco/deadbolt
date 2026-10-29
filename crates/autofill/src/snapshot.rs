//! The engine's input: a value-free description of a page's frames, forms and
//! fields, as the content script collects it (spec §8.3).
//!
//! A snapshot never carries what a person typed, only whether a field has a
//! value. Everything in it comes from the page, so it is untrusted: parsing
//! enforces the caps below and rejects references that don't resolve, instead
//! of trusting the collector.

use serde::{Deserialize, Serialize};

/// Most frames analysed per page.
pub const MAX_FRAMES: usize = 32;
/// Most forms kept per frame.
pub const MAX_FORMS: usize = 100;
/// Most fields (controls and buttons) kept per frame.
pub const MAX_FIELDS: usize = 600;
/// Longest short string (ids, names, labels), in characters.
pub const MAX_SHORT: usize = 200;
/// Longest form text, in characters.
pub const MAX_TEXT: usize = 3000;
/// Most labels, headings, data hints and select options kept per element.
pub const MAX_LIST: usize = 8;
/// Most select options kept per field.
pub const MAX_OPTIONS: usize = 50;

/// Why a snapshot was rejected.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("frame {frame}: field {field} refers to form {form}, which the frame doesn't have")]
    UnknownForm { frame: usize, field: u32, form: u32 },
    #[error("frame {frame}: field id {field} appears twice")]
    DuplicateField { frame: usize, field: u32 },
}

/// One page: its top-level URL and title and every frame that was collected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub frames: Vec<Frame>,
}

/// One frame's controls in document order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Frame {
    /// The collector's handle for the frame (never a browser frame id).
    #[serde(default)]
    pub frame_ref: String,
    /// Origin and path, without query or fragment.
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub dir: Dir,
    /// The first few headings of the document.
    #[serde(default)]
    pub headings: Vec<String>,
    /// Allow-listed `data-*` attributes on `<body>`.
    #[serde(default)]
    pub body_hints: Vec<(String, String)>,
    #[serde(default)]
    pub forms: Vec<Form>,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    #[default]
    Ltr,
    Rtl,
}

/// A `<form>` element.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Form {
    pub id: u32,
    #[serde(default)]
    pub html_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub method: String,
    /// Host and path of the action URL.
    #[serde(default)]
    pub action: String,
    /// The nearest heading in or before the form.
    #[serde(default)]
    pub header_text: String,
    /// The form's visible text, capped.
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub data_hints: Vec<(String, String)>,
}

/// What kind of control a field is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Element {
    #[default]
    Text,
    Email,
    Password,
    Tel,
    Number,
    Search,
    Url,
    Textarea,
    Select,
    Checkbox,
    Radio,
    Button,
    Hidden,
    Other,
}

impl Element {
    /// The name rule files use for it.
    pub fn as_str(self) -> &'static str {
        match self {
            Element::Text => "text",
            Element::Email => "email",
            Element::Password => "password",
            Element::Tel => "tel",
            Element::Number => "number",
            Element::Search => "search",
            Element::Url => "url",
            Element::Textarea => "textarea",
            Element::Select => "select",
            Element::Checkbox => "checkbox",
            Element::Radio => "radio",
            Element::Button => "button",
            Element::Hidden => "hidden",
            Element::Other => "other",
        }
    }

    pub fn parse(name: &str) -> Option<Element> {
        Some(match name {
            "text" => Element::Text,
            "email" => Element::Email,
            "password" => Element::Password,
            "tel" => Element::Tel,
            "number" => Element::Number,
            "search" => Element::Search,
            "url" => Element::Url,
            "textarea" => Element::Textarea,
            "select" => Element::Select,
            "checkbox" => Element::Checkbox,
            "radio" => Element::Radio,
            "button" => Element::Button,
            "hidden" => Element::Hidden,
            "other" => Element::Other,
            _ => return None,
        })
    }
}

/// A form control or a button.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Field {
    pub id: u32,
    /// The owning form's id: its `form=` owner or nearest ancestor `<form>`, across shadow roots.
    #[serde(default)]
    pub form: Option<u32>,
    #[serde(default)]
    pub element: Element,
    #[serde(default)]
    pub html_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub class: String,
    /// The raw `autocomplete` attribute.
    #[serde(default)]
    pub autocomplete: String,
    #[serde(default)]
    pub input_mode: String,
    #[serde(default)]
    pub placeholder: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub aria_label: String,
    /// `<label>` and `aria-labelledby` text.
    #[serde(default)]
    pub labels: Vec<String>,
    /// The closest text before the field, when it is short.
    #[serde(default)]
    pub label_before: String,
    /// The closest text after the field, when it is short.
    #[serde(default)]
    pub label_after: String,
    /// A button's text. Empty for every other element.
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub max_length: Option<u32>,
    #[serde(default)]
    pub min_length: Option<u32>,
    /// Allow-listed `data-*` attributes (ignore markers, test ids).
    #[serde(default)]
    pub data_hints: Vec<(String, String)>,
    /// A select's options as (text, value).
    #[serde(default)]
    pub options: Vec<(String, String)>,
    #[serde(default)]
    pub flags: Flags,
}

/// Booleans about a field. `has_value` is the only trace of its content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Flags {
    #[serde(default)]
    pub visible: bool,
    #[serde(default)]
    pub readonly: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub has_value: bool,
    /// Drawn as dots by CSS (`-webkit-text-security`) though not a password input.
    #[serde(default)]
    pub masked: bool,
    #[serde(default)]
    pub in_shadow: bool,
    /// A submit button.
    #[serde(default)]
    pub submit: bool,
    #[serde(default)]
    pub user_edited: bool,
    #[serde(default)]
    pub filled_by_us: bool,
}

impl Snapshot {
    /// Parses a snapshot, enforces the caps and checks its references.
    pub fn from_json(json: &str) -> Result<Snapshot, SnapshotError> {
        let mut snapshot: Snapshot = serde_json::from_str(json)?;
        snapshot.clamp();
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Cuts every list and string down to the engine's caps.
    pub fn clamp(&mut self) {
        clip(&mut self.url, MAX_SHORT * 2);
        clip(&mut self.title, MAX_SHORT);
        self.frames.truncate(MAX_FRAMES);
        for frame in &mut self.frames {
            clip(&mut frame.frame_ref, 64);
            clip(&mut frame.url, MAX_SHORT * 2);
            clip(&mut frame.title, MAX_SHORT);
            clip_list(&mut frame.headings, MAX_LIST, MAX_SHORT);
            clip_pairs(&mut frame.body_hints, MAX_LIST);
            frame.forms.truncate(MAX_FORMS);
            for form in &mut frame.forms {
                for s in [
                    &mut form.html_id,
                    &mut form.name,
                    &mut form.method,
                    &mut form.action,
                    &mut form.header_text,
                ] {
                    clip(s, MAX_SHORT);
                }
                clip(&mut form.text, MAX_TEXT);
                clip_pairs(&mut form.data_hints, MAX_LIST);
            }
            frame.fields.truncate(MAX_FIELDS);
            for field in &mut frame.fields {
                for s in [
                    &mut field.html_id,
                    &mut field.name,
                    &mut field.class,
                    &mut field.autocomplete,
                    &mut field.input_mode,
                    &mut field.placeholder,
                    &mut field.title,
                    &mut field.aria_label,
                    &mut field.label_before,
                    &mut field.label_after,
                    &mut field.text,
                ] {
                    clip(s, MAX_SHORT);
                }
                clip_list(&mut field.labels, MAX_LIST, MAX_SHORT);
                clip_pairs(&mut field.data_hints, MAX_LIST);
                field.options.truncate(MAX_OPTIONS);
                for (text, value) in &mut field.options {
                    clip(text, 80);
                    clip(value, 80);
                }
            }
        }
    }

    /// Checks that field ids are unique and form references resolve.
    pub fn validate(&self) -> Result<(), SnapshotError> {
        for (index, frame) in self.frames.iter().enumerate() {
            let mut seen = std::collections::HashSet::new();
            for field in &frame.fields {
                if !seen.insert(field.id) {
                    return Err(SnapshotError::DuplicateField {
                        frame: index,
                        field: field.id,
                    });
                }
                if let Some(form) = field.form
                    && !frame.forms.iter().any(|f| f.id == form)
                {
                    return Err(SnapshotError::UnknownForm {
                        frame: index,
                        field: field.id,
                        form,
                    });
                }
            }
        }
        Ok(())
    }
}

fn clip(s: &mut String, max_chars: usize) {
    if let Some((cut, _)) = s.char_indices().nth(max_chars) {
        s.truncate(cut);
    }
}

fn clip_list(list: &mut Vec<String>, max_items: usize, max_chars: usize) {
    list.truncate(max_items);
    for s in list {
        clip(s, max_chars);
    }
}

fn clip_pairs(list: &mut Vec<(String, String)>, max_items: usize) {
    list.truncate(max_items);
    for (k, v) in list {
        clip(k, 64);
        clip(v, 80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_json_and_clamps() {
        let long = "x".repeat(5000);
        let json = format!(
            r#"{{"url":"https://a.test/","frames":[{{"forms":[{{"id":0,"text":"{long}"}}],"fields":[{{"id":0,"form":0,"element":"password","name":"{long}"}}]}}]}}"#
        );
        let s = Snapshot::from_json(&json).unwrap();
        assert_eq!(s.frames[0].forms[0].text.chars().count(), MAX_TEXT);
        assert_eq!(s.frames[0].fields[0].name.chars().count(), MAX_SHORT);
        assert_eq!(s.frames[0].fields[0].element, Element::Password);
    }

    #[test]
    fn rejects_dangling_form_and_duplicate_ids() {
        let dangling = r#"{"frames":[{"fields":[{"id":0,"form":3}]}]}"#;
        assert!(matches!(
            Snapshot::from_json(dangling),
            Err(SnapshotError::UnknownForm { .. })
        ));
        let dup = r#"{"frames":[{"fields":[{"id":1},{"id":1}]}]}"#;
        assert!(matches!(
            Snapshot::from_json(dup),
            Err(SnapshotError::DuplicateField { .. })
        ));
        assert!(matches!(
            Snapshot::from_json(r#"{"frames":[],"value":"x"}"#),
            Err(SnapshotError::Json(_))
        ));
    }

    #[test]
    fn clips_on_char_boundaries() {
        let mut s = "パスワード".repeat(100);
        clip(&mut s, 7);
        assert_eq!(s.chars().count(), 7);
    }
}
