//! Pass 3: grouping. Fields in a `<form>` belong to it; fields outside any form
//! form virtual forms, one per run of such fields between real forms (in
//! document order), since single-page apps rarely use `<form>`.

use super::gate::Prepared;
use crate::snapshot::Frame;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The `<form>`'s id, or `None` for a virtual form.
    pub form: Option<u32>,
    /// Indexes into the frame's fields: eligible fields, in document order.
    pub fields: Vec<usize>,
    /// Indexes of the group's visible buttons.
    pub buttons: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Form(u32),
    Run(usize),
}

/// Groups with at least one eligible field, in order of their first element.
pub fn group(frame: &Frame, prepared: &[Prepared]) -> Vec<Group> {
    let mut keys: Vec<Key> = Vec::new();
    let mut groups: Vec<Group> = Vec::new();
    let mut run = 0;
    let mut in_form = false;
    for (i, (field, p)) in frame.fields.iter().zip(prepared).enumerate() {
        let key = match field.form {
            Some(id) => {
                in_form = true;
                Key::Form(id)
            }
            None => {
                // Any element inside a form ends the current run of orphans.
                if in_form {
                    run += 1;
                    in_form = false;
                }
                Key::Run(run)
            }
        };
        if !p.eligible && !p.button {
            continue;
        }
        let gi = match keys.iter().position(|k| *k == key) {
            Some(gi) => gi,
            None => {
                keys.push(key);
                groups.push(Group {
                    form: field.form,
                    fields: Vec::new(),
                    buttons: Vec::new(),
                });
                groups.len() - 1
            }
        };
        if p.eligible {
            groups[gi].fields.push(i);
        } else {
            groups[gi].buttons.push(i);
        }
    }
    groups.retain(|g| !g.fields.is_empty());
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{Field, Form};

    #[test]
    fn real_forms_and_runs_between_them() {
        let mut frame = Frame {
            forms: vec![Form {
                id: 0,
                ..Form::default()
            }],
            ..Frame::default()
        };
        let forms = [None, None, Some(0), Some(0), None, None];
        frame.fields = forms
            .iter()
            .enumerate()
            .map(|(i, f)| Field {
                id: i as u32,
                form: *f,
                ..Field::default()
            })
            .collect();
        let prepared: Vec<Prepared> = forms
            .iter()
            .map(|_| Prepared {
                eligible: true,
                ..Prepared::default()
            })
            .collect();
        let groups = group(&frame, &prepared);
        let got: Vec<(Option<u32>, Vec<usize>)> =
            groups.into_iter().map(|g| (g.form, g.fields)).collect();
        assert_eq!(
            got,
            vec![
                (None, vec![0, 1]),
                (Some(0), vec![2, 3]),
                (None, vec![4, 5])
            ]
        );
    }
}
