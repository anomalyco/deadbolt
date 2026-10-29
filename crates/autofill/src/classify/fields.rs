//! Pass 2: field clues. One matcher pass over the display and code text, then
//! autocomplete tokens, element type and input mode, for every field type.

use super::gate::Prepared;
use super::{Contribution, FIELD_THRESHOLD, FieldType};
use crate::clues::{Channel, Rules, Texts};
use crate::snapshot::Element;

/// A field's score per type, with how each was reached.
#[derive(Debug, Clone, Default)]
pub struct Scored {
    pub scores: [i32; FieldType::ALL.len()],
    pub trace: Vec<Contribution>,
}

impl Scored {
    pub fn add(
        &mut self,
        ty: FieldType,
        delta: i32,
        rule: impl Into<String>,
        channel: Option<Channel>,
    ) {
        if delta == 0 {
            return;
        }
        self.scores[ty as usize] += delta;
        self.trace.push(Contribution {
            rule: rule.into(),
            channel,
            target: ty.rule_name(),
            delta,
        });
    }

    /// The part of a type's score that came from the field's own text.
    pub fn wording(&self, ty: FieldType) -> i32 {
        self.trace
            .iter()
            .filter(|c| c.channel.is_some() && c.target == ty.rule_name())
            .map(|c| c.delta)
            .sum()
    }

    pub fn get(&self, ty: FieldType) -> i32 {
        self.scores[ty as usize]
    }

    /// The highest type at or above the threshold; ties go to the earlier type.
    pub fn best(&self) -> Option<FieldType> {
        let mut best: Option<FieldType> = None;
        for ty in FieldType::ALL {
            if self.get(ty) >= FIELD_THRESHOLD && best.is_none_or(|b| self.get(ty) > self.get(b)) {
                best = Some(ty);
            }
        }
        best
    }

    /// The chosen type's score (or the best score when none was chosen) and the runner-up.
    pub fn summary(&self, chosen: Option<FieldType>) -> (i32, Option<(FieldType, i32)>) {
        let mut order: Vec<FieldType> = FieldType::ALL.to_vec();
        // Stable: equal scores keep tie-break order.
        order.sort_by_key(|t| std::cmp::Reverse(self.get(*t)));
        let first = chosen.unwrap_or(order[0]);
        let runner = order
            .into_iter()
            .find(|t| *t != first)
            .map(|t| (t, self.get(t)));
        (self.get(first), runner)
    }
}

pub fn score(rules: &Rules, p: &Prepared) -> Scored {
    let mut s = Scored::default();
    for hit in rules.field_matcher.find(Texts {
        display: &p.display,
        code: &p.code,
    }) {
        let table = &rules.fields[hit.table];
        let clue = &table.clues[hit.clue];
        s.add(table.ty, clue.score, clue.id.as_str(), Some(hit.channel));
    }
    for table in &rules.fields {
        for token in &p.autocomplete {
            for w in table.autocomplete.iter().filter(|w| w.matches(token)) {
                s.add(table.ty, w.score, w.id.as_str(), None);
            }
        }
        if let Some(w) = table.element_weight(p.element) {
            s.add(table.ty, w.score, w.id.as_str(), None);
        }
        for w in table.input_modes.iter().filter(|w| w.mode == p.input_mode) {
            s.add(table.ty, w.score, w.id.as_str(), None);
        }
    }
    // Shape alone (a short numeric box) is also a birth year, zip or amount,
    // so it only strengthens a code field that text or autocomplete already
    // pointed at.
    if s.get(FieldType::OneTimeCode) > 0 {
        if p.element == Element::Number {
            s.add(FieldType::OneTimeCode, 2, "shape:otp-number", None);
        }
        if p.input_mode == "numeric" {
            s.add(FieldType::OneTimeCode, 1, "shape:otp-numeric", None);
        }
        if (4..=8).contains(&p.max_len) && p.element != Element::Password {
            s.add(FieldType::OneTimeCode, 2, "shape:otp-length", None);
        }
    }
    s
}
