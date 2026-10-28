//! The compiled matcher: every phrase of every table in four Aho-Corasick
//! automata (display words, display letters, code words, code letters), so
//! one scan per text finds all hits.

use std::collections::{BTreeSet, HashMap};

use aho_corasick::AhoCorasick;

use super::{Channel, Clue, Mode};
use crate::text;

/// The texts of one field or form, normalised with [`text::words`] /
/// [`text::code_words`] (padded).
#[derive(Debug, Clone, Copy)]
pub struct Texts<'a> {
    pub display: &'a str,
    pub code: &'a str,
}

/// A clue that matched: `(table, clue)` indexes the tables the matcher was
/// built from; `channel` is `Display` or `Code`, never `Both`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hit {
    pub table: usize,
    pub clue: usize,
    pub channel: Channel,
}

#[derive(Debug, Default)]
struct Builder {
    patterns: Vec<String>,
    refs: Vec<Vec<(usize, usize)>>,
    by_pattern: HashMap<String, usize>,
}

impl Builder {
    fn add(&mut self, pattern: String, target: (usize, usize)) {
        let i = *self.by_pattern.entry(pattern.clone()).or_insert_with(|| {
            self.patterns.push(pattern);
            self.refs.push(Vec::new());
            self.patterns.len() - 1
        });
        if !self.refs[i].contains(&target) {
            self.refs[i].push(target);
        }
    }

    fn build(self) -> Result<Auto, aho_corasick::BuildError> {
        Ok(Auto {
            ac: AhoCorasick::new(&self.patterns)?,
            refs: self.refs,
        })
    }
}

#[derive(Debug)]
struct Auto {
    ac: AhoCorasick,
    refs: Vec<Vec<(usize, usize)>>,
}

impl Auto {
    fn scan(&self, haystack: &str, channel: Channel, out: &mut BTreeSet<Hit>) {
        if self.refs.is_empty() {
            return;
        }
        for m in self.ac.find_overlapping_iter(haystack) {
            for &(table, clue) in &self.refs[m.pattern().as_usize()] {
                out.insert(Hit {
                    table,
                    clue,
                    channel,
                });
            }
        }
    }
}

/// All phrases of a set of tables, compiled.
#[derive(Debug)]
pub struct Matcher {
    display_words: Auto,
    display_letters: Auto,
    code_words: Auto,
    code_letters: Auto,
}

/// Code phrases this long or longer also match inside run-together names.
const CODE_SUBSTRING_MIN: usize = 4;

impl Matcher {
    pub fn build<'a>(
        tables: impl Iterator<Item = &'a [Clue]>,
    ) -> Result<Matcher, aho_corasick::BuildError> {
        let mut display_words = Builder::default();
        let mut display_letters = Builder::default();
        let mut code_words = Builder::default();
        let mut code_letters = Builder::default();
        for (t, clues) in tables.enumerate() {
            for (c, clue) in clues.iter().enumerate() {
                for phrase in &clue.phrases {
                    let cjk = phrase.chars().any(text::is_cjk);
                    let letters = text::squash(phrase);
                    if clue.channel.has_display() {
                        match clue.mode {
                            Mode::Word if cjk => display_words.add(phrase.clone(), (t, c)),
                            Mode::Word => display_words.add(format!(" {phrase} "), (t, c)),
                            Mode::Sanitised => display_letters.add(letters.clone(), (t, c)),
                        }
                    }
                    if clue.channel.has_code() {
                        if clue.mode == Mode::Sanitised
                            || cjk
                            || letters.chars().count() >= CODE_SUBSTRING_MIN
                        {
                            code_letters.add(letters, (t, c));
                        } else {
                            code_words.add(format!(" {phrase} "), (t, c));
                        }
                    }
                }
            }
        }
        Ok(Matcher {
            display_words: display_words.build()?,
            display_letters: display_letters.build()?,
            code_words: code_words.build()?,
            code_letters: code_letters.build()?,
        })
    }

    /// Every clue that matches, once per channel, in table and clue order.
    pub fn find(&self, texts: Texts<'_>) -> Vec<Hit> {
        let mut hits = BTreeSet::new();
        self.display_words
            .scan(texts.display, Channel::Display, &mut hits);
        self.display_letters
            .scan(&text::squash(texts.display), Channel::Display, &mut hits);
        self.code_words.scan(texts.code, Channel::Code, &mut hits);
        self.code_letters
            .scan(&text::squash(texts.code), Channel::Code, &mut hits);
        hits.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clue(phrase: &str, channel: Channel, mode: Mode) -> Clue {
        Clue {
            id: phrase.into(),
            phrases: vec![text::words(phrase).trim().to_owned()],
            score: 1,
            channel,
            mode,
            why: "test".into(),
        }
    }

    #[test]
    fn matches_each_channel_once() {
        let table = vec![
            clue("password", Channel::Both, Mode::Word),
            clue("pwd", Channel::Both, Mode::Word),
            clue("pass", Channel::Display, Mode::Word),
            clue("signin", Channel::Code, Mode::Sanitised),
        ];
        let m = Matcher::build(std::iter::once(table.as_slice())).unwrap();
        let display = text::words("Password password");
        let code = text::code_words("txtPassword user_pwd sign-in");
        let hits = m.find(Texts {
            display: &display,
            code: &code,
        });
        let got: Vec<(usize, Channel)> = hits.iter().map(|h| (h.clue, h.channel)).collect();
        assert_eq!(
            got,
            vec![
                (0, Channel::Display),
                (0, Channel::Code),
                (1, Channel::Code),
                (3, Channel::Code)
            ]
        );
    }

    #[test]
    fn short_code_phrases_need_a_word_boundary() {
        let table = vec![clue("pin", Channel::Code, Mode::Word)];
        let m = Matcher::build(std::iter::once(table.as_slice())).unwrap();
        let spinner = text::code_words("spinner");
        assert!(
            m.find(Texts {
                display: " ",
                code: &spinner
            })
            .is_empty()
        );
        let pin = text::code_words("userPin");
        assert_eq!(
            m.find(Texts {
                display: " ",
                code: &pin
            })
            .len(),
            1
        );
    }
}
