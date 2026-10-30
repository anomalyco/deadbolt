//! Item tags, nested `/` paths, and `#tag` / `is:favorite` query parsing.
//!
//! Tags are UTF-8 labels of 1–128 characters whose `/`-separated segments are
//! non-empty and trimmed (`work`, `work/aws`, `Tax 2026`). Matching and
//! per-item deduplication are case-insensitive while preserving display case.

use std::collections::{BTreeMap, BTreeSet};

/// Longest tag, in Unicode scalar values.
pub const MAX_TAG_LEN: usize = 128;

/// Most tags one item may hold when created or edited locally.
pub const MAX_TAGS: usize = 64;

/// Case-folded key for deduplicating and comparing tags.
pub fn fold_tag(tag: &str) -> String {
    tag.to_lowercase()
}

/// Whether `tag` is in canonical valid form: 1–128 characters, no control
/// characters, does not start with `#`, and every `/`-separated segment is
/// non-empty, trimmed, and uses single ASCII spaces only.
pub fn valid_tag(tag: &str) -> bool {
    let count = tag.chars().count();
    if !(1..=MAX_TAG_LEN).contains(&count)
        || tag.starts_with('#')
        || tag.chars().any(char::is_control)
    {
        return false;
    }
    tag.split('/').all(|seg| {
        !seg.is_empty()
            && seg.trim() == seg
            && !seg.contains("  ")
            && !seg.chars().any(|c| c.is_whitespace() && c != ' ')
    })
}

/// Normalizes user-typed tag input (`" #work / aws "` -> `"work/aws"`).
/// Returns `None` if empty, over [`MAX_TAG_LEN`], or containing an empty `/`
/// segment such as `"work/"` or `"work//aws"`.
pub fn normalize_tag(raw: &str) -> Option<String> {
    let body = raw.trim().strip_prefix('#').unwrap_or(raw).trim();
    if body.is_empty() {
        return None;
    }
    let mut segments = Vec::new();
    for part in body.split('/') {
        let seg = part
            .split(|c: char| c.is_whitespace() || c.is_control())
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if seg.is_empty() {
            return None;
        }
        segments.push(seg);
    }
    let out = segments.join("/");
    valid_tag(&out).then_some(out)
}

/// Normalizes a tag or folder name from an external export (1Password,
/// Bitwarden, CSV): drops empty `/` segments, strips leading `#` and control
/// characters, collapses whitespace, and truncates cleanly at [`MAX_TAG_LEN`].
pub fn import_tag(raw: &str) -> Option<String> {
    let body = raw.trim().strip_prefix('#').unwrap_or(raw);
    let segments: Vec<String> = body
        .split('/')
        .map(|part| {
            part.split(|c: char| c.is_whitespace() || c.is_control())
                .filter(|w| !w.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|seg| !seg.is_empty())
        .collect();
    if segments.is_empty() {
        return None;
    }
    let mut out = segments.join("/");
    if out.chars().count() > MAX_TAG_LEN {
        let truncated: String = out.chars().take(MAX_TAG_LEN).collect();
        out = truncated
            .trim_end_matches(|c: char| c == '/' || c.is_whitespace())
            .split('/')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
    }
    let out = out.trim_start_matches('#').trim().to_string();
    valid_tag(&out).then_some(out)
}

/// Whether `item_tag` matches `filter` on `/` segment boundaries
/// (`work` matches `work` and `work/aws`, never `network`), case-insensitively.
/// A hyphenated filter (`#tax-2026`) also matches spaces (`Tax 2026`).
pub fn tag_matches(item_tag: &str, filter: &str) -> bool {
    let filter = filter
        .trim()
        .strip_prefix('#')
        .unwrap_or(filter)
        .trim()
        .trim_matches('/');
    let fl = fold_tag(filter);
    if fl.is_empty() {
        return false;
    }
    let it = fold_tag(item_tag);
    let prefix_match = |needle: &str| {
        it == needle
            || it
                .strip_prefix(needle)
                .is_some_and(|rest| rest.starts_with('/'))
    };
    if prefix_match(&fl) {
        return true;
    }
    if !fl.contains(' ') && fl.contains('-') && it.contains(' ') {
        let spaced = fl.replace('-', " ");
        return prefix_match(&spaced);
    }
    false
}

/// Whether any tag in `tags` matches `filter` ([`tag_matches`]).
pub fn item_has_tag<'a>(tags: impl IntoIterator<Item = &'a str>, filter: &str) -> bool {
    tags.into_iter().any(|t| tag_matches(t, filter))
}

/// Every ancestor prefix and the tag itself: `"work/aws/prod"` yields
/// `"work"`, `"work/aws"`, `"work/aws/prod"`.
pub fn ancestors(tag: &str) -> impl Iterator<Item = &str> {
    let slashes = tag
        .char_indices()
        .filter_map(|(i, c)| (c == '/').then_some(i));
    slashes
        .chain(std::iter::once(tag.len()))
        .map(move |end| &tag[..end])
}

/// Distinct tags and parent prefixes across items, with how many items match
/// each, sorted case-insensitively.
pub fn tag_counts<'a, I, T>(items: I) -> Vec<(String, usize)>
where
    I: IntoIterator<Item = T>,
    T: IntoIterator<Item = &'a str>,
{
    let mut counts: BTreeMap<String, (String, usize, bool)> = BTreeMap::new();
    for item_tags in items {
        let mut seen_in_item = BTreeSet::new();
        for tag in item_tags {
            for (prefix, exact) in ancestors(tag).map(|p| (p, p.len() == tag.len())) {
                let key = fold_tag(prefix);
                let entry =
                    counts
                        .entry(key.clone())
                        .or_insert_with(|| (prefix.to_string(), 0, exact));
                if exact && !entry.2 {
                    entry.0 = prefix.to_string();
                    entry.2 = true;
                }
                if seen_in_item.insert(key) {
                    entry.1 += 1;
                }
            }
        }
    }
    counts
        .into_values()
        .map(|(display, count, _)| (display, count))
        .collect()
}

/// Parsed search input: plain words, `#tag` filters, `is:favorite`, and
/// whether a trailing bare `#` asks for any tagged item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub words: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub any_tag: bool,
}

impl Query {
    /// Parses a free-text search string (`#work/aws #"Tax 2026" is:favorite github`).
    pub fn parse(text: &str) -> Self {
        let mut out = Self::default();
        let mut chars = text.char_indices().peekable();
        while let Some(&(start, ch)) = chars.peek() {
            if ch.is_whitespace() {
                chars.next();
                continue;
            }
            if text[start..].starts_with("#\"") {
                chars.next();
                chars.next();
                let inner_start = start + 2;
                let mut inner_end = text.len();
                for (i, c) in chars.by_ref() {
                    if c == '"' {
                        inner_end = i;
                        break;
                    }
                }
                out.push_tag(&text[inner_start..inner_end]);
                continue;
            }
            let mut end = text.len();
            while let Some(&(i, c)) = chars.peek() {
                if c.is_whitespace() {
                    end = i;
                    break;
                }
                chars.next();
            }
            out.push_token(&text[start..end]);
        }
        out
    }

    /// Parses pre-split CLI/protocol query words, where one argument `"#Tax 2026"`
    /// may already contain spaces without inner quotes.
    pub fn from_words(words: &[String]) -> Self {
        let mut out = Self::default();
        for word in words {
            let trimmed = word.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('#') {
                let inner = trimmed[1..].trim().trim_matches('"');
                out.push_tag(inner);
            } else {
                out.push_token(trimmed);
            }
        }
        out
    }

    fn push_tag(&mut self, raw: &str) {
        let clean = raw.trim().trim_matches('/');
        if clean.is_empty() {
            self.any_tag = true;
        } else {
            self.tags.push(clean.to_string());
        }
    }

    fn push_token(&mut self, token: &str) {
        if let Some(rest) = token.strip_prefix('#') {
            self.push_tag(rest.trim_matches('"'));
        } else if matches!(
            token.to_ascii_lowercase().as_str(),
            "is:favorite" | "is:fav" | "is:starred"
        ) {
            self.favorite = true;
        } else {
            self.words.push(token.to_string());
        }
    }
}
