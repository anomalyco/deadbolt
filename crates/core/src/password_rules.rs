//! Passwords a web form will take: the `passwordrules` language from Apple's
//! password-manager-resources (also the HTML `passwordrules` attribute), and
//! generation within those rules and a field's own limits.
//!
//! Rules are `name: value` pairs separated by `;`. `required` lists classes
//! a password must use one of each of (one rule per class); `allowed` lists
//! classes it may also use; `minlength`, `maxlength` and `max-consecutive`
//! (the longest run of one character) are numbers. Classes are `upper`,
//! `lower`, `digit`, `special`, `ascii-printable`, `unicode` and custom sets
//! in brackets, such as `[-().&@?'#,/"+]`, where a `]` is written last as
//! `]]`. Unknown rules are ignored, as the format asks. Generated passwords
//! use printable ASCII only, never a space unless a custom set names it.
//!
//! Rules that allow only weak passwords get none: every password generated
//! here draws from at least [`MIN_ALPHABET`] characters and has at least
//! [`MIN_BITS`] of entropy, counted over the passwords the rules and the
//! field allow at the length it's made.

use zeroize::Zeroizing;

use crate::password::{SYMBOLS, random_index};

/// The length a site password gets unless the site's limits say otherwise.
pub const SITE_LENGTH: usize = 20;
/// The lengths a site password may have.
pub const SITE_LENGTHS: std::ops::RangeInclusive<usize> = 4..=256;
/// The least entropy a generated site password may have, in bits.
pub const MIN_BITS: f64 = 60.0;
/// The fewest characters a generated site password may draw from. Fewer
/// can't be made strong by length: no site takes a password long enough.
pub const MIN_ALPHABET: usize = 10;
/// The most `required` classes a site may name.
const MAX_REQUIRED: usize = 12;

/// A set of ASCII characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CharSet(u128);

impl CharSet {
    pub const LOWER: Self = Self::range(b'a', b'z');
    pub const UPPER: Self = Self::range(b'A', b'Z');
    pub const DIGIT: Self = Self::range(b'0', b'9');
    /// Printable ASCII but space, letters and digits.
    pub const SPECIAL: Self =
        Self(Self::range(b'!', b'~').0 & !Self::LOWER.0 & !Self::UPPER.0 & !Self::DIGIT.0);
    /// Printable ASCII, without space.
    pub const PRINTABLE: Self = Self::range(b'!', b'~');

    const fn range(from: u8, to: u8) -> Self {
        let mut bits = 0u128;
        let mut c = from;
        while c <= to {
            bits |= 1 << c;
            c += 1;
        }
        Self(bits)
    }

    /// The printable ASCII characters (space included) in `text`.
    pub fn of(text: &str) -> Self {
        Self::from_bytes(text.as_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self(
            bytes
                .iter()
                .filter(|b| (b' '..=b'~').contains(b))
                .fold(0, |bits, &b| bits | 1 << b),
        )
    }

    pub fn contains(self, c: u8) -> bool {
        c < 128 && self.0 & (1 << c) != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    fn bytes(self) -> Vec<u8> {
        (0u8..128).filter(|&c| self.contains(c)).collect()
    }

    pub fn len(self) -> usize {
        self.0.count_ones() as usize
    }
}

/// What a site asks of a password.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rules {
    /// One character of each.
    pub required: Vec<CharSet>,
    /// Characters it may also have.
    pub allowed: CharSet,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub max_consecutive: Option<usize>,
}

impl Rules {
    /// Parses `passwordrules` text, skipping what it doesn't understand.
    pub fn parse(text: &str) -> Self {
        let mut rules = Self::default();
        let mut chars = text.chars().peekable();
        loop {
            let mut name = String::new();
            while let Some(c) = chars.next_if(|&c| c != ':' && c != ';') {
                name.push(c);
            }
            match chars.next() {
                None => break,
                Some(';') => continue,
                Some(_) => {}
            }
            let mut set = CharSet::default();
            let mut words = vec![String::new()];
            while let Some(c) = chars.next() {
                match c {
                    ';' => break,
                    '[' => set = set.union(custom(&mut chars)),
                    ',' => words.push(String::new()),
                    c => words.last_mut().into_iter().for_each(|w| w.push(c)),
                }
            }
            let words: Vec<String> = words
                .iter()
                .map(|w| w.trim().to_ascii_lowercase())
                .collect();
            let number = words.first().and_then(|w| w.parse::<usize>().ok());
            let named = words.iter().fold(set, |set, w| set.union(class(w)));
            match name.trim().to_ascii_lowercase().as_str() {
                "required" if !named.is_empty() => rules.required.push(named),
                "allowed" => rules.allowed = rules.allowed.union(named),
                "minlength" => rules.min_length = number.max(rules.min_length),
                "maxlength" => rules.max_length = smaller(number, rules.max_length),
                "max-consecutive" => rules.max_consecutive = smaller(number, rules.max_consecutive),
                _ => {}
            }
        }
        rules
    }

    /// Whether any rule says which characters to use.
    pub fn has_classes(&self) -> bool {
        !self.required.is_empty() || !self.allowed.is_empty()
    }
}

fn smaller(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn class(name: &str) -> CharSet {
    match name {
        "upper" => CharSet::UPPER,
        "lower" => CharSet::LOWER,
        "digit" => CharSet::DIGIT,
        "special" => CharSet::SPECIAL,
        "ascii-printable" | "unicode" => CharSet::PRINTABLE,
        _ => CharSet::default(),
    }
}

/// A custom set after its `[`, to the `]` that ends it. As in Apple's
/// parser, a `]` right after that one is a literal `]`, and a `-` counts
/// only first.
fn custom(chars: &mut std::iter::Peekable<std::str::Chars>) -> CharSet {
    let mut set = String::new();
    while let Some(c) = chars.next() {
        if c == ']' {
            if chars.next_if_eq(&']').is_some() {
                set.push(']');
            }
            break;
        }
        if c != '-' || set.is_empty() {
            set.push(c);
        }
    }
    CharSet::of(&set)
}

/// What a form field itself allows: its `minlength` and `maxlength`, and the
/// characters its `pattern` takes, as the page worked them out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Field {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub allowed: Option<CharSet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("no password fits this field's rules")]
    Impossible,
    /// The rules allow passwords, but none strong enough: too few
    /// characters, or too short.
    #[error("this site's rules allow no strong password (at least 60 bits)")]
    Weak,
}

/// What a password for `rules` and `field` is made of.
struct Plan {
    alphabet: CharSet,
    length: usize,
    /// Sets it has a character of each of.
    required: Vec<CharSet>,
    /// The longest run of one character.
    run: usize,
}

impl Plan {
    /// Without classes in the rules, letters, digits and symbols. It has a
    /// character of each class the rules require, and of each of lower,
    /// upper, digit and special that it may use while there's room.
    /// [`SITE_LENGTH`] long if the limits allow it.
    fn new(rules: &Rules, field: Field) -> Result<Self, Refused> {
        let mut alphabet = if rules.has_classes() {
            rules
                .required
                .iter()
                .fold(rules.allowed, |a, &r| a.union(r))
        } else {
            CharSet::LOWER
                .union(CharSet::UPPER)
                .union(CharSet::DIGIT)
                .union(CharSet::from_bytes(SYMBOLS))
        };
        if let Some(only) = field.allowed {
            alphabet = alphabet.intersect(only);
        }
        let min = [rules.min_length, field.min_length]
            .into_iter()
            .flatten()
            .fold(*SITE_LENGTHS.start(), usize::max);
        let max = [rules.max_length, field.max_length]
            .into_iter()
            .flatten()
            .fold(*SITE_LENGTHS.end(), usize::min);
        if alphabet.is_empty() || min > max || rules.required.len() > MAX_REQUIRED {
            return Err(Refused::Impossible);
        }
        let length = SITE_LENGTH.clamp(min, max);
        let mut required = Vec::new();
        for set in &rules.required {
            let set = set.intersect(alphabet);
            if set.is_empty() {
                return Err(Refused::Impossible);
            }
            required.push(set);
        }
        if required.len() > length {
            return Err(Refused::Impossible);
        }
        for set in [
            CharSet::LOWER,
            CharSet::UPPER,
            CharSet::DIGIT,
            CharSet::SPECIAL,
        ] {
            let set = set.intersect(alphabet);
            if required.len() < length && !set.is_empty() && !required.contains(&set) {
                required.push(set);
            }
        }
        let run = rules.max_consecutive.unwrap_or(usize::MAX).max(1);
        let plan = Self {
            alphabet,
            length,
            required,
            run,
        };
        if alphabet.len() < MIN_ALPHABET || plan.bits() < MIN_BITS {
            return Err(Refused::Weak);
        }
        Ok(plan)
    }

    /// The entropy of a password made to this plan, never more than it has:
    /// log2 of how many passwords of its length use only its alphabet and
    /// have a character of each required set, counted by inclusion and
    /// exclusion over the sets a password could miss. With a run limit, it
    /// counts only those with no character twice in a row, which keep to any
    /// limit: exact for runs of one, and less than the real count for longer.
    fn bits(&self) -> f64 {
        let size = self.alphabet.len() as f64;
        let length = self.length as f64;
        let limited = self.run < self.length;
        // Of k characters, how many passwords there are, as a share of those
        // of the whole alphabet: k^length, or k(k-1)^(length-1) with no
        // character twice in a row.
        let share_of = |k: f64| {
            if limited {
                (k / size) * ((k - 1.0).max(0.0) / (size - 1.0)).powf(length - 1.0)
            } else {
                (k / size).powf(length)
            }
        };
        let mut share = 0.0;
        for subset in 0u32..1 << self.required.len() {
            let missed = self
                .required
                .iter()
                .enumerate()
                .filter(|(i, _)| subset & 1 << i != 0)
                .fold(CharSet::default(), |m, (_, &set)| m.union(set));
            let sign = if subset.count_ones() % 2 == 0 {
                1.0
            } else {
                -1.0
            };
            share += sign * share_of(size - missed.len() as f64);
        }
        let all = if limited {
            size.log2() + (length - 1.0) * (size - 1.0).log2()
        } else {
            length * size.log2()
        };
        all + share.max(f64::MIN_POSITIVE).log2()
    }
}

/// How strong a password [`generate`] makes for `rules` and `field` is, in
/// bits, or why it would make none.
pub fn strength(rules: &Rules, field: Field) -> Result<f64, Refused> {
    Ok(Plan::new(rules, field)?.bits())
}

/// A random password following `rules` and `field` (see [`Plan`]), with at
/// least [`MIN_BITS`] of entropy. A space only comes from a custom set
/// naming one.
pub fn generate(rules: &Rules, field: Field) -> Result<Zeroizing<String>, Refused> {
    let Plan {
        alphabet,
        length,
        required,
        run,
    } = Plan::new(rules, field)?;
    let bytes = Zeroizing::new(alphabet.bytes());
    for _ in 0..10_000 {
        let password: Zeroizing<Vec<u8>> = Zeroizing::new(
            (0..length)
                .map(|_| bytes[random_index(bytes.len())])
                .collect(),
        );
        let classes_met = required
            .iter()
            .all(|set| password.iter().any(|&b| set.contains(b)));
        if classes_met && longest_run(&password) <= run {
            return Ok(Zeroizing::new(
                password.iter().map(|&b| char::from(b)).collect(),
            ));
        }
    }
    Err(Refused::Impossible)
}

fn longest_run(bytes: &[u8]) -> usize {
    let mut longest = 0;
    let mut run = 0;
    let mut last = None;
    for &b in bytes {
        run = if last == Some(b) { run + 1 } else { 1 };
        last = Some(b);
        longest = longest.max(run);
    }
    longest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apple_rules() {
        let rules = Rules::parse(
            "minlength: 8; maxlength: 16; required: lower, upper; required: digit; required: [-().&@?'#,/\"+]; max-consecutive: 2;",
        );
        assert_eq!(rules.min_length, Some(8));
        assert_eq!(rules.max_length, Some(16));
        assert_eq!(rules.max_consecutive, Some(2));
        assert_eq!(rules.required.len(), 3);
        assert_eq!(rules.required[0], CharSet::LOWER.union(CharSet::UPPER));
        assert_eq!(rules.required[2], CharSet::of("-().&@?'#,/\"+"));
    }

    #[test]
    fn custom_sets_may_hold_brackets_semicolons_and_commas() {
        let rules = Rules::parse("required: [!#$%&'()+,.:?@[_`~]]; allowed: [;,]; minlength: 9");
        assert_eq!(rules.required, vec![CharSet::of("!#$%&'()+,.:?@[_`~]")]);
        assert_eq!(rules.allowed, CharSet::of(";,"));
        assert_eq!(rules.min_length, Some(9));
        assert_eq!(
            Rules::parse("required: [']]").required,
            vec![CharSet::of("']")]
        );
        // admiral.com's, from Apple's list.
        let admiral = Rules::parse(
            "minlength: 8; required: digit; required: [- !\"#$&'()*+,.:;<=>?@[^_`{|}~]]; allowed: lower, upper;",
        );
        assert_eq!(
            admiral.required[1],
            CharSet::of("- !\"#$&'()*+,.:;<=>?@[^_`{|}~]")
        );
        assert_eq!(admiral.allowed, CharSet::LOWER.union(CharSet::UPPER));
        assert_eq!(admiral.min_length, Some(8));
        assert_eq!(
            Rules::parse("required: [a-z]").required,
            vec![CharSet::of("az")]
        );
        assert_eq!(
            Rules::parse("allowed: lower, [-_]; required: digit").allowed,
            CharSet::LOWER.union(CharSet::of("-_"))
        );
    }

    #[test]
    fn unknown_rules_and_junk_are_ignored() {
        let rules = Rules::parse("frobnicate: 3; required: lower; minlength: lots; nonsense");
        assert_eq!(rules.required, vec![CharSet::LOWER]);
        assert_eq!(rules.min_length, None);
        assert_eq!(Rules::parse(""), Rules::default());
    }

    #[test]
    fn generated_passwords_follow_the_rules() {
        let rules = Rules::parse(
            "minlength: 8; maxlength: 12; required: lower; required: upper; required: digit; required: [!@]; max-consecutive: 1",
        );
        for _ in 0..200 {
            let password = generate(&rules, Field::default()).unwrap();
            assert_eq!(password.len(), 12);
            assert!(password.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(password.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(password.bytes().any(|b| b.is_ascii_digit()));
            assert!(password.bytes().any(|b| b == b'!' || b == b'@'));
            assert!(
                password
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'!' || b == b'@')
            );
            assert_eq!(longest_run(password.as_bytes()), 1);
        }
    }

    #[test]
    fn the_field_limits_length_and_characters() {
        let digits = Field {
            min_length: None,
            max_length: Some(24),
            allowed: Some(CharSet::DIGIT),
        };
        let pin = generate(&Rules::default(), digits).unwrap();
        assert_eq!(pin.len(), SITE_LENGTH);
        assert!(pin.bytes().all(|b| b.is_ascii_digit()));

        let short = generate(
            &Rules::default(),
            Field {
                max_length: Some(16),
                ..Field::default()
            },
        )
        .unwrap();
        assert_eq!(short.len(), 16);
        let long = generate(&Rules::parse("minlength: 32"), Field::default()).unwrap();
        assert_eq!(long.len(), 32);
    }

    #[test]
    fn defaults_use_every_class_and_no_spaces() {
        for _ in 0..200 {
            let password = generate(&Rules::default(), Field::default()).unwrap();
            assert_eq!(password.len(), SITE_LENGTH);
            assert!(password.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(password.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(password.bytes().any(|b| b.is_ascii_digit()));
            assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
            assert!(!password.contains(' '));
        }
        let printable =
            generate(&Rules::parse("allowed: ascii-printable"), Field::default()).unwrap();
        assert!(!printable.contains(' '));
    }

    #[test]
    fn impossible_limits_are_refused() {
        let rules = Rules::parse("minlength: 12; maxlength: 8");
        assert_eq!(generate(&rules, Field::default()), Err(Refused::Impossible));
        let letters = Field {
            allowed: Some(CharSet::LOWER),
            ..Field::default()
        };
        assert_eq!(
            generate(&Rules::parse("required: digit"), letters),
            Err(Refused::Impossible)
        );
        let tiny = Field {
            max_length: Some(3),
            ..Field::default()
        };
        assert_eq!(generate(&Rules::default(), tiny), Err(Refused::Impossible));
    }

    #[test]
    fn weak_rules_get_no_password() {
        let weak = |rules: &str, field: Field| {
            let rules = Rules::parse(rules);
            assert_eq!(strength(&rules, field), Err(Refused::Weak), "{rules:?}");
            assert_eq!(generate(&rules, field), Err(Refused::Weak), "{rules:?}");
        };
        // One character, or a few, at any length.
        weak("allowed: [a]", Field::default());
        weak("allowed: [a]; minlength: 200", Field::default());
        weak("required: [ab]; minlength: 128", Field::default());
        weak("allowed: [abcdefgh]; minlength: 64", Field::default());
        // A four-digit PIN, and six digits.
        let pin = |max| Field {
            max_length: Some(max),
            allowed: Some(CharSet::DIGIT),
            ..Field::default()
        };
        weak("", pin(4));
        weak("", pin(6));
        // Eight lowercase letters is 37.6 bits; ten letters either case 57.
        weak("allowed: lower; maxlength: 8", Field::default());
        weak("allowed: lower, upper; maxlength: 10", Field::default());
        // A field's pattern counts like the rules.
        let short = Field {
            max_length: Some(8),
            allowed: Some(CharSet::LOWER.union(CharSet::DIGIT)),
            ..Field::default()
        };
        weak("", short);
        // 18 digits is 59.8 bits.
        weak("allowed: digit; maxlength: 18", Field::default());
        // No repeats costs a little: 17 of 12 characters is 60.9 bits, 58.9
        // with none twice in a row.
        let twelve = Rules::parse("allowed: digit, [ab]; maxlength: 17");
        assert!(strength(&twelve, Field::default()).is_ok());
        weak(
            "allowed: digit, [ab]; maxlength: 17; max-consecutive: 1",
            Field::default(),
        ); // Runs of two: 59.98 bits exactly, so weak, though counting as if
        // runs didn't matter makes it 60.10.
        weak(
            "allowed: digit, [ab]; required: [0]; required: [1]; maxlength: 17; max-consecutive: 2;",
            Field::default(),
        );
    }

    /// How many passwords of `length` from `size` characters have a run of at
    /// most `run` and a character of each of `required` (as offsets in the
    /// alphabet), by brute force.
    fn count(size: u8, length: u32, run: usize, required: &[&[u8]]) -> f64 {
        let mut n = 0u64;
        let mut password = vec![0u8; length as usize];
        for code in 0..(size as u64).pow(length) {
            let mut c = code;
            for p in password.iter_mut() {
                *p = (c % size as u64) as u8;
                c /= size as u64;
            }
            if longest_run(&password) <= run
                && required
                    .iter()
                    .all(|set| password.iter().any(|b| set.contains(b)))
            {
                n += 1;
            }
        }
        n as f64
    }

    #[test]
    fn strength_is_never_more_than_the_passwords_counted_one_by_one() {
        // Ten digits, the one and the zero required, six long.
        let digits = |run: usize| Plan {
            alphabet: CharSet::DIGIT,
            length: 6,
            required: vec![CharSet::of("0"), CharSet::of("1")],
            run,
        };
        let required: &[&[u8]] = &[&[0], &[1]];
        for run in 1..=6 {
            let exact = count(10, 6, run, required).log2();
            let bits = digits(run).bits();
            assert!(bits <= exact + 1e-9, "run {run}: {bits} over {exact}");
            if run == 1 || run == 6 {
                assert!(
                    (bits - exact).abs() < 1e-9,
                    "run {run}: {bits}, exactly {exact}"
                );
            }
        }
    }

    #[test]
    fn strength_counts_the_alphabet_length_and_required_classes() {
        let bits = |rules: &str, field: Field| strength(&Rules::parse(rules), field).unwrap();
        // 20 of 90 characters, less the strings missing a class: 129.69 bits.
        let default = bits("", Field::default());
        assert!((129.6..129.8).contains(&default), "{default}");
        // 20 digits.
        assert!((bits("allowed: digit", Field::default()) - 20.0 * 10f64.log2()).abs() < 1e-9);
        // 12 of 62 characters, needing all three classes: 71.26 bits, a little under 12 × log2(62).
        let mixed = bits(
            "required: lower; required: upper; required: digit; maxlength: 12",
            Field::default(),
        );
        assert!(mixed < 12.0 * 62f64.log2() && mixed > 70.0, "{mixed}");
        // Lowercase letters and digits, with one of each: eleven is 56.8
        // bits, twelve enough.
        let twelve = Field {
            max_length: Some(12),
            allowed: Some(CharSet::LOWER.union(CharSet::DIGIT)),
            ..Field::default()
        };
        assert!(bits("", twelve) >= MIN_BITS);
        let eleven = Field {
            max_length: Some(11),
            ..twelve
        };
        assert_eq!(strength(&Rules::default(), eleven), Err(Refused::Weak));
    }
}
