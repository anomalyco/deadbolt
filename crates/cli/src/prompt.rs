//! Input for an agent-first CLI. Everything can be supplied with flags, env
//! or stdin. Only when stdin and stderr are both terminals ([`interactive`])
//! may the CLI prompt, and only to fill something that would otherwise be an
//! error ([`fill`]); supplied input is never asked for again.

use std::io::{BufRead, IsTerminal, Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use zeroize::Zeroizing;

/// Whether prompting is allowed: stdin and stderr are both terminals.
pub fn interactive() -> bool {
    allowed(
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn allowed(stdin_tty: bool, stderr_tty: bool) -> bool {
    stdin_tty && stderr_tty
}

/// Supplied input wins; otherwise ask when `interactive`, else fail with
/// `missing`.
pub fn fill<T>(
    supplied: Option<T>,
    interactive: bool,
    ask: impl FnOnce() -> Result<T>,
    missing: impl FnOnce() -> anyhow::Error,
) -> Result<T> {
    match supplied {
        Some(value) => Ok(value),
        None if interactive => ask(),
        None => Err(missing()),
    }
}

/// The passphrase: one line of stdin with `--passphrase-stdin`, else
/// `DEADBOLT_PASSPHRASE`, else asked (twice with `confirm`) on a terminal.
pub fn passphrase(from_stdin: bool, confirm: bool) -> Result<Zeroizing<String>> {
    let supplied = if from_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading the passphrase from stdin")?;
        Some(Zeroizing::new(strip_newline(&line).to_string()))
    } else {
        std::env::var("DEADBOLT_PASSPHRASE")
            .ok()
            .map(Zeroizing::new)
    };
    let passphrase = fill(
        supplied,
        interactive(),
        || ask_passphrase(confirm),
        || anyhow!("a passphrase is needed: set DEADBOLT_PASSPHRASE or pass --passphrase-stdin"),
    )?;
    if passphrase.is_empty() {
        bail!("the passphrase cannot be empty");
    }
    Ok(passphrase)
}

fn ask_passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(rpassword::prompt_password("passphrase: ")?);
    if confirm && !first.is_empty() {
        let second = Zeroizing::new(rpassword::prompt_password("repeat passphrase: ")?);
        if first != second {
            bail!("the passphrases do not match");
        }
    }
    Ok(first)
}

fn strip_newline(text: &str) -> &str {
    let text = text.strip_suffix('\n').unwrap_or(text);
    text.strip_suffix('\r').unwrap_or(text)
}

/// All of stdin, without one trailing newline.
pub fn stdin_value() -> Result<Zeroizing<String>> {
    let mut text = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut text)
        .context("reading stdin")?;
    Ok(Zeroizing::new(strip_newline(&text).to_string()))
}

/// Asks for a value on the terminal, without echo if `hidden`.
pub fn ask_value(label: &str, hidden: bool) -> Result<Zeroizing<String>> {
    let prompt = format!("{label}: ");
    let value = if hidden {
        rpassword::prompt_password(prompt)?
    } else {
        read_line(&prompt)?.unwrap_or_default()
    };
    Ok(Zeroizing::new(value))
}

fn read_line(prompt: &str) -> Result<Option<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading stdin")?;
    Ok((read > 0).then(|| strip_newline(&line).to_string()))
}

/// Asks a yes/no question on the terminal; anything but y/yes is no.
pub fn confirm(question: &str) -> Result<bool> {
    let answer = read_line(&format!("{question} [y/N] "))?.unwrap_or_default();
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// The device name: the flag, else the hostname.
pub fn device_name(flag: Option<String>) -> String {
    flag.unwrap_or_else(hostname)
}

fn hostname() -> String {
    let uname = rustix::system::uname();
    let name = uname.nodename().to_string_lossy().trim().to_string();
    if name.is_empty() {
        "device".into()
    } else {
        name
    }
}

const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
pub const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

fn random_index(n: usize) -> usize {
    // Rejection sampling keeps every index equally likely.
    let limit = 256 - 256 % n;
    loop {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).expect("OS random number generator failed");
        if (byte[0] as usize) < limit {
            return byte[0] as usize % n;
        }
    }
}

/// A random password from the OS random number generator, containing at
/// least one character of every class used.
pub fn generate_password(length: usize, symbols: bool) -> Result<Zeroizing<String>> {
    if !(8..=256).contains(&length) {
        bail!("--length must be between 8 and 256");
    }
    let classes: Vec<&[u8]> = if symbols {
        vec![LETTERS, DIGITS, SYMBOLS]
    } else {
        vec![LETTERS, DIGITS]
    };
    let alphabet: Vec<u8> = classes.concat();
    loop {
        let password: Zeroizing<String> = Zeroizing::new(
            (0..length)
                .map(|_| alphabet[random_index(alphabet.len())] as char)
                .collect(),
        );
        if classes
            .iter()
            .all(|class| password.bytes().any(|b| class.contains(&b)))
        {
            return Ok(password);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_only_with_two_terminals() {
        assert!(allowed(true, true));
        assert!(!allowed(true, false));
        assert!(!allowed(false, true));
        assert!(!allowed(false, false));
    }

    #[test]
    fn fill_prefers_supplied_then_asks_then_fails() {
        let never = || -> Result<u8> { panic!("asked although supplied") };
        let missing = || anyhow!("missing");
        assert_eq!(fill(Some(1), true, never, missing).unwrap(), 1);
        assert_eq!(fill(Some(1), false, never, missing).unwrap(), 1);
        assert_eq!(fill(None, true, || Ok(2), missing).unwrap(), 2);
        let err = fill(None, false, || -> Result<u8> { panic!("asked") }, missing);
        assert_eq!(err.unwrap_err().to_string(), "missing");
    }

    #[test]
    fn generated_passwords() {
        let password = generate_password(24, true).unwrap();
        assert_eq!(password.len(), 24);
        assert!(password.bytes().any(|b| SYMBOLS.contains(&b)));
        let plain = generate_password(40, false).unwrap();
        assert!(plain.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert!(generate_password(4, true).is_err());
        assert_ne!(*generate_password(24, true).unwrap(), *password);
    }

    #[test]
    fn strips_one_newline() {
        assert_eq!(strip_newline("a\n\n"), "a\n");
        assert_eq!(strip_newline("a\r\n"), "a");
        assert_eq!(strip_newline("a"), "a");
    }
}
