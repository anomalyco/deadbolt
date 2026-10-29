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

/// The passphrase given without asking: one line of stdin with
/// `--passphrase-stdin`, else `DEADBOLT_PASSPHRASE`. An empty one is refused.
pub fn supplied_passphrase(from_stdin: bool) -> Result<Option<Zeroizing<String>>> {
    let supplied = if from_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading the passphrase from stdin")?;
        Some(Zeroizing::new(strip_newline(&line).to_string()))
    } else {
        crate::config::env("DEADBOLT_PASSPHRASE")
            .ok()
            .map(Zeroizing::new)
    };
    if supplied.as_ref().is_some_and(|p| p.is_empty()) {
        bail!("the passphrase cannot be empty");
    }
    Ok(supplied)
}

/// The passphrase: [`supplied_passphrase`], else asked (twice with
/// `confirm`) on a terminal.
pub fn passphrase(from_stdin: bool, confirm: bool) -> Result<Zeroizing<String>> {
    let passphrase = fill(
        supplied_passphrase(from_stdin)?,
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

/// Asks for a new passphrase on the terminal, typed twice, until it is not
/// empty and both match (three tries).
pub fn new_passphrase(label: &str, again: &str) -> Result<Zeroizing<String>> {
    for _ in 0..3 {
        let first = Zeroizing::new(rpassword::prompt_password(format!("{label}: "))?);
        if first.is_empty() {
            eprintln!("The passphrase cannot be empty.");
            continue;
        }
        let second = Zeroizing::new(rpassword::prompt_password(format!("{again}: "))?);
        if first == second {
            return Ok(first);
        }
        eprintln!("They don't match; try again.");
    }
    bail!("no passphrase was set; nothing was saved on this device")
}

/// Asks to choose one of `options` on the terminal, by number or name;
/// Enter takes the first.
pub fn choose(question: &str, options: &[&str]) -> Result<String> {
    for (i, option) in options.iter().enumerate() {
        eprintln!("  {}) {option}", i + 1);
    }
    let first = options.first().context("nothing to choose from")?;
    let answer = read_line(&format!("{question} [{first}] "))?.unwrap_or_default();
    pick(answer.trim(), options)
}

fn pick(answer: &str, options: &[&str]) -> Result<String> {
    if answer.is_empty() {
        return options
            .first()
            .map(|o| o.to_string())
            .context("nothing to choose from");
    }
    if let Ok(n) = answer.parse::<usize>()
        && let Some(option) = n.checked_sub(1).and_then(|i| options.get(i))
    {
        return Ok(option.to_string());
    }
    options
        .iter()
        .find(|o| **o == answer)
        .map(|o| o.to_string())
        .ok_or_else(|| anyhow!("no vault {answer}"))
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
    Ok(yes(&answer))
}

/// The terminal itself, for questions while stdin carries data.
pub fn tty() -> Result<std::io::BufReader<std::fs::File>> {
    let tty = std::fs::File::open("/dev/tty").context("opening /dev/tty")?;
    Ok(std::io::BufReader::new(tty))
}

/// [`confirm`], reading the answer from `input` (such as [`tty`]).
pub fn confirm_from(question: &str, input: &mut impl BufRead) -> Result<bool> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer).context("reading the answer")?;
    Ok(yes(&answer))
}

fn yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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
    fn picks_by_number_name_or_default() {
        let options = ["personal", "work"];
        assert_eq!(pick("", &options).unwrap(), "personal");
        assert_eq!(pick("2", &options).unwrap(), "work");
        assert_eq!(pick("work", &options).unwrap(), "work");
        assert!(pick("3", &options).is_err());
        assert!(pick("home", &options).is_err());
    }

    #[test]
    fn strips_one_newline() {
        assert_eq!(strip_newline("a\n\n"), "a\n");
        assert_eq!(strip_newline("a\r\n"), "a");
        assert_eq!(strip_newline("a"), "a");
    }
}
