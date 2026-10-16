//! Terminal prompts. `DEADBOLT_PASSPHRASE` replaces the passphrase prompt for
//! headless use.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

pub fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(passphrase) = std::env::var("DEADBOLT_PASSPHRASE") {
        return Ok(Zeroizing::new(passphrase));
    }
    if !std::io::stdin().is_terminal() {
        bail!("no terminal to ask for the passphrase; set DEADBOLT_PASSPHRASE");
    }
    let first = Zeroizing::new(rpassword::prompt_password("passphrase: ")?);
    if first.is_empty() {
        bail!("the passphrase cannot be empty");
    }
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password("repeat passphrase: ")?);
        if first != second {
            bail!("the passphrases do not match");
        }
    }
    Ok(first)
}

fn read_line(prompt: &str) -> Result<Option<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading stdin")?;
    Ok((read > 0).then(|| line.trim().to_string()))
}

/// Asks a yes/no question; anything but y/yes is no.
pub fn confirm(question: &str) -> Result<bool> {
    // Hidden, for tests only.
    if std::env::var_os("DEADBOLT_TEST_AUTO_CONFIRM").is_some() {
        eprintln!("{question} [y/N] y");
        return Ok(true);
    }
    let answer = read_line(&format!("{question} [y/N] "))?.unwrap_or_default();
    Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// The device name: the flag, else asked on a terminal, else the hostname.
pub fn device_name(flag: Option<String>) -> Result<String> {
    if let Some(name) = flag {
        return Ok(name);
    }
    let default = hostname();
    let interactive =
        std::io::stdin().is_terminal() && std::env::var_os("DEADBOLT_PASSPHRASE").is_none();
    if !interactive {
        return Ok(default);
    }
    let answer = read_line(&format!("device name [{default}]: "))?.unwrap_or_default();
    Ok(if answer.is_empty() { default } else { answer })
}

fn hostname() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname NUL-terminates
    // within it on success.
    let ok = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } == 0;
    let name = if ok {
        let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
        String::from_utf8_lossy(&buffer[..end]).trim().to_string()
    } else {
        String::new()
    };
    if name.is_empty() {
        "device".into()
    } else {
        name
    }
}
