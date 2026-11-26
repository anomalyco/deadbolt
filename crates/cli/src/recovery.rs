//! The recovery kit as `deadbolt init` shows it.

use zeroize::Zeroizing;

/// The kit's words in numbered rows of six, the vault id, and what the kit
/// is for. Shown once; nothing keeps a copy.
pub fn kit_text(vault: &str, words: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    out.push_str(
        "\nRecovery kit: write these 24 words down and keep them somewhere offline.\n\
         They are shown only now.\n\n",
    );
    for (row, chunk) in words.split(' ').collect::<Vec<_>>().chunks(6).enumerate() {
        out.push(' ');
        for (i, word) in chunk.iter().enumerate() {
            out.push_str(&format!(" {:>2}. {word:<9}", row * 6 + i + 1));
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "\nVault id: {vault}\n\
         The words and a copy of the vault's frames bring it back if every\n\
         device is lost.\n"
    ));
    out
}

/// The new vault and its kit as one JSON object, for `deadbolt init --json`.
/// Built in wiped memory, like the text.
pub fn kit_json(
    vault: &str,
    name: &str,
    default: bool,
    words: &str,
) -> serde_json::Result<Zeroizing<String>> {
    #[derive(serde::Serialize)]
    struct Kit<'a> {
        vault: &'a str,
        name: &'a str,
        default: bool,
        recovery_kit: &'a str,
    }
    let mut out = Zeroizing::new(Vec::new());
    serde_json::to_writer(
        &mut *out,
        &Kit {
            vault,
            name,
            default,
            recovery_kit: words,
        },
    )?;
    let text = std::mem::take(&mut *out);
    Ok(Zeroizing::new(String::from_utf8(text).unwrap_or_else(
        |e| String::from_utf8_lossy(e.as_bytes()).into_owned(),
    )))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_json_kit_names_the_vault_and_holds_every_word() {
        let words: Vec<String> = (0..24).map(|i| format!("w{i}")).collect();
        let line = super::kit_json("abcd", "personal", true, &words.join(" ")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["vault"], "abcd");
        assert_eq!(v["name"], "personal");
        assert_eq!(v["default"], true);
        assert_eq!(v["recovery_kit"].as_str().unwrap().split(' ').count(), 24);
    }

    #[test]
    fn the_kit_shows_every_word_numbered() {
        let words: Vec<String> = (0..24).map(|i| format!("w{i}")).collect();
        let text = super::kit_text("abcd", &words.join(" "));
        assert!(text.contains(" 1. w0 ") && text.contains("24. w23"));
        assert!(text.contains("Vault id: abcd"));
        assert_eq!(text.lines().filter(|l| l.contains(". w")).count(), 4);
    }
}
