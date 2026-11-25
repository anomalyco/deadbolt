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
         With the words and a copy of the vault's frames (another device, or a\n\
         remote set with `deadbolt remote set`), `deadbolt recover` brings the\n\
         vault back if every device is lost.\n"
    ));
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_kit_shows_every_word_numbered() {
        let words: Vec<String> = (0..24).map(|i| format!("w{i}")).collect();
        let text = super::kit_text("abcd", &words.join(" "));
        assert!(text.contains(" 1. w0 ") && text.contains("24. w23"));
        assert!(text.contains("Vault id: abcd"));
        assert_eq!(text.lines().filter(|l| l.contains(". w")).count(), 4);
    }
}
