//! The recovery kit and parking from the command line: a stolen device
//! taken out, the kit handed on, and `status`.

use super::*;

#[test]
fn a_stolen_device_is_removed_and_the_kit_rotates() {
    let a = Device::new();
    let b = Device::new();
    let created: serde_json::Value =
        serde_json::from_str(&a.run(&["init", "--device-name", "alpha", "--json"])).unwrap();
    let words = created["recovery_kit"].as_str().unwrap().to_owned();
    pair(&a, &b, "beta", None);
    assert_eq!(a.devices(), ["alpha", "beta"]);

    // beta was stolen: alpha takes it out as of before the theft.
    assert_eq!(
        a.run(&["devices", "remove", "beta", "--stolen"]),
        "removed beta from personal\n"
    );
    assert_eq!(a.devices(), ["alpha"]);
    let out = b.try_run(&["sync"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success() && stdout.contains("rejected"),
        "a removed device no longer syncs: {stdout}"
    );
    let status = a.run(&["status"]);
    assert!(
        status.starts_with("unlocked\npersonal\t") && status.contains("\tok"),
        "{status}"
    );

    // The kit hands on: the new words come back once, the old ones stop.
    let (ok, out, err) = piped(
        &a,
        &["recovery", "rotate", "--words-stdin", "--json"],
        &words,
    );
    assert!(ok, "{err}");
    let rotated: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let new_words = rotated["recovery_kit"].as_str().unwrap();
    assert_eq!(new_words.split(' ').count(), 24);
    assert_ne!(new_words, words);
    let (ok, _, err) = piped(&a, &["recovery", "rotate", "--words-stdin"], &words);
    assert!(!ok && err.contains("recovery"), "{err}");
    let (ok, _, err) = piped(
        &a,
        &["recovery", "rotate", "--words-stdin", "--json"],
        new_words,
    );
    assert!(ok, "{err}");
}
