//! Where the quick panel opens, from headless `--panel` runs against
//! scripted displays and a pointer: Rune resolves `place()` against them and
//! records the result as `placed` in `--tree`.

#![cfg(test)]

use std::process::Command;

use deadbolt_app::panel;
use serde_json::{Value, json};

/// A 14-inch laptop as the primary display, and a 1080p display to its right
/// whose top sits 100 pt higher.
fn displays() -> Value {
    json!([
        {"id": 1, "frame": [0, 0, 1512, 982], "scale": 2, "primary": true},
        {"id": 7, "frame": [1512, -100, 1920, 1080], "scale": 1}
    ])
}

/// Where `--panel` places the panel with the pointer at `pointer`: the
/// display's id and the window's frame in global points. None without a GPU
/// to run headless on.
fn placed(pointer: [f64; 2]) -> Option<(u64, [f64; 4])> {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("script.json");
    let tree = dir.path().join("tree.json");
    let desktop = json!({"displays": displays(), "pointer": pointer, "events": []});
    std::fs::write(&script, desktop.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_deadbolt-app"))
        .args(["--window", "panel", "--panel", "--frames", "2", "--script"])
        .arg(&script)
        .arg("--tree")
        .arg(&tree)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && stderr.contains("no GPU adapter") {
        eprintln!("skipped: headless runs need a GPU ({stderr})");
        return None;
    }
    assert!(out.status.success(), "{stderr}");
    let tree: Value = serde_json::from_slice(&std::fs::read(&tree).unwrap()).unwrap();
    let placed = &tree["placed"];
    let frame = placed["frame"].as_array().expect("placed");
    let frame = [0, 1, 2, 3].map(|i| frame[i].as_f64().unwrap());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rune-placed "), "{stdout}");
    Some((placed["display"].as_u64().unwrap(), frame))
}

/// The frame centred on a display at `[x, y, width, _]`, its top 160 pt down.
fn centred(display: [f64; 4]) -> [f64; 4] {
    let (w, h) = (f64::from(panel::SIZE.0), f64::from(panel::SIZE.1));
    [
        display[0] + (display[2] - w) / 2.0,
        display[1] + 160.0,
        w,
        h,
    ]
}

#[test]
fn it_opens_on_the_display_under_the_pointer() {
    let Some(laptop) = placed([800.0, 400.0]) else {
        return;
    };
    assert_eq!(laptop, (1, centred([0.0, 0.0, 1512.0, 982.0])));
    let external = placed([2000.0, 300.0]).unwrap();
    assert_eq!(external, (7, centred([1512.0, -100.0, 1920.0, 1080.0])));
}

/// A pointer on no display (it was just unplugged): the primary display.
#[test]
fn it_falls_back_to_the_primary_display() {
    let Some(placed) = placed([-500.0, -500.0]) else {
        return;
    };
    assert_eq!(placed, (1, centred([0.0, 0.0, 1512.0, 982.0])));
}
