//! Compiles in the Apple team that signs this build (`DEADBOLT_TEAM_ID`), so
//! the agent and its clients know Deadbolt's own code by team and identifier.
//! Empty for ad-hoc builds, which know it by path and code hash instead.

#[expect(
    clippy::disallowed_methods,
    reason = "build script reads the signing identity Cargo was given"
)]
fn main() {
    println!("cargo:rerun-if-env-changed=DEADBOLT_APPLE_TEAM_ID");
    println!("cargo:rerun-if-env-changed=DEADBOLT_APPLE_SIGNING_IDENTITY");
    let given = |name| {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty() && v != "-")
    };
    let identity = given("DEADBOLT_APPLE_SIGNING_IDENTITY");
    let team = given("DEADBOLT_APPLE_TEAM_ID").or_else(|| identity.as_deref().and_then(team_of));
    if let (Some(identity), None) = (&identity, &team) {
        panic!(
            "DEADBOLT_APPLE_SIGNING_IDENTITY ({identity}) names no team: set DEADBOLT_APPLE_TEAM_ID"
        );
    }
    if let Some(team) = &team
        && !(team.len() == 10 && team.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        panic!("{team} isn't an Apple team ID");
    }
    println!(
        "cargo:rustc-env=DEADBOLT_TEAM_ID={}",
        team.unwrap_or_default()
    );
}

/// The team in "Developer ID Application: Name (TEAM123456)".
fn team_of(identity: &str) -> Option<String> {
    let open = identity.rfind('(')?;
    let team = identity.get(open + 1..)?.strip_suffix(')')?;
    Some(team.to_string())
}
