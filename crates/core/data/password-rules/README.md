# Password rules

`password-rules.json` is `quirks/password-rules.json` from Apple's
[password-manager-resources](https://github.com/apple/password-manager-resources)
at commit `6c0cedf7b5664cfc41bcc0a0d9e59325d0468271` (2026-11-19), unchanged,
under the MIT license in `LICENSE.md`. `deadbolt-core` compiles it in
(`crates/core/src/site_password.rs`) and never downloads it. To update, run
`bun scripts/sync-quirks.ts --latest` (or `--sha <commit>`), which also
updates the commit above.
