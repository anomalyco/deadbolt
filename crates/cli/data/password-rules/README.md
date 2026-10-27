# Password rules

`password-rules.json` is `quirks/password-rules.json` from Apple's
[password-manager-resources](https://github.com/apple/password-manager-resources)
at commit `d158201a3c67899494b1beea0a6c016a44d835d5` (2026-10-27), unchanged,
under the MIT license in `LICENSE.md`. The agent compiles it in
(`crates/cli/src/agent/generate.rs`) and never downloads it. To update, copy
the file from a newer commit and change the commit above.
