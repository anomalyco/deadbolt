# Desktop app

2026-10-22. Plan and first slice of Deadbolt's desktop UI, built in [Rune](https://github.com/anomalyco/rune). Questions for Kit are marked **Open**.

## Architecture

- **A thin client of the agent.** The app speaks the agent's socket protocol, as the CLI does, and starts the agent if none runs. It holds no keys and reads no store files: unlock, items, devices and pairing are all agent requests. Quitting the app leaves the agent (and its unlock) running.
- **`crates/client` (`deadbolt-client`)** holds what both clients need: the protocol types, where the files live (`Paths`) and the client (`call`, `status`, `ensure_running`, `stop`). The CLI wraps it in `crates/cli/src/client.rs` and behaves as before. `Launch { program, version }` says which binary runs the agent: the CLI passes itself and its build (so an agent of another build is replaced), the app passes `deadbolt` and no version (any agent speaking the protocol will do).
- **`crates/app` (`deadbolt-app`)** is a workspace member. Rune and rune-kit are git dependencies pinned to one rev (`3e5a158`), bumped deliberately by changing both `rev`s in `crates/app/Cargo.toml`. `deny.toml` allows that one git source, BSL-1.0 (arboard's Windows backend) and the unmaintained ttf-parser under winit; CI installs `libwayland-dev` on Linux.
- **Finding the agent binary:** `DEADBOLT_BIN`, else `deadbolt` next to the app's executable (the bundle will ship it there), else `/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`, else `PATH`. Apps opened from the Finder get a minimal `PATH`, hence the fixed places.
- **Threads:** one worker thread runs agent requests in order on a current-thread Tokio runtime and wakes the window when a reply lands. The UI drains replies in Rune's `poll`; nothing polls the socket. A status request every 10 s while unlocked notices a lock from the CLI or the idle timeout (`status` doesn't reset the idle timer).
- **Secrets in the app:** the passphrase field edits a mask of dots; the passphrase lives in a `Zeroizing<String>` all the way to the socket (the protocol's passphrase fields and the request buffer are wiped too) and copy, cut and undo do nothing. Item values are fetched one item at a time (`item-get`) and wiped when the selection changes, the store locks or the window closes. Copies are written with clipboard history exclusion (`org.nspasteboard.ConcealedType` on macOS) through one clipboard handle kept open for the app's life (on X11 the process serves the selection), and cleared after 30 s, or on lock and quit, only if the clipboard still holds them.
- **Keys:** the search field and the passphrase field handle their own keys (`on_input_key`) and get focus by rendering with `focused: true`; the window's `on_key` handles only ⌘L. This keeps working when Rune sends keys to the focused element before the window.
- **Look:** Deadbolt's own theme (`crates/app/assets/theme.json`): the site's black, white and red, paper `#e8e4dc` for light, IBM Plex Mono for everything, small radii, flat surfaces with hairline rings. `src/theme.rs` maps it onto rune-kit's tokens.

## Screens

| Screen | v1 | Later |
|---|---|---|
| First run | "Set up this device" pointing at `deadbolt init` / `join`, with Check again | Create a vault (device name, passphrase twice, strength) and Join (shows QR + ticket, then the 6-digit code to confirm) in the app |
| Unlock | Passphrase, Enter or Unlock; wrong passphrase says so in place and keeps focus | Touch ID once the agent stores the unlock key in the keychain (design.md) |
| List | Search-first: the field is focused, typing filters live, ↑↓ select, rows show label and username or expiry | Vault switcher, favourites, sort by recently used, agent-side search over URL host and cardholder |
| Item detail | Fields in schema order, secrets masked with Show, Copy per field, notes wrap | TOTP codes with their own countdown, open URL, password age |
| Copy | "Password copied · clears in 0:28" with a bar that empties, then "Clipboard cleared" | Configurable timeout, "copy and paste into the previous app" |
| Add / edit | — (CLI: `deadbolt new`, `set`) | Add login or card from the schema, edit in place, delete with confirm in place and a dim red surface |
| Generate | — (CLI generates when `password=` is omitted) | Length and symbols, regenerate, used by Add |
| Devices | — (CLI: `devices`, `pair`, `devices remove`) | List with presence; Add device (paste the new device's ticket, confirm the code); remove with confirm in place |
| Import | — (CLI: `import bitwarden`) | Pick a Bitwarden export, show counts, import |
| Lock | ⌘L or the lock button; clears our clipboard copy and forgets every value | Lock on sleep or screen lock |
| Errors, empty | Can't reach the agent (with the reason and Try again); no items; no matches; agent errors inline | Agent version mismatch help |

## Keyboard

Search first. The search field always has focus while unlocked.

| Key | Does |
|---|---|
| typing | filters (every word must match label, username/expiry, type or short id) |
| ↑ ↓ | move the selection (instant) |
| ↵ | copy the password (card: number) |
| ⇧↵ | copy the username |
| esc | clear the search |
| ⌘L | lock |
| ↵ on Unlock | unlock |

**Open:** ⌘C to copy the password when the search has no selection, as 1Password does? ⌘1–9 for the first rows?

## Motion

Rune's runtime already enforces no first-paint animation, reduced motion (travel off, short fade kept) and retargeting mid-flight.

| Change | Who causes it | Motion |
|---|---|---|
| Locked ↔ vault, any whole-screen change | user or agent | whole-state replacement: blur 4, scale .96, fade; enter `.3/0`, exit `.24/0`, the new screen enters on the frame the old one starts to leave |
| Typing filters the list | dependent on typing | rows that stay slide on `.4/0` and never blur; rows that leave or arrive fade in place (blur 3, scale .96, `.3/0` in, `.25/0` out) |
| ↑↓ selection, the selected item's fields | user's hand | instant |
| Copy icon → check | user | in-place replacement `.3/0` |
| Copy notice | user | rises 12 pt with a fade `.3/0`; text swaps by replacement; leaves the way it came, shorter |
| Countdown | time | the bar's width is a `rune::Live` set every 100 ms and smoothed on `.12/0`, so it empties without rebuilding the view; the text rebuilds once a second. Plex Mono's digits are all one width, so nothing shakes |
| Unlock error | agent | fades in |
| Hover | pointer | in 0 ms, out on Rune's snap |

## Breadboard

The main flows, as states (see the PR for the chat version):

1. Launch → agent starting ("Starting Deadbolt…") → locked or first-run.
2. Locked: type the passphrase → ↵ → vault, or the error in place.
3. Vault: type "git" → list narrows → ↵ → "Password copied · clears in 0:30" → 30 s → "Clipboard cleared" → notice leaves.
4. ⌘L → locked; the clipboard copy is gone.
5. Later: Devices → Add device → paste ticket → both screens show 482 913 → Confirm → device appears in the list.

## Open decisions

1. **Clipboard timeout:** 30 s now. 1Password uses 90 s, KeePassXC 10 s. Configurable?
2. **Where unlock lives:** the agent's idle timeout locks for both clients. Should the app offer its own timeout or lock on sleep, or should that be agent config only?
3. **First run in the app or the CLI:** v1 sends people to `deadbolt init`. Creating a vault and joining in the app is the onboarding and gets the most care; when?
4. **Bundling:** ship `deadbolt` inside `Deadbolt.app` (and start the agent from there), or require the CLI install?
5. **Window model:** a normal window now. A menu-bar / quick-access panel (global shortcut, search, ↵ copies, dismiss) may fit "open it every day" better.
6. **Live updates:** items synced from another device appear on the next list load. Add a `watch` command to the protocol that streams lock and item changes?
7. **Look:** the site's palette and Plex Mono now. Anton for the wordmark on the lock screen?

## Rune gaps (for the Rune team)

- **Secure text entry.** `TextEdit`/`text_input` have no password mode: the text is shown and kept in an undo history (`edit.rs` `History`), Cmd+C/X copy it, and IME preedit shows composed text in clear. Wanted: `text_input(..).secure()` that draws dots, keeps no history, refuses copy/cut, disables IME (macOS `EnableSecureEventInput` while focused) and zeroizes on drop. The app works around it in `crates/app/src/secret.rs`.
- **Secret clipboard writes.** `Tx::copy` can't mark a copy concealed or clear it later. Wanted: `Tx::copy_secret(text, clear_after)` that excludes it from clipboard history and clears it only if unchanged. The app uses `arboard` directly.
- **Tabular figures.** `TextStyle` has no font features (`tnum`). Not a problem with Plex Mono, but any proportional font needs digit cells laid out by hand.
- **Linear tracks.** `Live` plus `wake_after` drives the countdown bar without rebuilding, but the app still sets it 10 times a second. A linear tween run by the render thread ("go from 272 to 0 over 30 s") would need no app ticks.
- **Nested `clip_fade` washes out text.** A descendant takes the max fade width per side from its ancestors but applies it to its own, smaller clip rect (`runtime.rs` ~2361). A row label with a right-edge fade inside a list with 12/16 pt top/bottom fades gets those fades over its own 20 pt line, so the whole label goes faint and soft. The list has no soft edges for now.
- **Symbol fallback.** Fallback fonts are registered only for CJK scripts, so ⌘ ⇧ ↵ in a font without them (Plex Mono) draw as tofu, including in `rune_kit::Keybind`. The app draws its own keycaps with SVG icons.
- **Theme to kit.** No helper builds a `rune_kit::Kit` from theme data; the app mutates `Kit::neutral` field by field (about 60 tokens). The glyph set also has no lock or eye; the app hand-writes those SVGs.
- **`AppSpec::default()`** doesn't exist at this rev, so `spec()` lists every field; it moves to `..AppSpec::default()` when that lands.
- **Rolling labels.** No roll primitive for "Copy" → "Copied" or changing digits (`@kitlangton/rolling-number`); the app swaps icons by replacement.
- **Ellipsis by default.** `truncate()` ends in "…"; the app wraps lines in `clip_fade` rows to get the fade the UI guide prefers.
- **`rune_kit::TextInput` can't animate dependent layout** (`animate_edit_layout`), so the search field is built from `text_input` directly.
- **System reduced motion.** `Env` has no reduced-motion flag from the OS; the app takes `--reduced-motion`.
- **Window focus events** (to refresh status and the list when the window comes forward) aren't exposed to the app.

## Run, test, snapshot

```sh
cargo run --release -p deadbolt-app     # against your agent (starts it if needed)
cargo test -p deadbolt-cli -p deadbolt-app   # the real-agent test uses the deadbolt cargo built (or DEADBOLT_BIN)
crates/app/scripts/snap.sh              # headless PNGs of every scene into crates/app/snaps/
cargo run -p deadbolt-app -- --scene copied --at 2.4 --snap copied.png   # one scene; --theme light, --reduced-motion
```

Scenes (`--scene`): `connecting`, `setup`, `failed`, `locked`, `locked-error`, `vault`, `search`, `copied`, `revealed`, `empty`. They use synthetic data. Any tooling run (`--snap`, `--tree`, `--trace`, `--frames`, `--script`, `--scene`, …) gets no agent and an in-memory clipboard, so its output can't hold real items.
