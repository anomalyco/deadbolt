# Desktop app

2026-10-22. Plan and first slice of Deadbolt's desktop UI, built in [Rune](https://github.com/anomalyco/rune). Questions for Kit are marked **Open**.

## Architecture

- **A thin client of the agent.** The app speaks the agent's socket protocol, as the CLI does, and starts the agent if none runs. It holds no keys and reads no store files: unlock, items, devices and pairing are all agent requests. Quitting the app leaves the agent (and its unlock) running.
- **`crates/client` (`deadbolt-client`)** holds what both clients need: the protocol types, where the files live (`Paths`) and the client (`call`, `status`, `ensure_running`, `stop`). The CLI wraps it in `crates/cli/src/client.rs`. `Launch { program, version }` says which binary runs the agent; the replacement rule below lets a bundled app coexist with a separately installed CLI.
- **`crates/app` (`deadbolt-app`)** is a workspace member. Rune and rune-kit are git dependencies pinned to one rev (`43ff4f8`, on Rune's `dev` branch), bumped deliberately by changing both `rev`s in `crates/app/Cargo.toml`. `deny.toml` allows that one git source and BSL-1.0 (arboard's Windows backend). Linux needs no Wayland dev package: winit loads libwayland at run time.
- **Finding the agent binary:** in an `.app/Contents/MacOS` directory, always `../Helpers/deadbolt`, even when `DEADBOLT_BIN` or PATH points elsewhere. A missing helper is an error, not a fallback. Outside a bundle: `DEADBOLT_BIN`, an executable sibling (Cargo development), PATH, `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`. Finder launches have a minimal PATH, hence the fallback locations.
- **Threads:** one worker thread runs agent requests in order on a current-thread Tokio runtime and wakes the window when a reply lands. A second thread holds the agent's `watch` stream open and posts each change to the same inbox, reconnecting with backoff (100 ms doubling to 2 s) when the agent restarts; it never starts the agent itself. The UI drains both in Rune's `poll`; nothing polls the socket.
- **Live state:** the agent owns locking (idle timeout, `deadbolt lock`, sleep and screen lock) and the app mirrors it. `locked` or the agent stopping goes to the lock screen and forgets every value; `unlocked` from elsewhere enters the vault; `items` for the shown vault refetches the list, keeping the selection, search and scroll, then the selected item's values in place; `watching` (after each reconnect) and `resync` refetch everything.
- **Secrets in the app:** the passphrase fields are Rune's secure `TextEdit` (dots, no undo history, no copy, cut or IME, the text wiped whenever it's replaced or dropped, macOS Secure Event Input while focused). `src/secret.rs` adds two rules on top: text typed with ⌘ or ⌃ held types nothing, and control characters (a pasted line break, ⇧⏎) are dropped. The passphrase leaves the field into a `Zeroizing<String>` and stays in one all the way to the socket (the protocol's passphrase fields and the request buffer are wiped too). Item values are fetched one item at a time (`item-get`) and wiped when the selection changes, the store locks or the window closes. Copies are written with clipboard history exclusion (`org.nspasteboard.ConcealedType` on macOS) through one clipboard handle kept open for the app's life (on X11 the process serves the selection), and cleared after 30 s, or on lock and quit, only if the clipboard still holds them.
- **Keys:** the search field and the passphrase field handle their own keys (`on_input_key`) and get focus by rendering with `focused: true`; the window's `on_key` handles only ⌘L. This keeps working when Rune sends keys to the focused element before the window.
- **Look:** Deadbolt's own theme (`crates/app/assets/theme.json`): the site's black, white and red, paper `#e8e4dc` for light, IBM Plex Mono for everything but the wordmark, small radii, flat surfaces with hairline rings. `src/theme.rs` maps it onto rune-kit's tokens. The wordmark is Anton (OFL, the site's subset as TTF), on the lock and onboarding screens only, registered through `AppSpec::fonts` and named with `Family::Named("Anton")`; Plex Mono fills both of Rune's slots. Optical sizing is Rune's default (`OpticalSize::Auto`), and changes nothing here: neither face has an `opsz` axis.
- **First run** (`src/onboarding.rs`, `onboarding/{worker,view,qr}.rs`): creating and joining run on their own thread and connection (`onboarding/worker.rs`), beside the request worker, because a join holds its connection for minutes and waits on the person at the screen. The worker reports each stage as it starts, so progress shows only what really happened. It answers the join's code through `deadbolt_client::converse`, whose handler can wait while the socket is still read, so the other device declining ends the wait at once. A device that is set up but holds no vault (a cancelled join) goes back to onboarding without the passphrase step. Cancelling a join while the device is being set up waits for the setup (the agent finishes it even if the app hangs up), so the form never asks for a passphrase that wouldn't be used; a device set up elsewhere meanwhile refuses the new passphrase with a notice instead of keeping the old one silently. The ticket is a capability until it's used or expires: it's held in `Zeroizing` strings, and a copied `deadbolt pair …` leaves the clipboard (if it's still there) when the code shows, the join ends, onboarding is left or the window closes.

## Screens

| Screen | v1 | Later |
|---|---|---|
| First run | Welcome (wordmark, Create or Join). Create: device name (prefilled from the computer's name), vault name, passphrase with a strength meter and a repeat that confirms in place, then honest progress (Argon2, creating), then the moment and the empty vault. Join: device name and passphrase, then the ticket as a QR code and the `deadbolt pair` command to copy, then the six-digit code to compare, then the moment and the synced vault. Cancelling, declining the code, the other device declining, an expired ticket and agent failures each return to the form with a notice coloured by how serious it is (neutral, caution, danger) and what to do next | Scan the QR from a phone app |
| Unlock | Passphrase, Enter or Unlock; wrong passphrase says so in place and keeps focus | Touch ID once the agent stores the unlock key in the keychain (design.md) |
| List | Search-first: the field is focused, typing filters live, ↑↓ select, rows show label and username or expiry | Vault switcher, favourites, sort by recently used, agent-side search over URL host and cardholder |
| Item detail | Fields in schema order, secrets masked with Show, Copy per field, notes wrap | TOTP codes with their own countdown, open URL, password age |
| Copy | "Copied, clears in 0:28" with a bar that empties, then "Clipboard cleared" | Configurable timeout, "copy and paste into the previous app" |
| Add / edit | — (CLI: `deadbolt new`, `set`) | Add login or card from the schema, edit in place, delete with confirm in place and a dim red surface |
| Generate | — (CLI generates when `password=` is omitted) | Length and symbols, regenerate, used by Add |
| Devices | — (CLI: `devices`, `pair`, `devices remove`) | List with presence; Add device (paste the new device's ticket, confirm the code); remove with confirm in place |
| Import | — (CLI: `import bitwarden`) | Pick a Bitwarden export, show counts, import |
| Lock | ⌘L or the lock button, or the agent locking (idle timeout, sleep, screen lock, CLI); clears our clipboard copy and forgets every value | |
| Errors, empty | Can't reach the agent (with the reason and Try again); an empty vault shows how to add a login or import from Bitwarden with the CLI, with copy buttons; no matches; agent errors inline | Agent version mismatch help |

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
| ⇧⌘Space | open the quick panel (in Deadbolt only, for now); in any field it never types a space, and a passphrase field drops any text typed with ⌘ or ⌃ held |
| ↵ on Unlock | unlock |

**Open:** ⌘C to copy the password when the search has no selection, as 1Password does? ⌘1–9 for the first rows?

## Motion

Rune's runtime already enforces no first-paint animation, reduced motion (travel off, short fade kept; from the system's setting, or `--reduced-motion`) and retargeting mid-flight.

| Change | Who causes it | Motion |
|---|---|---|
| Locked ↔ vault, any whole-screen change | user or agent | whole-state replacement: blur 4, scale .96, fade; enter `.3/0`, exit `.24/0`, the new screen enters on the frame the old one starts to leave |
| Typing filters the list | dependent on typing | rows that stay slide on `.4/0` and never blur; rows that leave or arrive fade in place (blur 3, scale .96, `.3/0` in, `.25/0` out) |
| ↑↓ selection, the selected item's fields | user's hand | instant |
| Copy icon → check | user | in-place replacement `.3/0` |
| Copy notice | user | rises 12 pt with a fade `.3/0`; its label (`view::copy_line`, a `rune_kit::RollingText`) rolls only the characters that change, entering from the top; a failed copy's message swaps by replacement; leaves the way it came, shorter |
| Countdown | time | the bar empties on a linear `rune::Tween` run by the render thread, so it needs no app wakes; the app wakes once a second for the text, and only at the clear while the quick panel is hidden. Plex Mono's digits are all one width, so nothing shakes |
| Unlock error | agent | fades in |
| Command offer | app | rises 12 pt with a fade, like the copy notice; leaves the same way |
| Install page ↔ vault, its states | user | whole-state replacement; the page's body swaps by replacement (install → installed); Copy → Copied in place; errors fade in |
| Hover | pointer | in 0 ms, out on Rune's snap |
| Onboarding steps | user | whole-state replacement, as above; progress and its result share one panel |
| Field hints (strength, repeat, problems) | dependent on typing | swap in place with a fade; the strength and repeat lines are always there, so typing never moves the fields below |
| Progress stages | agent | the stage's glyph replaces in place (pending dot → breathing dot → check); the breath stops under reduced motion |
| Vault created or joined | agent | the one flourish: the bolt throws from the body into the strike on `.3/.3` (overshoots about 1 pt). On contact (`.11` s) the strike flashes hot and its glow lights (50 ms attack), then cools: hot → red on `.3/0`, red → rest on `.9/0`, the glow decays over 1.1 s, fast then slow. The title replaces; the vault opens at 1.5 s |

## Quick panel

A Spotlight-style panel for the everyday task: press ⇧⌘Space, type, ⏎ copies the password (⇧⏎ the username, a card's ⏎ its number) and the panel goes away.

- **Shortcut: ⇧⌘Space.** ⌘Space is Spotlight and ⌥⌘Space is the Finder search window on a stock Mac; ⇧⌘Space is free there and is 1Password Quick Access's default, so it's where people already reach. Configurable later. Rune has no global shortcuts on our pin yet, so for now it works only while Deadbolt is in front (see Stand-ins).
- **Window:** a second Rune window (`rune::run_windows`, key `panel`) with its own `App`: its own agent connection, `App::panel` set, started hidden. Borderless and transparent, 680×440 with the card inset 20 pt, centred near the top of the primary display.
- **What it reuses:** the vault view's search field (`view::search_input`), rows (`view::rows`, `list_row`), the passphrase field and unlock error, and the model's filtering, selection and copy-with-countdown. The panel adds only its phases (`Open`, `Copied`, `Closing`, `Hidden`) and its card. It has no install offer or Settings: it never gets an installer, and `App::overlay_key` ignores them in the panel, so its keys stay its own.
- **States:** connecting; the vault (empty search over every item, the first selected); filtering; no matches; an empty vault; locked, with the passphrase field in place and its error; not set up, which points to the main window (⏎ or Open Deadbolt opens it); can't reach the agent, with Try again.
- **Dismissing:** Escape (in the search or the passphrase field too), ⇧⌘Space again, or a copy: the footer's "Copy password" rolls into "Copied, clears in 0:30" for 1.1 s, then the card fades and the window hides. Rune doesn't poll a hidden window when the agent replies, so hiding forgets everything the panel read or was typed (the list, the query, an item's values, a part-typed passphrase) and moves to a new generation: replies still on their way are dropped, and an item's values are wiped when its reply is dropped, read or not (`agent::Values`). Each summon fetches the list again and starts from an empty search and the first item. The copy keeps counting down while hidden (one wake at its end, not every second) and is cleared on time, on lock, or when the app quits.
- **One clipboard:** both windows share the process's `Clipboard`. Each copy gets the next id, and a countdown clears only the latest copy, and only if the clipboard still holds it. A copy the other window has since replaced ends quietly: its notice leaves without "Clipboard cleared". Lock and quit clear the latest copy, whichever window made it.
- **Footer:** what ⏎ does ("Copy password", "Copy number", "Unlock", …), rolling into the copy's line, or replaced by a notice (an item "has no username", an agent error). ⇧⏎ Username shows only for a login with a username.

### Stand-ins

Rune 43ff4f8 can't yet do five things the panel wants. `crates/app/src/panel/window.rs` holds each stand-in (the ways in, opening, closing, placing, the shortcut, leaving), so moving to Rune's APIs is a change there plus the lines noted. The first five are assigned on Rune's side but not on `dev` yet.

| Now | Replaced by | Then |
|---|---|---|
| **The shortcut:** ⇧⌘Space only inside Deadbolt (`window::is_shortcut`, checked in `App::on_key`, the search field and the passphrase field) | `App::global_shortcut` / `AppHandle::register_shortcut` → `Result<ShortcutId, ShortcutError>` (Carbon, `RegisterHotKey`, `XGrabKey`, the Wayland portal); headless `{"shortcut": …}` steps | Register ⇧⌘Space in `run()`, say why on stderr on `ShortcutError` (a conflict); drop the in-app checks (the global key arrives first) |
| **The menu entry:** the main window's clickable "Quick panel ⇧⌘Space" hint (`window::entry`), and `deadbolt-app --panel` (`window::FLAG`, `Windows::start_with_panel`). No native menu or Dock menu: Rune has no menu API and the workspace forbids `unsafe` | Rune menus (queued after the shortcut recorder, sharing its accelerator type): app-menu and Dock-menu items with `fn(&mut S, &mut Tx)` actions, key equivalents and runtime enabled/checked state; headless `{"menu": "Open Quick Panel"}` steps. macOS first; Windows and Linux return `Unsupported` | An "Open Quick Panel" item in the app menu and the Dock menu, key equivalent ⇧⌘Space, calling `App::open_panel`; it replaces the hint and `--panel` as the way in. Where menus are `Unsupported` (Windows, Linux), keep both. A test with `{"menu": "Open Quick Panel"}` |
| **Leaving:** without the shortcut, a hidden panel can't come back while the main window is closed (`--panel`, the main window never opened), so the process would idle forever. It exits instead (`window::leave_if_stranded`, from `poll_panel` and the panel's `on_close`): once the panel's copy has been cleared on time, so copy then paste still works, or at once without one | Global shortcuts and launcher panels: `App::global_shortcut` / `AppHandle::register_shortcut` brings the panel back from anywhere, and a non-activating launcher panel (`MacWindowOptions::nonactivating_panel(true)`) lives without the main window | Drop `leave_if_stranded` and `Windows::stranded`; the process stays for the shortcut. Closing the panel's window still runs the main window's cleanup (`App::panel_closed`) |
| **Focus loss:** the window isn't always on top, so clicking another app at least sends it behind; it closes itself after 30 s without a key (`window::IDLE`, `App::panel_active`) | per-window `on_focus(fn(&mut S, bool, &mut Tx))`; headless `{"focus": false}` steps | `on_focus(false)` calls `dismiss`; always on top again; drop `IDLE` and `panel_active`; a test with `{"focus": false}` |
| **Activation:** `AppHandle::open` activates Deadbolt, so the main window can come forward with it and hiding doesn't hand focus back to the previous app; the panel stays on the Space it was made on | `MacWindowOptions::nonactivating_panel(true)` (takes keys without activating the app; focus returns to the previous app on hide) and `MacWindowOptions::collection_behavior` (MoveToActiveSpace, IgnoresCycle, FullScreenAuxiliary; already at Rune `86a04ef`) | Set both in `window::options` |
| **Placement:** `window::position` from the displays at launch: the primary display, 18% down | `AppHandle::place(DisplayTarget, OverlayPlacement)`, resolved when called (the active screen) | `Windows::summon_panel` calls `place` instead of `set_position`; drop `position` and the stored displays |

| Change | Motion |
|---|---|
| Summon | none: the card appears at rest (`Tx::settle`; a summon during the close lands at rest too) |
| Escape, after a copy | the card fades on `.25/0`; the window hides at 0.3 s |
| Typing filters | as the vault: rows that stay slide, rows that arrive or leave fade in place |
| ⏎ copies | the footer's label rolls into the copy's (`view::copy_line`, the vault notice's): "Cop" stays, the rest rolls; then only the changing digits roll each second |
| What ⏎ does changes (Copy password ↔ Copy number, lock, unlock) | the label rolls what changes; a notice swaps in by replacement |
| ⇧⏎ Username comes or goes | fades in place |
| The list lands after an open | at rest, like the open (`Tx::instant` for the panel's first list) |
| Screens inside the card | whole-state replacement, as in the main window |
| Reduced motion | Rune keeps only the fades: the label's changing characters crossfade in place |

## Breadboard

The main flows, as states (see the PR for the chat version):

1. Launch → agent starting ("Starting Deadbolt…") → locked or first-run.
   - First run → Create → device, vault, passphrase twice → Protecting your passphrase → Creating personal → the bolt throws → empty vault with the CLI guide.
   - First run → Join → device, passphrase twice → Making a pairing ticket → QR + `deadbolt pair …` (Copy command) → other device pairs → 482 913, They match → Receiving personal → the bolt throws → synced vault. They don't match, Cancel or Escape, or the other device declining → the join form with a notice; the device stays set up.
2. Locked: type the passphrase → ↵ → vault, or the error in place.
3. Vault: type "git" → list narrows → ↵ → "Copied, clears in 0:30" → 30 s → "Clipboard cleared" → notice leaves.
4. ⌘L → locked; the clipboard copy is gone.
5. Later: Devices → Add device → paste ticket → both screens show 482 913 → Confirm → device appears in the list.

## Open decisions

1. **Clipboard timeout:** 30 s now. 1Password uses 90 s, KeePassXC 10 s. Configurable?
2. **Where unlock lives:** decided: the agent owns locking (`unlock_timeout`, `lock_on_sleep` in its config); the app has no timer.
4. **Bundling:** decided: ship `deadbolt` inside `Deadbolt.app`, with an optional command link on first run.
5. **Window model:** decided: the main window plus the quick panel (see Quick panel). A menu-bar item is still open.
6. **Live updates:** done: the app follows the agent's `watch` stream.
7. **Weak passphrases:** the form refuses under 8 characters and only warns about weak ones (a rough estimate that flatters dictionary words). Refuse weak ones too?

## Rune gaps (for the Rune team)

Resolved at `43ff4f8`: `Kit::from_palette` floors near-black surfaces (pure black gets visible layers, borders and status tints), keeps a warm seed's hue in derived neutrals (the app now uses the derived muted ink) and takes a focus option (the app uses `PaletteFocus::Ink`); an invalid input tints only its outline, ring and message. At `f848cb2`: icon paths parse per the SVG grammar and strokes no longer scale twice, so the app uses the built-in `EYE` and `EYE_OFF` and every stroked icon is lighter; keyboard symbols come from the macOS system font at cap height, so the hints are plain `Keybind`s (`⏎`, since the system font has no `↵`); `Kit::from_palette` steps layers in OKLab, makes borders translucent and resolves elevation rings when painted. Earlier, at `3294968`: `Kit::from_palette` itself, the built-in glyphs, and ttf-parser gone from the Linux tree.

- **Secure fields take chords and control characters.** A secure `TextEdit` still inserts `Key::Text` with ⌘ or ⌃ held (an unclaimed ⇧⌘Space types a space you can't see), and a paste or ⇧⏎ puts tabs and line breaks into a single-line field. `src/secret.rs` swallows the chords in `on_key` and strips control characters in `on_change`.
- **Secret clipboard writes.** `Tx::copy_secret(text, clear_after)` (at `97bbc4f`) gives one process-wide owner, a concealed write and a clear at expiry or exit only if the text and pasteboard revision are unchanged, so a newer copy wins. The app still keeps its own owner (`src/clipboard.rs`, on `arboard`) because `copy_secret` can't: clear the latest copy now, if it's still there (lock, and closing a window while another stays); say whether a copy is still the latest (a superseded countdown ends quietly instead of saying "Clipboard cleared"); report a failed write ("Couldn't copy: …"); or be shared and observed by two headless runtimes in a test (headless runs never write). Wanted: a handle from `copy_secret` with `holds()`, `clear_now()` and the write's result, and a test backend.
- **Tabular figures.** `TextStyle` has no font features (`tnum`). Not a problem with Plex Mono, but any proportional font needs digit cells laid out by hand.
- **Scroll edges can't follow the scroll.** A `clip_fade` on a scroll is static, and `scroll_into_view` brings a row flush to the edge, so a soft edge would fade the selected row whenever it's first or last. The UI guide wants each edge to fade only once something is under it. Both lists keep `scroll()`'s hard clip. Wanted: edge fades whose strength follows the hidden extent per side, or a margin for `scroll_into_view`.
- **`Kit::from_palette` and Deadbolt's palette.** Still overridden at `43ff4f8`, by how far the derived value is off: the surface ramp (on paper, derived raised surfaces are darker than the background, `#e1ddd5`, where the site's are lighter, `#f3f0ea`; on black `layer_01` and `layer_04` match but `layer_02`/`layer_03` and the surface tokens are 3–13 levels off, as the site's surface sits below its raised layer), the status colours (derived roles are rune-kit's own, `#ff847d` and `#dfa11a` on black, since `PaletteSeed` has no danger or warning seed), and the faint ink on paper (derived `#807c75`, 5 levels darker than the site's `#857f74`). The opaque border tokens point at the hairline by choice: the derived steps are heavier lines. Muted ink, hover, pressed, the hairlines, focus and `blend_over` are derived.
- **Ellipsis by default.** `truncate()` ends in "…"; the app wraps lines in `clip_fade` rows (20 pt) to get the fade the UI guide prefers. Rune's `truncate_fade` fades only on overflow but over a fixed 1 em, short of the guide's 1.5 em. Wanted: a width for `truncate_fade`.
- **`rune_kit::TextInput` can't animate dependent layout** (`animate_edit_layout`), so the search field is built from `text_input` directly.
- **Waking a hidden window.** A `Waker` (the agent's replies, the watch stream) wakes a hidden window's event loop but doesn't poll its app; only its `wake_after` deadlines do. So a hidden quick panel would sit on a lock or a late item until it opens again. The panel forgets everything as it hides instead (Quick panel). Wanted: a `Waker` that polls the app while its window is hidden.
- **Window focus events** (to refresh status and the list when the window comes forward, and to dismiss the quick panel when it loses focus) aren't exposed to the app. Assigned: per-window `on_focus`.
- **Global shortcuts.** No API to register a system-wide key, so the quick panel's ⇧⌘Space works only inside Deadbolt. Assigned: `App::global_shortcut` / `AppHandle::register_shortcut`.
- **Non-activating key panels.** An ordinary window can't be a non-activating panel that still takes keys, so `AppHandle::open` activates the app (and the main window can come forward) when the quick panel opens. Assigned: `MacWindowOptions::nonactivating_panel`.
- **Placing a window on the active screen.** Overlays can (`DisplayTarget`); ordinary windows only take a position, so the panel opens on the primary display. Assigned: `AppHandle::place`.
- **Native menus.** No app menu or Dock menu items, so the quick panel has no "Open Quick Panel" menu entry; the main window's key hint and `--panel` stand in (`window::entry`, `window::FLAG`). Queued with the global-shortcuts work: app-menu and Dock-menu items with actions, key equivalents, enabled/checked state and a headless `{"menu": …}` step, macOS first (Quick panel, Stand-ins).
- **No accessibility bridge.** Roles and labels (the search field, the list, each field's Show/Copy, Lock, the quick panel's way in) reach Rune's element tree, its `--tree` output and the tests, but not VoiceOver: Rune has no AccessKit or `NSAccessibility` host yet. Wanted: an OS accessibility tree from `role`/`label`.
- **Timed sequences on an element.** `rune-motion` has keyframes and `Choreography`, but `El` can't take them: the bolt's flash, cool and fade are four app phases, each a `wake_after` and a view rebuild with new targets and springs. Wanted: keyframed opacity and fill on an element ("hot for 50 ms, then red on .3, then rest on .9").
- **Focus set from state lands a frame late.** A handler that moves focus (`edit.focused = true`) takes effect at the next frame, so keys already queued in the same frame still go to the old field. Rare by hand; tests must run a frame between Enter and typing.

## Run, test, snapshot

```sh
cargo run --release -p deadbolt-app     # against your agent (starts it if needed)
cargo test -p deadbolt-cli -p deadbolt-app   # the real-agent test uses the deadbolt cargo built (or DEADBOLT_BIN)
crates/app/scripts/snap.sh              # headless PNGs of every scene into crates/app/snaps/
cargo run -p deadbolt-app -- --scene copied --at 2.4 --snap copied.png   # one scene; --theme light, --reduced-motion
cargo run -p deadbolt-app -- --panel                                             # start with the quick panel
cargo run -p deadbolt-app -- --window panel --scene filtering --snap panel.png   # a quick panel scene
cargo run -p deadbolt-app -- --window panel --scene empty --script crates/app/scripts/panel-motion.json --frames 240 --trace motion/panel.jsonl   # motion-lint trace: filter, copy, close
```

Scenes (`--scene`): `connecting`, `failed`, `locked`, `locked-error`, `vault`, `search`, `copied`, `revealed`, `empty`, and first run: `welcome`, `welcome-set-up`, `create`, `create-typing`, `create-ready`, `create-invalid`, `create-failed`, `creating` (created at 1.2 s, the moment, the vault at 2.7 s), `join`, `ticket`, `code`, `joining` (joined at 0.6 s), `join-declined`, `join-cancelled`, `join-failed`, and the command: `command-offer`, `install-command`, `command-installed`. Quick panel scenes (`--window panel --scene`): `connecting`, `empty`, `filtering`, `no-match`, `empty-vault`, `copied` (closes at 1.1 s), `locked`, `locked-error`, `not-set-up`, `failed`. They use synthetic data. Any tooling run (`--snap`, `--tree`, `--trace`, `--frames`, `--script`, `--scene`, …) gets no agent and an in-memory clipboard, so its output can't hold real items.

## One bundle, one agent

```text
Deadbolt.app/Contents/
  Info.plist                 pw.deadbolt.app; version from Cargo
  MacOS/Deadbolt             Rune desktop client
  Helpers/deadbolt           CLI and background agent
  Resources/Deadbolt.icns    red keyhole, generated headlessly
```

The CLI uses Apple's `Helpers` code-signing location: `MacOS/Deadbolt` and `MacOS/deadbolt` would collide on a case-insensitive Mac disk. The helper is signed first, then the outer bundle. Fonts are embedded in the app binary. Rune currently has no bundle builder in its scripts or examples.

**One rule decides which agent runs**, and the app and the CLI share it (`deadbolt_client::ensure_running`), so two builds never take turns replacing each other's agent:

| The running agent's protocol | What a client does |
| --- | --- |
| the same as its own | reuses it, whatever build started it: the bundled helper, Homebrew or Cargo |
| older | stops it cleanly, then starts its own binary |
| newer | fails without stopping it, naming the agent's program, version and pid, and suggests updating this copy or running `deadbolt agent stop` |

A bundled app always starts its own helper; if that's missing the app says it's damaged and should be reinstalled, rather than falling back to another install. The app's watch reconnection never starts an agent. `deadbolt agent status` shows which build is running.

In development, a rebuilt agent of the same protocol isn't picked up while the old one runs. `deadbolt agent stop` hands over to whichever build runs next; there's no override that replaces a compatible agent. Tests use `DEADBOLT_TEST_VERSION` for another build and `DEADBOLT_TEST_PROTOCOL` for an older or newer agent (`crates/cli/tests/cli.rs`, and fake agents in `crates/client`).

**The command offer lives in the vault.** Nothing about the command appears before the vault opens: not over onboarding, the locked screen or a failure, and leaving the vault (a lock on sleep, say) closes it. Once the vault shows, a card at the bottom of the detail pane offers **Install…** when no `deadbolt` was found, or **Repair…** when the one found links to a Deadbolt that moved. Not now, or opening the install page, answers it for good: `app-command-offered` is written beside the agent config. The same page stays under **Settings** at the end of the vault's key hints. The page replaces the vault with a Back button and its panel centred, like an onboarding step; Install creates the link, confirms it in place and shows the `rm` that undoes it. While Settings or the page is open it takes every key first (Escape closes it, Tab moves between its buttons); nothing reaches the search field or the list behind it. Copy buttons turn into "Copied" in place, then back. Headless scenes (`command-offer`, `install-command`, `command-installed`) never read or write the preference or install a real link.

The installer prefers writable `~/.local/bin`, `/opt/homebrew/bin`, then `/usr/local/bin` directories on the app's PATH. Otherwise it prefers a writable user directory and supplies a copyable `export PATH=…` command. Finder's PATH may differ from the terminal's; the app doesn't execute shell startup files or change shell profiles. If the chosen directory needs administrator access, it shows an exact, quoted command to copy; it never invokes sudo.

It looks for an existing `deadbolt` in the same places the app looks for an agent binary (`binary::search_dirs`): PATH, then `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin` and `~/.cargo/bin`, which a Finder launch's PATH lacks. Directories that can't be read count as not having one. The scan and the install run off the UI thread. What it finds is this app's link, a link to a moved Deadbolt, Homebrew (a Cellar link), Cargo (`.cargo/bin`), or another install. A link is ours by its target's shape, `<anything>.app/Contents/Helpers/deadbolt`, whether or not the target still exists; the installer repoints it at this app (a new link renamed over the old one) or gives the `sudo ln -sfh` to do so. No other file or symlink, including a dangling one, is replaced: remove the old command through its installer, then Check again. A copy running from a disk image (`/Volumes`) or under App Translocation refuses to link and says to move Deadbolt to Applications first.

## Shipping the app

Build an ad-hoc-signed development bundle on a Mac worker:

```sh
hivemind run --kind cargo --fetch .lab-output -- bash crates/app/scripts/bundle.sh
# Universal, after installing aarch64-apple-darwin and x86_64-apple-darwin:
hivemind run --kind cargo --fetch .lab-output -- bash crates/app/scripts/bundle.sh --universal
```

The script builds both release binaries with `--locked`, assembles into a temporary directory, generates the icon, signs ad hoc and checks the plist, signature, bundled CLI's `--version` and app's headless `--list-scenes` before moving the bundle into `.lab-output/Deadbolt.app`. An optional final argument selects a fresh output path; an existing output is refused. Native is the default to reuse the build cache; universal builds both Rust targets and combines each executable with `lipo`. These bundles aren't distribution releases.

Dax's `publish.yml` currently builds four CLI targets, then `packages/cli/script/release.ts` publishes tarballs, checksums and a Homebrew **formula**. `site/public/install` consumes those CLI tarballs. To add the app, introduce a macOS bundle job in the same publish mode, call this script, sign and notarize, then pass its app archive/DMG to the publish job. Keep the CLI artifacts and installer contract. The release script must upload the app even when the `v<version>` release already exists; its current existence check skips all uploads on reruns.

Remaining release work, with Anomaly's identities and Dax's pipeline:

- Developer ID signing with hardened runtime on `fleet role releaseHost`, replacing the development signatures inside-out; verify the signing identity and entitlements there.
- Notarize and staple every app and DMG, then assess both with Gatekeeper before publishing.
- Add a Sparkle-style signed update feed and updater integration. Upload and verify artifacts before publishing the feed.
- Add the Homebrew **cask** (`brew install --cask anomalyco/tap/deadbolt`, or `brew install --cask deadbolt` after tapping), alongside the existing CLI formula.
- Add a Mac download button to deadbolt.pw. Site publishing needs Dax's approval.

Signing identities, notarization, updater integration and publishing are deliberately left to that release work.
