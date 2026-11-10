# The locked row's unlock, in a real browser

`e2e/standalone.ts` runs headless, and a headless browser has no toolbar: it
can't show that `chrome.action.openPopup` really opens the popup, what that
popup's first frame is, or what happens to it under macOS's own dialog.
`run.ts` checks those in a headed browser, with a profile it makes in a
temporary directory and removes.

```sh
cd extension
bun e2e/real/run.ts --browser "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
```

It needs a Mac with a desktop session and a Chromium browser that loads an
unpacked extension from the command line (Brave, Chromium; not Google
Chrome). It builds the standalone extension first (`scripts/wasm.sh`'s
toolchain), or takes a built one with `--dist <dir>`. It prints one `ok:` or
`FAILED:` line per check and exits non-zero if any failed.

What it checks: the menu's one locked row on a real sign-in page; that
clicking it opens the real toolbar popup and no tab; that the popup's first
frame is the locked panel at its own size, the passphrase field focused, the
row waiting by its field; that the passphrase unlocks; that the popup stays
for its unlock moment and then closes itself; that the menu by the field then
lists the logins, with nothing filled.

`--dialog` repeats it with macOS's verification dialog up over the panel, the
passphrase typed under it. That takes a platform passkey, which the browser
and macOS each ask a person for once (Continue, then Touch ID or the Mac's
password). Deadbolt's Touch ID slot is then set with a made-up key, only so
the panel asks and the dialog comes up.

`--timing <n>` first presses the row `n` times and prints where the time goes
from the click to the panel on screen (`timing.ts`): the press, each browser
call the background makes, the panel's loading and painting, and when macOS
lists the panel's window. `--corners` photographs the panel with a
see-through page and round corners (Brave's bubble stays square).

`--driver <dir>` is for running it where nobody is at the keyboard (we use a
throwaway macOS VM driven over VNC, which also records its screen). The run
writes `<dir>/need/<n>-<kind>-<name>` and waits for the same name in
`<dir>/ack/`: `shot` (photograph the screen), `passkey` (answer the two
dialogs), `type` (type the passphrase `correct horse battery staple 42` and
Return on the real keyboard). It leaves `<dir>/result.json`.

Touch ID's own logic needs no sensor and runs in CI: `e2e/standalone.ts`
("the panel: …" checks) enrolls and unlocks in the panel's page with
DevTools' virtual platform authenticator, with and without PRF.

Only a Mac with a sensor can show the Touch ID wording of macOS's dialog, and
whether a given browser's passkey store has PRF (Deadbolt's Touch ID needs
it; `--dialog` prints which the browser's own has).
