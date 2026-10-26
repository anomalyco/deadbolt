#!/bin/sh
# Renders the app's scenes headless (offscreen, no window) to PNGs.
# Usage: crates/app/scripts/snap.sh [OUT] [extra Rune flags...]   (default OUT: crates/app/snaps)
set -eu
cd "$(dirname "$0")/.."
out=${1:-snaps}
[ $# -gt 0 ] && shift
mkdir -p "$out"
bin=$(cargo build --release --quiet -p deadbolt-app --message-format=json | sed -n 's/.*"executable":"\([^"]*deadbolt-app\)".*/\1/p' | tail -1)
for scene in command-offer install-command command-installed locked locked-error vault search revealed code-copied empty failed \
  welcome welcome-set-up create create-typing create-ready create-invalid create-failed \
  join ticket code join-declined join-cancelled join-failed; do
  "$bin" --scene "$scene" --snap "$out/$scene.png" "$@"
done
# The moment: working, the bolt at contact, cooling, and joined.
"$bin" --scene creating --at 0.5 --snap "$out/creating.png" "$@"
"$bin" --scene creating --at 1.34 --snap "$out/created-contact.png" "$@"
"$bin" --scene creating --at 1.9 --snap "$out/created.png" "$@"
"$bin" --scene joining --at 1.3 --snap "$out/joined.png" "$@"
# The copy notice mid-countdown: 2.4 s after copying.
"$bin" --scene copied --at 2.4 --snap "$out/copied.png" "$@"
"$bin" --scene copied --at 2.4 --theme light --snap "$out/copied-light.png" "$@"
"$bin" --scene locked --theme light --snap "$out/locked-light.png" "$@"
# Item kinds, dark and light: a secure note (masked, then shown), an SSH
# key and an identity.
for theme in dark light; do
  for scene in note note-revealed ssh identity; do
    "$bin" --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# The quick panel's shortcut, dark and light: Settings at rest, recording, a
# conflict shown in place (Finder search holds ⌥⌘Space), changed (with a way
# back to the default), and when it couldn't be registered: the vault's notice
# and Settings with Try again.
for theme in dark light; do
  "$bin" --scene settings --theme "$theme" --snap "$out/settings-$theme.png" "$@"
  "$bin" --scene settings --script scripts/settings-shortcut.json --at 1.2 --theme "$theme" --snap "$out/settings-recording-$theme.png" "$@"
  "$bin" --scene settings --script scripts/settings-shortcut.json --theme "$theme" --snap "$out/settings-conflict-$theme.png" "$@"
  "$bin" --scene settings-changed --theme "$theme" --snap "$out/settings-changed-$theme.png" "$@"
  "$bin" --scene shortcut-conflict --theme "$theme" --snap "$out/shortcut-conflict-$theme.png" "$@"
  "$bin" --scene settings-unavailable --theme "$theme" --snap "$out/settings-unavailable-$theme.png" "$@"
  "$bin" --scene settings-touch-id --theme "$theme" --snap "$out/settings-touch-id-$theme.png" "$@"
  "$bin" --scene locked-touch-id --theme "$theme" --snap "$out/locked-touch-id-$theme.png" "$@"
  "$bin" --scene locked-touch-id-reset --theme "$theme" --snap "$out/locked-touch-id-reset-$theme.png" "$@"
done
# Importing, dark and light: the empty vault's drop zone, an export dragged
# over it, a preview, one with nothing new, a file it can't read, and ⇧⌘I in
# a vault with items.
for theme in dark light; do
  for scene in empty import-hover import-preview import-nothing-new import-nothing-to-import import-changed import-error import; do
    "$bin" --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# Adding, changing and deleting, dark and light: a new login with a generated
# password, a new card, a new identity, an edit, an SSH key's edit (its
# private key shown, locked), a refused card number, the delete confirm,
# and an edit another device changed meanwhile.
for theme in dark light; do
  for scene in new-login new-card new-identity edit edit-ssh edit-invalid delete-confirm edit-conflict; do
    "$bin" --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# The quick panel, dark and light: just opened, filtering, nothing found, an
# empty vault, locked, a wrong passphrase, not set up, failed, and 0.6 s after
# a copy (the footer shows the countdown).
for theme in dark light; do
  for scene in empty filtering no-match empty-vault locked locked-error locked-touch-id locked-touch-id-reset not-set-up failed; do
    "$bin" --window panel --scene "$scene" --theme "$theme" --snap "$out/panel-$scene-$theme.png" "$@"
  done
  "$bin" --window panel --scene copied --at 0.6 --theme "$theme" --snap "$out/panel-copied-$theme.png" "$@"
done
