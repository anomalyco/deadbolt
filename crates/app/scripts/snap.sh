#!/bin/sh
# Renders the app's scenes headless (offscreen, no window) to PNGs.
# Usage: crates/app/scripts/snap.sh [OUT] [extra Rune flags...]   (default OUT: crates/app/snaps)
set -eu
cd "$(dirname "$0")/.."
out=${1:-snaps}
[ $# -gt 0 ] && shift
mkdir -p "$out"
# The app is built into `deadbolt`, and runs in-process as `deadbolt ui`.
bin=$(cargo build --release --quiet -p deadbolt-cli --message-format=json | sed -n 's/.*"executable":"\([^"]*\/deadbolt\)".*/\1/p' | tail -1)
app() { "$bin" ui "$@"; }
for scene in command-offer install-command command-installed locked locked-error vault search revealed code-copied empty failed \
  welcome welcome-set-up create create-typing create-ready create-invalid create-failed \
  join code join-wrong-code join-cancelled join-failed; do
  app --scene "$scene" --snap "$out/$scene.png" "$@"
done
# The moment: working, the bolt at contact, cooling, and joined.
app --scene creating --at 0.5 --snap "$out/creating.png" "$@"
app --scene creating --at 1.34 --snap "$out/created-contact.png" "$@"
app --scene creating --at 1.9 --snap "$out/created.png" "$@"
app --scene joining --at 1.3 --snap "$out/joined.png" "$@"
# The copy notice mid-countdown: 2.4 s after copying.
app --scene copied --at 2.4 --snap "$out/copied.png" "$@"
app --scene copied --at 2.4 --theme light --snap "$out/copied-light.png" "$@"
app --scene locked --theme light --snap "$out/locked-light.png" "$@"
# Item kinds, dark and light: a login, a secure note (masked, then shown), an
# SSH key (its public key wrapping, then its private key shown), an identity,
# a passkey (delete only), then its delete confirm, a card, an API
# credential, a database, a Wi-Fi network, a document and a passport.
for theme in dark light; do
  for scene in vault note note-revealed ssh ssh-revealed identity passkey passkey-delete card api database wifi document passport; do
    app --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# The keys, dark and light: ⇥ into a login's fields, the ⌘K action menu, the
# ? shortcut sheet, and the ⌘, Settings page on its second row.
for theme in dark light; do
  for scene in field actions sheet settings-page security vault-risk fix-password; do
    app --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# The quick panel's shortcut, dark and light: Settings at rest, recording, a
# conflict shown in place (Finder search holds ⌥⌘Space), changed (with a way
# back to the default), and when it couldn't be registered: the vault's notice
# and Settings with Try again.
for theme in dark light; do
  app --scene settings --theme "$theme" --snap "$out/settings-$theme.png" "$@"
  app --scene settings --script scripts/settings-shortcut.json --at 1.2 --theme "$theme" --snap "$out/settings-recording-$theme.png" "$@"
  app --scene settings --script scripts/settings-shortcut.json --theme "$theme" --snap "$out/settings-conflict-$theme.png" "$@"
  app --scene settings-changed --theme "$theme" --snap "$out/settings-changed-$theme.png" "$@"
  app --scene shortcut-conflict --theme "$theme" --snap "$out/shortcut-conflict-$theme.png" "$@"
  app --scene settings-unavailable --theme "$theme" --snap "$out/settings-unavailable-$theme.png" "$@"
  app --scene settings-touch-id --theme "$theme" --snap "$out/settings-touch-id-$theme.png" "$@"
  app --scene settings-ssh --theme "$theme" --snap "$out/settings-ssh-$theme.png" "$@"
  app --scene settings-agents --script scripts/settings-agents.json --at 1.5 --theme "$theme" --snap "$out/settings-agents-$theme.png" "$@"
  app --scene locked-touch-id --theme "$theme" --snap "$out/locked-touch-id-$theme.png" "$@"
  app --scene locked-touch-id-reset --theme "$theme" --snap "$out/locked-touch-id-reset-$theme.png" "$@"
done
# Importing, dark and light: the empty vault's drop zone, an export dragged
# over it, a preview, one with nothing new, a file it can't read, and ⇧⌘I in
# a vault with items.
for theme in dark light; do
  for scene in empty import-hover import-preview import-nothing-new import-nothing-to-import import-changed import-error import; do
    app --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# Adding, changing and deleting, dark and light: a new login with a generated
# password, the type list as ⌘N opens it and filtered by "key", a new card, a new secure note, a new SSH key, a new identity, a
# new API credential, database, Wi-Fi network and document, an
# edit, an SSH key's edit (its private key hidden, then shown), a refused
# card number, the delete confirm, and an edit another device changed
# meanwhile.
for theme in dark light; do
  for scene in new-login picker-open picker-key new-card new-note new-ssh new-identity new-api new-database new-wifi new-document edit edit-ssh edit-ssh-revealed edit-invalid delete-confirm edit-conflict; do
    app --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# Mirrored from 1Password, dark and light: an item, its edit's warning, and
# Settings after a sync and after one 1Password refused.
for theme in dark light; do
  for scene in mirrored edit-mirrored settings-synced settings-sync-failed; do
    app --scene "$scene" --theme "$theme" --snap "$out/$scene-$theme.png" "$@"
  done
done
# The quick panel, dark and light: just opened, filtering, nothing found, an
# empty vault, locked, a wrong passphrase, not set up, failed, and 0.6 s after
# a copy (the footer shows the countdown).
for theme in dark light; do
  for scene in empty filtering no-match empty-vault locked locked-error locked-touch-id locked-touch-id-reset not-set-up failed; do
    app --window panel --scene "$scene" --theme "$theme" --snap "$out/panel-$scene-$theme.png" "$@"
  done
  app --window panel --scene copied --at 0.6 --theme "$theme" --snap "$out/panel-copied-$theme.png" "$@"
done
