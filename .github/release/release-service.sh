#!/bin/sh
# Publishes Deadbolt to the Anomaly release service through its shared client,
# https://anoma.ly/release/client.sh (anomalyco/release docs/publishing.md):
# a one-hour publish session from the job's OIDC token, parallel uploads that
# skip stored files, retries with backoff. Runs only in the Release workflow's
# jobs with `id-token: write`.
#
#   release-service.sh publish <artifact> <dist> <notes-url>   # upload its targets, then the release
#   release-service.sh distribution <artifact> <kind> <version> # a package manager now serves <version>
#
# Artifacts (docs/releasing.md), each with a manifest at
# $RELEASE/deadbolt/<artifact>/<channel>.json:
#
#   cli        macos-arm64, macos-x64, linux-x64, linux-arm64 (glibc, the
#              app built in), linux-x64-musl, linux-arm64-musl (static, no
#              app): the `deadbolt` tarballs
#   desktop    macos-arm64, macos-x64: the universal Deadbolt.app zip (the
#              updater's file, one per target as Hex's updater expects);
#              macos-arm64-dmg, macos-x64-dmg: the universal DMG
#   extension  chromium: the browser extension zip (native host build);
#              chromium-standalone: the standalone build's zip
#
# RELEASE is the service origin, https://anoma.ly/release; DEADBOLT_VERSION
# the version the files were built as and name; DEADBOLT_RELEASE_CHANNEL the
# channel (default stable). `publish` writes <dist>/manifest-<artifact>.json
# after checking every file the service serves against the local bytes.
# Publishing the channel's current version again succeeds only when the
# service already has exactly these files, so a rerun is safe. An artifact
# with none of its files in <dist> (an unsigned dev build has no app) is
# skipped.
set -eu

: "${RELEASE:?Set RELEASE to the release service origin}"
: "${DEADBOLT_VERSION:?Set DEADBOLT_VERSION}"
channel=${DEADBOLT_RELEASE_CHANNEL:-stable}
release_version=$DEADBOLT_VERSION
app=deadbolt
case "$RELEASE" in
  https://anoma.ly/release) ;;
  *) echo "RELEASE must be https://anoma.ly/release." >&2; exit 1 ;;
esac

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl -fsSL --retry 5 --retry-all-errors "$RELEASE/client.sh" -o "$temporary/client.sh"
client() { RELEASE=$RELEASE bash "$temporary/client.sh" "$@"; }

# targets <artifact>: target=file pairs, the names docs/releasing.md pins.
targets() {
  v=$release_version
  case "$1" in
    cli)
      echo "macos-arm64=deadbolt-$v-darwin-arm64.tar.gz"
      echo "macos-x64=deadbolt-$v-darwin-x64.tar.gz"
      echo "linux-x64=deadbolt-$v-linux-x64.tar.gz"
      echo "linux-arm64=deadbolt-$v-linux-arm64.tar.gz"
      echo "linux-x64-musl=deadbolt-$v-linux-x64-musl.tar.gz"
      echo "linux-arm64-musl=deadbolt-$v-linux-arm64-musl.tar.gz"
      ;;
    desktop)
      echo "macos-arm64=Deadbolt-$v-macos-universal.zip"
      echo "macos-x64=Deadbolt-$v-macos-universal.zip"
      echo "macos-arm64-dmg=Deadbolt-$v-macos-universal.dmg"
      echo "macos-x64-dmg=Deadbolt-$v-macos-universal.dmg"
      ;;
    extension)
      echo "chromium=deadbolt-extension-$v.zip"
      echo "chromium-standalone=deadbolt-extension-standalone-$v.zip"
      ;;
    *)
      echo "Unknown artifact $1." >&2
      exit 1
      ;;
  esac
}

# distributions <artifact>: the package managers that mirror it, each as the
# service lists it.
distributions() {
  case "$1" in
    cli) echo '[{"kind": "brew", "formula": "anomalyco/tap/deadbolt", "command": "brew upgrade anomalyco/tap/deadbolt"}]' ;;
    desktop) echo '[{"kind": "brew", "cask": "anomalyco/tap/deadbolt", "command": "brew upgrade --cask anomalyco/tap/deadbolt"}]' ;;
    *) echo '[]' ;;
  esac
}

publish() {
  artifact=$1
  dist=$2
  notes_url=$3
  set --
  for pair in $(targets "$artifact"); do
    target=${pair%%=*}
    name=${pair#*=}
    [ -f "$dist/$name" ] || continue
    set -- "$@" --target "$target=$dist/$name"
  done
  if [ $# -eq 0 ]; then
    echo "No $artifact files for $release_version; not publishing $artifact." >&2
    return 0
  fi
  jq -n --arg channel "$channel" --arg version "$release_version" --arg notes_url "$notes_url" \
    --argjson distributions "$(distributions "$artifact")" \
    '{channel: $channel, version: $version, notes_url: $notes_url,
      distributions: ([{kind: "direct"}] + $distributions)}' > "$temporary/release.json"
  client publish --app "$app" --artifact "$artifact" --release "$temporary/release.json" \
    --out "$dist/manifest-$artifact.json" --verify-downloads "$@"
}

distribution() {
  # The whole entry, so recording a version never drops its command.
  entry=$(distributions "$1" | jq -ec --arg kind "$2" --arg version "$3" \
    'map(select(.kind == $kind))[0] // error("unknown distribution \($kind)") | . + {version: $version}')
  client distribution --app "$app" --artifact "$1" --channel "$channel" --entry "$entry"
}

case "${1:-}" in
  publish)
    [ $# -eq 4 ] || { echo "Usage: $0 publish <artifact> <dist> <notes-url>" >&2; exit 1; }
    publish "$2" "$3" "$4"
    ;;
  distribution)
    [ $# -eq 4 ] || { echo "Usage: $0 distribution <artifact> <kind> <version>" >&2; exit 1; }
    distribution "$2" "$3" "$4"
    ;;
  *)
    echo "Usage: $0 publish <artifact> <dist> <notes-url> | distribution <artifact> <kind> <version>" >&2
    exit 1
    ;;
esac
