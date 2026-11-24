# shellcheck shell=sh
# release_targets <artifact> <version>: the artifact's target=file pairs, the
# names docs/releasing.md pins. Sourced by release-service.sh (publishing)
# and sign-update.sh (signing what is published), never executed.
release_targets() {
  v=$2
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

# update_keys_pinned: whether .github/release/update-keys.txt lists a key, in
# which case every published artifact must carry a release signature.
update_keys_pinned() {
  grep -qv '^[[:space:]]*\(#.*\)\{0,1\}$' "$(dirname "$0")/update-keys.txt"
}

# signature_name <artifact> <version>: the release signature's file name.
signature_name() {
  echo "deadbolt-$2-$1.update-signature.json"
}
