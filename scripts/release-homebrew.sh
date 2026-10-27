#!/bin/sh
# Renders the Homebrew formula anomalyco/tap/deadbolt (the CLI, deadbolt.rb at
# the tap root) and cask anomalyco/tap/deadbolt (the app, Casks/deadbolt.rb)
# from packaging/homebrew/ and the release service's stable manifests, without
# secrets. The Release workflow checks them with brew, then pushes them with
# .github/release/push-homebrew.sh.
#
#   scripts/release-homebrew.sh render <version> <cli manifest> <desktop manifest> <out>
#
# Writes <out>/deadbolt.rb and <out>/deadbolt-cask.rb.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
origin=https://anoma.ly
usage() {
  echo "Usage: $0 render <version> <cli manifest> <desktop manifest> <out>" >&2
  exit 1
}
fail() {
  echo "$*" >&2
  exit 1
}

# target <manifest> <artifact> <target> <url|sha256>: one field of a target,
# after checking the manifest is Deadbolt's stable <artifact> at $version.
target() {
  jq -e --arg artifact "$2" --arg version "$version" \
    '.app == "deadbolt" and .artifact == $artifact and .channel == "stable" and .release.version == $version' "$1" > /dev/null ||
    fail "$1 is not Deadbolt's stable $2 $version."
  value=$(jq -er --arg target "$3" --arg field "$4" '.release.targets[$target][$field]' "$1") ||
    fail "$1 has no $3 target."
  case "$4" in
    url)
      printf '%s\n' "$value" | grep -Eq '^/release/deadbolt/files/[0-9a-f]{64}/[A-Za-z0-9._-]+$' || fail "Unexpected URL $value."
      case "$value" in *"-$version-"*) ;; *) fail "$value does not name version $version." ;; esac
      value="$origin$value"
      ;;
    sha256) printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{64}$' || fail "Unexpected SHA-256 $value." ;;
  esac
  printf '%s' "$value"
}

case "${1:-}" in
  render)
    [ $# -eq 5 ] || usage
    version=$2 cli=$3 desktop=$4 out=$5
    printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || fail "Homebrew serves stable X.Y.Z versions, not $version."
    mkdir -p "$out"
    # One assignment each, so a failing lookup stops the script.
    set --
    for t in macos-arm64 macos-x64 linux-arm64 linux-x64; do
      key=$(printf '%s' "$t" | tr 'a-z-' 'A-Z_')
      url=$(target "$cli" cli "$t" url)
      sha256=$(target "$cli" cli "$t" sha256)
      set -- "$@" -e "s|@${key}_URL@|$url|" -e "s|@${key}_SHA256@|$sha256|"
    done
    sed "$@" "$root/packaging/homebrew/deadbolt.rb" > "$out/deadbolt.rb"
    dmg=$(target "$desktop" desktop macos-arm64-dmg url)
    dmg_sha256=$(target "$desktop" desktop macos-arm64-dmg sha256)
    # Homebrew wants the cask URL to interpolate the version.
    # shellcheck disable=SC2016
    versioned=$(printf '%s' "$dmg" | sed "s|-$(printf '%s' "$version" | sed 's/[.]/\\./g')-|-#{version}-|")
    sed -e "s|@VERSION@|$version|" -e "s|@SHA256@|$dmg_sha256|" -e "s|@URL@|$versioned|" \
      "$root/packaging/homebrew/deadbolt-cask.rb" > "$out/deadbolt-cask.rb"
    if grep -q '@[A-Z0-9_]*@' "$out/deadbolt.rb" "$out/deadbolt-cask.rb"; then
      fail "The formula or cask has an unfilled placeholder."
    fi
    echo "$out/deadbolt.rb"
    echo "$out/deadbolt-cask.rb"
    ;;
  *) usage ;;
esac
