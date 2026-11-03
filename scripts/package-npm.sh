#!/usr/bin/env bash
# Packs Deadbolt's npm packages, as OpenCode packs @opencode/cli: one package
# per platform with its `deadbolt`, and the @deadbolt/cli wrapper, which
# depends on all of them (optionalDependencies, picked by os, cpu and libc)
# and whose postinstall links bin/deadbolt to the one installed
# (packaging/npm/postinstall.mjs).
#
#   scripts/package-npm.sh <version> <in> <out>
#
# <in> holds the release build's artifacts: build-cli-linux-*/ (the Linux
# tarballs) and sign-macos/ (the signed, notarized, stapled
# Deadbolt-<version>-macos-universal.zip). The darwin packages carry that
# Deadbolt.app: the command is its Contents/Helpers/deadbolt, so the CLI, the
# daemon and the app are one install. Run on macOS (ditto keeps the bundle as
# signed). Writes <out>/deadbolt-cli-*.tgz.
set -euo pipefail

[ $# -eq 3 ] || { echo "Usage: $0 <version> <in> <out>" >&2; exit 1; }
v=$1 in=$2 out=$3
root=$(cd "$(dirname "$0")/.." && pwd)
repository=git+https://github.com/anomalyco/deadbolt.git
fail() { echo "$*" >&2; exit 1; }
[ "$(uname -s)" = Darwin ] || fail "Packing the darwin packages needs macOS (ditto)."
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# package_json <name> <description> [os cpu [libc]]
package_json() {
  jq -n --arg name "$1" --arg version "$v" --arg description "$2" --arg repository "$repository" \
    --arg os "${3:-}" --arg cpu "${4:-}" --arg libc "${5:-}" '
    {name: $name, version: $version, description: $description, license: "UNLICENSED",
     homepage: "https://deadbolt.pw", repository: {type: "git", url: $repository},
     bugs: {url: "https://github.com/anomalyco/deadbolt/issues"}}
    + (if $os == "" then {} else {os: [$os], cpu: [$cpu]} end)
    + (if $libc == "" then {} else {libc: [$libc]} end)'
}

pack() {
  (cd "$1" && npm pack --ignore-scripts --silent --pack-destination "$out" > /dev/null)
}

dependencies='{}'
for target in linux-x64 linux-arm64 linux-x64-musl linux-arm64-musl darwin-arm64 darwin-x64; do
  name="@deadbolt/cli-$target"
  dir="$work/cli-$target"
  mkdir -p "$dir"
  arch=${target#*-}
  arch=${arch%-musl}
  case "$target" in
    linux-*-musl)
      libc=musl
      description="Deadbolt for Linux $arch (musl, static, without the desktop app), installed by @deadbolt/cli."
      ;;
    linux-*)
      libc=glibc
      description="Deadbolt for Linux $arch (glibc 2.28+), installed by @deadbolt/cli."
      ;;
    darwin-*)
      libc=
      description="Deadbolt.app and its deadbolt for macOS $arch, installed by @deadbolt/cli."
      ;;
  esac
  case "$target" in
    linux-*)
      tarball="$in/build-cli-$target/deadbolt-$v-$target.tar.gz"
      [ -f "$tarball" ] || fail "$tarball is missing."
      mkdir "$dir/bin"
      tar -xzf "$tarball" -C "$dir/bin"
      [ "$(ls "$dir/bin")" = deadbolt ] || fail "$tarball must hold exactly deadbolt."
      chmod 755 "$dir/bin/deadbolt"
      ;;
    darwin-*)
      zip="$in/sign-macos/Deadbolt-$v-macos-universal.zip"
      [ -f "$zip" ] || fail "$zip is missing."
      /usr/bin/ditto -x -k "$zip" "$dir"
      [ "$(ls "$dir")" = Deadbolt.app ] || fail "$zip must hold exactly Deadbolt.app."
      # npm packs regular files and directories only.
      [ -z "$(find "$dir/Deadbolt.app" ! -type f ! -type d)" ] || fail "Deadbolt.app holds something npm can't pack."
      ;;
  esac
  os=${target%%-*}
  package_json "$name" "$description" "$os" "$arch" "$libc" > "$dir/package.json"
  pack "$dir"
  dependencies=$(jq -c --arg name "$name" --arg version "$v" '. + {($name): $version}' <<< "$dependencies")
done

wrapper="$work/cli"
mkdir -p "$wrapper/bin"
cp "$root/packaging/npm/deadbolt" "$wrapper/bin/deadbolt"
cp "$root/packaging/npm/postinstall.mjs" "$wrapper/postinstall.mjs"
chmod 755 "$wrapper/bin/deadbolt"
package_json @deadbolt/cli "Deadbolt, a local-first password manager: the CLI, with the desktop app built in." |
  jq --argjson dependencies "$dependencies" '. + {
    bin: {deadbolt: "./bin/deadbolt"},
    scripts: {postinstall: "node ./postinstall.mjs"},
    os: ["darwin", "linux"], cpu: ["arm64", "x64"],
    optionalDependencies: $dependencies}' > "$wrapper/package.json"
pack "$wrapper"
ls -l "$out"
