#!/usr/bin/env bash
# assemble.sh <in> <dist>: gathers the release files from the verified
# artifacts in <in>/<name>/ into <dist>, refusing any file that is not a
# release file of DEADBOLT_VERSION or that two artifacts both hold, and writes
# <dist>/SHA256SUMS (GitHub release, pinned-version installs). A stable
# release (DEADBOLT_RELEASE_CHANNEL=stable) must have every file.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

in=$(posix "$1")
dist=$(posix "$2")
v=$DEADBOLT_VERSION
files=(
  "deadbolt-$v-linux-x64.tar.gz" "deadbolt-$v-linux-arm64.tar.gz"
  "deadbolt-$v-darwin-x64.tar.gz" "deadbolt-$v-darwin-arm64.tar.gz"
  "Deadbolt-$v-macos-universal.zip" "Deadbolt-$v-macos-universal.dmg"
  "deadbolt-extension-$v.zip"
)
mkdir -p "$dist"
for file in "$in"/*/*; do
  name=$(basename "$file")
  [ "$name" = SHA256SUMS ] && continue
  known=false
  for release in "${files[@]}"; do [ "$name" != "$release" ] || known=true; done
  $known || die "$name is not a release file of Deadbolt $v."
  [ ! -e "$dist/$name" ] || die "Two artifacts hold $name."
  cp "$file" "$dist/$name"
done
if [ "${DEADBOLT_RELEASE_CHANNEL:-}" = stable ]; then
  for release in "${files[@]}"; do
    [ -f "$dist/$release" ] || die "A stable release needs $release."
  done
fi
sums=$(mktemp)
(cd "$dist" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r file; do sha256 "$file"; done) > "$sums"
chmod 644 "$sums"
mv "$sums" "$dist/SHA256SUMS"
(cd "$dist" && ls -l && cat SHA256SUMS) | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
