#!/bin/sh
# Stamps the version the release service publishes into the workspace
# version ([workspace.package] in Cargo.toml, which every crate inherits) and
# every workspace crate's Cargo.lock entry, so the binaries report it: a dev
# build's 0.0.0-dev-<run number>[.<attempt>] (as OpenCode numbers its dev
# builds) or a prerelease X.Y.Z-beta.N of the checked-out version. Release
# builds only; the change is never committed.
#
#   scripts/set-crate-version.sh <source root> <version>
set -eu

[ $# -eq 2 ] || { echo "Usage: $0 <source root> <version>" >&2; exit 1; }
root=$1
version=$2
current=$(awk '/^\[workspace\.package\]/ { p = 1; next } /^\[/ { p = 0 } p && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }' "$root/Cargo.toml")
[ -n "$current" ] || { echo "$root/Cargo.toml has no [workspace.package] version." >&2; exit 1; }
[ "$version" = "$current" ] && exit 0
printf '%s\n' "$version" | grep -Eq "^(0\.0\.0-dev-[1-9][0-9]*(\.[1-9][0-9]*)?|$(printf '%s' "$current" | sed 's/\./\\./g')-beta\.[0-9]+)\$" || {
  echo "Can only stamp 0.0.0-dev-<run> or a $current-beta.N prerelease, not $version." >&2
  exit 1
}

# The workspace crates: every crates/*/Cargo.toml [package] name.
crates=$(for manifest in "$root"/crates/*/Cargo.toml; do
  awk '/^\[package\]/ { p = 1; next } /^\[/ { p = 0 } p && /^name = "/ { gsub(/^name = "|"$/, ""); print; exit }' "$manifest"
done)
[ -n "$crates" ] || { echo "No workspace crates under $root/crates." >&2; exit 1; }

# awk, not sed's GNU-only 0,/re/ address: this also runs on the macOS runner.
awk -v current="$current" -v version="$version" '
  /^\[/ { section = $0 }
  section == "[workspace.package]" && $0 == "version = \"" current "\"" { $0 = "version = \"" version "\"" }
  { print }
' "$root/Cargo.toml" > "$root/Cargo.toml.next"
mv "$root/Cargo.toml.next" "$root/Cargo.toml"
# The crate list goes through the environment: BSD awk refuses a newline in -v.
CRATES=$crates awk -v current="$current" -v version="$version" '
  BEGIN { n = split(ENVIRON["CRATES"], list, "\n"); for (i = 1; i <= n; i++) ours["name = \"" list[i] "\""] = 1 }
  /^\[\[package\]\]/ { package = 0 }
  $0 in ours { package = 1 }
  package && $0 == "version = \"" current "\"" { $0 = "version = \"" version "\""; package = 0 }
  { print }
' "$root/Cargo.lock" > "$root/Cargo.lock.next"
mv "$root/Cargo.lock.next" "$root/Cargo.lock"

grep -q "^version = \"$version\"" "$root/Cargo.toml" || { echo "Stamping $root/Cargo.toml failed." >&2; exit 1; }
stamped=$(grep -c "^version = \"$version\"" "$root/Cargo.lock" || true)
expected=$(printf '%s\n' "$crates" | wc -l | tr -d ' ')
[ "$stamped" = "$expected" ] || { echo "Stamped $stamped of $expected crates in $root/Cargo.lock." >&2; exit 1; }
echo "Building Deadbolt as $version." >&2
