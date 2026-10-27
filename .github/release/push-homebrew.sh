#!/usr/bin/env bash
# push-homebrew.sh <dir> <version>: pushes the rendered formula and cask
# (checked with brew in a job without secrets) to anomalyco/homebrew-tap as
# deadbolt.rb (the CLI, at the tap root as before) and Casks/deadbolt.rb (the
# app), with the tap deploy key HOMEBREW_TAP_KEY. Files that already match are
# left alone, so reruns are no-ops.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

dir=$(posix "$1")
version=$2
: "${HOMEBREW_TAP_KEY:?Set HOMEBREW_TAP_KEY to the tap deploy key}"
grep -q "/deadbolt-$version-darwin-arm64\.tar\.gz\"$" "$dir/deadbolt.rb" || die "The formula is not version $version."
grep -q "^  version \"$version\"$" "$dir/deadbolt-cask.rb" || die "The cask is not version $version."
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
(umask 077 && printf '%s\n' "$HOMEBREW_TAP_KEY" > "$temporary/key")
# github.com's published ED25519 host key.
echo 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' > "$temporary/known_hosts"
export GIT_SSH_COMMAND="ssh -i $temporary/key -o IdentitiesOnly=yes -o UserKnownHostsFile=$temporary/known_hosts -o StrictHostKeyChecking=yes"
git clone -q --depth 1 git@github.com:anomalyco/homebrew-tap.git "$temporary/tap"
mkdir -p "$temporary/tap/Casks"
cp "$dir/deadbolt.rb" "$temporary/tap/deadbolt.rb"
cp "$dir/deadbolt-cask.rb" "$temporary/tap/Casks/deadbolt.rb"
cd "$temporary/tap" || exit
git add deadbolt.rb Casks/deadbolt.rb
if git diff --cached --quiet; then
  echo "anomalyco/tap already serves deadbolt $version." >&2
  exit 0
fi
git -c user.name='Deadbolt release' -c user.email='deadbolt@anoma.ly' commit -qm "deadbolt $version"
git push -q origin HEAD
echo "https://github.com/anomalyco/homebrew-tap/commit/$(git rev-parse HEAD)"
