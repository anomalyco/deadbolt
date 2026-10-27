#!/bin/sh
# Mirrors a stable release's files to its GitHub release, byte for byte, with
# their SHA256SUMS (installs of a pinned version read these: site/public/install).
# Tags v<version> at the release commit with git when the run did not come
# from that tag (a tag pushed with GITHUB_TOKEN starts no workflow), and marks
# the release Latest.
#
#   publish-github-release.sh <dist>
#
# Environment: DEADBOLT_VERSION, DEADBOLT_RELEASE_COMMIT, DEADBOLT_RELEASE_TAG,
# DEADBOLT_RELEASE_SOURCE (a checkout of the commit with push credentials and
# docs/releases/), GH_TOKEN.
set -eu

repo=${DEADBOLT_RELEASE_REPO:-anomalyco/deadbolt}
[ $# -eq 1 ] || {
  echo "Usage: $0 <dist>" >&2
  exit 1
}
dist=$1
version=${DEADBOLT_VERSION:?Set DEADBOLT_VERSION}
commit=${DEADBOLT_RELEASE_COMMIT:?Set DEADBOLT_RELEASE_COMMIT}
tag=${DEADBOLT_RELEASE_TAG:?Set DEADBOLT_RELEASE_TAG}
source=${DEADBOLT_RELEASE_SOURCE:?Set DEADBOLT_RELEASE_SOURCE}

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

assets=$(cd "$dist" && { ls deadbolt-*.tar.gz Deadbolt-*.zip Deadbolt-*.dmg deadbolt-extension-*.zip SHA256SUMS 2>/dev/null || true; })
[ -n "$assets" ] || {
  echo "No release files in $dist." >&2
  exit 1
}

notes="$source/docs/releases/$version.md"
test -f "$notes" || {
  echo "Add release notes at docs/releases/$version.md." >&2
  exit 1
}
# An annotated tag's peeled commit is listed last.
tagged=$(git -C "$source" ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}" | awk 'END { print $1 }')
if [ -z "$tagged" ]; then
  git -C "$source" tag "$tag" "$commit"
  git -C "$source" push origin "refs/tags/$tag"
elif [ "$tagged" != "$commit" ]; then
  echo "Tag $tag already names $tagged, not $commit." >&2
  exit 1
fi
if ! gh release view "$tag" -R "$repo" --json name >/dev/null 2>&1; then
  gh release create "$tag" -R "$repo" --verify-tag --title "Deadbolt $version" \
    --notes-file "$notes" --latest
fi
gh release view "$tag" -R "$repo" --json assets > "$temporary/release.json"
mkdir -p "$temporary/mirror"
for name in $assets; do
  if ! jq -e --arg name "$name" '.assets | any(.name == $name)' "$temporary/release.json" >/dev/null; then
    gh release upload "$tag" "$dist/$name" -R "$repo"
  fi
  gh release download "$tag" -R "$repo" --pattern "$name" --dir "$temporary/mirror" --clobber
  cmp -s "$dist/$name" "$temporary/mirror/$name" || {
    echo "GitHub's $name differs from the release bytes." >&2
    exit 1
  }
  rm -f "$temporary/mirror/$name"
done
echo "https://github.com/$repo/releases/tag/$tag"
