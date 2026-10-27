#!/usr/bin/env bash
# plan.sh: decides what this run builds and where it publishes, from the event
# and the ref, and writes the plan to $GITHUB_OUTPUT.
#
#   dev    a push to dev (or a dispatch from dev): 0.0.0-dev-<run number> on
#          the release service's dev channel, as OpenCode numbers dev builds
#          (a full rerun adds .<attempt>, so it never reuses a version).
#   check  a dispatch: the same build, signed and verified, published
#          nowhere. From dev it is built as dev; from production, as stable.
#   stable a push to production, a pushed v<version> tag, or a dispatch from
#          production: the workspace version from Cargo.toml, which must be a
#          new X.Y.Z with docs/releases/<version>.md.
#
# Environment: EVENT, REF_NAME, REF_TYPE, CHANNEL, SHA, GITHUB_REPOSITORY,
# GITHUB_RUN_NUMBER, GITHUB_RUN_ATTEMPT, and Cargo.toml and docs/releases/ of
# the commit in the working directory. SERVICE overrides the release service
# origin read for the current stable release (tests only).
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

service=https://anoma.ly/release
version=$(awk '/^\[workspace\.package\]/ { package = 1; next } /^\[/ { package = 0 } package && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }' Cargo.toml)
[ -n "$version" ] || die "Cargo.toml has no [workspace.package] version."

dev_version="0.0.0-dev-$GITHUB_RUN_NUMBER"
if [ "${GITHUB_RUN_ATTEMPT:-1}" != 1 ]; then dev_version="$dev_version.$GITHUB_RUN_ATTEMPT"; fi

# stable_checks: a stable version must be new, tagged at most at this commit,
# and have release notes.
stable_checks() {
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Stable releases need an X.Y.Z workspace version, not $version."
  [ "$version" != 0.0.0 ] || die "Set [workspace.package] version in Cargo.toml before a stable release."
  [ -f "docs/releases/$version.md" ] || die "Add release notes at docs/releases/$version.md."
  tagged=$(git ls-remote "https://github.com/$GITHUB_REPOSITORY.git" "refs/tags/v$version" "refs/tags/v$version^{}" | awk 'END { print $1 }')
  if [ -n "$tagged" ] && [ "$tagged" != "$SHA" ]; then
    die "v$version is already tagged at $tagged; bump [workspace.package] version for a new release."
  fi
  current=$(curl -fsS "${SERVICE:-$service}/deadbolt/cli/stable.json" 2>/dev/null | jq -r '.release.version // empty' || true)
  [ "$current" != "$version" ] || die "$version is already the current stable release."
}

case "$CHANNEL" in
  stable)
    case "$REF_TYPE:$REF_NAME" in
      branch:production) ;;
      tag:v*) [ "$REF_NAME" = "v$version" ] || die "Tag $REF_NAME does not match workspace version $version." ;;
      *) die "Stable releases run from production or a v<version> tag, not $REF_TYPE $REF_NAME." ;;
    esac
    stable_checks
    release_channel=stable release_version=$version tag="v$version"
    notes="https://github.com/$GITHUB_REPOSITORY/releases/tag/$tag"
    ;;
  dev)
    [ "$REF_TYPE:$REF_NAME" = branch:dev ] || die "The dev channel runs from dev, not $REF_TYPE $REF_NAME."
    release_channel=dev release_version=$dev_version tag=""
    notes="https://github.com/$GITHUB_REPOSITORY/commit/$SHA"
    ;;
  check)
    case "$REF_TYPE:$REF_NAME" in
      branch:dev)
        release_channel=dev release_version=$dev_version tag=""
        notes="https://github.com/$GITHUB_REPOSITORY/commit/$SHA"
        ;;
      branch:production)
        stable_checks
        release_channel=stable release_version=$version tag="v$version"
        notes="https://github.com/$GITHUB_REPOSITORY/releases/tag/$tag"
        ;;
      *) die "Checks run from dev or production (the release environment admits only those), not $REF_TYPE $REF_NAME." ;;
    esac
    ;;
  *) die "Unknown channel $CHANNEL." ;;
esac

{
  echo "sha=$SHA"
  echo "channel=$CHANNEL"
  echo "service=$service"
  echo "tag=$tag"
  echo "notes-url=$notes"
  echo "release-channel=$release_channel"
  echo "release-version=$release_version"
} >> "$GITHUB_OUTPUT"
echo "Releasing $SHA ($CHANNEL) as $release_channel $release_version." >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
