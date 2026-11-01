#!/usr/bin/env bash
# publish-npm.sh <build-npm dir>: publishes Deadbolt's npm packages, as
# OpenCode's publish-npm.sh does: every tarball DEADBOLT_VERSION needs, under
# the channel's dist-tag (stable: latest, else the channel's name), with
# provenance, through npm trusted publishing (this job's OIDC token; there is
# no npm token). Names, the version and the package set come from this
# script, never from the tarballs: each tarball's package.json is read as data
# and must match. Platform packages publish before @deadbolt/cli, which
# resolves them; versions already on the registry are skipped, so a rerun is
# safe.
#
# Environment: DEADBOLT_VERSION, DEADBOLT_RELEASE_CHANNEL, GH_TOKEN (to verify
# the tarballs' build provenance).
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

npm_dir=$(cd "$(posix "$1")" && pwd)
v=$DEADBOLT_VERSION
case "${DEADBOLT_RELEASE_CHANNEL:-}" in
  stable) tag=latest ;;
  dev | beta) tag=$DEADBOLT_RELEASE_CHANNEL ;;
  *) die "No npm dist-tag for channel ${DEADBOLT_RELEASE_CHANNEL:-(unset)}." ;;
esac
targets="darwin-arm64 darwin-x64 linux-x64 linux-arm64 linux-x64-musl linux-arm64-musl"
expected=""
for target in $targets; do expected="$expected @deadbolt/cli-$target"; done
expected="$expected @deadbolt/cli"

for file in "$npm_dir"/*.tgz; do
  gh attestation verify "$file" --repo anomalyco/deadbolt --signer-workflow anomalyco/deadbolt/.github/workflows/release.yml > /dev/null ||
    die "$(basename "$file") has no build provenance from this repository's Release workflow."
done

list=$(mktemp)
for file in "$npm_dir"/*.tgz; do
  IFS=$'\t' read -r name version config install < <(tar -xzOf "$file" package/package.json |
    jq -r '[.name, .version, ((.publishConfig // {}) | keys - ["access"] | length > 0),
      ((.scripts // {}) | (has("preinstall") or has("install") or has("postinstall")))] | @tsv')
  # shellcheck disable=SC2086 # $expected is a word list
  printf '%s\n' $expected | grep -qxF -- "$name" || die "Unexpected package $name in $file"
  ! cut -f1 "$list" | grep -qxF -- "$name" || die "Two tarballs hold $name."
  [ "$version" = "$v" ] || die "$name has version $version, expected $v"
  [ "$config" = false ] || die "$name sets publishConfig beyond access"
  # Only the wrapper runs a script: its postinstall links bin/deadbolt.
  [ "$install" = false ] || [ "$name" = @deadbolt/cli ] || die "$name has an install script"
  case "$name" in
    @deadbolt/cli-darwin-*)
      # The signed app, whose helper is the command (scripts/package-npm.sh).
      tar -tzf "$file" | grep -qxF package/Deadbolt.app/Contents/Helpers/deadbolt-enclave ||
        die "$name doesn't carry Deadbolt.app."
      ;;
    @deadbolt/cli-linux-*)
      [ "$(tar -tzf "$file" | LC_ALL=C sort | tr '\n' ' ')" = "package/bin/deadbolt package/package.json " ] ||
        die "$name must hold exactly bin/deadbolt."
      ;;
  esac
  printf '%s\t%s\n' "$name" "$file" >> "$list"
done
for name in $expected; do cut -f1 "$list" | grep -qxF -- "$name" || die "Missing package $name"; done

# The wrapper resolves its platform packages, so it publishes last.
order=$(mktemp)
{ grep -v $'^@deadbolt/cli\t' "$list" || true; grep $'^@deadbolt/cli\t' "$list"; } > "$order"
cat "$order"

# A clean directory and config, so nothing from an artifact can redirect the registry.
printf 'registry=https://registry.npmjs.org/\n' > "$RUNNER_TEMP/npmrc"
export NPM_CONFIG_USERCONFIG="$RUNNER_TEMP/npmrc"
cd "$(mktemp -d)"
while IFS=$'\t' read -r name file; do
  if npm view "$name@$v" version > /dev/null 2>&1; then
    echo "already published $name@$v"
    continue
  fi
  npm publish "$file" --tag "$tag" --access public --ignore-scripts --provenance
done < "$order"
for name in $expected; do
  [ "$(npm view "$name@$v" version 2> /dev/null)" = "$v" ] || echo "::warning::The registry doesn't show $name@$v yet."
done
{ echo "### npm"; echo; echo "\`npm i -g @deadbolt/cli@$tag\` ($v)"; } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
