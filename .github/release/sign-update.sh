#!/usr/bin/env bash
# sign-update.sh <dist> <out>: signs what this release built, for
# `deadbolt update` (docs/releasing.md, "Signed releases"). For each artifact
# with files in <dist> it writes <out>/deadbolt-<v>-<artifact>.update-signature.json:
#
#   {"schema": 1, "key": <base64 public key>, "statement": <base64 bytes>,
#    "signature": <base64 Ed25519 signature over those bytes>}
#
# where the statement is {"schema": 1, "app": "deadbolt", "artifact",
# "channel", "version", "targets": {<target>: {"file", "size", "sha256"}}},
# the targets release-service.sh publishes. UPDATE_SIGNING_KEY is the PEM
# (PKCS#8) Ed25519 private key; its public half must be listed in
# update-keys.txt. Uses only openssl and jq, on files treated as data.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"
# shellcheck source=.github/release/targets.sh
. "$(dirname "$0")/targets.sh"

dist=$(posix "$1")
out=$(posix "$2")
: "${DEADBOLT_VERSION:?Set DEADBOLT_VERSION}"
: "${DEADBOLT_RELEASE_CHANNEL:?Set DEADBOLT_RELEASE_CHANNEL}"
[ -n "${UPDATE_SIGNING_KEY:-}" ] || die "UPDATE_SIGNING_KEY is not set."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077
printf '%s\n' "$UPDATE_SIGNING_KEY" > "$work/key.pem"
openssl pkey -in "$work/key.pem" -noout 2> /dev/null || die "UPDATE_SIGNING_KEY is not a PEM private key."
public=$(openssl pkey -in "$work/key.pem" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')
[ "$(openssl pkey -in "$work/key.pem" -pubout -outform DER | wc -c | tr -d ' ')" = 44 ] ||
  die "UPDATE_SIGNING_KEY is not an Ed25519 key."
awk -v key="$public" '{ $1 = $1 } $0 == key { found = 1 } END { exit !found }' "$(dirname "$0")/update-keys.txt" ||
  die "UPDATE_SIGNING_KEY's public key $public is not listed in update-keys.txt."
openssl pkey -in "$work/key.pem" -pubout -out "$work/public.pem"

mkdir -p "$out"
umask 022
signed=0
for artifact in cli desktop extension; do
  targets='{}'
  for pair in $(release_targets "$artifact" "$DEADBOLT_VERSION"); do
    target=${pair%%=*}
    name=${pair#*=}
    [ -f "$dist/$name" ] || continue
    size=$(wc -c < "$dist/$name" | tr -d ' ')
    sha=$(sha256 "$dist/$name" | cut -c1-64)
    targets=$(jq -c --arg t "$target" --arg file "$name" --argjson size "$size" --arg sha "$sha" \
      '. + {($t): {file: $file, size: $size, sha256: $sha}}' <<< "$targets")
  done
  [ "$targets" != '{}' ] || continue
  jq -cj -n --arg artifact "$artifact" --arg channel "$DEADBOLT_RELEASE_CHANNEL" \
    --arg version "$DEADBOLT_VERSION" --argjson targets "$targets" \
    '{schema: 1, app: "deadbolt", artifact: $artifact, channel: $channel, version: $version, targets: $targets}' \
    > "$work/statement"
  openssl pkeyutl -sign -inkey "$work/key.pem" -rawin -in "$work/statement" -out "$work/signature"
  openssl pkeyutl -verify -pubin -inkey "$work/public.pem" -rawin -in "$work/statement" \
    -sigfile "$work/signature" > /dev/null || die "The $artifact signature doesn't verify."
  jq -n --arg key "$public" --arg statement "$(base64 < "$work/statement" | tr -d '\n')" \
    --arg signature "$(base64 < "$work/signature" | tr -d '\n')" \
    '{schema: 1, key: $key, statement: $statement, signature: $signature}' \
    > "$out/$(signature_name "$artifact" "$DEADBOLT_VERSION")"
  echo "Signed $artifact $DEADBOLT_VERSION ($DEADBOLT_RELEASE_CHANNEL) with $public:" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  jq . "$work/statement" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  signed=$((signed + 1))
done
[ "$signed" -gt 0 ] || die "Nothing in $dist to sign."
