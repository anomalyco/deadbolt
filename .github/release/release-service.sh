#!/bin/sh
# Publishes Deadbolt to the Anomaly release service with curl and the
# workflow's GitHub OIDC token (anomalyco/release docs/publishing.md). Runs
# only in the Release workflow's jobs with `id-token: write`.
#
#   release-service.sh publish <artifact> <dist> <notes-url>   # upload its targets, then the release
#   release-service.sh distribution <artifact> <kind> <version> # a package manager now serves <version>
#
# Artifacts (docs/releasing.md), each with a manifest at
# $RELEASE/deadbolt/<artifact>/<channel>.json:
#
#   cli        macos-arm64, macos-x64, linux-x64, linux-arm64: the CLI tarballs
#   desktop    macos-arm64, macos-x64: the universal Deadbolt.app zip (the
#              updater's file, one per target as Hex's updater expects);
#              macos-arm64-dmg, macos-x64-dmg: the universal DMG
#   extension  chromium: the browser extension zip
#
# RELEASE is the service origin, https://anoma.ly/release; DEADBOLT_VERSION
# the version the files were built as and name; DEADBOLT_RELEASE_CHANNEL the
# channel (default stable). `publish` writes <dist>/manifest-<artifact>.json
# after checking every file the service serves against the local bytes.
# Publishing the channel's current version again succeeds only when the
# service already has exactly these files, so a rerun is safe. An artifact
# with none of its files in <dist> (an unsigned dev build has no app) is
# skipped.
set -eu

: "${RELEASE:?Set RELEASE to the release service origin}"
: "${DEADBOLT_VERSION:?Set DEADBOLT_VERSION}"
channel=${DEADBOLT_RELEASE_CHANNEL:-stable}
release_version=$DEADBOLT_VERSION
app=deadbolt
# One request stays under Cloudflare's 100 MB limit; bigger files go in parts.
single_limit=$((95 * 1024 * 1024))
part_size=90m

case "$RELEASE" in
  https://anoma.ly/release) ;;
  *)
    echo "RELEASE must be https://anoma.ly/release." >&2
    exit 1
    ;;
esac
for command in curl jq sha256sum split; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Publishing requires $command." >&2
    exit 1
  }
done
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Run in a GitHub Actions job with id-token: write}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Run in a GitHub Actions job with id-token: write}"

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

# The token stays in a curl config file, never in argv or the log.
token_config="$temporary/token.curl"
(
  umask 077
  token=$(curl -fsS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$RELEASE" | jq -er .value)
  printf 'header = "Authorization: Bearer %s"\n' "$token" > "$token_config"
)

# request <curl arguments>: an authenticated request; prints the body and
# sets $status.
request() {
  status=$(curl -sS --config "$token_config" --retry 3 --retry-all-errors \
    -o "$temporary/response" -w '%{http_code}' "$@") || {
    echo "Request to the release service failed: $*" >&2
    exit 1
  }
  cat "$temporary/response"
}

# api <curl arguments>: a request that must succeed.
api() {
  request "$@"
  case "$status" in
    2??) ;;
    *)
      echo "The release service answered $status: $(cat "$temporary/response")" >&2
      exit 1
      ;;
  esac
}

# targets <artifact>: target=file pairs, the names docs/releasing.md pins.
targets() {
  v=$release_version
  case "$1" in
    cli)
      echo "macos-arm64=deadbolt-$v-darwin-arm64.tar.gz"
      echo "macos-x64=deadbolt-$v-darwin-x64.tar.gz"
      echo "linux-x64=deadbolt-$v-linux-x64.tar.gz"
      echo "linux-arm64=deadbolt-$v-linux-arm64.tar.gz"
      ;;
    desktop)
      echo "macos-arm64=Deadbolt-$v-macos-universal.zip"
      echo "macos-x64=Deadbolt-$v-macos-universal.zip"
      echo "macos-arm64-dmg=Deadbolt-$v-macos-universal.dmg"
      echo "macos-x64-dmg=Deadbolt-$v-macos-universal.dmg"
      ;;
    extension) echo "chromium=deadbolt-extension-$v.zip" ;;
    *)
      echo "Unknown artifact $1." >&2
      exit 1
      ;;
  esac
}

# distributions <artifact>: the package managers that mirror it, each as the
# service lists it.
distributions() {
  case "$1" in
    cli) echo '[{"kind": "brew", "formula": "anomalyco/tap/deadbolt", "command": "brew upgrade anomalyco/tap/deadbolt"}]' ;;
    desktop) echo '[{"kind": "brew", "cask": "anomalyco/tap/deadbolt", "command": "brew upgrade --cask anomalyco/tap/deadbolt"}]' ;;
    *) echo '[]' ;;
  esac
}

# resolve <url>: a target URL from the manifest, an absolute path on the
# service's host, as a full URL.
resolve() {
  case "$1" in
    /*) printf '%s%s\n' "${RELEASE%/release}" "$1" ;;
    *)
      echo "Unexpected target URL $1." >&2
      exit 1
      ;;
  esac
}

sha256_of() {
  sha256sum < "$1" | awk '{ print $1 }'
}

# upload <file>: stores the file under its own name, refused unless the
# service computes the same SHA-256.
upload() {
  file=$1
  name=$(basename "$file")
  sha256=$(sha256_of "$file")
  size=$(wc -c < "$file" | tr -d ' ')
  if [ "$size" -le "$single_limit" ]; then
    api -X PUT -H "x-checksum-sha256: $sha256" --data-binary @"$file" \
      "$RELEASE/$app/files/$name" > /dev/null
  else
    upload_id=$(api -X POST "$RELEASE/$app/files/$name?uploads" | jq -er .upload)
    rm -rf "$temporary/parts"
    mkdir "$temporary/parts"
    split -b "$part_size" "$file" "$temporary/parts/part."
    part=1
    for chunk in "$temporary"/parts/part.*; do
      api -X PUT --data-binary @"$chunk" "$RELEASE/$app/files/$name?upload=$upload_id&part=$part" > /dev/null
      part=$((part + 1))
    done
    api -X POST -H "x-checksum-sha256: $sha256" "$RELEASE/$app/files/$name?upload=$upload_id" > /dev/null
  fi
  echo "Uploaded $name ($size bytes, $sha256)." >&2
}

publish() {
  artifact=$1
  dist=$2
  notes_url=$3
  manifest="$dist/manifest-$artifact.json"
  manifest_url="$RELEASE/$app/$artifact/$channel.json"
  pinned='{}'
  uploaded=' '
  for pair in $(targets "$artifact"); do
    target=${pair%%=*}
    name=${pair#*=}
    [ -f "$dist/$name" ] || continue
    case "$uploaded" in
      *" $name "*) ;;
      *)
        upload "$dist/$name"
        uploaded="$uploaded$name "
        ;;
    esac
    pinned=$(printf '%s' "$pinned" | jq --arg target "$target" --arg file "$name" --arg sha256 "$(sha256_of "$dist/$name")" \
      '.[$target] = {file: $file, sha256: $sha256}')
  done
  if [ "$(printf '%s' "$pinned" | jq 'length')" -eq 0 ]; then
    echo "No $artifact files for $release_version; not publishing $artifact." >&2
    return 0
  fi
  jq -n \
    --arg channel "$channel" \
    --arg version "$release_version" \
    --arg notes_url "$notes_url" \
    --argjson targets "$pinned" \
    --argjson distributions "$(distributions "$artifact")" \
    '{channel: $channel, version: $version, notes_url: $notes_url, targets: $targets,
      distributions: ([{kind: "direct"}] + $distributions)}' > "$temporary/release.json"
  request -H 'content-type: application/json' --data-binary @"$temporary/release.json" \
    "$RELEASE/$app/$artifact/releases" > "$manifest"
  case "$status" in
    2??) ;;
    400)
      # A rerun: the channel already has this version; the checks below
      # require it to be exactly these files.
      grep -Fq "$release_version is already the current release" "$manifest" || {
        echo "The release service answered 400: $(cat "$manifest")" >&2
        exit 1
      }
      echo "$artifact $channel already has $release_version; checking that it is these files." >&2
      curl -fsS "$manifest_url" -o "$manifest"
      ;;
    *)
      echo "The release service answered $status: $(cat "$manifest")" >&2
      exit 1
      ;;
  esac

  # The service must serve exactly these bytes at the URLs it published.
  test "$(jq -r '"\(.app) \(.artifact) \(.channel) \(.release.version)"' "$manifest")" = "$app $artifact $channel $release_version"
  for target in $(printf '%s' "$pinned" | jq -r 'keys[]'); do
    name=$(printf '%s' "$pinned" | jq -r --arg target "$target" '.[$target].file')
    expected=$(sha256_of "$dist/$name")
    entry=$(jq -c --arg target "$target" '.release.targets[$target]' "$manifest")
    test "$(printf '%s' "$entry" | jq -r .sha256)" = "$expected"
    test "$(printf '%s' "$entry" | jq -r .size)" = "$(wc -c < "$dist/$name" | tr -d ' ')"
    url=$(resolve "$(printf '%s' "$entry" | jq -r .url)")
    curl -fsS --retry 3 "$url" -o "$temporary/served"
    test "$(sha256_of "$temporary/served")" = "$expected"
    echo "$target $url" >&2
  done
  curl -fsS "$manifest_url" | jq -e --arg version "$release_version" '.release.version == $version' > /dev/null
  echo "Published Deadbolt $artifact $release_version to $manifest_url." >&2
}

distribution() {
  artifact=$1
  kind=$2
  version=$3
  # The whole entry, so recording a version never drops its command.
  distributions "$artifact" | jq -e --arg kind "$kind" --arg version "$version" \
    'map(select(.kind == $kind))[0] // error("unknown distribution \($kind)") | . + {version: $version}' \
    > "$temporary/distribution.json"
  api -H 'content-type: application/json' --data-binary @"$temporary/distribution.json" \
    "$RELEASE/$app/$artifact/$channel/distribution" \
    | jq -e --arg kind "$kind" --arg version "$version" \
      '.release.distributions | any(.kind == $kind and .version == $version)' > /dev/null
  echo "Recorded that $kind serves Deadbolt $artifact $version." >&2
}

case "${1:-}" in
  publish)
    [ $# -eq 4 ] || { echo "Usage: $0 publish <artifact> <dist> <notes-url>" >&2; exit 1; }
    publish "$2" "$3" "$4"
    ;;
  distribution)
    [ $# -eq 4 ] || { echo "Usage: $0 distribution <artifact> <kind> <version>" >&2; exit 1; }
    distribution "$2" "$3" "$4"
    ;;
  *)
    echo "Usage: $0 publish <artifact> <dist> <notes-url> | distribution <artifact> <kind> <version>" >&2
    exit 1
    ;;
esac
