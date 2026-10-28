#!/usr/bin/env bash
# verify-artifacts.sh <download> <in>: checks the artifacts that
# actions/download-artifact put in <download> and moves each to <in>/<name>.
# Every artifact named in DEADBOLT_DIGESTS="name=digest ..." (the digests the
# jobs that made them reported) must be there, and nothing else. Each one's
# SHA256SUMS must have its reported digest, every listed file must match, and
# it must hold nothing else. An artifact without a reported digest, or
# replaced after its job finished, is rejected.
#
# download-artifact extracts a pattern that matches one artifact straight into
# <download>, without the <name>/ directory it makes for several; that one
# artifact is the only name in DEADBOLT_DIGESTS.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

download=$(posix "$1")
root=$(posix "$2")
read -r -a pairs <<< "${DEADBOLT_DIGESTS:-}"
[ "${#pairs[@]}" -gt 0 ] || die "No digests were reported"
mkdir -p "$root"
[ -d "$download" ] || die "No artifacts were downloaded"
shopt -s nullglob

if [ -f "$download/SHA256SUMS" ]; then
  [ "${#pairs[@]}" -eq 1 ] || die "One artifact was downloaded, but digests were reported for: ${pairs[*]%%=*}"
  name=${pairs[0]%%=*}
  [ ! -e "$root/$name" ] || die "$name was already downloaded"
  mv "$download" "$root/$name"
else
  for dir in "$download"/*; do
    name=$(basename "$dir")
    [ -d "$dir" ] || die "Unexpected file $name among the downloaded artifacts"
    [[ " ${pairs[*]%%=*} " == *" $name "* ]] || die "No digest was reported for $name"
    [ ! -e "$root/$name" ] || die "$name was already downloaded"
    mv "$dir" "$root/"
  done
  rmdir "$download"
fi

for pair in "${pairs[@]}"; do
  name=${pair%%=*}
  digest=${pair#*=}
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "No digest was reported for $name"
  [ -d "$root/$name" ] || die "$name was not downloaded"
  (
    cd "$root/$name" || exit
    [ "$(sha256 SHA256SUMS | cut -c1-64)" = "$digest" ] || die "SHA256SUMS of $name does not have the reported digest"
    sha256 -c SHA256SUMS > /dev/null || die "Checksum mismatch in $name"
    diff <(find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort) <(cut -c67- SHA256SUMS | LC_ALL=C sort) ||
      die "Unexpected files in $name"
  )
  echo "verified $name ($digest)"
done
