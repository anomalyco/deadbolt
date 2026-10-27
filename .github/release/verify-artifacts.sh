#!/usr/bin/env bash
# verify-artifacts.sh <dir>: checks every artifact downloaded into <dir>/<name>.
# Its SHA256SUMS must have the digest the job that made it reported
# (DEADBOLT_DIGESTS="name=digest ..."), every listed file must match, and it must
# hold nothing else. An artifact without a reported digest, or replaced after
# its job finished, is rejected.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

root=$(posix "$1")
found=0
for dir in "$root"/*/; do
  name=$(basename "$dir")
  digest=""
  for pair in ${DEADBOLT_DIGESTS:-}; do
    if [ "${pair%%=*}" = "$name" ]; then digest=${pair#*=}; fi
  done
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "No digest was reported for $name"
  (
    cd "$dir" || exit
    [ "$(sha256 SHA256SUMS | cut -c1-64)" = "$digest" ] || die "SHA256SUMS of $name does not have the reported digest"
    sha256 -c SHA256SUMS > /dev/null || die "Checksum mismatch in $name"
    diff <(find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort) <(cut -c67- SHA256SUMS | LC_ALL=C sort) ||
      die "Unexpected files in $name"
  )
  echo "verified $name ($digest)"
  found=$((found + 1))
done
[ "$found" -gt 0 ] || die "No artifacts in $root"
