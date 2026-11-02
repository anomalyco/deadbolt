# shellcheck shell=bash
# Shared helpers for the release scripts. Sourced, never executed.
#
# .github/release/ and .github/workflows/release.yml are the security boundary
# for releases (docs/releasing.md). Jobs that hold a secret or an OIDC token
# check out only this directory and run only these scripts, on verified
# artifacts that they treat as data: they never build, install dependencies,
# or execute repository code or artifact contents. Every value that names a
# destination comes from the environment the workflow sets.

set -euo pipefail

die() {
  echo "::error::$*" >&2
  exit 1
}

sha256() {
  if command -v sha256sum > /dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# Windows runners pass D:\a\_temp style paths; Git Bash tools want /d/a/_temp.
posix() {
  if command -v cygpath > /dev/null; then cygpath -u "$1"; else printf '%s' "$1"; fi
}

# The code identities a release signs with. The Touch ID helper's identifier
# comes from its embedded Info.plist (crates/cli/src/daemon/enclave-Info.plist);
# the app's from Deadbolt.app's Info.plist (crates/app/scripts/bundle.sh).
# shellcheck disable=SC2034 # Used by the scripts that source this.
DEADBOLT_APP_ID=pw.deadbolt.app
# shellcheck disable=SC2034
DEADBOLT_CLI_ID=pw.deadbolt.cli
# shellcheck disable=SC2034
DEADBOLT_ENCLAVE_ID=pw.deadbolt.app.enclave

# developer_id_requirement <identifier>: a code requirement for code signed by
# Deadbolt's Developer ID Application certificate (team DEADBOLT_TEAM_ID) with
# that identifier.
developer_id_requirement() {
  : "${DEADBOLT_TEAM_ID:?Set DEADBOLT_TEAM_ID}"
  printf 'anchor apple generic and identifier "%s" and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "%s"' \
    "$1" "$DEADBOLT_TEAM_ID"
}

# check_developer_id <identifier> <path>: the code at <path> is signed with
# the Developer ID as <identifier>, with the hardened runtime and a secure
# timestamp.
check_developer_id() {
  codesign --verify --strict --all-architectures --verbose=2 -R="$(developer_id_requirement "$1")" "$2" ||
    die "$2 is not signed with Deadbolt's Developer ID as $1."
  local details
  details=$(codesign -d --verbose=4 "$2" 2>&1)
  grep -q 'flags=.*(runtime)' <<< "$details" || die "$2 is not signed with the hardened runtime."
  grep -q '^Timestamp=' <<< "$details" || die "$2 has no secure timestamp."
}

# mach_o_files <dir>: every Mach-O file under <dir>, relative and sorted.
mach_o_files() {
  (cd "$1" && find . -type f -exec sh -c 'file -b "$1" | grep -q Mach-O && printf "%s\n" "${1#./}"' _ {} \; | LC_ALL=C sort)
}
