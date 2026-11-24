#!/usr/bin/env bash
# deploy-site.sh <dev> <dir>: deploys the dev site static-assets Worker from a
# verified artifact (<dir>, holding dist/ from deploy-site.yml's build job)
# with the wrangler CLI pinned in wrangler/package-lock.json, which the
# workflow installs (npm ci --ignore-scripts) before the token is in reach.
#
# The artifact was built from repository code without secrets, so everything
# in it is untrusted. Its static assets may change freely, but the config
# wrangler deploys is always the pinned target in targets/site-<mode>.json
# (Worker name, account_id, routes, and no bindings): any config or unexpected
# file in the artifact is refused, and production stays manual until wired.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

[ $# -eq 2 ] || die "Usage: deploy-site.sh <dev> <dir>"
mode=$1
release=$(cd "$(dirname "$0")" && pwd)
case "$mode" in
  dev)
    target="$release/targets/site-dev.json"
    ;;
  *) die "Unsupported site mode: $mode (only dev is enabled for CI deploy)" ;;
esac
[ -f "$target" ] || die "No pinned site target for $mode: $target"

: "${CLOUDFLARE_API_TOKEN:?Set CLOUDFLARE_API_TOKEN}"
account=$(jq -er '.account_id' "$target") || die "Pinned target $target has no account_id."
case "$account" in
  *[!0-9a-f]*|"") die "Pinned target $target account_id must be a 32-character lowercase hex id." ;;
esac
[ ${#account} -eq 32 ] || die "Pinned target $target account_id must be a 32-character lowercase hex id."
if [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ] && [ "$CLOUDFLARE_ACCOUNT_ID" != "$account" ]; then
  die "CLOUDFLARE_ACCOUNT_ID ($CLOUDFLARE_ACCOUNT_ID) does not match pinned target $target ($account)."
fi
export CLOUDFLARE_ACCOUNT_ID="$account"

src=$(cd "$2" && pwd)

# Only dist/ (plus SHA256SUMS from upload); nothing else is accepted or copied
# to where wrangler runs.
unexpected=$(cd "$src" && find . ! -type d ! -type f -o -type f ! -path ./SHA256SUMS \
  ! -path './dist/*')
[ -z "$unexpected" ] || die "Unexpected files in the site artifact: $unexpected"
[ -f "$src/dist/index.html" ] || die "Missing dist/index.html in the site artifact"
[ -f "$src/dist/architecture/index.html" ] || die "Missing dist/architecture/index.html in the site artifact"
[ -f "$src/dist/r.html" ] || die "Missing dist/r.html in the site artifact"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$target" "$work/wrangler.json"
cp -R "$src/dist" "$work/dist"

wrangler="$release/wrangler/node_modules/.bin/wrangler"
[ -x "$wrangler" ] || die "Install the pinned wrangler CLI first: npm ci --ignore-scripts in .github/release/wrangler"
cd "$work" || exit 1
WRANGLER_SEND_METRICS=false "$wrangler" deploy --config "$work/wrangler.json"
