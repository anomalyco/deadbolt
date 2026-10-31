#!/bin/sh
# Linux only. No host interfaces/routes/qdiscs, browser profiles or trust stores are modified.
set -eu
mode=full
if [ "${1:-}" = --smoke ]; then mode=smoke; shift; fi
if [ "$#" != 4 ]; then echo "usage: $0 [--smoke] <standalone dist> <iroh-relay 1.3.0> <relay_store example> <debug fixture CLI>" >&2; exit 2; fi
dist=$(realpath "$1"); relay=$(realpath "$2"); store=$(realpath "$3"); cli=$(realpath "$4")
[ -f "$dist/offscreen.html" ] && [ -x "$relay" ] && [ -x "$store" ] && [ -x "$cli" ] || exit 2
browsers=${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}
root=$(mktemp -d); trap 'rm -rf "$root"' EXIT
umask 077
mkdir "$root/home" "$root/tmp" "$root/run"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -addext "subjectAltName=DNS:use1-1.relay.n0.iroh.link,DNS:dns.iroh.link" -addext "basicConstraints=critical,CA:FALSE" -subj /CN=private-relay.test -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl x509 -in "$root/cert.pem" -outform der -out "$root/cert.der"
printf "%s\n" "127.0.0.1 localhost" "127.0.0.2 use1-1.relay.n0.iroh.link" "127.0.0.3 dns.iroh.link" "::1 use1-1.relay.n0.iroh.link dns.iroh.link" >"$root/hosts"
printf "%s\n" "nameserver 127.0.0.1" >"$root/resolv.conf"
pin=$(openssl x509 -in "$root/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64 -A)
# sudo creates the namespaces, not the browser. PID 1 exit also reaps all children on failure.
sudo unshare --net --mount --propagation private --pid --fork --mount-proc --kill-child sh -eu -c '
  mount --bind "$4/hosts" /etc/hosts
  mount --bind "$4/resolv.conf" /etc/resolv.conf
  sysctl -qw net.ipv4.ip_unprivileged_port_start=443
  ip link set lo mtu 1500 up
  ethtool -K lo tso off gso off gro off
  exec setpriv --reuid="$1" --regid="$2" --init-groups env -i PATH="$3" HOME="$4/home" \
    TMPDIR="$4/tmp" XDG_RUNTIME_DIR="$4/run" PLAYWRIGHT_BROWSERS_PATH="$5" \
    timeout -k 5s 12m bun "$6" "$4" "$7" "$8" "$9" "${10}" "${11}" "${12}"
' sh "$(id -u)" "$(id -g)" "$PATH" "$root" "$browsers" "$(realpath "$(dirname "$0")/run.ts")" "$dist" "$relay" "$store" "$pin" "$cli" "$mode"
