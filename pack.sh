#!/bin/sh
# Build a Splunk-installable tarball of TA-checkmk (no Checkmk site plugin).
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
version=$(awk -F' = ' '/^version = / {print $2; exit}' "$root/default/app.conf")
out="${1:-$root/../TA-checkmk-${version}.tar.gz}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/TA-checkmk"
tar -C "$root" \
  --exclude='tests' \
  --exclude='pack.sh' \
  --exclude='.gitignore' \
  --exclude='local' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -cf - . | tar -C "$tmp/TA-checkmk" -xf -
tar -C "$tmp" -czf "$out" TA-checkmk
echo "$out"
