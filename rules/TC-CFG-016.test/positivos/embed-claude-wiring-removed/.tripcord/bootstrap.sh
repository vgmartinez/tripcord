#!/bin/sh
# Written by tripcord init --embed. Re-pin with:
#   tripcord init --embed --force --version <v> --sha256 <os-arch>=<hex>
#
# Installs the pinned Tripcord release, checks the binary against the
# pinned SHA-256, and runs tripcord scan --config on this repository.
# It fails closed: an unpinned platform, no network, or a checksum
# mismatch exits non-zero, and no unverified binary is ever run. There
# is no fallback to another version, to latest, or to curl | sh.
#
# Usage: bash .tripcord/bootstrap.sh install|session-start
set -eu

TRIPCORD_VERSION='0.1.0'

# ---------------------------------------------------------------------
# Install source. Tried in order; every candidate is verified against
# the pinned SHA-256 before it is used.
#   npm    npm pack @tripcord/cli-<os>-<arch>@<version> from the
#          configured npm registry
#   pypi   pip download tripcord==<version> from the configured index
#   cache  a binary already in the cache directory (for example, one a
#          cloud agent snapshot kept)
# The npm and PyPI packages are pending the distribution pipeline and
# are not published yet; until they are, only cache can succeed.
TRIPCORD_INSTALL_SOURCES='npm pypi cache'
# ---------------------------------------------------------------------

fail() {
  printf 'tripcord bootstrap: %s\n' "$1" >&2
  exit "${2:-1}"
}

pinned_sha256() {
  case "$1" in
    linux-x64) printf '%s\n' '0000000000000000000000000000000000000000000000000000000000000000' ;;
    *) return 1 ;;
  esac
}

mode="${1:-}"
case "$mode" in
  install|session-start) ;;
  *) fail "usage: bootstrap.sh install|session-start" 2 ;;
esac

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported operating system: $(uname -s)" 3 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" 3 ;;
esac
platform="$os-$arch"

if ! want="$(pinned_sha256 "$platform")"; then
  fail "no SHA-256 is pinned for $platform; rerun tripcord init --embed --force with --sha256 $platform=<hex>" 3
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  sha_tool=shasum
else
  fail "neither sha256sum nor shasum is installed" 3
fi

sha256_of() {
  if [ "$sha_tool" = sha256sum ]; then
    sum="$(sha256sum "$1")" || return 1
  else
    sum="$(shasum -a 256 "$1")" || return 1
  fi
  printf '%s\n' "${sum%% *}"
}

verified() {
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  got="$(sha256_of "$1")" || return 1
  [ "$got" = "$want" ]
}

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd -P)"
cache_root="${XDG_CACHE_HOME:-${HOME:?HOME is not set}/.cache}"
cache_dir="$cache_root/tripcord/$TRIPCORD_VERSION/$platform"
cached="$cache_dir/tripcord"

umask 077
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tripcord-bootstrap.XXXXXX")"
chmod 0700 "$tmp"
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

fetch_npm() {
  command -v npm >/dev/null 2>&1 || return 1
  dir="$tmp/npm"
  mkdir -m 0700 "$dir" || return 1
  (cd "$dir" && npm pack --ignore-scripts --silent "@tripcord/cli-$platform@$TRIPCORD_VERSION") >/dev/null 2>&1 || return 1
  for tgz in "$dir"/*.tgz; do
    [ -f "$tgz" ] || return 1
    tar -xzf "$tgz" -C "$dir" package/bin/tripcord >/dev/null 2>&1 || return 1
  done
  candidate="$dir/package/bin/tripcord"
  verified "$candidate"
}

fetch_pypi() {
  command -v python3 >/dev/null 2>&1 || return 1
  dir="$tmp/pypi"
  mkdir -m 0700 "$dir" "$dir/out" || return 1
  python3 -m pip download --quiet --no-deps --only-binary=:all: --dest "$dir" "tripcord==$TRIPCORD_VERSION" >/dev/null 2>&1 || return 1
  for whl in "$dir"/*.whl; do
    [ -f "$whl" ] || return 1
    python3 - "$whl" "$dir/out" <<'PY' || return 1
import os, sys, zipfile
wheel, out = sys.argv[1], sys.argv[2]
count = 0
with zipfile.ZipFile(wheel) as z:
    for info in z.infolist():
        if info.is_dir() or os.path.basename(info.filename) != "tripcord":
            continue
        if info.file_size > 256 << 20:
            continue
        count += 1
        with z.open(info) as src, open(os.path.join(out, "c%d" % count), "wb") as dst:
            dst.write(src.read())
PY
  done
  for candidate in "$dir/out"/c*; do
    if verified "$candidate"; then
      return 0
    fi
  done
  return 1
}

fetch_cache() {
  candidate="$cached"
  verified "$candidate"
}

found=''
for source in $TRIPCORD_INSTALL_SOURCES; do
  candidate=''
  case "$source" in
    npm) fetch_npm || continue ;;
    pypi) fetch_pypi || continue ;;
    cache) fetch_cache || continue ;;
    *) fail "unknown install source: $source" 3 ;;
  esac
  found="$source"
  break
done
if [ -z "$found" ]; then
  fail "could not install tripcord $TRIPCORD_VERSION for $platform with a matching SHA-256 (tried: $TRIPCORD_INSTALL_SOURCES)"
fi

if [ "$found" != cache ]; then
  mkdir -p "$cache_dir"
  cp "$candidate" "$cache_dir/.tripcord.$$"
  chmod 0755 "$cache_dir/.tripcord.$$"
  mv -f "$cache_dir/.tripcord.$$" "$cached"
  verified "$cached" || fail "installed binary does not match the pinned SHA-256"
fi

if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$cache_dir" >>"$GITHUB_PATH"
fi
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  case "$cache_dir" in
    *"'"*) fail "cache directory contains a single quote: $cache_dir" 3 ;;
  esac
  printf "export PATH='%s':\"\$PATH\"\n" "$cache_dir" >>"$CLAUDE_ENV_FILE"
fi

"$cached" scan --config "$repo_root"
