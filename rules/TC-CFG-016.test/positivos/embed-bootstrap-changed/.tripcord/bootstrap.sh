#!/bin/sh
# Written by tripcord init --embed. Re-pin with:
#   tripcord init --embed --force --version <v> --sha256 <os-arch>=<hex>
#
# Installs the pinned Tripcord release, checks the binary against the
# pinned SHA-256, and runs it. It fails closed: an unpinned platform, no
# network, or a checksum mismatch exits non-zero, and no unverified
# binary is ever run. There is no fallback to another version, to
# latest, or to curl | sh. tripcord scan compares this file with the
# pin recorded in .tripcord/embed.json (TC-CFG-016); do not edit it.
#
# Usage:
#   bash .tripcord/bootstrap.sh install
#   bash .tripcord/bootstrap.sh session-start [--harness claude|cursor|copilot]
#   bash .tripcord/bootstrap.sh hook --harness <h> --event <e>
#
# install and session-start install the release and run
# tripcord scan --config. hook runs the installed binary's hook mode by
# absolute path and never installs. Diagnostics and scan output go to
# stderr; stdout carries only what the harness reads: {} for a Cursor
# session start, and the binary's own output in hook mode.
set -eu

TRIPCORD_VERSION='0.1.0'

# ---------------------------------------------------------------------
# Install sources, tried in order. Every candidate is verified against
# the pinned SHA-256 before it is used.
#   npm    npm pack @tripcord/cli-<os>-<arch>@<version> from the
#          configured npm registry
#   pypi   pip download tripcord==<version> from the configured index
#   cache  a binary already in the cache directory (for example, one a
#          cloud agent snapshot kept)
# The npm and PyPI packages are pending the distribution pipeline and
# are not published yet; until they are, only cache can succeed. Set
# TRIPCORD_INSTALL_SOURCES in the environment, to a space-separated
# subset of these, to change the order or skip a source for one run.
TRIPCORD_INSTALL_SOURCES="${TRIPCORD_INSTALL_SOURCES:-npm pypi cache}"
# ---------------------------------------------------------------------

emit_json=''
tmp=''
on_exit() {
  status=$?
  if [ -n "$tmp" ]; then
    rm -rf "$tmp"
  fi
  if [ -n "$emit_json" ]; then
    printf '{}\n'
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 1' HUP INT TERM

fail() {
  printf 'tripcord bootstrap: %s\n' "$1" >&2
  exit "${2:-1}"
}

usage='usage: bootstrap.sh install | session-start [--harness claude|cursor|copilot] | hook --harness <h> --event <e>'
mode="${1:-}"
case "$mode" in
  install)
    [ "$#" -eq 1 ] || fail "$usage" 2
    ;;
  session-start)
    case "$#:${2:-}" in
      1:) ;;
      3:--harness)
        case "$3" in
          cursor) emit_json=1 ;;
          claude|copilot) ;;
          *) fail "$usage" 2 ;;
        esac
        ;;
      *) fail "$usage" 2 ;;
    esac
    ;;
  hook) ;;
  *) fail "$usage" 2 ;;
esac
shift

pinned_sha256() {
  case "$1" in
    linux-x64) printf '%s\n' '0000000000000000000000000000000000000000000000000000000000000000' ;;
    *) return 1 ;;
  esac
}

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
  true
}

# pwd -P below resolves the script's directory: through a symlinked
# .tripcord it would name another tree and scan that instead.
if [ -L "$0" ] || [ -L "$(dirname -- "$0")" ]; then
  fail ".tripcord and .tripcord/bootstrap.sh must not be symlinks; rerun tripcord init --embed --force"
fi
script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd -P)"
cache_root="${XDG_CACHE_HOME:-${HOME:?HOME is not set}/.cache}"
case "$cache_root" in
  /*) ;;
  *) fail "the cache directory must be an absolute path: $cache_root" 3 ;;
esac
cache_dir="$cache_root/tripcord/$TRIPCORD_VERSION/$platform"
cached="$cache_dir/tripcord"

if [ "$mode" = hook ]; then
  verified "$cached" || fail "tripcord $TRIPCORD_VERSION for $platform is not installed with a matching SHA-256; run bash .tripcord/bootstrap.sh install"
  exec "$cached" hook "$@"
fi

for source in $TRIPCORD_INSTALL_SOURCES; do
  case "$source" in
    npm|pypi|cache) ;;
    *) fail "unknown install source: $source (want npm, pypi, or cache)" 3 ;;
  esac
done

umask 077
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tripcord-bootstrap.XXXXXX")"
chmod 0700 "$tmp"

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

"$cached" scan --config "$repo_root" >&2
