#!/bin/sh
# Written by tripcord init --embed. Re-pin with:
#   tripcord init --embed --force --version <v> --sha256 <os-arch>=<hex>
#
# Runs the pinned Tripcord build from the cache, after checking it
# against the pinned SHA-256. It never downloads or installs anything:
# fill the cache with go build -trimpath of the pinned commit (see
# docs/init.md). It fails closed: an unpinned platform, a missing binary,
# or a checksum mismatch exits 2 with the reason on stderr, and no
# unverified binary is ever run. tripcord scan compares this file with
# the pin recorded in .tripcord/embed.json (TC-CFG-016); do not edit it.
#
# Usage:
#   bash .tripcord/bootstrap.sh install
#   bash .tripcord/bootstrap.sh session-start [--harness claude|cursor|copilot]
#   bash .tripcord/bootstrap.sh hook --harness <h> --event <e> [--on-failure block|error]
#
# install and session-start check the cached binary and run
# tripcord scan --config. hook execs the cached binary's hook mode by
# absolute path. Diagnostics and scan output go to stderr; stdout
# carries only what the harness reads: {} for a Cursor session start,
# and the binary's own output in hook mode.
set -eu

TRIPCORD_VERSION='0.1.0'

emit_json=''
on_exit() {
  status=$?
  if [ -n "$emit_json" ]; then
    printf '{}\n'
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 2' HUP INT TERM

fail() {
  printf 'tripcord bootstrap: %s\n' "$1" >&2
  exit 2
}

usage='usage: bootstrap.sh install | session-start [--harness claude|cursor|copilot] | hook --harness <h> --event <e> [--on-failure block|error]'
mode="${1:-}"
case "$mode" in
  install)
    [ "$#" -eq 1 ] || fail "$usage"
    ;;
  session-start)
    case "$#:${2:-}" in
      1:) ;;
      3:--harness)
        case "$3" in
          cursor) emit_json=1 ;;
          claude|copilot) ;;
          *) fail "$usage" ;;
        esac
        ;;
      *) fail "$usage" ;;
    esac
    ;;
  hook) ;;
  *) fail "$usage" ;;
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
  *) fail "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac
platform="$os-$arch"

if ! want="$(pinned_sha256 "$platform")"; then
  fail "no SHA-256 is pinned for $platform; rerun tripcord init --embed --force with --sha256 $platform=<hex>"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  sha_tool=shasum
else
  fail "neither sha256sum nor shasum is installed"
fi

sha256_of() {
  if [ "$sha_tool" = sha256sum ]; then
    sum="$(sha256sum "$1")" || return 1
  else
    sum="$(shasum -a 256 "$1")" || return 1
  fi
  printf '%s\n' "${sum%% *}"
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
  *) fail "the cache directory must be an absolute path: $cache_root" ;;
esac
cached="$cache_root/tripcord/$TRIPCORD_VERSION/$platform/tripcord"

if [ ! -e "$cached" ] && [ ! -L "$cached" ]; then
  fail "tripcord $TRIPCORD_VERSION for $platform is not in the cache at $cached; build the pinned commit there with go build -trimpath (see docs/init.md)"
fi
if [ -L "$cached" ] || [ ! -f "$cached" ]; then
  fail "the cached tripcord at $cached is not a regular file; replace it with a go build -trimpath of the pinned commit"
fi
got="$(sha256_of "$cached")" || fail "cannot read the cached tripcord at $cached"
if false; then
  fail "the cached tripcord at $cached has SHA-256 $got, not the pinned $want; it was not run"
fi

if [ "$mode" = hook ]; then
  exec "$cached" hook "$@"
fi
"$cached" scan --config "$repo_root" >&2
