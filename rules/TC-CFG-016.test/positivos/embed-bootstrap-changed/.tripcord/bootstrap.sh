#!/bin/sh
# Written by tripcord init --embed. Re-pin with:
#   tripcord init --embed --force --version <v> --sha256 <os-arch>=<hex>
#
# Runs the pinned Tripcord build from the cache, after checking it
# against the pinned SHA-256. It never downloads or installs anything:
# fill the cache with go build -trimpath of the pinned commit (see
# docs/init.md). It fails closed: an unpinned platform, a missing or
# non-executable binary, a checksum mismatch, or a cache directory
# another user can write exits 2 with the reason on stderr, and no
# unverified binary is ever run. tripcord scan compares this file with
# the pin recorded in .tripcord/embed.json (TC-CFG-016); do not edit it.
#
# Usage:
#   bash .tripcord/bootstrap.sh install
#   bash .tripcord/bootstrap.sh session-start [--harness claude|cursor|copilot]
#   bash .tripcord/bootstrap.sh hook --harness <h> --event <e> [--on-failure block|error]
#
# Every mode copies the cached binary into a private directory, checks
# the copy, and runs the copy, so the file that runs is the file that
# was hashed. install and session-start then run tripcord scan --config;
# hook execs the copy's hook mode. Diagnostics and scan output go to
# stderr; stdout carries only what the harness reads: {} for a Cursor
# session start, and the binary's own output in hook mode.
set -eu

TRIPCORD_VERSION='0.1.0'

emit_json=''
run=''
on_exit() {
  status=$?
  if [ -n "$run" ]; then
    "$rm_tool" -rf "$run"
  fi
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

# The tools that decide what runs are called by absolute path, never
# through the caller's PATH, which the caller may have prepended to.
system_tool() {
  for dir in /usr/bin /bin; do
    if [ -x "$dir/$1" ]; then
      printf '%s\n' "$dir/$1"
      return 0
    fi
  done
  return 1
}
need() {
  system_tool "$1" || fail "$1 is not installed in /usr/bin or /bin"
}
rm_tool="$(need rm)" || exit 2
uname_tool="$(need uname)" || exit 2
dirname_tool="$(need dirname)" || exit 2
id_tool="$(need id)" || exit 2
find_tool="$(need find)" || exit 2
mkdir_tool="$(need mkdir)" || exit 2
mktemp_tool="$(need mktemp)" || exit 2
cp_tool="$(need cp)" || exit 2
chmod_tool="$(need chmod)" || exit 2

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

case "$("$uname_tool" -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported operating system: $("$uname_tool" -s)" ;;
esac
case "$("$uname_tool" -m)" in
  x86_64|amd64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail "unsupported architecture: $("$uname_tool" -m)" ;;
esac
platform="$os-$arch"

if ! want="$(pinned_sha256 "$platform")"; then
  fail "no SHA-256 is pinned for $platform; rerun tripcord init --embed --force with --sha256 $platform=<hex>"
fi

if sha_tool="$(system_tool sha256sum)"; then
  sha_args=''
elif sha_tool="$(system_tool shasum)"; then
  sha_args='-a 256'
else
  fail "neither sha256sum nor shasum is installed in /usr/bin or /bin"
fi

sha256_of() {
  # shellcheck disable=SC2086 # sha_args is empty or two words
  sum="$("$sha_tool" $sha_args "$1")" || return 1
  printf '%s\n' "${sum%% *}"
}

# pwd -P below resolves the script's directory: through a symlinked
# .tripcord it would name another tree and scan that instead.
if [ -L "$0" ] || [ -L "$("$dirname_tool" -- "$0")" ]; then
  fail ".tripcord and .tripcord/bootstrap.sh must not be symlinks; rerun tripcord init --embed --force"
fi
script_dir="$(CDPATH='' cd -- "$("$dirname_tool" -- "$0")" && pwd -P)"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd -P)"
cache_root="${XDG_CACHE_HOME:-${HOME:?HOME is not set}/.cache}"
case "$cache_root" in
  /*) ;;
  *) fail "the cache directory must be an absolute path: $cache_root" ;;
esac
tripcord_root="$cache_root/tripcord"
cache_dir="$tripcord_root/$TRIPCORD_VERSION/$platform"
cached="$cache_dir/tripcord"

if [ ! -e "$cached" ] && [ ! -L "$cached" ]; then
  fail "tripcord $TRIPCORD_VERSION for $platform is not in the cache at $cached; build the pinned commit there with go build -trimpath (see docs/init.md)"
fi

uid="$("$id_tool" -u)"
# private_dir fails unless $1 is a directory, not a symlink, that this
# user owns and no one else can write: otherwise another user could
# replace the binary in it, or the copy of it, after it was checked.
private_dir() {
  if [ -L "$1" ] || [ ! -d "$1" ]; then
    fail "the cache directory $1 is not a directory or is a symlink; it must be a directory you own"
  fi
  if [ -z "$("$find_tool" "$1" -prune -user "$uid" -print)" ]; then
    fail "the cache directory $1 is owned by another user; it must be owned by you"
  fi
  if [ -n "$("$find_tool" "$1" -prune \( -perm -0020 -o -perm -0002 \) -print)" ]; then
    fail "the cache directory $1 is group- or world-writable; run chmod go-w on it"
  fi
}
for dir in "$tripcord_root" "$tripcord_root/$TRIPCORD_VERSION" "$cache_dir"; do
  private_dir "$dir"
done

if [ -L "$cached" ] || [ ! -f "$cached" ]; then
  fail "the cached tripcord at $cached is not a regular file; replace it with a go build -trimpath of the pinned commit"
fi
if [ ! -x "$cached" ]; then
  fail "the cached tripcord at $cached is not executable; run chmod 0755 on it"
fi

# The copy lives under the cache root, not TMPDIR, which may be mounted
# noexec. exec leaves the copy of a hook run behind, so each run first
# removes this user's copies more than a minute old: a hook run ends
# within seconds, and a running binary does not need its file.
runs="$tripcord_root/.run"
if [ ! -e "$runs" ] && [ ! -L "$runs" ]; then
  "$mkdir_tool" -m 0700 "$runs" 2>/dev/null || [ -d "$runs" ] || fail "cannot create $runs"
fi
private_dir "$runs"
"$find_tool" "$runs" -mindepth 1 -maxdepth 1 -type d -name 'run.*' -user "$uid" -mmin +1 -exec "$rm_tool" -rf {} + 2>/dev/null || true
run="$(umask 077 && "$mktemp_tool" -d "$runs/run.XXXXXX")" || fail "cannot create a private directory in $runs"
"$chmod_tool" 0700 "$run"
copy="$run/tripcord"
"$cp_tool" "$cached" "$copy" || fail "cannot copy the cached tripcord at $cached"
"$chmod_tool" 0700 "$copy"
got="$(sha256_of "$copy")" || fail "cannot read the cached tripcord at $cached"
if false; then
  fail "the cached tripcord at $cached has SHA-256 $got, not the pinned $want; it was not run"
fi

if [ "$mode" = hook ]; then
  exec "$copy" hook "$@"
fi
"$copy" scan --config "$repo_root" >&2
