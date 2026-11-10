package embedded

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Platforms are the os-arch names bootstrap.sh can pin.
var Platforms = []string{"darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"}

var (
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Pin is the Tripcord build bootstrap.sh runs: a version, which names
// its cache directory, and the SHA-256 of the tripcord binary for each
// platform.
type Pin struct {
	Version string
	SHA256  map[string]string
}

// Validate rejects a pin that bootstrap.sh could not verify against.
// Every value is later written into a shell script, so each one must
// match a pattern with no shell metacharacters.
func (p Pin) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("--version is required with --embed: bootstrap.sh runs only a pinned build")
	}
	if !versionPattern.MatchString(p.Version) {
		return fmt.Errorf("--version %q: want a release version such as 0.1.0", p.Version)
	}
	if len(p.SHA256) == 0 {
		return fmt.Errorf("--sha256 <os-arch>=<hex> is required with --embed: bootstrap.sh never runs an unverified binary")
	}
	for platform, sum := range p.SHA256 {
		if !slices.Contains(Platforms, platform) {
			return fmt.Errorf("--sha256 %s: unknown platform; want one of %s", platform, strings.Join(Platforms, ", "))
		}
		if !sha256Pattern.MatchString(sum) {
			return fmt.Errorf("--sha256 %s: want 64 lowercase hex characters", platform)
		}
	}
	return nil
}

// ParsePinSHA256 parses one --sha256 value, <os-arch>=<hex>, into sums.
func ParsePinSHA256(sums map[string]string, value string) error {
	platform, sum, ok := strings.Cut(value, "=")
	if !ok || platform == "" || sum == "" {
		return fmt.Errorf("--sha256 %q: want <os-arch>=<hex>", value)
	}
	if _, dup := sums[platform]; dup {
		return fmt.Errorf("--sha256 %s: given more than once", platform)
	}
	sums[platform] = sum
	return nil
}

// Bootstrap returns .tripcord/bootstrap.sh for p. p must be valid.
func Bootstrap(p Pin) []byte {
	platforms := make([]string, 0, len(p.SHA256))
	for platform := range p.SHA256 {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	var cases strings.Builder
	for _, platform := range platforms {
		fmt.Fprintf(&cases, "    %s) printf '%%s\\n' '%s' ;;\n", platform, p.SHA256[platform])
	}
	script := strings.ReplaceAll(bootstrapTemplate, "@VERSION@", p.Version)
	script = strings.ReplaceAll(script, "@CASES@", cases.String())
	return []byte(script)
}

const bootstrapTemplate = `#!/bin/sh
# Written by tripcord init --embed. Re-pin with --embed --force.
# Fails closed: exit 2 and run nothing. scan compares this file with
# .tripcord/embed.json (TC-CFG-016); do not edit it. install and
# session-start record device, inode, size, mtime, and ctime. hook runs
# the cached file only when that record matches.
set -eu

TRIPCORD_VERSION='@VERSION@'

emit_json=''
run=''
rm_tool=''
sha_tool=''
sha_args=''
stat_kind=''
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

fold_home() {
  rest=$1
  out=''
  case "${HOME:-}" in
    ''|/) printf '%s\n' "$rest"; return 0 ;;
  esac
  while :; do
    case "$rest" in
      *"$HOME/"*) ;;
      *) break ;;
    esac
    before=${rest%%"$HOME/"*}
    case "$before" in
      ''|*' ') out="$out$before~/" ;;
      *) out="$out$before$HOME/" ;;
    esac
    rest=${rest#*"$HOME/"}
  done
  printf '%s\n' "$out$rest"
}

fail() {
  printf 'tripcord bootstrap: %s\n' "$(fold_home "$1")" >&2
  exit 2
}

nix_tools_safe() {
  nix_bin=/run/current-system/sw/bin
  [ -d "$nix_bin" ] && [ -x "$nix_bin/stat" ] || return 1
  nix_owner_mode="$("$nix_bin/stat" -c '%u:%a' "$nix_bin" 2>/dev/null)" || return 1
  case "$nix_owner_mode" in
    0:[0-7][0-5][0-5]|0:[0-7][0-5][0-5][0-5]) return 0 ;;
    *) return 1 ;;
  esac
}
system_tool() {
  for dir in /usr/bin /bin; do
    if [ -x "$dir/$1" ]; then
      printf '%s\n' "$dir/$1"
      return 0
    fi
  done
  if nix_tools_safe && [ -x "/run/current-system/sw/bin/$1" ]; then
    printf '%s\n' "/run/current-system/sw/bin/$1"
    return 0
  fi
  return 1
}
need() {
  system_tool "$1" || fail "$1 is not installed in /usr/bin or /bin"
}
if [ -x /usr/bin/stat ]; then stat_tool=/usr/bin/stat
elif [ -x /bin/stat ]; then stat_tool=/bin/stat
elif nix_tools_safe && [ -x /run/current-system/sw/bin/stat ]; then stat_tool=/run/current-system/sw/bin/stat
else fail "stat is not installed in /usr/bin or /bin"
fi

file_id() {
  [ -L "$1" ] && return 1
  if [ "$stat_kind" = gnu ]; then "$stat_tool" -c '%d %i %s %.Y %.Z' "$1"
  else "$stat_tool" -f '%d %i %z %m %c' "$1"; fi
}
group_or_other_write() {
  perm=$1
  while [ "${#perm}" -gt 3 ]; do perm=${perm#?}; done
  while [ "${#perm}" -lt 3 ]; do perm=0$perm; done
  case "${perm#?}" in
    [0145][0145]) return 1 ;;
    *) return 0 ;;
  esac
}

usage='usage: bootstrap.sh install | session-start [--harness name] | hook [args]'
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
@CASES@    *) return 1 ;;
  esac
}

# shellcheck disable=SC3028
uid=${EUID:-}; os=''; arch=''
# shellcheck disable=SC3028
case "${OSTYPE:-}" in linux*) os=linux;; darwin*) os=darwin;; esac
# shellcheck disable=SC3028
case "${HOSTTYPE:-}" in x86_64|amd64) arch=x64;; aarch64|arm64) arch=arm64;; esac
if [ -z "$uid" ]; then id_tool="$(need id)" || exit 2; uid=$("$id_tool" -u) || fail "cannot read the user id"; fi
if [ -z "$os" ] || [ -z "$arch" ]; then
  uname_tool="$(need uname)" || exit 2
  uname_sm=$("$uname_tool" -sm) || fail "cannot run uname"
  case "${uname_sm%% *}" in Linux) os=linux;; Darwin) os=darwin;; *) fail "unsupported operating system: ${uname_sm%% *}";; esac
  case "${uname_sm#* }" in x86_64|amd64) arch=x64;; aarch64|arm64) arch=arm64;; *) fail "unsupported architecture: ${uname_sm#* }";; esac
fi
platform="$os-$arch"

if ! want="$(pinned_sha256 "$platform")"; then
  fail "no SHA-256 is pinned for $platform"
fi

sha256_of() {
  # shellcheck disable=SC2086 # sha_args is empty or two words
  sum="$("$sha_tool" $sha_args "$1")" || return 1
  printf '%s\n' "${sum%% *}"
}

case "$0" in
  /*/*) script_parent=${0%/*} ;;
  /*) script_parent=/ ;;
  */*) script_parent=${0%/*} ;;
  *) script_parent=. ;;
esac
if [ -L "$0" ] || [ -L "$script_parent" ]; then
  fail ".tripcord and .tripcord/bootstrap.sh must not be symlinks"
fi
cache_root="${XDG_CACHE_HOME:-${HOME:?HOME is not set}/.cache}"
case "$cache_root" in
  /*) ;;
  *) fail "the cache directory must be an absolute path: $cache_root" ;;
esac
tripcord_root="$cache_root/tripcord"
cache_dir="$tripcord_root/$TRIPCORD_VERSION/$platform"
cached="$cache_dir/tripcord"

if [ ! -e "$cached" ] && [ ! -L "$cached" ]; then
  fail "tripcord $TRIPCORD_VERSION for $platform is not in the cache at $cached; fill the cache"
fi

private_dirs() {
  bad_type=''
  bad_owner=''
  bad_mode=''
  for dir in "$@"; do
    if [ -L "$dir" ] || [ ! -d "$dir" ]; then
      bad_type="$bad_type $dir"
      continue
    fi
    if [ -z "$("$find_tool" "$dir" -prune -user "$uid" -print)" ]; then
      bad_owner="$bad_owner $dir"
    fi
    if [ -n "$("$find_tool" "$dir" -prune \( -perm -0020 -o -perm -0002 \) -print)" ]; then
      bad_mode="$bad_mode $dir"
    fi
  done
  if [ -n "$bad_type" ]; then
    fail "cache directories are not directories or are symlinks:$bad_type"
  fi
  if [ -n "$bad_owner$bad_mode" ]; then
    message="unsafe cache directories:$bad_owner$bad_mode"
    if [ -n "$bad_mode" ]; then
      message="$message (group- or world-writable); run chmod go-w$bad_mode"
    fi
    if [ -n "$bad_owner" ]; then
      message="$message; cache directories must be owned by uid $uid"
    fi
    fail "$message"
  fi
}
if [ -L "$cached" ] || [ ! -f "$cached" ]; then
  fail "the cached tripcord at $cached is not a regular file"
fi
if [ ! -x "$cached" ]; then
  fail "the cached tripcord at $cached is not executable; run chmod 0755 on it"
fi

marker="$cache_dir/verified"
hook_fast() {
  [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
  a=$tripcord_root; b=$a/$TRIPCORD_VERSION; c=$cache_dir
  for dir in "$a" "$b" "$c"; do [ -d "$dir" ] && [ ! -L "$dir" ] || return 1; done
  if stats=$("$stat_tool" -c '%u %a %d %i %s %.Y %.Z' "$a" "$b" "$c" "$marker" "$cached" 2>/dev/null); then
    stat_kind=gnu
  else
    stat_kind=bsd
    stats=$("$stat_tool" -f '%u %Lp %d %i %z %m %c' "$a" "$b" "$c" "$marker" "$cached") || return 1
  fi
  nl='
'; rest=$stats; n=0
  while [ "$n" -lt 4 ]; do
    line=${rest%%"$nl"*}
    case "$rest" in *"$nl"*) rest=${rest#*"$nl"} ;; *) return 1 ;; esac
    u=${line%% *}; p=${line#* }; p=${p%% *}
    [ "$u" = "$uid" ] || return 1
    group_or_other_write "$p" && return 1
    n=$((n + 1))
  done
  p=${rest#* }; p=${p%% *}
  group_or_other_write "$p" && return 1
  id=${rest#* }; id=${id#* }
  IFS= read -r line < "$marker" || return 1
  [ "$line" = "v1 $want $id" ]
}
run_bin() {
  bin=$1
  if "$@"; then
    return 0
  else
    status=$?
  fi
  case "$status" in
    126|127) fail "cannot execute $bin; a noexec mount is a likely cause" ;;
    *) exit "$status" ;;
  esac
}
if [ "$mode" = hook ] && hook_fast; then
  run_bin "$cached" hook "$@"
  exit 0
fi
find_tool="$(need find)" || exit 2
private_dirs "$tripcord_root" "$tripcord_root/$TRIPCORD_VERSION" "$cache_dir"
if [ "$mode" = hook ] && { [ -e "$marker" ] || [ -L "$marker" ]; }; then
  fail "the cached tripcord at $cached no longer matches the binary that was verified; it was not run"
fi

rm_tool="$(need rm)" || exit 2
mkdir_tool="$(need mkdir)" || exit 2
mktemp_tool="$(need mktemp)" || exit 2
cp_tool="$(need cp)" || exit 2
chmod_tool="$(need chmod)" || exit 2
mv_tool="$(need mv)" || exit 2
if sha_tool="$(system_tool sha256sum)"; then
  sha_args=''
elif sha_tool="$(system_tool shasum)"; then
  sha_args='-a 256'
else
  fail "no sha256sum or shasum in /usr/bin or /bin"
fi
runs="$tripcord_root/.run"
if [ ! -e "$runs" ] && [ ! -L "$runs" ]; then
  "$mkdir_tool" -m 0700 "$runs" 2>/dev/null || [ -d "$runs" ] || fail "cannot create $runs"
fi
private_dirs "$runs"
"$find_tool" "$runs" -mindepth 1 -maxdepth 1 -type d -name 'run.*' -user "$uid" -mmin +1 -exec "$rm_tool" -rf {} + 2>/dev/null || true
if [ -z "$stat_kind" ]; then
  if "$stat_tool" -c '%d' "$cached" >/dev/null 2>&1; then stat_kind=gnu; else stat_kind=bsd; fi
fi
id_before=$(file_id "$cached") || fail "cannot stat $cached"
run="$(umask 077 && "$mktemp_tool" -d "$runs/run.XXXXXX")" || fail "cannot create $runs"
"$chmod_tool" 0700 "$run"
copy="$run/tripcord"
"$cp_tool" "$cached" "$copy" || fail "cannot copy the cached tripcord at $cached"
"$chmod_tool" 0700 "$copy"
got="$(sha256_of "$copy")" || fail "cannot hash $copy"
id_after=$(file_id "$cached") || fail "cannot stat $cached"
if [ "$id_before" != "$id_after" ]; then
  fail "the cached tripcord at $cached changed while it was being verified"
fi
if [ "$got" != "$want" ]; then
  fail "the cached tripcord at $cached has SHA-256 $got, not the pinned $want; it was not run"
fi

record_verification() {
  if [ -L "$marker" ]; then
    "$rm_tool" -f "$marker" || return 0
  fi
  tmp=$(umask 077 && "$mktemp_tool" "$cache_dir/verified.XXXXXX") || return 0
  printf 'v1 %s %s\n' "$want" "$id_after" > "$tmp" || { "$rm_tool" -f "$tmp"; return 0; }
  "$chmod_tool" 0400 "$tmp" || { "$rm_tool" -f "$tmp"; return 0; }
  "$mv_tool" -f "$tmp" "$marker" || { "$rm_tool" -f "$tmp"; return 0; }
}
record_verification || true
if [ "$mode" = hook ]; then
  run_bin "$copy" hook "$@"
  exit 0
fi
script_dir="$(CDPATH='' cd -- "$script_parent" && pwd -P)" || fail "cannot resolve $script_parent"
repo_root="$(CDPATH='' cd -- "$script_dir/.." && pwd -P)" || fail "cannot resolve $script_dir"
run_bin "$copy" scan --config "$repo_root" >&2
`
