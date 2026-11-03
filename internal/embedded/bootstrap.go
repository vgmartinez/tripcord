package embedded

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Platforms are the os-arch names bootstrap.sh can pin, matching the
// npm platform packages in the spec (@tripcord/cli-<os>-<arch>).
var Platforms = []string{"darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"}

var (
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Pin is the Tripcord release bootstrap.sh installs: a version and the
// SHA-256 of the tripcord binary for each platform.
type Pin struct {
	Version string
	SHA256  map[string]string
}

// Validate rejects a pin that bootstrap.sh could not verify against.
// Every value is later written into a shell script, so each one must
// match a pattern with no shell metacharacters.
func (p Pin) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("--version is required with --embed: bootstrap.sh installs only a pinned release")
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

TRIPCORD_VERSION='@VERSION@'

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
@CASES@    *) return 1 ;;
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
`
