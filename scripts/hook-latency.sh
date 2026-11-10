#!/usr/bin/env bash
# Print p50, p95, and max, in milliseconds, for three series on one
# locked policy (enforce, locked.mode, locked.rules TC-CFG-001, and the
# two custom hook rules the cold-start gate uses):
#
#   direct     tripcord hook
#   bootstrap  bash bootstrap.sh hook, offline, from a local cache
#   overhead   bootstrap minus direct, paired in the same iteration
#
# Each harness gets 5 warmup runs and then 100 measured runs. Direct
# and bootstrap alternate inside an iteration. The percentile is the
# nearest rank: sort, then take the element at ceil(q * n). The first
# bootstrap run verifies the cached binary; warmup drops it.
#
# The script prints the numbers and exits 0. It does not compare them
# to a budget.
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64|Linux-amd64) platform=linux-x64 ;;
  Linux-aarch64|Linux-arm64) platform=linux-arm64 ;;
  Darwin-arm64) platform=darwin-arm64 ;;
  Darwin-x86_64) platform=darwin-x64 ;;
  *) printf 'unsupported platform %s %s\n' "$(uname -s)" "$(uname -m)" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bin=$work/tripcord
repo=$work/repo
cache=$work/cache
home=$work/home
mkdir -p "$repo" "$home"

(
  cd "$root"
  CGO_ENABLED=0 go build -trimpath -o "$bin" ./cmd/tripcord
)
if command -v sha256sum >/dev/null 2>&1; then
  sum=$(sha256sum "$bin" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  sum=$(shasum -a 256 "$bin" | awk '{print $1}')
else
  printf 'sha256sum or shasum is required\n' >&2
  exit 1
fi

git -C "$repo" init -q
(
  cd "$repo"
  "$bin" init --embed --version 0.1.0 --sha256 "$platform=$sum" >/dev/null
)
cached=$cache/tripcord/0.1.0/$platform
mkdir -p "$cached"
cp "$bin" "$cached/tripcord"
chmod 0755 "$cached/tripcord"
cat > "$repo/.tripcord/policy.yaml" <<'EOF'
version: 1
mode: enforce
fail-on: high
locked:
  mode: true
  rules: [TC-CFG-001]
custom:
  - id: ACME-001
    deny_if: 'event.command != "" && "pipe" in shell.risks(event.command)'
    message: piping a download into a shell is not allowed
  - id: ACME-002
    deny_if: 'event.paths.exists(p, p.endsWith("/.env"))'
    message: reading .env is not allowed
EOF

export HOME=$home XDG_CACHE_HOME=$cache TMPDIR=$work
export CLAUDE_PROJECT_DIR=$repo CURSOR_PROJECT_DIR=$repo CI=true
python3 - "$bin" "$repo/.tripcord/bootstrap.sh" "$repo" "$root" <<'PY'
import math, os, subprocess, sys, time

binp, boot, repo, root = sys.argv[1:]
cases = [
    ("claude", ["hook", "--harness", "claude", "--event", "pre-tool", "--on-failure", "block"],
     os.path.join(root, "internal/adapters/claude/testdata/hook/pre-tool-use-bash-deny.json"), 2),
    ("cursor", ["hook", "--harness", "cursor", "--event", "before-shell", "--on-failure", "block"],
     os.path.join(root, "internal/adapters/cursor/testdata/hook/before-shell-execution-allow.json"), 0),
    ("copilot", ["hook", "--harness", "copilot", "--event", "pre-tool", "--on-failure", "block"],
     os.path.join(root, "internal/adapters/copilot/testdata/hook/pre-tool-use-bash-deny.json"), 2),
]

def pct(xs, q):
    return sorted(xs)[max(0, math.ceil(q * len(xs)) - 1)]

def show(label, xs):
    print(f"{label} n={len(xs)} p50={pct(xs, 0.5):.2f} p95={pct(xs, 0.95):.2f} max={max(xs):.2f}", flush=True)

env = os.environ.copy()
for name, args, fixture, code in cases:
    inp = open(fixture, "rb").read()
    direct, boot_ms, overhead = [], [], []
    for i in range(105):
        t = time.perf_counter()
        p = subprocess.run([binp, *args], input=inp, cwd=repo, env=env, capture_output=True)
        d = (time.perf_counter() - t) * 1000
        if p.returncode != code:
            sys.exit(f"direct {name} run {i} exit {p.returncode}: {p.stderr[:300]!r}")
        t = time.perf_counter()
        p = subprocess.run(["bash", boot, *args], input=inp, cwd=repo, env=env, capture_output=True)
        b = (time.perf_counter() - t) * 1000
        if p.returncode != code:
            sys.exit(f"bootstrap {name} run {i} exit {p.returncode}: {p.stderr[:400]!r}")
        direct.append(d)
        boot_ms.append(b)
        overhead.append(b - d)
    print(f"{name}")
    show("  direct", direct[5:])
    show("  bootstrap", boot_ms[5:])
    show("  overhead", overhead[5:])
PY
