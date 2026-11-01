package shellcmd

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLocate(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		// Inside the project: relative paths, project variables, and
		// programs found on PATH.
		{`./.claude/hooks/format.sh`, nil},
		{`.claude/hooks/check.py --strict`, nil},
		{`"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.sh`, nil},
		{`${CLAUDE_PROJECT_DIR}/.claude/hooks/guard.sh pre`, nil},
		{`${CLAUDE_PLUGIN_ROOT}/scripts/lint.sh`, nil},
		{`bash "$CLAUDE_PROJECT_DIR/.claude/hooks/x.sh"`, nil},
		{`powershell -NoProfile -File %CLAUDE_PROJECT_DIR%\.claude\hooks\x.ps1`, nil},
		{`$env:GEMINI_PROJECT_DIR\hooks\x.ps1`, nil},
		{`tripcord hook --harness claude --event pre-tool`, nil},
		{`npx prettier --write .`, nil},
		{`python3 -m tools.lint`, nil},
		{`python -c 'print(1)'`, nil},
		{`node -e 'console.log(1)'`, nil},
		{`.cursor/hooks/../hooks/audit.sh`, nil},
		// Arguments are not what runs.
		{`echo /tmp/x.sh`, nil},
		{`cat ~/.ssh/config`, nil},
		{`jq . /home/alice/x.json`, nil},
		// System binaries are not scripts outside the repository.
		{`/usr/bin/env node .claude/hooks/x.js`, nil},
		{`/bin/bash .claude/hooks/x.sh`, nil},
		{`/usr/local/bin/tripcord hook --event pre-tool`, nil},
		{`/opt/homebrew/bin/prettier --write .`, nil},
		{`"C:\Program Files\nodejs\node.exe" .claude\hooks\x.js`, nil},
		// Unknown variables and substitutions have no location.
		{`$HOOKS_DIR/check.sh`, nil},
		{`$HOMEBREW_PREFIX/bin/prettier`, nil},
		{`$(git rev-parse --show-toplevel)/hooks/x.sh`, nil},
		{`bash <(cat hooks/x.sh)`, nil},

		// Home.
		{`~/.claude/hooks/notify.sh`, []string{Home}},
		{`~alice/bin/x`, []string{Home}},
		{`$HOME/.config/agent/hook.sh`, []string{Home}},
		{`"${HOME}/.local/bin/sync"`, []string{Home}},
		{`bash ~/.cache/.x/run.sh`, []string{Home}},
		{`node $HOME/.npm/_x/index.js`, []string{Home}},
		{`python3 -u ~/.agent/hook.py`, []string{Home}},
		{`/home/alice/.local/share/x/hook`, []string{Home}},
		{`/Users/alice/Library/x/hook.sh`, []string{Home}},
		{`/root/.x/hook.sh`, []string{Home}},
		{`%USERPROFILE%\.agent\hook.ps1`, []string{Home}},
		{`pwsh -File $env:APPDATA\agent\hook.ps1`, []string{Home}},
		{`powershell -ExecutionPolicy Bypass -File:C:\Users\bob\hook.ps1`, []string{Home}},
		{`source ~/.agentrc`, []string{Home}},
		{`. $XDG_CONFIG_HOME/agent/env.sh`, []string{Home}},

		// Temp.
		{`/tmp/.x/payload.sh`, []string{Temp}},
		{`sh /var/tmp/run`, []string{Temp}},
		{`bash -c 'cd /src && /dev/shm/.k'`, []string{Temp}},
		{`$TMPDIR/hook.sh`, []string{Temp}},
		{`%TEMP%\hook.cmd`, []string{Temp}},
		{`C:\Windows\Temp\hook.bat`, []string{Temp}},
		{`powershell -File C:\Users\bob\AppData\Local\Temp\h.ps1`, []string{Temp}},
		{`/private/tmp/h.sh`, []string{Temp}},

		// Other absolute paths, and system directories holding a script.
		{`/srv/agent/hooks/check`, []string{Absolute}},
		{`/opt/acme/hooks/check.sh`, []string{Absolute}},
		{`/etc/agent/hook.py`, []string{Absolute}},
		{`D:\tools\hook.ps1`, []string{Absolute}},
		{`deno run /srv/hooks/x.ts`, []string{Absolute}},

		// Above the project directory.
		{`../shared/hooks/check.sh`, []string{Parent}},
		{`bash ../../x.sh`, []string{Parent}},
		{`$CLAUDE_PROJECT_DIR/../tools/x.sh`, []string{Parent}},
		{`..\tools\x.ps1`, []string{Parent}},
		{`hooks/../../x.sh`, []string{Parent}},

		// Network.
		{`deno run https://cdn.example.invalid/hook.ts`, []string{Network}},
		{`https://hooks.example.invalid/notify`, []string{Network}},
		// A POSIX shell reads \\ as one backslash, so an unquoted UNC
		// path is \fileserver\... there: absolute, not a share.
		{`\\fileserver\share\hooks\x.cmd`, []string{Absolute}},
		{`'\\fileserver\share\hooks\x.cmd'`, []string{Network}},
		{`//fileserver/share/x.sh`, []string{Network}},
		{`http://localhost:8080/hook`, nil},

		// Wrappers and payloads are read like Analyze reads them.
		{`sudo -u build /tmp/x.sh`, []string{Temp}},
		{`env FOO=1 ~/.x/hook.sh`, []string{Home}},
		{`bash -c "test -f x && ~/.x/run.sh"`, []string{Home}},
		{`cmd /c %TEMP%\x.bat`, []string{Temp}},
		{`powershell -Command "& $env:USERPROFILE\x.ps1"`, []string{Home}},
		{`pwsh -c "~\x.ps1"`, []string{Home}},
		{`./a.sh && /tmp/b.sh; ../c.sh | ~/d.sh`, []string{Home, Temp, Parent}},
		{`/tmp/a.sh; /tmp/b.sh`, []string{Temp}},
	}
	for _, tc := range cases {
		got := Locate(tc.line).Locations
		if !slices.Equal(got, append([]string{}, tc.want...)) {
			t.Errorf("Locate(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestLocateArgv(t *testing.T) {
	cases := []struct {
		argv []string
		want []string
	}{
		{[]string{"/tmp/x.sh"}, []string{Temp}},
		{[]string{"bash", "~/.x/hook.sh"}, []string{Home}},
		{[]string{"node", ".github/hooks/check.js", "/tmp/arg"}, nil},
		{[]string{"bash", "-c", "../x.sh"}, []string{Parent}},
		{[]string{`\\fileserver\share\x.cmd`}, []string{Network}},
		{nil, nil},
	}
	for _, tc := range cases {
		got := LocateArgv(tc.argv).Locations
		if !slices.Equal(got, append([]string{}, tc.want...)) {
			t.Errorf("LocateArgv(%q) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}

// TestLocateLargeInput keeps Locate linear, as Risks is.
func TestLocateLargeInput(t *testing.T) {
	pad := strings.Repeat("echo setup step && mkdir -p .cache; ", (1<<20)/36)
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"bash -c '" + pad + "'", nil},
		{"bash -c '" + pad + "~/.x/run.sh'", []string{Home}},
		{strings.Repeat("$(", 1<<19), nil},
		{strings.Repeat("bash -c '", (1<<20)/9), nil},
	} {
		start := time.Now()
		got := Locate(tc.line)
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("%d bytes: %v", len(tc.line), elapsed)
		}
		if !slices.Equal(got.Locations, append([]string{}, tc.want...)) {
			t.Errorf("%d bytes: Locate = %q, want %q", len(tc.line), got.Locations, tc.want)
		}
		if got.Work < len(tc.line) {
			t.Errorf("%d bytes: Work = %d", len(tc.line), got.Work)
		}
	}
}

func FuzzLocate(f *testing.F) {
	for _, seed := range []string{
		`bash ~/.x/run.sh`,
		`"$CLAUDE_PROJECT_DIR"/../x.sh`,
		`powershell -File:%TEMP%\x.ps1`,
		`${HOME`,
		`%TEMP`,
		`$env:`,
		`C:`,
		"$(`'\"\\",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r := Locate(line)
		passes := 1
		if strings.Contains(line, "`") {
			passes = 2
		}
		if r.Work < len(line) || r.Work > passes*(maxDepth+2)*(len(line)+1) {
			t.Fatalf("Locate(%q).Work = %d", line, r.Work)
		}
		if len(r.Locations) > len(locationOrder) {
			t.Fatalf("Locate(%q) = %q", line, r.Locations)
		}
	})
}
