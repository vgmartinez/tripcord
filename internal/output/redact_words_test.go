package output

import (
	"slices"
	"strings"
	"testing"
)

const wordSecret = "Zq8Lm2Nv9Rx4Kt7W"

// The netrc grammar and "-p X" next to a user name have no flag or
// assignment name for the other passes to key on.
func TestRedactPasswordWordsAndUserContextPassword(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"machine github.com login bot password " + wordSecret:                    "machine github.com login bot password [REDACTED]",
		"machine h\n  login bot\n  password " + wordSecret + "\nmachine h2":      "machine h\n  login bot\n  password [REDACTED]\nmachine h2",
		"machine h login b password '" + wordSecret + "'":                        "machine h login b password '[REDACTED]'",
		"npx -y @someorg/setup password " + wordSecret:                           "npx -y @someorg/setup password [REDACTED]",
		"setup PASSWD " + wordSecret + "; ls":                                    "setup PASSWD [REDACTED]; ls",
		"setup password \\\n  " + wordSecret + " run":                            "setup password \\\n  [REDACTED] run",
		"docker login -u bot -p " + wordSecret + " ghcr.io":                      "docker login -u bot -p [REDACTED] ghcr.io",
		"regcli --user bot -p " + wordSecret + " push":                           "regcli --user bot -p [REDACTED] push",
		"regcli --username=bot -p '" + wordSecret + " x' push":                   "regcli --username=bot -p '[REDACTED]' push",
		"regcli -p " + wordSecret + " -U bot push":                               "regcli -p [REDACTED] -U bot push",
		"helm registry login h -p " + wordSecret:                                 "helm registry login h -p [REDACTED]",
		"regcli -u bot -p \\\n  " + wordSecret:                                   "regcli -u bot -p \\\n  [REDACTED]",
		"useradd -u 1000 -p " + wordSecret + " bob":                              "useradd -u 1000 -p [REDACTED] bob",
		"echo '" + "x" + "' | regcli --login bot -p " + wordSecret + " && ls -p": "echo 'x' | regcli --login bot -p [REDACTED] && ls -p",
	}
	for in, want := range cases {
		got := DefaultRedactor(in)
		if got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		cmd, removed := RedactCommand(in)
		if strings.Contains(cmd, wordSecret) || !slices.ContainsFunc(removed, func(r string) bool { return strings.Contains(r, wordSecret) }) {
			t.Errorf("RedactCommand(%q) = %q, %q; want the secret removed", in, cmd, removed)
		}
	}
}

// Without a credential shape these stay as written: a flag that merely
// contains the word, an assignment (RedactAssignments reads it), a
// placeholder, literal message text, a bare -p, and port mappings.
func TestRedactPasswordWordsKeepsOtherText(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"docker login --password-stdin ghcr.io",
		"setup db_password " + "x",
		"password -x",
		"password $PASSWORD",
		"password <your-password>",
		"password changeme",
		"password",
		"git commit -m 'fix password handling now'",
		"mkdir -p build/out",
		"cp -p a b",
		"ssh -p 22 host",
		"docker run -p 8080:80 img",
		"docker run -u 1000 -p 8080:80 img",
		"docker run -u 1000 -p 127.0.0.1:8080:80/tcp img",
		"x -u a; mkdir -p dir",
		"x -p $PW -u bot",
		"x --user bot -p -v",
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
	for in, want := range map[string]string{
		"password: " + wordSecret:       "password: [REDACTED]",
		"password = " + wordSecret:      "password = [REDACTED]",
		"x --password " + wordSecret:    "x --password [REDACTED]",
		"PASSWORD=" + wordSecret + " x": "PASSWORD=[REDACTED] x",
	} {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactToolArgvPasswordWords(t *testing.T) {
	t.Parallel()
	cases := []struct {
		argv, want, removed []string
	}{
		{[]string{"setup", "password", wordSecret}, []string{"setup", "password", "[REDACTED]"}, []string{wordSecret}},
		{[]string{"--user", "bot", "-p", wordSecret}, []string{"--user", "bot", "-p", "[REDACTED]"}, []string{wordSecret}},
		{[]string{"login", "-p", "'" + wordSecret + "'"}, []string{"login", "-p", "'[REDACTED]'"}, []string{wordSecret}},
		{[]string{"-p", "8080:80"}, []string{"-p", "8080:80"}, nil},
		{[]string{"-u", "1000", "-p", "8080:80"}, []string{"-u", "1000", "-p", "8080:80"}, nil},
		{[]string{"mkdir", "-p", "x"}, []string{"mkdir", "-p", "x"}, nil},
		{[]string{"password", "$PW"}, []string{"password", "$PW"}, nil},
	}
	for _, tc := range cases {
		got, removed := RedactToolArgv(tc.argv)
		if !slices.Equal(got, tc.want) || !slices.Equal(removed, tc.removed) {
			t.Errorf("RedactToolArgv(%q) = %q, %q; want %q, %q", tc.argv, got, removed, tc.want, tc.removed)
		}
	}
}
