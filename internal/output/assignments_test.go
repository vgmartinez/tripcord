package output

import (
	"strings"
	"testing"
)

// A credential-named "key: value" is redacted anywhere; the only
// exception is the argument of a literal-text flag of git, grep, rg,
// sed, awk, or gh.
func TestColonAssignmentsRedactedExceptToolLiteralText(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"git commit -m 'fix token: handling'",
		`git commit -m "fix secret: rotation" && git push`,
		`git commit -m "token: rotate weekly"`,
		"git commit -m 'password: hashing'",
		"git commit --message='token: rotate'",
		"/usr/bin/git commit -m 'token: x'",
		"sudo git commit -m 'token: x'",
		"git log --grep 'secret: x'",
		"grep -e 'token: x' file",
		"rg -e 'api_key: x' src",
		"sed -e 's/token: x/token: y/' f",
		"awk -F 'password: ' '{print $2}' f",
		`gh pr create --title "fix token: leak" --body "password: rotated"`,
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
		if got, removed := RedactAssignments(in); got != in || len(removed) != 0 {
			t.Errorf("RedactAssignments(%q) = %q, %q; want unchanged", in, got, removed)
		}
	}
	redacted := map[string]string{
		"curl -H 'X-Token: HDRTOK' https://x":         "curl -H 'X-Token: [REDACTED]' https://x",
		`curl --header "X-Api-Key: HDRKEY" https://x`: `curl --header "X-Api-Key: [REDACTED]" https://x`,
		"curl --header=X-Auth-Token:GLUEDHDR x":       "curl --header=X-Auth-Token:[REDACTED] x",
		"token: YAMLTOK":                              "token: [REDACTED]",
		"env:\n  - API_KEY: LISTTOK\n":                "env:\n  - API_KEY: [REDACTED]\n",
		`{"api_key": "JSONTOK"}`:                      `{"api_key": "[REDACTED]"}`,
		"env: {TOKEN: FLOWTOK, B: 1}":                 "env: {TOKEN: [REDACTED], B: 1}",
		`echo "token: PXC5" > .env`:                   `echo "token: [REDACTED]" > .env`,
		"echo 'password: PXC6' >> config.yml":         "echo 'password: [REDACTED]' >> config.yml",
		"printf 'api_key: PXC8'":                      "printf 'api_key: [REDACTED]'",
		"http example.com X-Api-Key:PXC7":             "http example.com X-Api-Key:[REDACTED]",
		"http example.com 'X-API-Token:PXC7B' a=1":    "http example.com 'X-API-Token:[REDACTED]' a=1",
		`echo "db password: PXC9" > .env`:             `echo "db password: [REDACTED]" > .env`,
		`echo "my token: PXC10"`:                      `echo "my token: [REDACTED]"`,
		"echo 'user: a password: PXC11'":              "echo 'user: a password: [REDACTED]'",
		`echo "export A=1; token: PXC12"`:             `echo "export A=1; token: [REDACTED]"`,
		"http h x-api-key:PXC13":                      "http h x-api-key:[REDACTED]",
		"http h api_key:PXC14 a=1":                    "http h api_key:[REDACTED] a=1",
		"echo -e 'token: PXC15'":                      "echo -e 'token: [REDACTED]'",
		"sh -c 'echo token: PXC16'":                   "sh -c 'echo token: [REDACTED]'",
		"echo password: PXC17 > f":                    "echo password: [REDACTED]",
		"echo secret: foo && run":                     "echo secret: [REDACTED] && run",
		"echo -m 'token: PXC18'":                      "echo -m 'token: [REDACTED]'",
		"git commit -m ok; echo 'token: PXC19'":       "git commit -m ok; echo 'token: [REDACTED]'",
		"grep -e x 'token: PXC20'":                    "grep -e x 'token: [REDACTED]'",
	}
	for in, want := range redacted {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		if got, _ := RedactAssignments(in); got != want {
			t.Errorf("RedactAssignments(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactAssignmentsKeepsSpaceBeforeOperator(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"secret: foo && run":     "secret: [REDACTED] && run",
		"token: abc || fallback": "token: [REDACTED] || fallback",
		"password: pw ; next":    "password: [REDACTED] ; next",
	}
	for in, want := range cases {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		got, removed := RedactAssignments(in)
		if got != want || len(removed) != 1 || strings.HasSuffix(removed[0], " ") {
			t.Errorf("RedactAssignments(%q) = %q, %q", in, got, removed)
		}
	}
}

func TestLiteralTextExemptionIsToolAndCommandSpecific(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"grep -F --password QN18X f":                 "grep -F --password [REDACTED] f",
		"rg -F --password QN18Y f":                   "rg -F --password [REDACTED] f",
		"gh secret set CFG --body 'password: QN06X'": "gh secret set CFG --body 'password: [REDACTED]'",
		`git commit -m "$(echo token: QN04X)"`:       `git commit -m "$(echo token: [REDACTED])"`,
		"git commit -m ${A:-token: QN04Y}":           "git commit -m ${A:-token: [REDACTED]}",
		"echo git -m 'token: QN05X'":                 "echo git -m 'token: [REDACTED]'",
	} {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DefaultRedactor("docker run registry/token-svc:1.2"); got != "docker run registry/token-svc:1.2" {
		t.Errorf("DefaultRedactor image tag = %q, want unchanged", got)
	}
	if got := DefaultRedactor("echo 'x; docker run password:S y'"); got != "echo 'x; docker run password:[REDACTED] y'" {
		t.Errorf("DefaultRedactor quoted image-looking text = %q", got)
	}
	for in, want := range map[string]string{
		"--proxy-header=X-Api-Key:S":         "--proxy-header=X-Api-Key:[REDACTED]",
		"kubectl --from-literal=api-token:S": "kubectl --from-literal=api-token:[REDACTED]",
		"helm --set-string=password:S":       "helm --set-string=password:[REDACTED]",
		"docker run -e=token:S":              "docker run -e=token:[REDACTED]",
		"cli --opt=x/secret:S":               "cli --opt=x/secret:[REDACTED]",
		"echo a/token:S":                     "echo a/token:[REDACTED]",
		"echo ./config/password:S":           "echo ./config/password:[REDACTED]",
		"echo /tmp/password:S":               "echo /tmp/password:[REDACTED]",
		"echo x-y/api-key:S >> .env":         "echo x-y/api-key:[REDACTED] >> .env",
	} {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
}
