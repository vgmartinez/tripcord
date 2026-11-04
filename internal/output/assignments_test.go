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

// A YAML block scalar value ("|" literal, ">" folded, with an optional
// chomping indicator and/or indentation indicator in either order) is
// redacted as a whole: the header line is untouched and every line of
// the block's body, however many, becomes one [REDACTED] line at the
// body's own indentation.
func TestColonAssignmentsRedactYAMLBlockScalars(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"api_key: |\n  BLOCKA\n":                                    "api_key: |\n  [REDACTED]\n",
		"api_key: >-\n  BLOCKB\nnext: ok\n":                         "api_key: >-\n  [REDACTED]\nnext: ok\n",
		"api_key: |2\n  BLOCKC\n":                                   "api_key: |2\n  [REDACTED]\n",
		"api_key: |-\n  BLOCKD\n":                                   "api_key: |-\n  [REDACTED]\n",
		"api_key: |2-\n  BLOCKE\n":                                  "api_key: |2-\n  [REDACTED]\n",
		"api_key: >+\n  BLOCKF\nnext: ok\n":                         "api_key: >+\n  [REDACTED]\nnext: ok\n",
		"api_key: | # comment\n  BLOCKG\n":                          "api_key: | # comment\n  [REDACTED]\n",
		"env:\n  TOKEN: |\n    MULTI1\n    MULTI2\n":                "env:\n  TOKEN: |\n    [REDACTED]\n",
		"password: |\n  BLOCKH\nother: 1\n":                         "password: |\n  [REDACTED]\nother: 1\n",
		"api_key: |\nb: 2\n":                                        "api_key: |\nb: 2\n",
		"config:\n  password: |\n    BLOCKI\n  other: 1\n":          "config:\n  password: |\n    [REDACTED]\n  other: 1\n",
		"config:\n  db:\n    api_key: |\n      BLOCKJ\n    d: 1\n":  "config:\n  db:\n    api_key: |\n      [REDACTED]\n    d: 1\n",
		"token:\n  password: |\n    BLOCKK\n  other: 1\nnext: ok\n": "token:\n  [REDACTED]\nnext: ok\n",
		`"api_key": |` + "\n  BLOCKL\n":                             `"api_key": |` + "\n  [REDACTED]\n",
		`'api_key': |` + "\n  BLOCKM\n":                             `'api_key': |` + "\n  [REDACTED]\n",
		"- api_key: |\n    BLOCKN\n- b: 2\n":                        "- api_key: |\n    [REDACTED]\n- b: 2\n",
		"api_key: |x":                                               "api_key: |x",
	} {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		if got, _ := RedactAssignments(in); got != want {
			t.Errorf("RedactAssignments(%q) = %q, want %q", in, got, want)
		}
	}
}

// A credential-named key whose colon is followed only by a newline holds
// a nested mapping when the next, more-indented line is itself a key: a
// name, optionally quoted, then a ":". An unquoted key needs a blank, a
// line break, or the end of input after that colon; a quoted key is a
// key even when its value is glued on ("\"pw\":X"). The mapping is the
// key's value and is redacted whole, whatever its own keys are named. A
// plain scalar wrapped onto the next line, including a glued unquoted
// "name:value" or a URL, is still that key's own value. A key at the
// outer key's own indentation is a sibling, found on its own.
func TestColonAssignmentsNestedMappingKeyHasNoOwnValue(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"token:\n  secret_value\nnext: ok\n":             "token:\n  [REDACTED]\nnext: ok\n",
		"token:\n  https://example.com/path\nnext: ok\n": "token:\n  [REDACTED]\nnext: ok\n",
		"token:\n  password: secret_value\nnext: ok\n":   "token:\n  [REDACTED]\nnext: ok\n",
		"api_key:\n  sk:NESTA\n":                         "api_key:\n  [REDACTED]\n",
		"password:\n  admin:NESTB\n":                     "password:\n  [REDACTED]\n",
		"secret:\n  a_b:NESTC\n":                         "secret:\n  [REDACTED]\n",
		"token:\n  \"pw\": NESTD\nnext: ok\n":            "token:\n  [REDACTED]\nnext: ok\n",
		"token:\n  'pw':\n    NESTE\nnext: ok\n":         "token:\n  [REDACTED]\nnext: ok\n",
		"token:\n  user: NESTF\n  other: NESTG\n":        "token:\n  [REDACTED]\n",
		"token:\n  user:":                                "token:\n  [REDACTED]",
		"token:\npassword: NESTH\n":                      "token:\npassword: [REDACTED]\n",
		"- token:\n    a: NESTI\n  b: ok\n":              "- token:\n    [REDACTED]\n  b: ok\n",
		"token:\n  \"pw\":NESTJ\n":                       "token:\n  [REDACTED]\n",
		"token:\n  'pw':NESTK\nnext: ok\n":               "token:\n  [REDACTED]\nnext: ok\n",
	} {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		if got, _ := RedactAssignments(in); got != want {
			t.Errorf("RedactAssignments(%q) = %q, want %q", in, got, want)
		}
	}
}

// A "#" between a credential key and a more-indented value is a YAML
// comment, not the value: colonValue stops at the newline and would
// leave the indented lines behind. Those lines are redacted as one,
// and the comment stays. A "#" with nothing indented after it is the
// value itself and is still redacted. A following line at the key's
// own indentation is the next line, not the value.
func TestColonAssignmentsCommentGap(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"token: # c\n  GAPAxx\n":                                 "token: [REDACTED]\n",
		"token:\n  # c\n  GAPBxx\n":                              "token:\n  [REDACTED]\n",
		"token:\n  # c\n  # d\n  GAPCxx\n":                       "token:\n  [REDACTED]\n",
		"token: # c\n  A\n  B\nnext: ok\n":                       "token: [REDACTED]\nnext: ok\n",
		"token: #secret\n":                                       "token: [REDACTED]\n",
		"token: # c\nnext: ok\n":                                 "token: [REDACTED]\nnext: ok\n",
		"token:\n  # c\nnext: ok\n":                              "token:\n  [REDACTED]\nnext: ok\n",
		"  token: # c\n    GAPDxx\n  other: 1\n":                 "  token: [REDACTED]\n  other: 1\n",
		"password: # old GAPE\n  from_env: DB_PASS\n":            "password: [REDACTED]\n",
		"db:\n  password: # was GAPF\n    env: DB_PASS\n":        "db:\n  password: [REDACTED]\n",
		"password: #GAPG\n  x\n":                                 "password: [REDACTED]\n",
		"token:\n  # GAPH\n  value: x\n":                         "token:\n  [REDACTED]\n",
		"      token: #a\n# api_key: | # c\n    # GAPI\n    y\n": "      token: [REDACTED]\n# api_key: | # c\n    [REDACTED]\n",
	} {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		if got, _ := RedactAssignments(in); got != want {
			t.Errorf("RedactAssignments(%q) = %q, want %q", in, got, want)
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
