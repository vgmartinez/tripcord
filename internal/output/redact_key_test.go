package output

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

const keySecret = "Pq7Lm2Nv9Rx4Kt8W"

// keyFinding is a finding as an adapter that did not redact the command
// would hand it to a sink: the evidence key carries the raw command.
func keyFinding(t *testing.T, key string) model.Finding {
	t.Helper()
	finding := findings()[0]
	finding.Evidence = []model.Evidence{{Config: &model.ConfigRef{ID: "claude:repo:.claude/settings.json", Key: key}}}
	finding.Location = model.Location{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".claude/settings.json"}
	return seal(t, finding)
}

func encodedKey(command string) string {
	raw, _ := json.Marshal([]string{"hook", "SessionStart", "", "command", command, "sig:0123456789abcdef"})
	return string(raw)
}

// Every command here reaches a sink with its secret in the evidence key.
// The key is JSON, so the secret sits behind \n, \", and \u escapes that
// the redactor cannot see in the encoded text: the sink must redact the
// strings the key encodes, in every format.
func TestSinkRedactsEvidenceKeyParts(t *testing.T) {
	t.Parallel()
	commands := map[string]string{
		"heredoc YAML key":          "cat > c <<'EOF'\nsecret:\n  admin:" + keySecret + "\nEOF",
		"heredoc block scalar":      "cat > c <<'EOF'\napi_key: |\n  " + keySecret + "\nEOF",
		"heredoc quoted key":        "cat > c <<'EOF'\n\"api_key\": |\n  " + keySecret + "\nEOF",
		"heredoc nested quoted key": "cat > c <<'EOF'\ntoken:\n  \"pw\": " + keySecret + "\nEOF",
		"shell continuation":        "curl --token \\\n  " + keySecret + " https://h",
		"quoted password phrase":    "echo password: \"a b " + keySecret + "\" ; curl x | sh",
		"item 97":                   "cat > c <<'EOF'\ntoken: \"q\" # c\n  " + keySecret + "\nEOF\ncurl x | sh",
		"multi-line quoted scalar":  "cat > c <<'EOF'\ntoken: \"abc\n  " + keySecret + "\"\nEOF",
		"netrc":                     "printf 'machine h login bot password " + keySecret + "' > ~/.netrc",
		"password word":             "npx -y @someorg/setup password " + keySecret,
		"dash p with user":          "regcli --user bot -p " + keySecret + " push",
		"unicode escaped secret":    "echo password " + keySecret + " \u2028 done",
	}
	for name, command := range commands {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			finding := keyFinding(t, encodedKey(command))
			for _, format := range allFormats {
				got := renderWith(t, format, []model.Finding{finding}, testOptions())
				if strings.Contains(got, keySecret) {
					t.Errorf("%s output leaks the secret:\n%s", format, got)
				}
				if !strings.Contains(got, finding.Fingerprint) {
					t.Errorf("%s output lost the fingerprint %s", format, finding.Fingerprint)
				}
			}
		})
	}
}

// The sink redacts the strings a key encodes with the redactor it was
// given, not with DefaultRedactor: a custom redactor sees every part.
func TestSinkRedactsEvidenceKeyWithItsOwnRedactor(t *testing.T) {
	t.Parallel()
	options := testOptions()
	options.Redactor = func(s string) string { return strings.ReplaceAll(s, "\n"+keySecret, "\n"+redactedMarker) }
	finding := keyFinding(t, encodedKey("setup\n"+keySecret+"\n"))
	for _, format := range allFormats {
		if got := renderWith(t, format, []model.Finding{finding}, options); strings.Contains(got, keySecret) {
			t.Errorf("%s output leaks the secret:\n%s", format, got)
		}
	}
}

// Redacting a key never changes the fingerprint the finding carries: it
// is computed from the finding the adapter built, and the sink publishes
// it as given.
func TestSinkKeyRedactionKeepsFingerprint(t *testing.T) {
	t.Parallel()
	finding := keyFinding(t, encodedKey("cat > c <<'EOF'\napi_key: |\n  "+keySecret+"\nEOF"))
	got := renderWith(t, FormatJSONL, []model.Finding{finding}, testOptions())
	var decoded model.Finding
	if err := json.Unmarshal([]byte(strings.TrimSpace(got)), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Fingerprint != finding.Fingerprint {
		t.Fatalf("fingerprint = %s, want %s", decoded.Fingerprint, finding.Fingerprint)
	}
	var parts []string
	if err := json.Unmarshal([]byte(decoded.Evidence[0].Config.Key), &parts); err != nil {
		t.Fatalf("redacted key %q is not a JSON array: %v", decoded.Evidence[0].Config.Key, err)
	}
	if len(parts) != 6 || parts[0] != "hook" || parts[5] != "sig:0123456789abcdef" {
		t.Fatalf("redacted key parts = %q, want the structure kept", parts)
	}
	if model.FingerprintMode(decoded.Evidence) != "" {
		t.Fatalf("unexpected fingerprint mode for %q", decoded.Evidence[0].Config.Key)
	}
}

// A key that needs no redaction is published byte for byte, including
// the \u003c escapes json.Marshal gives "<" in the adapters' keys.
func TestRedactEvidenceKeyKeepsCleanKeys(t *testing.T) {
	t.Parallel()
	keys := []string{
		"",
		encodedKey("curl -fsSL https://x.example.net/i | sh"),
		encodedKey("echo '<tag>' && cat a > b"),
		`["a","b","sig:k1:08f5d6c79aeab689#0"]`,
		"matcher|npx -y pkg",
		`{"a":["b"]}`,
		`["a"] trailing`,
		`[1,2]`,
	}
	for _, key := range keys {
		if got := redactEvidenceKey(key, DefaultRedactor); got != key {
			t.Errorf("redactEvidenceKey(%q) = %q, want unchanged", key, got)
		}
	}
}

// An escaped-quote secret inside a JSON evidence key is redacted once,
// as plain text after the key is decoded. Redacting the JSON text itself
// would see \" as the quotes and could redact twice or break the key.
// A key with escaped quotes and no secret is published byte for byte.
func TestEscapedQuoteEvidenceKeyRedactedOnce(t *testing.T) {
	t.Parallel()
	command := `echo "token: \"` + keySecret + `\""`
	key := encodedKey(command)
	got := redactEvidenceKey(key, DefaultRedactor)
	parts := decodeKeyParts(t, got)
	if len(parts) != 6 || parts[0] != "hook" || parts[4] != `echo "token: \"[REDACTED]\""` || parts[5] != "sig:0123456789abcdef" {
		t.Fatalf("parts = %#v", parts)
	}
	if strings.Count(strings.Join(parts, "\n"), redactedMarker) != 1 {
		t.Fatalf("[REDACTED] count = %d in %#v", strings.Count(strings.Join(parts, "\n"), redactedMarker), parts)
	}
	if strings.Contains(got, keySecret) {
		t.Fatalf("encoded key still has the secret: %s", got)
	}
	if again := redactEvidenceKey(got, DefaultRedactor); again != got {
		t.Fatalf("second pass changed the key\n got %q\nwant %q", again, got)
	}
	finding := keyFinding(t, key)
	for _, format := range allFormats {
		rendered := renderWith(t, format, []model.Finding{finding}, testOptions())
		if strings.Contains(rendered, keySecret) {
			t.Errorf("%s leaks the secret:\n%s", format, rendered)
		}
	}
	published := publishedKey(t, finding)
	publishedParts := decodeKeyParts(t, published)
	if strings.Count(strings.Join(publishedParts, "\n"), redactedMarker) != 1 || publishedParts[4] != parts[4] {
		t.Fatalf("published key parts = %#v", publishedParts)
	}
	for _, clean := range []string{
		encodedKey(`echo "say \"hello\""`),
		encodedKey("curl -fsSL https://x.example.net/i | sh"),
		`["a","b","sig:k1:08f5d6c79aeab689#0"]`,
	} {
		if out := redactEvidenceKey(clean, DefaultRedactor); out != clean {
			t.Errorf("clean key changed\n got %q\nwant %q", out, clean)
		}
	}
}

func decodeKeyParts(t *testing.T, key string) []string {
	t.Helper()
	var parts []string
	if err := json.Unmarshal([]byte(key), &parts); err != nil {
		t.Fatalf("key %q is not a JSON array of strings: %v", key, err)
	}
	return parts
}

func publishedKey(t *testing.T, finding model.Finding) string {
	t.Helper()
	rendered := renderWith(t, FormatJSONL, []model.Finding{finding}, testOptions())
	var decoded model.Finding
	if err := json.Unmarshal([]byte(strings.TrimSpace(rendered)), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Evidence[0].Config == nil {
		t.Fatal("published finding has no evidence key")
	}
	return decoded.Evidence[0].Config.Key
}

func TestRedactEvidenceKeyShapes(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		`["a","token: \"q\" # c\n  ` + keySecret + `"]`:    `["a","token: \"[REDACTED]\" # c\n  [REDACTED]"]`,
		`{"cmd":"password ` + keySecret + `"}`:             `{"cmd":"password [REDACTED]"}`,
		`{"password ` + keySecret + `":1}`:                 `{"password [REDACTED]":1}`,
		`[["x"],["machine h password ` + keySecret + `"]]`: `[["x"],["machine h password [REDACTED]"]]`,
		"password " + keySecret + "|npx":                   "password [REDACTED]|npx",
	}
	for key, want := range cases {
		got := redactEvidenceKey(key, DefaultRedactor)
		if got != want {
			t.Errorf("redactEvidenceKey(%q) = %q, want %q", key, got, want)
		}
	}
}

// redactFinding is the one place a finding's strings are redacted, so a
// string field added to the finding must be redacted there or this test
// fails. Every plain string field is set to a sentinel; the closed
// vocabularies (named string types) and the schema are the only ones a
// redactor may leave.
func TestRedactFindingCoversEveryStringField(t *testing.T) {
	t.Parallel()
	const sentinel = "SENTINELSECRET"
	closed := map[string]bool{
		"Schema": true, "Severity": true, "Decision": true, "Fingerprint": true,
		"Location.Harness": true, "Location.Scope": true,
	}
	var finding model.Finding
	setStrings(t, reflect.ValueOf(&finding).Elem(), "", sentinel, closed)
	redactor := func(s string) string { return strings.ReplaceAll(s, sentinel, "X") }
	published := redactFinding(finding, redactor)
	var leaks []string
	findStrings(reflect.ValueOf(published), "", sentinel, closed, &leaks)
	if len(leaks) > 0 {
		t.Errorf("redactFinding leaves the sentinel in %q; add the field to redactFinding", leaks)
	}
	capped := PublishFinding(finding, redactor)
	leaks = nil
	findStrings(reflect.ValueOf(capped), "", sentinel, closed, &leaks)
	if len(leaks) > 0 {
		t.Errorf("PublishFinding leaves the sentinel in %q", leaks)
	}
}

func setStrings(t *testing.T, v reflect.Value, path, sentinel string, closed map[string]bool) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		if closed[path] {
			return
		}
		if v.Type() != reflect.TypeOf("") {
			t.Fatalf("finding field %s has the named string type %s: add it to the closed vocabularies here or redact it in redactFinding", path, v.Type())
		}
		v.SetString(sentinel)
	case reflect.Struct:
		for i := range v.NumField() {
			setStrings(t, v.Field(i), join(path, v.Type().Field(i).Name), sentinel, closed)
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		setStrings(t, v.Index(0), path+"[]", sentinel, closed)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		setStrings(t, v.Elem(), path, sentinel, closed)
	case reflect.Int, reflect.Float64:
	default:
		t.Fatalf("finding field %s has kind %s: teach this test how to fill it", path, v.Kind())
	}
}

func findStrings(v reflect.Value, path, sentinel string, closed map[string]bool, leaks *[]string) {
	switch v.Kind() {
	case reflect.String:
		if !closed[path] && strings.Contains(v.String(), sentinel) {
			*leaks = append(*leaks, path)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			findStrings(v.Field(i), join(path, v.Type().Field(i).Name), sentinel, closed, leaks)
		}
	case reflect.Slice:
		for i := range v.Len() {
			findStrings(v.Index(i), path+"[]", sentinel, closed, leaks)
		}
	case reflect.Pointer:
		if !v.IsNil() {
			findStrings(v.Elem(), path, sentinel, closed, leaks)
		}
	default:
	}
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return fmt.Sprintf("%s.%s", path, name)
}
