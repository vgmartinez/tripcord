package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFingerprintGoldens(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		rule     string
		harness  Harness
		scope    Scope
		session  string
		path     string
		line     int
		evidence []Evidence
		preimage string
		want     string
	}{
		{
			name:    "spec sample",
			rule:    "TC-SEC-018",
			harness: HarnessClaude,
			session: "00893aaf-19fa-41d2",
			evidence: []Evidence{{
				Event:   "evt_01JD7Q2M9X",
				Excerpt: "cat /proc/$PPID/environ",
			}},
			preimage: `{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"}]}`,
			want:     "tcf_bf8994fdb9dc73ed",
		},
		{
			// Default (unset) scope is repo scope: the path is already
			// repo-relative. line is NOT hashed (see Fingerprint): it is
			// set here to prove it has no effect on the digest.
			name:    "repo scope path",
			rule:    "TC-CFG-002",
			harness: SurfaceVSCode,
			path:    ".vscode/tasks.json",
			line:    12,
			evidence: []Evidence{
				{Event: "evt_a", Excerpt: "a && b < c"},
				{Event: "evt_b", Excerpt: "runOn: folderOpen"},
			},
			preimage: `{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","path":".vscode/tasks.json"},"evidence":[{"excerpt":"a && b < c"},{"excerpt":"runOn: folderOpen"}]}`,
			want:     "tcf_4dbb91737d62173a",
		},
		{
			name:     "empty evidence",
			rule:     "TC-CFG-001",
			harness:  SurfaceGeneric,
			preimage: `{"v":1,"rule":"TC-CFG-001","location":{"harness":"generic"},"evidence":[]}`,
			want:     "tcf_6dcfe79827b07f1b",
		},
		{
			name:    "duplicate evidence is kept",
			rule:    "TC-SEC-018",
			harness: HarnessClaude,
			session: "00893aaf-19fa-41d2",
			evidence: []Evidence{
				{Event: "evt_01JD7Q2M9X", Excerpt: "cat /proc/$PPID/environ"},
				{Event: "evt_01JD7Q2M9X", Excerpt: "cat /proc/$PPID/environ"},
			},
			preimage: `{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"},{"excerpt":"cat /proc/$PPID/environ"}]}`,
			want:     "tcf_eaaf73b622312f0e",
		},
		{
			name:    "user scope path",
			rule:    "TC-CFG-007",
			harness: HarnessClaude,
			scope:   ScopeUser,
			path:    "~/.claude/settings.json",
			evidence: []Evidence{
				{Event: "evt_x", Excerpt: "hooks: SessionStart -> curl | bash"},
			},
			preimage: `{"v":1,"rule":"TC-CFG-007","location":{"harness":"claude","path":"~/.claude/settings.json"},"evidence":[{"excerpt":"hooks: SessionStart -> curl | bash"}]}`,
			want:     "tcf_1a124c7ffb40127b",
		},
		{
			// Managed scope is not restricted to a relative shape: the
			// managed config files in the adapter table are fixed
			// absolute system paths.
			name:     "managed scope path",
			rule:     "TC-CFG-016",
			harness:  HarnessCursor,
			scope:    ScopeManaged,
			path:     "/etc/cursor/hooks.json",
			preimage: `{"v":1,"rule":"TC-CFG-016","location":{"harness":"cursor","path":"/etc/cursor/hooks.json"},"evidence":[]}`,
			want:     "tcf_de048560c3426d6c",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			loc := Location{Harness: tc.harness, Scope: tc.scope, Session: tc.session, Path: tc.path}
			if tc.line > 0 {
				line := tc.line
				loc.Line = &line
			}
			pre, err := fingerprintPreimage(tc.rule, loc, tc.evidence)
			if err != nil {
				t.Fatal(err)
			}
			if string(pre) != tc.preimage {
				t.Fatalf("preimage = %s", pre)
			}
			sum := sha256.Sum256([]byte(tc.preimage))
			fromPreimage := "tcf_" + hex.EncodeToString(sum[:])[:fingerprintHexLen]
			if fromPreimage != tc.want {
				t.Fatalf("sha256(preimage) = %s, want %s", fromPreimage, tc.want)
			}
			got, err := Fingerprint(tc.rule, loc, tc.evidence)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("Fingerprint = %s, want %s", got, tc.want)
			}
			if strings.Contains(tc.preimage, "secret") || strings.Contains(tc.preimage, "password") || strings.Contains(tc.preimage, "token") {
				t.Fatalf("preimage contains a secret-shaped key: %s", tc.preimage)
			}
			if strings.Contains(tc.preimage, `"event"`) || strings.Contains(tc.preimage, `"line"`) {
				t.Fatalf("preimage hashes an excluded field: %s", tc.preimage)
			}
		})
	}
}

func TestFingerprintLineIsNotHashed(t *testing.T) {
	t.Parallel()
	withLine := 12
	without, err := Fingerprint("TC-CFG-002", Location{Harness: SurfaceVSCode, Path: ".vscode/tasks.json"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	with, err := Fingerprint("TC-CFG-002", Location{Harness: SurfaceVSCode, Path: ".vscode/tasks.json", Line: &withLine}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if with != without {
		t.Fatalf("line changed the fingerprint: with=%s without=%s", with, without)
	}
}

func TestFingerprintEventIDIsNotHashed(t *testing.T) {
	t.Parallel()
	loc := Location{Harness: HarnessClaude, Session: "00893aaf-19fa-41d2"}
	fromHookEvent, err := Fingerprint("TC-SEC-018", loc, []Evidence{
		{Event: "evt_01JD7Q2M9X", Excerpt: "cat /proc/$PPID/environ"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same occurrence, reimported with a new ULID minted at ingest.
	fromReimport, err := Fingerprint("TC-SEC-018", loc, []Evidence{
		{Event: "evt_09ZZZZZZZZ", Excerpt: "cat /proc/$PPID/environ"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fromHookEvent != fromReimport {
		t.Fatalf("event id changed the fingerprint: hook=%s reimport=%s", fromHookEvent, fromReimport)
	}
	// Cited by a config item instead of an event: still the same text,
	// so still the same fingerprint.
	fromConfig, err := Fingerprint("TC-SEC-018", loc, []Evidence{
		{Config: "claude:repo:.claude/settings.json", Excerpt: "cat /proc/$PPID/environ"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fromConfig != fromHookEvent {
		t.Fatalf("evidence kind changed the fingerprint: config=%s event=%s", fromConfig, fromHookEvent)
	}
}

func TestFingerprintNormalization(t *testing.T) {
	t.Parallel()
	spec, err := Fingerprint("TC-SEC-018", Location{
		Harness: " claude ",
		Session: "  00893aaf-19fa-41d2  ",
	}, []Evidence{{
		Event:   " evt_01JD7Q2M9X ",
		Excerpt: "  cat\t/proc/$PPID/environ \n",
	}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := Fingerprint("TC-SEC-018", Location{
		Harness: HarnessClaude,
		Session: "00893aaf-19fa-41d2",
	}, []Evidence{{Event: "evt_01JD7Q2M9X", Excerpt: "cat /proc/$PPID/environ"}})
	if err != nil {
		t.Fatal(err)
	}
	if spec != want {
		t.Fatalf("normalized spec = %s, want %s", spec, want)
	}

	messy := []Evidence{
		{Event: "evt_b", Excerpt: "runOn:\u00a0  folderOpen"},
		{Event: "evt_a", Excerpt: "a   &&  b < c"},
	}
	before := append([]Evidence(nil), messy...)
	got, err := Fingerprint("TC-CFG-002", Location{
		Harness: SurfaceVSCode,
		Path:    ` .vscode\tasks.json/ `,
	}, messy)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := Fingerprint("TC-CFG-002", Location{
		Harness: SurfaceVSCode,
		Path:    ".vscode/tasks.json",
	}, []Evidence{
		{Excerpt: "a && b < c"},
		{Excerpt: "runOn: folderOpen"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != clean {
		t.Fatalf("normalized path/evidence = %s, want %s", got, clean)
	}
	if !reflect.DeepEqual(messy, before) {
		t.Fatalf("evidence mutated: %+v", messy)
	}
	slashy, err := Fingerprint("TC-CFG-002", Location{
		Harness: SurfaceVSCode,
		Path:    ".vscode//tasks.json",
	}, []Evidence{
		{Excerpt: "a && b < c"},
		{Excerpt: "runOn: folderOpen"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if slashy != got {
		t.Fatalf("slash collapse = %s, want %s", slashy, got)
	}

	dropped, err := Fingerprint("TC-CFG-001", Location{Harness: SurfaceGeneric}, []Evidence{
		{Event: "evt_a", Excerpt: " \n\t "},
	})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := Fingerprint("TC-CFG-001", Location{Harness: SurfaceGeneric}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != empty {
		t.Fatalf("dropped evidence = %s, want %s", dropped, empty)
	}
}

func TestFingerprintRejectsBadInput(t *testing.T) {
	t.Parallel()
	_, err := Fingerprint("", Location{Harness: HarnessClaude}, nil)
	if !errors.Is(err, errEmptyRule) {
		t.Fatalf("empty rule: %v", err)
	}
	_, err = Fingerprint("TC-SEC-018", Location{}, nil)
	if !errors.Is(err, errEmptyHarness) {
		t.Fatalf("empty harness: %v", err)
	}
	_, err = Fingerprint("TC-SEC-018", Location{Harness: "devin"}, nil)
	if !errors.Is(err, errUnknownHarness) {
		t.Fatalf("devin: %v", err)
	}
}

func TestFingerprintRejectsAbsolutePaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		scope Scope
		path  string
		want  error
	}{
		{"repo scope, unix absolute", ScopeRepo, "/home/runner/work/acme/acme/.vscode/tasks.json", errPathNotRelative},
		{"default scope, unix absolute", "", "/home/runner/work/acme/acme/.vscode/tasks.json", errPathNotRelative},
		{"repo scope, windows drive", ScopeRepo, `C:\Users\runner\acme\.vscode\tasks.json`, errPathNotRelative},
		{"repo scope, home-relative", ScopeRepo, "~/.claude/settings.json", errPathNotRelative},
		{"user scope, absolute (no tilde)", ScopeUser, "/home/dev/.claude/settings.json", errPathNotUserHome},
		{"user scope, repo-relative", ScopeUser, ".claude/settings.json", errPathNotUserHome},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Fingerprint("TC-CFG-002", Location{Harness: HarnessClaude, Scope: tc.scope, Path: tc.path}, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("path %q, scope %q: err = %v, want %v", tc.path, tc.scope, err, tc.want)
			}
		})
	}
}

func TestFingerprintPreimageKeys(t *testing.T) {
	t.Parallel()
	pre, err := fingerprintPreimage("TC-SEC-018", Location{
		Harness: HarnessClaude,
		Session: "00893aaf-19fa-41d2",
	}, []Evidence{{Event: "evt_01JD7Q2M9X", Excerpt: "cat /proc/$PPID/environ"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(pre, &doc); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, doc, "v", "rule", "location", "evidence")
	location, ok := doc["location"].(map[string]any)
	if !ok {
		t.Fatalf("location %T", doc["location"])
	}
	assertKeys(t, location, "harness", "session")
	evidence, ok := doc["evidence"].([]any)
	if !ok || len(evidence) != 1 {
		t.Fatalf("evidence %#v", doc["evidence"])
	}
	item, ok := evidence[0].(map[string]any)
	if !ok {
		t.Fatalf("item %T", evidence[0])
	}
	assertKeys(t, item, "excerpt")
}

func TestFingerprintDocMatchesGoldens(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "fingerprint.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"}]}`,
		`{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","path":".vscode/tasks.json"},"evidence":[{"excerpt":"a && b < c"},{"excerpt":"runOn: folderOpen"}]}`,
		`{"v":1,"rule":"TC-CFG-001","location":{"harness":"generic"},"evidence":[]}`,
		"tcf_6dcfe79827b07f1b",
	} {
		if !bytes.Contains(raw, []byte(fragment)) {
			t.Fatalf("docs/fingerprint.md missing %s", fragment)
		}
	}
}

func assertKeys(t *testing.T, obj map[string]any, want ...string) {
	t.Helper()
	if len(obj) != len(want) {
		t.Fatalf("keys = %v, want %v", obj, want)
	}
	for _, key := range want {
		if _, ok := obj[key]; !ok {
			t.Fatalf("missing %s in %v", key, obj)
		}
	}
}
