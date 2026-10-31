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
			preimage: `{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"event":"evt_01JD7Q2M9X","excerpt":"cat /proc/$PPID/environ"}]}`,
			want:     "tcf_c95f982d5479e942",
		},
		{
			name:    "path line and excerpt",
			rule:    "TC-CFG-002",
			harness: SurfaceVSCode,
			path:    ".vscode/tasks.json",
			line:    12,
			evidence: []Evidence{
				{Event: "evt_a", Excerpt: "a && b < c"},
				{Event: "evt_b", Excerpt: "runOn: folderOpen"},
			},
			preimage: `{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","path":".vscode/tasks.json","line":12},"evidence":[{"event":"evt_a","excerpt":"a && b < c"},{"event":"evt_b","excerpt":"runOn: folderOpen"}]}`,
			want:     "tcf_420dd950a238d29b",
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
			preimage: `{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"event":"evt_01JD7Q2M9X","excerpt":"cat /proc/$PPID/environ"},{"event":"evt_01JD7Q2M9X","excerpt":"cat /proc/$PPID/environ"}]}`,
			want:     "tcf_0191a7ba1321eda7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			loc := Location{Harness: tc.harness, Session: tc.session, Path: tc.path}
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
		})
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
	if spec != "tcf_c95f982d5479e942" {
		t.Fatalf("normalized spec = %s", spec)
	}

	line := 12
	messy := []Evidence{
		{Event: "evt_b", Excerpt: "runOn:\u00a0  folderOpen"},
		{Event: "evt_a", Excerpt: "a   &&  b < c"},
	}
	before := append([]Evidence(nil), messy...)
	got, err := Fingerprint("TC-CFG-002", Location{
		Harness: SurfaceVSCode,
		Path:    ` .vscode\tasks.json/ `,
		Line:    &line,
	}, messy)
	if err != nil {
		t.Fatal(err)
	}
	if got != "tcf_420dd950a238d29b" {
		t.Fatalf("normalized path = %s", got)
	}
	if !reflect.DeepEqual(messy, before) {
		t.Fatalf("evidence mutated: %+v", messy)
	}
	slashy, err := Fingerprint("TC-CFG-002", Location{
		Harness: SurfaceVSCode,
		Path:    ".vscode//tasks.json",
		Line:    &line,
	}, []Evidence{
		{Event: "evt_a", Excerpt: "a && b < c"},
		{Event: "evt_b", Excerpt: "runOn: folderOpen"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if slashy != got {
		t.Fatalf("slash collapse = %s, want %s", slashy, got)
	}

	dropped, err := Fingerprint("TC-CFG-001", Location{Harness: SurfaceGeneric}, []Evidence{
		{Event: "  ", Excerpt: " \n\t "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dropped != "tcf_6dcfe79827b07f1b" {
		t.Fatalf("dropped evidence = %s", dropped)
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
	line := 0
	_, err = Fingerprint("TC-SEC-018", Location{Harness: HarnessClaude, Line: &line}, nil)
	if !errors.Is(err, errLocationLine) {
		t.Fatalf("line 0: %v", err)
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
	assertKeys(t, item, "event", "excerpt")
}

func TestFingerprintDocMatchesGoldens(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "fingerprint.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"event":"evt_01JD7Q2M9X","excerpt":"cat /proc/$PPID/environ"}]}`,
		"tcf_c95f982d5479e942",
		`{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","path":".vscode/tasks.json","line":12},"evidence":[{"event":"evt_a","excerpt":"a && b < c"},{"event":"evt_b","excerpt":"runOn: folderOpen"}]}`,
		"tcf_420dd950a238d29b",
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
