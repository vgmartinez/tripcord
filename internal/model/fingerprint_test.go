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
			preimage: `{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2","scope":"repo"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"}]}`,
			want:     "tcf_c761c03b24e7b179",
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
			preimage: `{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","scope":"repo","path":".vscode/tasks.json"},"evidence":[{"excerpt":"a && b < c"},{"excerpt":"runOn: folderOpen"}]}`,
			want:     "tcf_591bc1431fb15369",
		},
		{
			name:     "empty evidence",
			rule:     "TC-CFG-001",
			harness:  SurfaceGeneric,
			preimage: `{"v":1,"rule":"TC-CFG-001","location":{"harness":"generic","scope":"repo"},"evidence":[]}`,
			want:     "tcf_0877dad3c1549226",
		},
		{
			// Identical normalized evidence collapses to one item, so N
			// repeats of this command hash as the spec sample does.
			name:    "duplicate evidence collapses to one",
			rule:    "TC-SEC-018",
			harness: HarnessClaude,
			session: "00893aaf-19fa-41d2",
			evidence: []Evidence{
				{Event: "evt_01JD7Q2M9X", Excerpt: "cat /proc/$PPID/environ"},
				{Event: "evt_09ZZZZZZZZ", Excerpt: "cat /proc/$PPID/environ"},
			},
			preimage: `{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2","scope":"repo"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"}]}`,
			want:     "tcf_c761c03b24e7b179",
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
			preimage: `{"v":1,"rule":"TC-CFG-007","location":{"harness":"claude","scope":"user","path":"~/.claude/settings.json"},"evidence":[{"excerpt":"hooks: SessionStart -> curl | bash"}]}`,
			want:     "tcf_be9d29a5dd7a25fd",
		},
		{
			name:     "managed scope path",
			rule:     "TC-CFG-016",
			harness:  HarnessCursor,
			scope:    ScopeManaged,
			path:     "/etc/cursor/hooks.json",
			preimage: `{"v":1,"rule":"TC-CFG-016","location":{"harness":"cursor","scope":"managed","path":"/etc/cursor/hooks.json"},"evidence":[]}`,
			want:     "tcf_87e0e591cef79388",
		},
		{
			// A Windows drive path case-folds to one canonical spelling
			// (see normalizeScopedPath), so this golden is also the
			// value TestFingerprintWindowsPathsNormalizeIdentically
			// checks a differently-spelled equivalent path against.
			name:     "managed scope windows drive path",
			rule:     "TC-CFG-020",
			harness:  HarnessCursor,
			scope:    ScopeManaged,
			path:     `C:\ProgramData\cursor\hooks.json`,
			preimage: `{"v":1,"rule":"TC-CFG-020","location":{"harness":"cursor","scope":"managed","path":"C:/programdata/cursor/hooks.json"},"evidence":[]}`,
			want:     "tcf_fbae6525ff920e63",
		},
		{
			// A config-only citation (no excerpt) is still hashed: see
			// TestFingerprintDifferentConfigsHaveDifferentFingerprints
			// for the companion case this must NOT collide with.
			name:     "config evidence, no excerpt",
			rule:     "TC-CFG-003",
			harness:  HarnessClaude,
			evidence: []Evidence{{Config: &ConfigRef{ID: "claude:repo:.claude/settings.json"}}},
			preimage: `{"v":1,"rule":"TC-CFG-003","location":{"harness":"claude","scope":"repo"},"evidence":[{"config":{"id":"claude:repo:.claude/settings.json"}}]}`,
			want:     "tcf_301e4605a5ed0534",
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
			if !fingerprintPattern.MatchString(got) || len(got) != len("tcf_")+fingerprintHexLen {
				t.Fatalf("Fingerprint %q is not tcf_ plus %d hex digits", got, fingerprintHexLen)
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

func TestFingerprintWindowsPathsNormalizeIdentically(t *testing.T) {
	t.Parallel()
	backslashMixedCase, err := Fingerprint("TC-CFG-020", Location{
		Harness: HarnessCursor, Scope: ScopeManaged, Path: `C:\ProgramData\cursor\hooks.json`,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forwardSlashLowercase, err := Fingerprint("TC-CFG-020", Location{
		Harness: HarnessCursor, Scope: ScopeManaged, Path: "c:/programdata/cursor/hooks.json",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if backslashMixedCase != forwardSlashLowercase {
		t.Fatalf("Windows paths normalized differently: %s vs %s", backslashMixedCase, forwardSlashLowercase)
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

func TestFingerprintScopeDefaultsToRepo(t *testing.T) {
	t.Parallel()
	unset, err := Fingerprint("TC-CFG-002", Location{Harness: SurfaceVSCode, Path: ".vscode/tasks.json"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := Fingerprint("TC-CFG-002", Location{Harness: SurfaceVSCode, Scope: ScopeRepo, Path: ".vscode/tasks.json"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unset != explicit {
		t.Fatalf("unset scope = %s, explicit repo scope = %s", unset, explicit)
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
	// Same occurrence, reimported with a new ULID minted at ingest: only
	// the event id differs, so the fingerprint must not move.
	fromReimport, err := Fingerprint("TC-SEC-018", loc, []Evidence{
		{Event: "evt_09ZZZZZZZZ", Excerpt: "cat /proc/$PPID/environ"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fromHookEvent != fromReimport {
		t.Fatalf("event id changed the fingerprint: hook=%s reimport=%s", fromHookEvent, fromReimport)
	}
}

func TestFingerprintConfigIDIsHashed(t *testing.T) {
	t.Parallel()
	loc := Location{Harness: HarnessClaude, Session: "00893aaf-19fa-41d2"}
	fromEvent, err := Fingerprint("TC-SEC-018", loc, []Evidence{
		{Event: "evt_01JD7Q2M9X", Excerpt: "cat /proc/$PPID/environ"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same excerpt, but cited by a config item instead of an event:
	// unlike an event id, a config id is content-stable (ConfigItem.ID
	// has no sha256), so hashing it is safe, and it must change the
	// fingerprint: the two citations are not interchangeable evidence.
	fromConfig, err := Fingerprint("TC-SEC-018", loc, []Evidence{
		{Config: &ConfigRef{ID: "claude:repo:.claude/settings.json"}, Excerpt: "cat /proc/$PPID/environ"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fromConfig == fromEvent {
		t.Fatalf("config id did not change the fingerprint: %s", fromConfig)
	}
	if fromConfig != "tcf_d6e7076be31ef7c2" {
		t.Fatalf("config-cited fingerprint = %s", fromConfig)
	}
}

func TestFingerprintDifferentConfigsHaveDifferentFingerprints(t *testing.T) {
	t.Parallel()
	// Before config ids were hashed, a config-only citation (no
	// excerpt) with no Location.Path reduced the preimage to just rule,
	// harness, and an empty evidence list: two findings citing
	// different config files collided onto the same fingerprint. These
	// must now differ.
	settings, err := Fingerprint("TC-CFG-003", Location{Harness: HarnessClaude}, []Evidence{
		{Config: &ConfigRef{ID: "claude:repo:.claude/settings.json"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := Fingerprint("TC-CFG-003", Location{Harness: HarnessClaude}, []Evidence{
		{Config: &ConfigRef{ID: "claude:repo:other/settings.json"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if settings == other {
		t.Fatalf("different config ids collided: %s", settings)
	}
	if settings != "tcf_301e4605a5ed0534" {
		t.Fatalf("settings fingerprint = %s", settings)
	}
	if other != "tcf_27c7eaa6b414761d" {
		t.Fatalf("other fingerprint = %s", other)
	}
}

func TestFingerprintConfigKeyDistinguishesEntries(t *testing.T) {
	t.Parallel()
	// Two entries in the same config file. key is content-derived (an
	// MCP server name, and a hook matcher+command), not an index, so
	// the fingerprints differ even though the config id is the same.
	loc := Location{Harness: HarnessClaude}
	id := "claude:repo:.claude/settings.json"
	server, err := Fingerprint("TC-CFG-003", loc, []Evidence{
		{Config: &ConfigRef{ID: id, Key: "filesystem"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hook, err := Fingerprint("TC-CFG-003", loc, []Evidence{
		{Config: &ConfigRef{ID: id, Key: "PreToolUse|curl"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if server == hook {
		t.Fatalf("different keys collided: %s", server)
	}
	if server != "tcf_30f590ab0e43e08e" {
		t.Fatalf("filesystem fingerprint = %s", server)
	}
	if hook != "tcf_fd9d1e862f831120" {
		t.Fatalf("hook fingerprint = %s", hook)
	}
	// A missing key is a different citation from either entry.
	wholeFile, err := Fingerprint("TC-CFG-003", loc, []Evidence{
		{Config: &ConfigRef{ID: id}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if wholeFile == server || wholeFile == hook {
		t.Fatalf("absent key collided with a keyed entry: %s", wholeFile)
	}
}

func TestFingerprintConfigKeyOrderDoesNotMatter(t *testing.T) {
	t.Parallel()
	loc := Location{Harness: HarnessClaude}
	id := "claude:repo:.claude/settings.json"
	forward, err := Fingerprint("TC-CFG-003", loc, []Evidence{
		{Config: &ConfigRef{ID: id, Key: "filesystem"}},
		{Config: &ConfigRef{ID: id, Key: "PreToolUse|curl"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := Fingerprint("TC-CFG-003", loc, []Evidence{
		{Config: &ConfigRef{ID: id, Key: "PreToolUse|curl"}},
		{Config: &ConfigRef{ID: id, Key: "filesystem"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if forward != reversed {
		t.Fatalf("reordering entries changed the fingerprint: %s vs %s", forward, reversed)
	}
	if forward != "tcf_b88dd3cb84d5dde8" {
		t.Fatalf("reordered fingerprint = %s", forward)
	}
	padded, err := Fingerprint("TC-CFG-003", loc, []Evidence{
		{Config: &ConfigRef{ID: "  " + id + "  ", Key: "  filesystem  "}},
		{Config: &ConfigRef{ID: id, Key: "PreToolUse|curl"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if padded != forward {
		t.Fatalf("untrimmed key changed the fingerprint: %s vs %s", padded, forward)
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
	_, err = Fingerprint("TC-SEC-018", Location{Harness: HarnessClaude, Scope: "global"}, nil)
	if !errors.Is(err, errUnknownScope) {
		t.Fatalf("unknown scope: %v", err)
	}
}

func TestFingerprintRejectsBadPaths(t *testing.T) {
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
		{"repo scope, dotdot segment", ScopeRepo, "../etc/passwd", errPathDotDot},
		{"repo scope, raw dotdot", ScopeRepo, "a/../b", errPathDotDot},
		{"repo scope, trailing dotdot", ScopeRepo, "x/..", errPathDotDot},
		{"user scope, raw dotdot", ScopeUser, "a/../b", errPathDotDot},
		{"user scope, trailing dotdot", ScopeUser, "x/..", errPathDotDot},
		{"managed scope, raw dotdot", ScopeManaged, "a/../b", errPathDotDot},
		{"managed scope, trailing dotdot", ScopeManaged, "x/..", errPathDotDot},
		{"repo scope, unresolved dotdot", ScopeRepo, "foo/../../etc/passwd", errPathDotDot},
		{"user scope, absolute (no tilde)", ScopeUser, "/home/dev/.claude/settings.json", errPathNotUserHome},
		{"user scope, repo-relative", ScopeUser, ".claude/settings.json", errPathNotUserHome},
		{"managed scope, repo-relative", ScopeManaged, "cursor/hooks.json", errPathNotAbsolute},
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

func TestFingerprintCanonicalizesNonCanonicalPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		canonical string
		raw       string
	}{
		{"a/b", "a/./b"},
		{"x", "./x"},
		{"a/b", "a//b"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			loc := Location{Harness: HarnessClaude, Scope: ScopeRepo}
			loc.Path = tc.canonical
			want, err := Fingerprint("TC-CFG-002", loc, nil)
			if err != nil {
				t.Fatal(err)
			}
			loc.Path = tc.raw
			got, err := Fingerprint("TC-CFG-002", loc, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("Fingerprint(%q) = %s, Fingerprint(%q) = %s", tc.raw, got, tc.canonical, want)
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
	assertKeys(t, location, "harness", "session", "scope")
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
		`{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2","scope":"repo"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"}]}`,
		`{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","scope":"repo","path":".vscode/tasks.json"},"evidence":[{"excerpt":"a && b < c"},{"excerpt":"runOn: folderOpen"}]}`,
		`{"v":1,"rule":"TC-CFG-001","location":{"harness":"generic","scope":"repo"},"evidence":[]}`,
		"tcf_0877dad3c1549226",
		`{"v":1,"rule":"TC-CFG-003","location":{"harness":"claude","scope":"repo"},"evidence":[{"config":{"id":"claude:repo:.claude/settings.json","key":"filesystem"}}]}`,
		"tcf_30f590ab0e43e08e",
		"tcf_b88dd3cb84d5dde8",
	} {
		if !bytes.Contains(raw, []byte(fragment)) {
			t.Fatalf("docs/fingerprint.md missing %s", fragment)
		}
	}
}

func TestFingerprintMode(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		evidence []Evidence
		want     string
	}{
		"no evidence":            {nil, ""},
		"event evidence":         {[]Evidence{{Event: "evt_1"}}, ""},
		"config with no key":     {[]Evidence{{Config: &ConfigRef{ID: "x"}}}, ""},
		"config key with no sig": {[]Evidence{{Config: &ConfigRef{ID: "x", Key: `["mcp","app"]`}}}, ""},
		"k1": {
			[]Evidence{{Config: &ConfigRef{ID: "x", Key: `["mcp","app","sig:k1:0123456789abcdef#0"]`}}},
			"k1",
		},
		"s1": {
			[]Evidence{{Config: &ConfigRef{ID: "x", Key: `["mcp","app","sig:s1:env[0]#0"]`}}},
			"s1",
		},
		"s1 with an empty structural part": {
			[]Evidence{{Config: &ConfigRef{ID: "x", Key: `["mcp","app","sig:s1:#0"]`}}},
			"s1",
		},
		"k1 wins when an earlier evidence item has no sig": {
			[]Evidence{
				{Config: &ConfigRef{ID: "x", Key: `["a"]`}},
				{Config: &ConfigRef{ID: "y", Key: `["mcp","app","sig:k1:0123456789abcdef#0"]`}},
			},
			"k1",
		},
		// A non-discriminator key part can be arbitrary command or
		// header text that happens to contain the marker text as a
		// substring, not at the start of the last element: it must not
		// be mistaken for a real discriminator. "sig:" + a digest (no
		// mode) is the actual last part here, the same shape a
		// genuinely non-discriminated entry gets.
		"user text containing the s1 marker is not a discriminator": {
			[]Evidence{{Config: &ConfigRef{ID: "x", Key: `["cmd","echo sig:s1:x[0]","sig:0123456789abcdef"]`}}},
			"",
		},
		// A real s1 entry whose own command text happens to contain
		// "sig:k1:" must still report s1: only the last element is
		// ever inspected, and it starts with sig:s1:.
		"user text containing the k1 marker does not relabel an s1 entry": {
			[]Evidence{{Config: &ConfigRef{ID: "x", Key: `["cmd","echo sig:k1:deadbeef","sig:0123456789abcdef","sig:s1:env[0]#0"]`}}},
			"s1",
		},
		"key is not a JSON array": {
			[]Evidence{{Config: &ConfigRef{ID: "x", Key: "sig:s1:env[0]#0"}}},
			"",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := FingerprintMode(tc.evidence); got != tc.want {
				t.Errorf("FingerprintMode(%+v) = %q, want %q", tc.evidence, got, tc.want)
			}
		})
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
