package prcontext

import "testing"

func TestParseReviews(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		available bool
		logins    []string
		wantErr   bool
	}{
		{name: "absent", body: `{"pull_request":{"user":{"login":"octocat"}}}`, available: false},
		{name: "null", body: `{"reviews":null}`, available: false},
		{name: "object", body: `{"reviews":{"state":"APPROVED"}}`, available: false},
		{name: "empty array", body: `{"reviews":[]}`, available: true, logins: []string{}},
		{
			name:      "array under pull_request",
			body:      `{"pull_request":{"reviews":[{"state":"APPROVED","user":{"login":"Ada","type":"User"}}]}}`,
			available: true,
			logins:    []string{"Ada"},
		},
		{
			name:      "bare array",
			body:      `[{"state":"COMMENTED","user":{"login":"grace","type":"User"}}]`,
			available: true,
			logins:    []string{"grace"},
		},
		{
			name:      "lone review is not the whole set",
			body:      `{"review":{"state":"APPROVED","user":{"login":"Ada","type":"User"}},"pull_request":{"user":{"login":"claude[bot]"}}}`,
			available: false,
			logins:    []string{"Ada"},
		},
		{name: "control character", body: `{"reviews":[{"user":{"login":"a\nb"}}]}`, wantErr: true},
		{name: "bad json", body: `{`, wantErr: true},
		{name: "empty", body: ``, available: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseReviews([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Available != tc.available {
				t.Fatalf("available = %v, want %v", got.Available, tc.available)
			}
			if len(got.Reviews) != len(tc.logins) {
				t.Fatalf("reviews = %+v, want logins %v", got.Reviews, tc.logins)
			}
			for i, login := range tc.logins {
				if got.Reviews[i].Login != login {
					t.Fatalf("review %d login = %q, want %q", i, got.Reviews[i].Login, login)
				}
			}
		})
	}
}

func TestParseReviewArray(t *testing.T) {
	set, err := ParseReviewArray([]byte(`[{"state":"APPROVED","commit_id":"abc","user":{"login":"Ada","type":"User"}}]`))
	if err != nil {
		t.Fatal(err)
	}
	if !set.Available || len(set.Reviews) != 1 || set.Reviews[0].Login != "Ada" || set.Reviews[0].CommitID != "abc" {
		t.Fatalf("set = %+v", set)
	}
	for _, body := range []string{``, `{}`, `{"reviews":[]}`, `null`, `{`} {
		if _, err := ParseReviewArray([]byte(body)); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	empty, err := ParseReviewArray([]byte(`[]`))
	if err != nil || !empty.Available || len(empty.Reviews) != 0 {
		t.Fatalf("empty array = %+v, %v", empty, err)
	}
}

func TestParseRawDiff(t *testing.T) {
	raw := []byte(":100644 100644 1111111 2222222 M\x00README\x00" +
		":000000 100644 0000000 3333333 A\x00.cursor/hooks.json\x00" +
		":100644 000000 4444444 0000000 D\x00old.md\x00" +
		":000000 120000 0000000 5555555 A\x00.claude\x00")
	changes, truncated, err := parseRawDiff(raw, 10)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatal("truncated a short diff")
	}
	paths := pathsOf(changes)
	want := []string{"README", ".cursor/hooks.json", "old.md", ".claude"}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v", paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths = %v, want %v", paths, want)
		}
	}
	if changes[3].NewMode != ModeSymlink {
		t.Fatalf("symlink mode = %s", changes[3].NewMode)
	}
	renamed, _, err := parseRawDiff([]byte(":100644 100644 1111111 2222222 R100\x00old\x00new\x00"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(renamed) != 1 || renamed[0].OldPath != "old" || renamed[0].Path != "new" {
		t.Fatalf("rename = %+v", renamed)
	}
	kept, truncated, err := parseRawDiff([]byte(":100644 100644 1111111 2222222 M\x00a\x00:100644 100644 1111111 2222222 M\x00b\x00"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(kept) != 1 || kept[0].Path != "a" {
		t.Fatalf("truncated = %v, changes = %+v", truncated, kept)
	}
	if _, _, err := parseRawDiff([]byte(":100644 100644 1111111 2222222 R100\x00only-old\x00"), 10); err == nil {
		t.Fatal("rename with one path was accepted")
	}
}
