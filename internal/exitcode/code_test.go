package exitcode

import (
	"strings"
	"testing"
)

func TestCodesMatchSpecTable(t *testing.T) {
	t.Parallel()
	want := []struct {
		code Code
		text string
	}{
		{OK, "no findings above --fail-on"},
		{Findings, "findings above the threshold"},
		{Block, "hook mode: block (Claude, Copilot, and Windsurf convention)"},
		{Config, "configuration error or invalid policy"},
		{Internal, "internal or I/O error (hook mode translates this to fail-closed when policy asks)"},
	}
	if len(All()) != len(want) {
		t.Fatalf("All() len = %d, want %d", len(All()), len(want))
	}
	seen := map[Code]bool{}
	for i, item := range want {
		if int(item.code) != i {
			t.Fatalf("code %v = %d, want %d", item.code, int(item.code), i)
		}
		got, err := Parse(i)
		if err != nil {
			t.Fatal(err)
		}
		if got != item.code {
			t.Fatalf("Parse(%d) = %v, want %v", i, got, item.code)
		}
		if got.String() != item.text {
			t.Fatalf("String(%d) = %q, want %q", i, got.String(), item.text)
		}
		if !got.Valid() {
			t.Fatalf("%v: not valid", got)
		}
		if seen[got] {
			t.Fatalf("duplicate %v", got)
		}
		seen[got] = true
		if All()[i] != item.code {
			t.Fatalf("All()[%d] = %v", i, All()[i])
		}
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	t.Parallel()
	for _, n := range []int{-1, 5, 99} {
		_, err := Parse(n)
		if err == nil {
			t.Fatalf("Parse(%d) succeeded", n)
		}
		if !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("Parse(%d) error = %v", n, err)
		}
		if Code(n).Valid() {
			t.Fatalf("Code(%d) is valid", n)
		}
		if strings.Contains(Code(n).String(), "above") || strings.Contains(Code(n).String(), "hook mode") {
			t.Fatalf("String(%d) = %q", n, Code(n).String())
		}
	}
}
