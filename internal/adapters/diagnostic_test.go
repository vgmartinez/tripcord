package adapters

import (
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func symlinkDiag(harness model.Harness, path string) Diagnostic {
	return Diagnostic{
		Harness: harness,
		Scope:   model.ScopeRepo,
		Path:    path,
		Message: "symlink resolves outside the repository; " + string(harness) + " may load its target, which was not scanned",
	}
}

func TestDedupeEscapingSymlinkDiagnosticsDropsClaudeWhenAnotherHarnessAgrees(t *testing.T) {
	t.Parallel()
	in := []Diagnostic{
		symlinkDiag(model.HarnessClaude, ".codex/skills"),
		symlinkDiag(model.HarnessCodex, ".codex/skills"),
	}
	got := DedupeEscapingSymlinkDiagnostics(in)
	if len(got) != 1 || got[0].Harness != model.HarnessCodex {
		t.Fatalf("got = %+v, want only the codex diagnostic", got)
	}
}

func TestDedupeEscapingSymlinkDiagnosticsKeepsSoleClaudeReport(t *testing.T) {
	t.Parallel()
	in := []Diagnostic{symlinkDiag(model.HarnessClaude, "my-plugin/skills")}
	got := DedupeEscapingSymlinkDiagnostics(in)
	if len(got) != 1 || got[0].Harness != model.HarnessClaude {
		t.Fatalf("got = %+v, want Claude's own report kept when nothing else flags the symlink", got)
	}
}

func TestDedupeEscapingSymlinkDiagnosticsKeepsBothForDistinctPaths(t *testing.T) {
	t.Parallel()
	in := []Diagnostic{
		symlinkDiag(model.HarnessClaude, ".codex/skills"),
		symlinkDiag(model.HarnessCodex, ".codex/rules"),
	}
	got := DedupeEscapingSymlinkDiagnostics(in)
	if len(got) != 2 {
		t.Fatalf("got = %+v, want both kept since they are different paths", got)
	}
}

func TestDedupeEscapingSymlinkDiagnosticsIgnoresOtherMessages(t *testing.T) {
	t.Parallel()
	in := []Diagnostic{
		{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: "x", Message: "cannot resolve symlink: too many levels"},
		{Harness: model.HarnessCodex, Scope: model.ScopeRepo, Path: "x", Message: "cannot resolve symlink: too many levels"},
	}
	got := DedupeEscapingSymlinkDiagnostics(in)
	if len(got) != 2 {
		t.Fatalf("got = %+v, want non-symlink-escape diagnostics untouched", got)
	}
}

func TestDedupeEscapingSymlinkDiagnosticsScopesIndependently(t *testing.T) {
	t.Parallel()
	in := []Diagnostic{
		{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".codex/skills", Message: "symlink resolves outside the repository; Claude Code may load its target, which was not scanned"},
		{Harness: model.HarnessCodex, Scope: model.ScopeUser, Path: "~/.codex/skills", Message: "symlink resolves outside the directory; Codex may load its target, which was not scanned"},
	}
	got := DedupeEscapingSymlinkDiagnostics(in)
	if len(got) != 2 {
		t.Fatalf("got = %+v, want both kept since scope and path differ", got)
	}
}

func TestDedupeEscapingSymlinkDiagnosticsPreservesOrder(t *testing.T) {
	t.Parallel()
	in := []Diagnostic{
		symlinkDiag(model.HarnessCodex, "a"),
		symlinkDiag(model.HarnessClaude, "a"),
		symlinkDiag(model.HarnessCursor, "b"),
	}
	got := DedupeEscapingSymlinkDiagnostics(in)
	if len(got) != 2 || got[0].Harness != model.HarnessCodex || got[1].Harness != model.HarnessCursor {
		t.Fatalf("got = %+v, want codex then cursor in original order", got)
	}
}
