package project

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestRepositoryMatchesModulePath(t *testing.T) {
	t.Parallel()
	owner, repo, found := strings.Cut(Repository, "/")
	if !found || owner == "" || repo == "" || strings.Contains(repo, "/") {
		t.Fatalf("Repository = %q, want one owner/repo", Repository)
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("build info unavailable")
	}
	want := "github.com/" + Repository
	if info.Main.Path != want {
		t.Fatalf("module path = %q, want %q", info.Main.Path, want)
	}
}
