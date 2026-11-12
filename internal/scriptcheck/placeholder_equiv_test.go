package scriptcheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
)

// oversizePlaceholder is the size preopen writes for a blob larger than
// the configuration cap, and equals the size of a real over-cap file
// that the scan would also refuse.
const oversizePlaceholder = adapters.MaxConfigFileBytes + 1

func writeSized(t *testing.T, path string, n int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(n); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func annotateRoots(t *testing.T, setup func(root string), items []model.ConfigItem) []model.ConfigItem {
	t.Helper()
	root := t.TempDir()
	setup(root)
	cp := make([]model.ConfigItem, len(items))
	copy(cp, items)
	if err := Annotate(root, cp); err != nil {
		t.Fatal(err)
	}
	return cp
}

// TestAnnotateOversizePlaceholderMatchesFullBlob is the confirmation
// that scriptcheck's tree reads treat a preopen placeholder the same as
// the real >1 MiB blob f08138f would have written: checksum_files only
// reads the (small) sums file, checksum_symlinks and repo_script only
// Stat the target, and a dotenv larger than 64 KiB is refused before
// its bytes are read.
func TestAnnotateOversizePlaceholderMatchesFullBlob(t *testing.T) {
	sum := "abababababababababababababababababababababababababababababababab  tool.bin\n"
	const copilot = ".github/workflows/copilot-setup-steps.yml"
	items := []model.ConfigItem{
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":"curl -fsSLo tool.bin https://x.invalid/tool.bin && sha256sum -c SHA256SUMS && ./tool.bin"}`),
		{
			Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".claude/settings.json",
			Kind:    model.ConfigKindHook,
			Payload: []byte(`{"command":"./tool.bin"}`),
		},
		{
			Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".mcp.json",
			Kind:    model.ConfigKindMCPServer,
			Payload: []byte(`{"command":"bash","args":["-c","set -a && source .env && npx -y pkg"]}`),
		},
	}

	setup := func(size int64) func(string) {
		return func(root string) {
			if err := os.WriteFile(filepath.Join(root, "SHA256SUMS"), []byte(sum), 0o644); err != nil {
				t.Fatal(err)
			}
			writeSized(t, filepath.Join(root, "tool.bin"), size)
			writeSized(t, filepath.Join(root, ".env"), size)
		}
	}

	full := annotateRoots(t, setup(2<<20), items)
	hole := annotateRoots(t, setup(oversizePlaceholder), items)
	if len(full) != len(hole) {
		t.Fatalf("len full=%d hole=%d", len(full), len(hole))
	}

	// checksum_files: both get credit from the small sums file, listing tool.bin.
	if got, want := full[0].ChecksumFiles, map[string][]string{"SHA256SUMS": {"tool.bin"}}; !checksumFilesEq(got, want) {
		t.Fatalf("full checksum_files = %#v, want %#v", got, want)
	}
	if !checksumFilesEq(full[0].ChecksumFiles, hole[0].ChecksumFiles) {
		t.Fatalf("checksum_files diverged: full %#v hole %#v", full[0].ChecksumFiles, hole[0].ChecksumFiles)
	}
	if len(full[0].ChecksumSymlinks) != 0 || len(hole[0].ChecksumSymlinks) != 0 {
		t.Fatalf("checksum_symlinks full=%v hole=%v, want none (regular file)", full[0].ChecksumSymlinks, hole[0].ChecksumSymlinks)
	}

	// repo_script / hook script: ./tool.bin exists in both trees.
	if full[1].MissingScripts != 0 || hole[1].MissingScripts != 0 {
		t.Fatalf("MissingScripts full=%d hole=%d, want 0 (script is present)", full[1].MissingScripts, hole[1].MissingScripts)
	}

	// dotenv: both files are far over dotenvMax, so the wrapper stays a finding.
	if full[2].RepoScript || hole[2].RepoScript {
		t.Fatalf("RepoScript full=%v hole=%v, want false (dotenv too large to quiet)", full[2].RepoScript, hole[2].RepoScript)
	}
}

func checksumFilesEq(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
	}
	return true
}
