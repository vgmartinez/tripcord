package embedded

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testPin = Pin{Version: "0.1.0", SHA256: map[string]string{"linux-x64": strings.Repeat("0", 64)}}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
