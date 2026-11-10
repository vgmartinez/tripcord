package benignscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hexSum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

const pinA = "https://raw.githubusercontent.com/vgmartinez/schemas/0123456789abcdef0123456789abcdef01234567/a.json"

func TestCommittedUpstreamLock(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "upstream.lock"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseUpstream(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"claude-code-settings.json":     "https://json.schemastore.org/claude-code-settings.json",
		"devContainer.base.schema.json": "https://raw.githubusercontent.com/devcontainers/spec/main/schemas/devContainer.base.schema.json",
	}
	for _, r := range rows {
		if url, ok := want[r.Name]; ok && r.URL == url {
			delete(want, r.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("upstream.lock is missing %v", want)
	}
}

func TestParseUpstreamRejects(t *testing.T) {
	good := "a.json\thttps://example.test/a.json\t" + hexSum("a") + "\t" + pinA
	if _, err := ParseUpstream([]byte("# header\n" + good + "\n")); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"empty":         "# only comments\n",
		"three columns": "a.json\thttps://example.test/a.json\t" + hexSum("a") + "\n",
		"http":          "a.json\thttp://example.test/a.json\t" + hexSum("a") + "\t" + pinA + "\n",
		"short hash":    "a.json\thttps://example.test/a.json\tabc\t" + pinA + "\n",
		"upper hash":    "a.json\thttps://example.test/a.json\t" + strings.ToUpper(hexSum("a")) + "\t" + pinA + "\n",
		"branch pin":    "a.json\thttps://example.test/a.json\t" + hexSum("a") + "\thttps://raw.githubusercontent.com/vgmartinez/schemas/main/a.json\n",
		"bad name":      "../a\thttps://example.test/a.json\t" + hexSum("a") + "\t" + pinA + "\n",
		"duplicate":     good + "\n" + good + "\n",
	} {
		if _, err := ParseUpstream([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func fakeGet(pages map[string]string) Getter {
	return func(_ context.Context, url string) ([]byte, error) {
		body, ok := pages[url]
		if !ok {
			return nil, errors.New("HTTP 404 Not Found")
		}
		return []byte(body), nil
	}
}

func TestCheckUpstream(t *testing.T) {
	old := "{\n  \"a\": 1,\n  \"b\": 2\n}\n"
	rows := []Upstream{{Name: "a.json", URL: "https://example.test/a.json", SHA256: hexSum(old), Pinned: pinA}}

	if d := CheckUpstream(context.Background(), rows, fakeGet(map[string]string{rows[0].URL: old, pinA: old})); len(d) != 0 {
		t.Fatalf("matching file drifted: %v", d)
	}

	changed := "{\n  \"a\": 1,\n  \"b\": 3\n}\n"
	d := CheckUpstream(context.Background(), rows, fakeGet(map[string]string{rows[0].URL: changed, pinA: old}))
	if len(d) != 1 || d[0].Got != hexSum(changed) || d[0].Want != hexSum(old) {
		t.Fatalf("drift: %+v", d)
	}
	for _, want := range []string{"--- a/a.json", "+++ b/a.json", "-  \"b\": 2", "+  \"b\": 3"} {
		if !strings.Contains(d[0].Diff, want) {
			t.Errorf("diff missing %q:\n%s", want, d[0].Diff)
		}
	}
	if !strings.Contains(d[0].String(), "want sha256 "+hexSum(old)) {
		t.Errorf("report: %s", d[0].String())
	}

	d = CheckUpstream(context.Background(), rows, fakeGet(map[string]string{rows[0].URL: changed, pinA: "tampered"}))
	if len(d) != 1 || !strings.Contains(d[0].Diff, "not the locked value") {
		t.Fatalf("a pinned copy that does not match the lock was diffed: %+v", d)
	}

	d = CheckUpstream(context.Background(), rows, fakeGet(map[string]string{}))
	if len(d) != 1 || d[0].Err == nil {
		t.Fatalf("an unreachable URL passed: %+v", d)
	}
}
