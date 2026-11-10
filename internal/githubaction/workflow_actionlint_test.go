package githubaction_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// actionlintStub is the fixture binary. Running it leaves a marker, so a
// test can tell that the step executed whatever it extracted.
const actionlintStub = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$ACTIONLINT_MARKER\"\n"

// TestActionlintDownloadFailsClosed runs both actionlint steps from ci.yml
// against a local server. The pinned checksum and URL are replaced only
// in the copy of the script under test, never in the workflow.
func TestActionlintDownloadFailsClosed(t *testing.T) {
	for _, step := range []struct{ job, name string }{
		{"actionlint", "actionlint"},
		{"embed-lint", "actionlint generated workflows"},
	} {
		run := stepRun(t, step.job, step.name)
		good := actionlintTarball(t, map[string]string{"actionlint": actionlintStub, "LICENSE.txt": "MIT\n"})
		missing := actionlintTarball(t, map[string]string{
			"bin/actionlint": actionlintStub,
			"actionlint.sh":  actionlintStub,
			"LICENSE.txt":    "MIT\n",
		})
		t.Run(step.job+"/control", func(t *testing.T) {
			res := runActionlintStep(t, run, good, sha256Hex(good))
			if res.err != nil {
				t.Fatalf("matching checksum failed: %v", res.err)
			}
			if !res.extracted || !res.ran {
				t.Fatalf("extracted %v ran %v, want both", res.extracted, res.ran)
			}
		})
		t.Run(step.job+"/wrong checksum", func(t *testing.T) {
			res := runActionlintStep(t, run, good, "")
			if res.err == nil {
				t.Fatal("checksum mismatch exited 0")
			}
			if !strings.Contains(res.out, "FAILED") {
				t.Fatalf("sha256sum did not report the mismatch: %s", res.out)
			}
			if res.extracted || res.ran {
				t.Fatalf("extracted %v ran %v after a checksum mismatch", res.extracted, res.ran)
			}
		})
		t.Run(step.job+"/archive without actionlint", func(t *testing.T) {
			res := runActionlintStep(t, run, missing, sha256Hex(missing))
			if res.err == nil {
				t.Fatal("archive without actionlint exited 0")
			}
			if res.extracted || res.ran {
				t.Fatalf("extracted %v ran %v from an archive without actionlint", res.extracted, res.ran)
			}
			for _, name := range []string{"bin", "actionlint.sh"} {
				if _, err := os.Lstat(filepath.Join(res.temp, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s was extracted: %v", name, err)
				}
			}
		})
	}
}

type actionlintRun struct {
	err            error
	out, temp      string
	extracted, ran bool
}

// runActionlintStep serves body as the release tarball and runs the step
// script with sum in place of the pinned checksum. An empty sum keeps the
// pinned one, which a fixture tarball cannot match.
func runActionlintStep(t *testing.T, run string, body []byte, sum string) actionlintRun {
	t.Helper()
	for _, pin := range []string{actionlintURL, actionlintSum} {
		if strings.Count(run, pin) != 1 {
			t.Fatalf("step names %s %d times, want once", pin, strings.Count(run, pin))
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/actionlint.tar.gz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	script := strings.Replace(run, actionlintURL, srv.URL+"/actionlint.tar.gz", 1)
	if sum != "" {
		script = strings.Replace(script, actionlintSum, sum, 1)
	}
	dir := t.TempDir()
	temp := filepath.Join(dir, "runner-temp")
	work := filepath.Join(dir, "work")
	for _, d := range []string{temp, filepath.Join(work, "embed-out", ".github", "workflows")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "embed-out", ".github", "workflows", "ci.yml"), []byte("on: push\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "ran")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "RUNNER_TEMP="+temp, "ACTIONLINT_MARKER="+marker)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("step timed out, output %s", out)
	}
	_, extractErr := os.Lstat(filepath.Join(temp, "actionlint"))
	_, ranErr := os.Lstat(marker)
	if err != nil {
		err = fmt.Errorf("%w: %s", err, out)
	}
	return actionlintRun{
		err:       err,
		out:       string(out),
		temp:      temp,
		extracted: extractErr == nil,
		ran:       ranErr == nil,
	}
}

func actionlintTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
