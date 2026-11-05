package benignscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/fpkey"
)

// Scanner scans one fetched tree.
type Scanner interface {
	Scan(ctx context.Context, dir string) (findings []Finding, diagnostics int, err error)
}

// Tripcord runs `tripcord scan -format json` on a directory. Exit codes
// 0, 1, and 3 are a completed scan; 3 means some configuration could
// not be read, and those diagnostics are counted. The scan stops at
// the directory's parent, so a tree under a Git work tree is never
// widened to that repository.
//
// The scan always fingerprints in s1 mode. A finding whose evidence lost
// a secret to redaction is fingerprinted with the fingerprint key, and
// triage.tsv rows must match on every machine and in the nightly job, so
// the host's TRIPCORD_FINGERPRINT_KEY and ~/.tripcord/fingerprint.key
// are never used: the key variable is removed, HOME is the directory's
// parent, which holds no key file, and CI is set so none is created.
type Tripcord struct {
	Bin string
}

func (t Tripcord) Scan(ctx context.Context, dir string) ([]Finding, int, error) {
	cmd := exec.CommandContext(ctx, t.Bin, "scan", "-format", "json", "-scope", "repo", dir)
	cmd.Env = scanEnv(os.Environ(), filepath.Dir(dir))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return nil, 0, err
	}
	if exit != nil {
		switch exitcode.Code(exit.ExitCode()) {
		case exitcode.Findings, exitcode.Config:
		default:
			return nil, 0, fmt.Errorf("tripcord exit %d: %s", exit.ExitCode(), lastLine(stderr.String()))
		}
	}
	return ParseScan(&stdout)
}

// scanEnv is environ without the fingerprint key, HOME, or CI, plus
// HOME and CI for an s1 scan and the Git ceiling at parent.
func scanEnv(environ []string, parent string) []string {
	env := make([]string, 0, len(environ)+3)
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case fpkey.EnvVar, "HOME", "CI", "GIT_CEILING_DIRECTORIES":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "HOME="+parent, "CI=true", "GIT_CEILING_DIRECTORIES="+parent)
}

// ParseScan reads tripcord's JSON Lines output: finding and diagnostic
// records. Any other record is an error, so a format change is noticed.
func ParseScan(r io.Reader) ([]Finding, int, error) {
	var findings []Finding
	diags := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Schema      string `json:"schema"`
			Rule        string `json:"rule"`
			Severity    string `json:"severity"`
			Fingerprint string `json:"fingerprint"`
			Location    struct {
				Path string `json:"path"`
			} `json:"location"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, 0, fmt.Errorf("tripcord output: %w", err)
		}
		switch rec.Schema {
		case "tripcord.finding/v1":
			if rec.Rule == "" || rec.Fingerprint == "" || rec.Severity == "" {
				return nil, 0, fmt.Errorf("tripcord output: finding without rule, severity, or fingerprint")
			}
			findings = append(findings, Finding{Rule: rec.Rule, Severity: rec.Severity, Fingerprint: rec.Fingerprint, Path: rec.Location.Path})
		case "tripcord.diagnostic/v1":
			diags++
		default:
			return nil, 0, fmt.Errorf("tripcord output: unknown record schema %q", rec.Schema)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	return findings, diags, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
