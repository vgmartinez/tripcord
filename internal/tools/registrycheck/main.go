// Command registrycheck fails when a rule REGISTRY edit would let a
// rule id be reused. CI builds this program from the base commit and
// runs that binary with the base rules/REGISTRY and the head version:
//
//	registrycheck OLD NEW
//
// An empty or missing OLD file is a registry with no entries.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vgmartinez/tripcord/internal/advisory"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// baseSHAPattern is a git object name. Anything else is not passed to git.
var baseSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) != 2 {
		return fail(stderr, 2, errors.New("usage: registrycheck OLD NEW"))
	}
	old, err := load(args[0], true)
	if err != nil {
		return fail(stderr, 1, err)
	}
	next, err := load(args[1], false)
	if err != nil {
		return fail(stderr, 1, err)
	}
	if err := rules.CheckRegistryEvolution(old, next); err != nil {
		return fail(stderr, 1, err)
	}
	if err := checkAdvisories(args[0], args[1]); err != nil {
		return fail(stderr, 1, err)
	}
	return 0
}

// checkAdvisories validates ADVISORIES.json next to a head REGISTRY and
// compares it with the base copy. CI invokes this tool as
// `registrycheck OLD NEW` where NEW is rules/REGISTRY, so the advisory
// file is NEW's sibling. The base SHA is read from the same environment
// variables the registry job sets, and a missing file in the base
// commit is an empty list. A file missing at head fails when the base
// still has entries.
func checkAdvisories(oldReg, newReg string) error {
	if filepath.Base(newReg) != rules.RegistryFile {
		return nil
	}
	newPath := filepath.Join(filepath.Dir(newReg), advisory.AdvisoryFile)
	data, err := os.ReadFile(newPath)
	missing := errors.Is(err, fs.ErrNotExist)
	if err != nil && !missing {
		return err
	}
	oldData, err := baseAdvisories(oldReg)
	if err != nil {
		return err
	}
	old, err := advisory.Parse(oldData)
	if err != nil {
		return fmt.Errorf("base %s: %w", advisory.AdvisoryFile, err)
	}
	if missing {
		if old.Len() > 0 {
			return fmt.Errorf("%s removed: the base has %d advisories; set withdrawn instead of deleting the file", advisory.AdvisoryFile, old.Len())
		}
		return nil
	}
	next, err := advisory.Parse(data)
	if err != nil {
		return err
	}
	if err := advisory.CheckEvolution(old, next); err != nil {
		return err
	}
	rulePath := filepath.Join(filepath.Dir(newReg), "TC-CFG-023.yaml")
	if _, err := os.Stat(rulePath); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return citeAdvisories(next, filepath.Dir(newReg))
}

func baseAdvisories(oldReg string) ([]byte, error) {
	sib := filepath.Join(filepath.Dir(oldReg), advisory.AdvisoryFile)
	data, err := os.ReadFile(sib)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	sha, err := baseSHA()
	if err != nil {
		return nil, err
	}
	if sha == "" {
		return nil, nil
	}
	out, err := exec.Command("git", "show", sha+":rules/"+advisory.AdvisoryFile).CombinedOutput()
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "does not exist") || strings.Contains(msg, "exists on disk, but not in") || strings.Contains(msg, "Not a valid object name") {
			return nil, nil
		}
		return nil, fmt.Errorf("git show %s:rules/%s: %s", sha, advisory.AdvisoryFile, strings.TrimSpace(msg))
	}
	return out, nil
}

func baseSHA() (string, error) {
	zero := "0000000000000000000000000000000000000000"
	var sha string
	switch os.Getenv("EVENT_NAME") {
	case "":
		return "", nil
	case "pull_request":
		sha = os.Getenv("PR_BASE_SHA")
		if sha == "" {
			return "", errors.New("advisories: pull request event has no base SHA")
		}
	case "push":
		sha = os.Getenv("PUSH_BEFORE_SHA")
		if sha == "" || sha == zero {
			branch := os.Getenv("DEFAULT_BRANCH")
			if branch == "" {
				return "", errors.New("advisories: push has no previous commit and no default branch")
			}
			out, err := exec.Command("git", "merge-base", "HEAD", "origin/"+branch).Output()
			if err != nil {
				return "", fmt.Errorf("advisories: merge-base with origin/%s: %w", branch, err)
			}
			sha = strings.TrimSpace(string(out))
		}
	default:
		return "", fmt.Errorf("advisories: unsupported event %s", os.Getenv("EVENT_NAME"))
	}
	if !baseSHAPattern.MatchString(sha) {
		return "", fmt.Errorf("advisories: base SHA %q is not a hex object name", sha)
	}
	return sha, nil
}

func citeAdvisories(db *advisory.DB, rulesDir string) error {
	docPath := filepath.Join(filepath.Dir(rulesDir), "docs", "rules", "TC-CFG-023.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		return fmt.Errorf("advisories: %w", err)
	}
	posRoot := filepath.Join(rulesDir, "TC-CFG-023.test", "positivos")
	var pos bytes.Buffer
	err = filepath.WalkDir(posRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pos.Write(b)
		pos.WriteByte('\n')
		return nil
	})
	if err != nil {
		return fmt.Errorf("advisories: %w", err)
	}
	body := pos.Bytes()
	var errs []error
	for _, a := range db.Current() {
		if !bytes.Contains(doc, []byte(a.ID)) {
			errs = append(errs, fmt.Errorf("%s: missing from %s", a.ID, docPath))
		}
		if !citesPackage(body, a) {
			errs = append(errs, fmt.Errorf("%s: no positive fixture names its package, repository, or module signature", a.ID))
		}
	}
	return errors.Join(errs...)
}

func citesPackage(body []byte, a advisory.Advisory) bool {
	for _, aff := range a.Affected {
		if aff.Name != "" && bytes.Contains(body, []byte(aff.Name)) {
			return true
		}
		if aff.Repo != "" && bytes.Contains(body, []byte(aff.Repo)) {
			return true
		}
		for _, sig := range aff.Signatures {
			if sig.Module != "" && bytes.Contains(body, []byte(sig.Module)) {
				return true
			}
			if sig.PathSuffix != "" && bytes.Contains(body, []byte(sig.PathSuffix)) {
				return true
			}
		}
	}
	return false
}

func fail(stderr io.Writer, code int, err error) int {
	_, _ = fmt.Fprintln(stderr, err)
	return code
}

func load(path string, missingOK bool) (*rules.Registry, error) {
	data, err := os.ReadFile(path)
	if missingOK && errors.Is(err, fs.ErrNotExist) {
		data, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	r, err := rules.ParseRegistry(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}
