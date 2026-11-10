package rules

import (
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// cfg009FixtureOwner owns every GitHub path the TC-CFG-009 fixtures name.
// The rule needs the real hosts, so the paths must be ones no third party
// can register.
const cfg009FixtureOwner = "vgmartinez"

var cfg009FixtureURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'` + "`" + `)<>|\\]+`)

// TestCFG009FixtureURLsAreInert fails when a TC-CFG-009 fixture URL could
// reach a repository outside cfg009FixtureOwner, before or after its dot
// segments resolve, or names a host that is neither GitHub nor reserved.
func TestCFG009FixtureURLsAreInert(t *testing.T) {
	root := filepath.Join("..", "..", "rules", "TC-CFG-009.test")
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		for _, s := range cfg009FixtureURL.FindAllString(string(raw), -1) {
			seen[s] = true
			if why := cfg009URLProblem(s); why != "" {
				t.Errorf("%s: %s: %s", rel, s, why)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	const literal = "https://raw.githubusercontent.com/vgmartinez/tools/abababababababababababababababababababab/../../../vgmartinez/repo/main/i.sh"
	if !seen[literal] {
		t.Fatalf("copilot-traversal-other-repo no longer names %s", literal)
	}
	u, err := url.Parse(literal)
	if err != nil {
		t.Fatal(err)
	}
	if got := path.Clean(u.Path); got != "/vgmartinez/repo/main/i.sh" {
		t.Fatalf("traversal resolves to %s", got)
	}
}

func cfg009URLProblem(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "does not parse: " + err.Error()
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	switch {
	case host == "localhost" || strings.HasSuffix(host, ".invalid") || host == "example" || strings.HasSuffix(host, ".example"):
		return ""
	case host == "raw.githubusercontent.com" || host == "github.com":
		return cfg009OwnerProblem(u.Path, 1)
	case host == "cdn.jsdelivr.net":
		if !strings.HasPrefix(u.Path, "/gh/") {
			return "jsDelivr path is not /gh/"
		}
		return cfg009OwnerProblem(u.Path, 2)
	default:
		return "host is neither GitHub nor reserved"
	}
}

// cfg009OwnerProblem checks the owner segment, at index i of the slash-split
// path, as written and after dot segments resolve.
func cfg009OwnerProblem(p string, i int) string {
	for _, form := range []string{p, path.Clean(p)} {
		parts := strings.Split(form, "/")
		if len(parts) <= i || parts[i] != cfg009FixtureOwner {
			return "path " + form + " is not under " + cfg009FixtureOwner
		}
	}
	return ""
}
