package rules

import (
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
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

// cfg009MaxUnescape is how many percent-encoding layers the guard peels
// after the one url.Parse already decoded. A path still encoded past that
// fails closed.
const cfg009MaxUnescape = 4

// cfg009OwnerProblem checks the owner segment, at index i of the slash-split
// path, as written and after dot segments resolve, at every percent-decoding
// layer. %252e%252e is ".." once a server decodes it twice, and path.Clean
// only resolves it after the guard decodes it.
func cfg009OwnerProblem(p string, i int) string {
	layers, why := cfg009Unescaped(p)
	if why != "" {
		return why
	}
	for _, layer := range layers {
		for _, form := range []string{layer, path.Clean(layer)} {
			parts := strings.Split(form, "/")
			if len(parts) <= i || parts[i] != cfg009FixtureOwner {
				return "path " + form + " is not under " + cfg009FixtureOwner
			}
		}
	}
	return ""
}

// cfg009Unescaped returns p and each further percent-decoded layer of it,
// until decoding no longer changes the path.
func cfg009Unescaped(p string) ([]string, string) {
	layers := []string{p}
	for range cfg009MaxUnescape {
		next, err := url.PathUnescape(p)
		if err != nil {
			return nil, "path " + p + " has a bad percent escape"
		}
		if next == p {
			return layers, ""
		}
		layers = append(layers, next)
		p = next
	}
	if next, err := url.PathUnescape(p); err != nil || next != p {
		return nil, "path " + p + " is still percent-encoded after " + strconv.Itoa(cfg009MaxUnescape) + " decodes"
	}
	return layers, ""
}

func TestCFG009URLProblemDecodesBeforeClean(t *testing.T) {
	const raw = "https://raw.githubusercontent.com/vgmartinez/tools/abababababababababababababababababababab/"
	const jsd = "https://cdn.jsdelivr.net/gh/vgmartinez/tools@abababababababababababababababababababab/"
	cases := map[string]bool{
		raw + "main/i.sh": false,
		raw + "%2e%2e/%2e%2e/%2e%2e/other/repo/main/i.sh":                         true,
		raw + "%252e%252e/%252e%252e/%252e%252e/other/repo/main/i.sh":             true,
		raw + "%252E%252E/%252e%252E/%252E%252e/other/repo/main/i.sh":             true,
		raw + ".%252e/.%252E/%252e./other/repo/main/i.sh":                         true,
		raw + "%25252e%25252e/%25252e%25252e/%25252e%25252e/other/repo/main/i.sh": true,
		raw + "%252e%252e%252f%252e%252e%252f%252e%252e%252fother/repo/main/i.sh": true,
		raw + "%2525252525252e%2525252525252e/main/i.sh":                          true,
		raw + "%25zz/main/i.sh":                                   true,
		raw + "%252e%252e/main/i.sh":                              false,
		jsd + "%252e%252e/%252e%252e/%252e%252e/other/tools/i.sh": true,
		jsd + "%252e%252e/i.sh":                                   false,
		"https://github.com/vgmartinez/tools/raw/%252e%252e/%252e%252e/%252e%252e/x/y": true,
	}
	for u, bad := range cases {
		if got := cfg009URLProblem(u); (got != "") != bad {
			t.Errorf("cfg009URLProblem(%s) = %q, want problem %v", u, got, bad)
		}
	}
}
