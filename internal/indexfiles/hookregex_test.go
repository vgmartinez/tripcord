package indexfiles

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"go.yaml.in/yaml/v3"
)

func TestHookRegexMatchesDiscoveryPaths(t *testing.T) {
	re := hookFileRegex(t)
	var missed []string
	for _, path := range hookProbes(t) {
		if !HookPath(path) {
			continue
		}
		if !re.MatchString(path) {
			missed = append(missed, path)
		}
		swapped := swapCasePath(path)
		if swapped != path && HookPath(swapped) && !re.MatchString(swapped) {
			missed = append(missed, swapped)
		}
	}
	if len(missed) > 0 {
		if len(missed) > 30 {
			missed = missed[:30]
		}
		t.Fatalf("files regex misses discovery paths:\n%s", strings.Join(missed, "\n"))
	}
}

func hookFileRegex(t *testing.T) *regexp.Regexp {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks []map[string]any
	if err := yaml.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 {
		t.Fatalf("hooks = %d", len(hooks))
	}
	files, ok := hooks[0]["files"].(string)
	if !ok || files == "" {
		t.Fatal("hook files regex missing")
	}
	re, err := regexp.Compile(files)
	if err != nil {
		t.Fatal(err)
	}
	return re
}

func hookProbes(t *testing.T) []string {
	t.Helper()
	segs := adapterLiterals(t)
	var files, dirs []string
	for _, seg := range segs {
		if strings.Contains(seg, ".") {
			files = append(files, seg)
			continue
		}
		dirs = append(dirs, seg)
	}
	middles := []string{"skills", "rules", "agents", "commands", "hooks", "plugins", "plugin", "copilot", "instructions", "workflows", ".claude-plugin"}
	out := make([]string, 0, len(files)*(len(dirs)+1))
	for _, file := range files {
		out = append(out, file, "skills/name/"+file, "agents/"+file, "commands/"+file, "hooks/"+file)
		for _, dir := range dirs {
			out = append(out, dir+"/"+file)
			for _, mid := range middles {
				out = append(out, dir+"/"+mid+"/"+file, dir+"/"+mid+"/name/"+file)
			}
		}
	}
	return out
}

func adapterLiterals(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "adapters")
	fset := token.NewFileSet()
	seen := map[string]bool{}
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value := strings.Trim(lit.Value, "`\"")
			if !segmentLiteral(value) || seen[value] {
				return true
			}
			seen[value] = true
			out = append(out, value)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no adapter literals")
	}
	return out
}

func segmentLiteral(value string) bool {
	if value == "" || len(value) > 80 || strings.ContainsAny(value, " \t\n/\\{}()[]") {
		return false
	}
	for _, r := range value {
		if r > unicode.MaxASCII || unicode.IsSpace(r) {
			return false
		}
	}
	return strings.Contains(value, ".") || strings.HasPrefix(value, ".") || value == strings.ToLower(value)
}

func swapCasePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		var b strings.Builder
		for _, r := range part {
			switch {
			case unicode.IsLower(r):
				b.WriteRune(unicode.ToUpper(r))
			case unicode.IsUpper(r):
				b.WriteRune(unicode.ToLower(r))
			default:
				b.WriteRune(r)
			}
		}
		parts[i] = b.String()
	}
	return strings.Join(parts, "/")
}
