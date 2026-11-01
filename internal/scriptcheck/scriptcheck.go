// Package scriptcheck counts, for each repository hook, the
// project-relative scripts it runs that are not in the scanned tree. A
// hook that runs a script nobody committed runs whatever a later
// checkout, a build step, or another program puts at that path.
//
// It never runs git: a script that exists but is untracked or ignored
// counts as present. A script is resolved against the hook's project
// directory, the directory that holds the harness's config directory
// (.claude, .cursor, .github, .windsurf, .devin, .codex, .gemini, or
// .agents), and a Copilot hook's relative cwd. A hook in a file with no
// such directory, such as a Claude plugin's hooks/hooks.json, is not
// checked, nor is a script ProjectScripts leaves out (see shellcmd).
package scriptcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
)

// configDirs mark a project directory: the parent of the first of them
// in a hook's path.
var configDirs = []string{".claude", ".cursor", ".github", ".windsurf", ".devin", ".codex", ".gemini", ".agents"}

// Annotate sets MissingScripts on every repository hook in items. root
// is the scanned repository; scripts are looked up through a
// adapters.SafeReader, so a path that leaves root is never opened and
// is not counted as missing.
func Annotate(root string, items []model.ConfigItem) error {
	reader, err := adapters.NewSafeReader(root)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	for i := range items {
		item := &items[i]
		if item.Kind != model.ConfigKindHook || item.Scope != model.ScopeRepo {
			continue
		}
		item.MissingScripts = 0
		for _, rel := range Scripts(*item) {
			if _, err := reader.Stat(rel); errors.Is(err, fs.ErrNotExist) {
				item.MissingScripts++
			}
		}
	}
	return nil
}

// Scripts returns the repository-relative paths of the project scripts
// item runs, or nil when it cannot tell where they are.
func Scripts(item model.ConfigItem) []string {
	base, ok := projectDir(item.Path)
	if !ok {
		return nil
	}
	payload := decode(item)
	if payload == nil {
		return nil
	}
	if cwd, ok := payload["cwd"]; ok {
		dir, ok := cwd.(string)
		if !ok {
			return nil
		}
		dir = path.Clean(dir)
		if strings.ContainsAny(dir, "$%~`\\") || path.IsAbs(dir) || dir == ".." || strings.HasPrefix(dir, "../") {
			return nil
		}
		base = path.Join(base, dir)
	}
	var found []string
	for _, field := range model.HookCommandFields {
		if line, ok := payload[field].(string); ok {
			found = append(found, shellcmd.ProjectScripts(line)...)
		}
	}
	if args, ok := payload["args"].([]any); ok {
		argv := make([]string, 0, len(args)+1)
		program, _ := payload["exec"].(string)
		if program == "" {
			program, _ = payload["command"].(string)
		}
		argv = append(argv, program)
		for _, a := range args {
			s, ok := a.(string)
			if !ok {
				argv = nil
				break
			}
			argv = append(argv, s)
		}
		if argv != nil {
			found = append(found, shellcmd.ProjectScriptsArgv(argv)...)
		}
	}
	var out []string
	for _, p := range found {
		rel := path.Join(base, p)
		if !slices.Contains(out, rel) {
			out = append(out, rel)
		}
	}
	return out
}

func projectDir(itemPath string) (string, bool) {
	segments := strings.Split(itemPath, "/")
	for i, s := range segments[:len(segments)-1] {
		if slices.Contains(configDirs, s) {
			return path.Join(segments[:i]...), true
		}
	}
	return "", false
}

// decode reads the Detect view, which keeps the command as written, or
// the payload when the adapter kept none.
func decode(item model.ConfigItem) map[string]any {
	src := []byte(item.Payload)
	if item.Detect != nil {
		src = item.Detect
	}
	if len(bytes.TrimSpace(src)) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(src, &payload); err != nil {
		return nil
	}
	return payload
}
