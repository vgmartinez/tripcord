// Package scriptcheck counts, for each repository hook, the
// project-relative scripts it runs that are not in the scanned tree. A
// hook that runs a script nobody committed runs whatever a later
// checkout, a build step, or another program puts at that path.
//
// It never runs git: a script that exists but is untracked or ignored
// counts as present. A script is resolved against the hook's project
// directory, the directory that holds the harness's config directory
// (.claude, .cursor, .github, .windsurf, .devin, .codex, .gemini, or
// .agents), and a Copilot hook's relative cwd. A symlink is resolved
// with filepath.EvalSymlinks on the whole path, so a symlink in a parent
// directory counts as well as a symlink in the last component. A target
// outside the repository is reported by that target's location class, and
// a link that does not resolve counts as missing, as does any other lookup
// error. A hook in a file with no
// such directory, such as a Claude plugin's hooks/hooks.json, is not
// checked, nor is a script ProjectScripts leaves out (see shellcmd).
//
// It also reads, for each repository env-setup entry, the committed sums
// files its sha256sum -c checks name, so TC-CFG-009 can tell a checked
// download from one checked against a file nobody committed.
package scriptcheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
)

// configDirs mark a project directory: the parent of the first of them
// in a hook's path.
var configDirs = []string{".claude", ".cursor", ".github", ".windsurf", ".devin", ".codex", ".gemini", ".agents"}

// Annotate sets MissingScripts and ScriptLocations on every repository
// hook in items. root is the scanned repository. A lookup error, including
// a broken symlink, counts as missing. A path that resolves outside root,
// through a symlink in any component, is recorded by the target's location
// class, not by its path. root is resolved first so a repository whose own
// path contains a symlink is not reported as outside itself. It also sets
// ChecksumFiles on every repository env-setup entry (see
// annotateChecksums).
func Annotate(root string, items []model.ConfigItem) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	for i := range items {
		item := &items[i]
		if item.Kind != model.ConfigKindHook || item.Scope != model.ScopeRepo {
			continue
		}
		item.MissingScripts = 0
		item.ScriptLocations = nil
		for _, rel := range Scripts(*item) {
			switch class, missing := lookupScript(resolvedRoot, rel); {
			case missing:
				item.MissingScripts++
			case class != "":
				if !slices.Contains(item.ScriptLocations, class) {
					item.ScriptLocations = append(item.ScriptLocations, class)
				}
			}
		}
	}
	return annotateChecksums(resolvedRoot, items)
}

// lookupScript reports whether rel is missing or resolves outside root.
// Any error counts as missing, so an unreadable or broken path cannot pass
// as present. The returned class is empty when the script stays inside root.
func lookupScript(root, rel string) (class string, missing bool) {
	cleaned := filepath.Clean(filepath.FromSlash(rel))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || filepath.IsAbs(cleaned) {
		return "", true
	}
	abs := filepath.Join(root, cleaned)
	if _, err := os.Stat(abs); err != nil {
		return "", true
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", true
	}
	if insideRoot(root, resolved) {
		return "", false
	}
	return outsideClass(resolved), false
}

func insideRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}

// outsideClass is the severity class of a resolved path. Home and temp stay
// distinct; a system path such as /etc/passwd is absolute, so it is medium
// rather than ignored the way a direct system-binary command is.
func outsideClass(resolved string) string {
	for _, class := range shellcmd.Locate(resolved).Locations {
		switch class {
		case shellcmd.Home, shellcmd.Temp, shellcmd.Absolute, shellcmd.Network:
			return class
		}
	}
	return shellcmd.Absolute
}

// ReferencedPaths returns repository-relative hook scripts and checksum
// files that items name. A path the index does not contain is still
// listed; the caller treats that as missing.
func ReferencedPaths(items []model.ConfigItem) []string {
	var out []string
	seen := map[string]bool{}
	for _, item := range items {
		if item.Scope != model.ScopeRepo {
			continue
		}
		for _, rel := range ItemReferencedPaths(item) {
			if seen[rel] {
				continue
			}
			seen[rel] = true
			out = append(out, rel)
		}
	}
	return out
}

// ItemReferencedPaths returns item's own repository-relative hook
// scripts and checksum files, named whether or not the index contains
// them: a staged deletion of one of these paths can still change a
// rule's verdict (TC-CFG-006 on a deleted hook script, TC-CFG-009 on a
// deleted sums file), so a --staged scan's SourcePaths must include it
// even though scriptcheck.Annotate's ChecksumFiles and ScriptLocations,
// which only record a path that resolved, would not.
func ItemReferencedPaths(item model.ConfigItem) []string {
	if item.Scope != model.ScopeRepo {
		return nil
	}
	var out []string
	add := func(rel string) {
		cleaned, ok := cleanRepoRelative(rel)
		if !ok {
			return
		}
		out = append(out, cleaned)
	}
	for _, rel := range Scripts(item) {
		add(rel)
	}
	if item.Kind == model.ConfigKindEnvSetup {
		for _, name := range checksumNames(decode(item)) {
			add(name)
		}
	}
	return out
}

// cleanRepoRelative cleans a referenced path the way ReferencedPaths and
// ItemReferencedPaths have always required: relative, inside the
// repository, and non-empty once cleaned.
func cleanRepoRelative(rel string) (string, bool) {
	cleaned := path.Clean(rel)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return "", false
	}
	return cleaned, true
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
