// Package autorun lists repository hooks that run committed code on an
// event the harness fires by itself when a session starts, and the
// module a Claude Code mod loads. The list is informational: it is not
// a rule, it produces no finding, and it never changes the exit code or
// --fail-on. See docs/autorun-hooks.md.
//
// TC-CFG-006 reports a hook whose script is not committed and tells the
// user to commit it, so a hook that runs a committed script is quiet.
// TC-CFG-002 reports a folder-open task that runs the same script. This
// inventory shows the committed case to a reviewer of an untrusted
// repository without making it a finding.
package autorun

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/scriptcheck"
)

// EventModules is the Event of an entry for a Claude Code mod: the
// modules member of a plugin's hooks.json, which Claude Code loads with
// the plugin.
const EventModules = "modules"

// maxConfigBytes bounds the read that locates an entry's line. It
// matches the largest configuration file an adapter reads
// (adapters.MaxConfigFileBytes); a larger file gets no line.
const maxConfigBytes = 1 << 20

// Entry is one hook, or one mod module, and the committed path it runs.
type Entry struct {
	Harness model.Harness
	// Path is the repository-relative configuration file.
	Path string
	// Line is the 1-based line of the command in Path, or of the event
	// when the command cannot be found. Zero means neither was found.
	Line int
	// Event is the hook event (SessionStart, Setup, sessionStart), or
	// EventModules for a mod.
	Event string
	// Command is the hook's command as reports show it, after the
	// adapter's sanitization. For a mod it is the module path as the
	// file wrote it, sanitized the same way.
	Command string
	// Target is the repository-relative path of the committed file the
	// entry runs or loads.
	Target string
}

// autoRunEvents are the hook events, per harness, that fire when a
// session starts, with no tool call or prompt from the user.
var autoRunEvents = map[model.Harness][]string{
	model.HarnessClaude: {"SessionStart", "Setup"},
	model.HarnessCursor: {"sessionStart"},
}

// Inventory returns the entries for items, sorted by path, line, event,
// and target. root is the scanned repository. Only repository-scope
// items are read: hooks in a project's .claude/settings.json,
// .claude/settings.local.json, or .cursor/hooks.json whose event is an
// auto-run event and whose scripts exist inside root (see
// scriptcheck.InTree), and mod modules from a Claude plugin's
// hooks.json. A hook in a skill's or an agent's frontmatter, or in a
// plugin's hooks.json, is not listed: it does not run when a session
// starts in the project.
func Inventory(root string, items []model.ConfigItem) ([]Entry, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	read := func(rel string) []byte {
		if raw, ok := files[rel]; ok {
			return raw
		}
		raw := readConfig(resolvedRoot, rel)
		files[rel] = raw
		return raw
	}
	var out []Entry
	for _, item := range items {
		if item.Scope != model.ScopeRepo {
			continue
		}
		switch item.Kind {
		case model.ConfigKindHook:
			out = append(out, hookEntries(resolvedRoot, item, read)...)
		case model.ConfigKindPlugin:
			if e, ok := moduleEntry(item, read); ok {
				out = append(out, e)
			}
		}
	}
	slices.SortFunc(out, compare)
	return slices.CompactFunc(out, func(a, b Entry) bool { return a == b }), nil
}

func compare(a, b Entry) int {
	if c := strings.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	if a.Line != b.Line {
		return a.Line - b.Line
	}
	if c := strings.Compare(a.Event, b.Event); c != 0 {
		return c
	}
	if c := strings.Compare(a.Target, b.Target); c != 0 {
		return c
	}
	if c := strings.Compare(string(a.Harness), string(b.Harness)); c != 0 {
		return c
	}
	return strings.Compare(a.Command, b.Command)
}

func hookEntries(resolvedRoot string, item model.ConfigItem, read func(string) []byte) []Entry {
	if !hookFile(item.Harness, item.Path) {
		return nil
	}
	payload := decode(item.Payload)
	event, _ := payload["event"].(string)
	if !slices.Contains(autoRunEvents[item.Harness], event) {
		return nil
	}
	targets := scriptcheck.InTree(resolvedRoot, item)
	if len(targets) == 0 {
		return nil
	}
	command := commandOf(payload)
	// The line is found from the command as the file wrote it (the
	// Detect view), or from the payload when the adapter kept no raw view.
	raw := commandOf(payload)
	if detect := decode(item.Detect); detect != nil {
		raw = commandOf(detect)
	}
	line := locate(read(item.Path), event, raw)
	out := make([]Entry, 0, len(targets))
	for _, target := range targets {
		out = append(out, Entry{
			Harness: item.Harness,
			Path:    item.Path,
			Line:    line,
			Event:   event,
			Command: command,
			Target:  target,
		})
	}
	return out
}

// hookFile reports whether rel is a project hook configuration file the
// harness reads when a session starts in that project.
func hookFile(h model.Harness, rel string) bool {
	dir, base := path.Split(rel)
	parent := path.Base(path.Clean("/" + dir))
	switch h {
	case model.HarnessClaude:
		return parent == ".claude" && (base == "settings.json" || base == "settings.local.json")
	case model.HarnessCursor:
		return parent == ".cursor" && base == "hooks.json"
	}
	return false
}

// moduleEntry is the entry for a mod's module item, which the Claude
// adapter emits from a plugin hooks.json with a well-formed modules
// member: setting "modules", module as written, and module_path joined
// onto the hooks file's directory and kept inside the plugin.
func moduleEntry(item model.ConfigItem, read func(string) []byte) (Entry, bool) {
	if item.Harness != model.HarnessClaude {
		return Entry{}, false
	}
	payload := decode(item.Payload)
	if setting, _ := payload["setting"].(string); setting != "modules" {
		return Entry{}, false
	}
	module, _ := payload["module"].(string)
	target, _ := payload["module_path"].(string)
	if target == "" {
		return Entry{}, false
	}
	raw := module
	if detect := decode(item.Detect); detect != nil {
		if m, ok := detect["module"].(string); ok {
			raw = m
		}
	}
	return Entry{
		Harness: item.Harness,
		Path:    item.Path,
		Line:    locate(read(item.Path), EventModules, raw),
		Event:   EventModules,
		Command: module,
		Target:  target,
	}, true
}

// commandOf is the first command field a hook payload sets.
func commandOf(payload map[string]any) string {
	for _, field := range model.HookCommandFields {
		if s, ok := payload[field].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func decode(raw []byte) map[string]any {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return payload
}

// readConfig reads a regular file of at most maxConfigBytes inside root.
// Anything else, including a symlink, reads as empty: the line is then
// unknown, and nothing else depends on it.
func readConfig(root, rel string) []byte {
	cleaned := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return nil
	}
	abs := filepath.Join(root, cleaned)
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return nil
	}
	raw, err := os.ReadFile(abs)
	if err != nil || len(raw) > maxConfigBytes {
		return nil
	}
	return raw
}

// locate returns the 1-based line of the first JSON string equal to
// value at or after the first line that names key as a JSON string, or
// that line when value is not found after it. It returns 0 when key is
// not found. A value the file writes with other escapes than
// encoding/json's falls back to the key's line.
func locate(raw []byte, key, value string) int {
	if len(raw) == 0 || key == "" {
		return 0
	}
	lines := bytes.Split(raw, []byte("\n"))
	keyToken := jsonString(key)
	start := -1
	for i, line := range lines {
		if bytes.Contains(line, keyToken) {
			start = i
			break
		}
	}
	if start < 0 {
		return 0
	}
	if value != "" {
		valueToken := jsonString(value)
		for i := start; i < len(lines); i++ {
			if bytes.Contains(lines[i], valueToken) {
				return i + 1
			}
		}
	}
	return start + 1
}

func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
