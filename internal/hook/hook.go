// Package hook is the harness-independent half of `tripcord hook`: the
// event names, the input limits, the normalized tripcord.event/v1 a
// harness adapter builds from its hook JSON, and the verdict an adapter
// renders back in its harness's format. hookpolicy reaches the verdict.
//
// Each hook harness adapter (internal/adapters/claude, cursor, copilot)
// provides ParseHookInput and RenderDecision on top of this package. It
// must not import the rule engine or the policy loader: the rule
// engine's tests import the adapters.
package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
)

// Events `tripcord hook --event` accepts. Each adapter accepts the
// subset its harness has.
const (
	// EventPreTool is a tool call about to run: Claude Code PreToolUse,
	// Cursor preToolUse, and Copilot preToolUse.
	EventPreTool = "pre-tool"
	// EventBeforeShell is Cursor beforeShellExecution.
	EventBeforeShell = "before-shell"
	// EventBeforeRead is Cursor beforeReadFile.
	EventBeforeRead = "before-read"
)

// MaxStdinBytes caps the hook JSON read from stdin. It equals
// rules.HookMaxInputBytes, the cap on the normalized event, so any input
// under it can be decided; the adapter keeps only the fields rules see,
// so the event is rarely larger than the input. Over it, the run fails
// and follows --on-failure.
const MaxStdinBytes = 4 << 20

// Timeout bounds one hook run from start to verdict. It is shorter than
// the harnesses' own hook timeouts (Claude Code's default command-hook
// timeout is 600 s; init --embed sets Copilot's pre-tool timeoutSec to
// 60), so a slow run ends in Tripcord's verdict rather than the
// harness's: a timed-out Copilot hook lets the tool call through.
const Timeout = 10 * time.Second

// OnFailure is what `tripcord hook` does when it cannot reach a verdict:
// invalid flags or input, an invalid policy, or an internal error.
type OnFailure string

const (
	// OnFailureError exits 3 (configuration or input) or 4 (internal),
	// and leaves the decision to the harness.
	OnFailureError OnFailure = "error"
	// OnFailureBlock fails closed: the tool call is denied in the
	// harness's format and the run exits 2, with the failure as reason.
	OnFailureBlock OnFailure = "block"
)

// ParseOnFailure parses the --on-failure value.
func ParseOnFailure(s string) (OnFailure, error) {
	switch f := OnFailure(s); f {
	case OnFailureError, OnFailureBlock:
		return f, nil
	default:
		return "", fmt.Errorf("--on-failure %q: want block or error", s)
	}
}

// InputError is hook JSON that cannot be used: malformed, over the size
// limit, or for another event. It maps to exit 3.
type InputError struct{ Err error }

func (e *InputError) Error() string { return "hook input: " + e.Err.Error() }

func (e *InputError) Unwrap() error { return e.Err }

// Inputf returns an *InputError.
func Inputf(format string, args ...any) error {
	return &InputError{Err: fmt.Errorf(format, args...)}
}

// DecodeObject decodes data, which must be one JSON object, into v.
func DecodeObject(data []byte, v any) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return Inputf("stdin is empty; want the harness's hook JSON")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return Inputf("want a JSON object")
	}
	if err := json.Unmarshal(data, v); err != nil {
		return Inputf("malformed JSON: %v", err)
	}
	return nil
}

// Call is the part of a tool call rules see, before it becomes an event.
type Call struct {
	Harness   model.Harness
	Origin    string
	SessionID string
	Version   string
	Tool      string
	// Input is the tool's input object. Only command, path, and URL
	// fields are kept.
	Input map[string]any
	// Command, when set, is used as given (Cursor beforeShellExecution
	// carries it at top level).
	Command string
	// Paths, including Cursor beforeReadFile's file_path, are cleaned
	// and made absolute against Dir before the policy runs.
	Paths []string
	// Dir is the directory a relative tool path is resolved against:
	// the hook JSON's cwd, or a project root when the harness sends
	// one and no cwd. Empty uses the process working directory, and
	// only when a path is relative.
	Dir  string
	Kind model.EventKind
}

var (
	readTools  = []string{"read", "grep", "glob", "ls", "view", "notebookread", "search", "codebase_search", "file_search", "list_dir", "read_file"}
	writeTools = []string{"write", "edit", "multiedit", "notebookedit", "create", "str_replace", "delete", "apply_patch", "edit_file", "write_file", "delete_file"}
	netTools   = []string{"webfetch", "fetch", "web_fetch"}
	pathKeys   = []string{"file_path", "path", "notebook_path", "target_file", "filePath", "target_directory", "directory"}
	commandKey = "command"
	urlKey     = "url"
)

// Event normalizes c into a tripcord.event/v1. raw is the hook JSON the
// event was parsed from: its digest is the event id, so the same input
// always yields the same id.
func (c Call) Event(raw []byte, now time.Time) model.Event {
	sum := sha256.Sum256(raw)
	ev := model.Event{
		Schema:  model.SchemaEvent,
		ID:      "hook-" + hex.EncodeToString(sum[:16]),
		TS:      now.UTC(),
		Source:  model.Source{Harness: c.Harness, Version: c.Version, Origin: c.Origin},
		Session: model.EventSession{ID: c.SessionID},
		Tool:    c.Tool,
		Command: c.Command,
		Kind:    c.Kind,
	}
	if ev.Session.ID == "" {
		ev.Session.ID = "unknown"
	}
	if ev.Command == "" {
		if s, ok := c.Input[commandKey].(string); ok {
			ev.Command = s
		}
	}
	rawPaths := slices.Clone(c.Paths)
	for _, k := range pathKeys {
		if s, ok := c.Input[k].(string); ok && s != "" {
			rawPaths = append(rawPaths, s)
		}
	}
	ev.Paths = normalizeToolPaths(rawPaths, c.Dir, runtime.GOOS == "windows")
	if s, ok := c.Input[urlKey].(string); ok && s != "" {
		n := model.NetEvent{URL: s}
		if u, err := url.Parse(s); err == nil {
			n.Host = u.Hostname()
		}
		ev.Net = append(ev.Net, n)
	}
	if ev.Kind == "" {
		ev.Kind = kindOf(c.Tool, ev)
	}
	return ev
}

// normalizeToolPaths cleans each path and makes a relative path
// absolute against dir (the process working directory when dir is
// empty). The result uses forward slashes. On Windows, ASCII letters
// are lowercased, because the filesystem does not distinguish them;
// other platforms keep case. Duplicate paths are dropped.
func normalizeToolPaths(paths []string, dir string, windows bool) []string {
	if len(paths) == 0 {
		return nil
	}
	base := ""
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" && !pathKeepsURL(p) && !filepath.IsAbs(p) {
			base = toolBase(dir)
			break
		}
	}
	var out []string
	for _, p := range paths {
		n := cleanToolPath(p, base, windows)
		if n == "" || slices.Contains(out, n) {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func toolBase(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return ""
		}
		return wd
	}
	dir = filepath.Clean(dir)
	if filepath.IsAbs(dir) {
		return dir
	}
	wd, err := os.Getwd()
	if err != nil {
		return dir
	}
	return filepath.Clean(filepath.Join(wd, dir))
}

// pathKeepsURL reports a value filepath.Clean would damage. Clean
// collapses "://" to ":/", so "https://user:secret@host" becomes a
// string the redactor does not recognize, and a policy error then
// prints the secret. Those values are not filesystem paths.
func pathKeepsURL(p string) bool {
	return strings.Contains(p, "://")
}

// cleanToolPath is one tool path after normalization. base is already
// absolute when a working directory could be resolved; a relative path
// with an empty base is cleaned and left relative. A value that carries
// a URL is returned unchanged (see pathKeepsURL).
func cleanToolPath(p, base string, windows bool) string {
	p = strings.TrimSpace(p)
	if p == "" || pathKeepsURL(p) {
		return p
	}
	p = filepath.Clean(p)
	if base != "" && !filepath.IsAbs(p) {
		p = filepath.Clean(filepath.Join(base, p))
	}
	p = filepath.ToSlash(p)
	if windows {
		p = asciiLower(p)
	}
	return p
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func kindOf(tool string, ev model.Event) model.EventKind {
	name := strings.ToLower(tool)
	switch {
	case ev.Command != "":
		return model.EventKindToolCall
	case slices.Contains(readTools, name):
		return model.EventKindRead
	case slices.Contains(writeTools, name):
		return model.EventKindWrite
	case slices.Contains(netTools, name) || len(ev.Net) > 0:
		return model.EventKindNet
	default:
		return model.EventKindToolCall
	}
}

// Verdict is the decision on one hook event. Reason is shown to the
// user or the agent; it is empty for a plain allow.
type Verdict struct {
	Decision model.Decision
	Reason   string
}

// Exit is the exit status for v: 2 for deny, 0 otherwise.
func (v Verdict) Exit() exitcode.Code {
	if v.Decision == model.DecisionDeny {
		return exitcode.Block
	}
	return exitcode.OK
}

// Output is a rendered verdict: what `tripcord hook` writes and its
// exit status.
type Output struct {
	Stdout []byte
	Stderr string
	Exit   exitcode.Code
}

// Failed is the fail-closed verdict for err.
func Failed(err error) Verdict {
	return Verdict{Decision: model.DecisionDeny, Reason: "tripcord hook failed closed: " + err.Error()}
}
