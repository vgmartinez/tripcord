package kit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
)

// UserDir is a per-user configuration directory: its absolute path, and
// the logical "~/"-rooted name used in items and diagnostics.
type UserDir struct {
	Abs     string
	Logical string
}

// File names a file below the directory.
func (d UserDir) File(name string) (abs, logical string) {
	return filepath.Join(d.Abs, filepath.FromSlash(name)), d.Logical + "/" + name
}

// ResolveHome returns override, or os.UserHomeDir when override is empty.
// It records a diagnostic and returns false when there is no usable home.
func ResolveHome(c *Collector, override string) (string, bool) {
	home := override
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			c.Warn(model.ScopeUser, "~", "cannot determine the home directory")
			return "", false
		}
	}
	if clean := filepath.Clean(home); len(clean) <= 1 || (len(clean) <= 3 && clean[1] == ':') {
		c.Warn(model.ScopeUser, "", "home directory is too short to scope user configuration under it; user configuration was not scanned")
		return "", false
	}
	c.SetHome(home)
	return home, true
}

// ResolveUserDir returns home/defaultRel, or the directory named by the
// environment variable envName when envValue is set. A relative override
// is refused. An override outside home is scanned and named
// "~/<envName>" so no absolute path reaches an item; an informational
// note says so.
func ResolveUserDir(c *Collector, home, envName, envValue, defaultRel string) (UserDir, bool) {
	dir := filepath.Join(home, filepath.FromSlash(defaultRel))
	if v := strings.TrimSpace(envValue); v != "" {
		if !filepath.IsAbs(v) {
			c.Warn(model.ScopeUser, "", "%s is not an absolute path; user configuration was not scanned", envName)
			return UserDir{}, false
		}
		dir = filepath.Clean(v)
	}
	logical := TildePath(home, dir)
	if logical != "~" && !strings.HasPrefix(logical, "~/") {
		c.Note(model.ScopeUser, "~/"+envName, true, "%s is outside the home directory; configuration is scanned and paths are shown as ~/%s", envName, envName)
		logical = "~/" + envName
	}
	return UserDir{Abs: dir, Logical: logical}, true
}

// ReadLocal reads a user or managed file through adapters.ReadLocal. A
// missing file is skipped silently; any other failure is recorded.
func (c *Collector) ReadLocal(scope model.Scope, abs, logical string) ([]byte, bool) {
	raw, err := adapters.ReadLocal(abs, adapters.MaxConfigFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	case err != nil:
		c.Warn(scope, logical, "cannot read: %v", err)
		return nil, false
	}
	return raw, true
}

// ListLocal returns the sorted names of files in dir whose lower-cased
// name ends with suffix, skipping dot files, at most max of them. A
// missing directory is skipped silently.
func (c *Collector) ListLocal(scope model.Scope, dir, logicalDir, suffix string, max int) []string {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		c.Warn(scope, logicalDir, "cannot list directory")
		return nil
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), suffix) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > max {
		c.Warn(scope, logicalDir, "more than %d files; the rest were not scanned", max)
		names = names[:max]
	}
	return names
}

// TildePath rewrites an absolute path under home as "~/...", using
// forward slashes.
func TildePath(home, p string) string {
	home = strings.TrimSuffix(strings.ReplaceAll(home, `\`, "/"), "/")
	p = strings.ReplaceAll(p, `\`, "/")
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// ManagedPath is the logical form of a managed absolute path in the
// canonical shape model.ConfigItem requires: forward slashes, and a
// Windows drive path lower-cased with an upper-case drive letter.
func ManagedPath(abs string) string {
	p := strings.ReplaceAll(abs, `\`, "/")
	if len(p) >= 3 && p[1] == ':' && p[2] == '/' {
		p = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return p
}
