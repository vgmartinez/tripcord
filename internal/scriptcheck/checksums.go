package scriptcheck

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
)

// commandFields are the env-setup payload fields that hold a command.
var commandFields = []string{"run", "value", "command"}

// annotateChecksums sets ChecksumFiles on every repository env-setup
// entry: the sums files its commands check with sha256sum -c that are
// committed regular files inside root, in sha256sum's format, with the
// names each lists. A sums file is resolved against root, where Copilot,
// Cursor, and dev containers run setup commands. An entry that runs
// elsewhere (a Copilot working-directory, a devcontainer.json that sets
// workspaceFolder) gets none, since its check reads another file.
func annotateChecksums(root string, items []model.ConfigItem) error {
	reader, err := adapters.NewSafeReader(root)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	elsewhere := map[string]bool{}
	for _, item := range items {
		if item.Kind == model.ConfigKindEnvSetup && item.Harness == model.SurfaceDevcontainer {
			if payload := decode(item); payload != nil && payload["setting"] == "workspaceFolder" {
				elsewhere[item.Path] = true
			}
		}
	}
	for i := range items {
		item := &items[i]
		if item.Kind != model.ConfigKindEnvSetup || item.Scope != model.ScopeRepo {
			continue
		}
		item.ChecksumFiles = nil
		item.ChecksumSymlinks = nil
		payload := decode(*item)
		if payload == nil || elsewhere[item.Path] {
			continue
		}
		if _, ok := payload["working-directory"]; ok {
			continue
		}
		item.ChecksumSymlinks = symlinkTargets(root, payload)
		for _, name := range checksumNames(payload) {
			if _, done := item.ChecksumFiles[name]; done {
				continue
			}
			if listed, ok := readSums(root, reader, name); ok {
				if item.ChecksumFiles == nil {
					item.ChecksumFiles = map[string][]string{}
				}
				item.ChecksumFiles[name] = listed
			}
		}
	}
	return nil
}

func symlinkTargets(root string, payload map[string]any) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		// A target that cannot be inspected must not get checksum credit.
		return checksumTargets(payload)
	}
	var out []string
	for _, name := range checksumTargets(payload) {
		if foldedAlias(entries, name) {
			out = append(out, name)
		}
	}
	return out
}

// foldedAlias reports whether any directory entry matching name
// case-insensitively is a symlink or otherwise not a regular file.
// Every match is checked: a regular spelling that sorts first does not
// hide a later symlink, which is the file a case-insensitive checkout
// can open.
func foldedAlias(entries []os.DirEntry, name string) bool {
	for _, entry := range entries {
		if !strings.EqualFold(entry.Name(), name) {
			continue
		}
		if !regularEntry(entry) {
			return true
		}
	}
	return false
}

func regularSumsFile(root, name string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	found := false
	for _, entry := range entries {
		if !strings.EqualFold(entry.Name(), name) {
			continue
		}
		// On a case-insensitive checkout either spelling could be read.
		// A second spelling is ambiguous even if both are regular files,
		// and a later symlink must not be hidden by an earlier regular one.
		if entry.Name() != name || !regularEntry(entry) {
			return false
		}
		found = true
	}
	return found
}

func regularEntry(entry os.DirEntry) bool {
	if entry.Type()&os.ModeSymlink != 0 {
		return false
	}
	info, err := entry.Info()
	return err == nil && info.Mode().IsRegular()
}

func checksumNames(payload map[string]any) []string {
	var out []string
	for _, field := range commandFields {
		switch v := payload[field].(type) {
		case string:
			out = append(out, shellcmd.ChecksumFiles(v)...)
		case []any:
			argv := make([]string, 0, len(v))
			for _, a := range v {
				s, ok := a.(string)
				if !ok {
					argv = nil
					break
				}
				argv = append(argv, s)
			}
			out = append(out, shellcmd.ChecksumFilesArgv(argv)...)
		}
	}
	return out
}

func checksumTargets(payload map[string]any) []string {
	var out []string
	for _, field := range commandFields {
		switch v := payload[field].(type) {
		case string:
			out = append(out, shellcmd.ChecksumTargets(v)...)
		case []any:
			argv := stringsOnly(v)
			out = append(out, shellcmd.ChecksumTargetsArgv(argv)...)
		}
	}
	return slices.Compact(out)
}

func stringsOnly(v []any) []string {
	argv := make([]string, 0, len(v))
	for _, a := range v {
		s, ok := a.(string)
		if !ok {
			return nil
		}
		argv = append(argv, s)
	}
	return argv
}

// readSums returns the names the sums file name lists, with the symlink
// rules of lookupScript: its final component must itself be a regular
// file (not a symlink), its parent path must resolve inside root, and it
// must parse (see shellcmd.ParseSums).
func readSums(root string, reader *adapters.SafeReader, name string) ([]string, bool) {
	if !regularSumsFile(root, name) {
		return nil, false
	}
	info, err := os.Lstat(filepath.Join(root, name))
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	if class, missing := lookupScript(root, name); missing || class != "" {
		return nil, false
	}
	info, err = reader.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	data, err := reader.ReadFile(name, shellcmd.MaxSumsBytes)
	if err != nil {
		return nil, false
	}
	return shellcmd.ParseSums(data)
}
