package scriptcheck

import (
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
		payload := decode(*item)
		if payload == nil || elsewhere[item.Path] {
			continue
		}
		if _, ok := payload["working-directory"]; ok {
			continue
		}
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

// readSums returns the names the sums file name lists, with the symlink
// rules of lookupScript: it must exist, resolve inside root, be a regular
// file, and parse (see shellcmd.ParseSums).
func readSums(root string, reader *adapters.SafeReader, name string) ([]string, bool) {
	if class, missing := lookupScript(root, name); missing || class != "" {
		return nil, false
	}
	info, err := reader.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	data, err := reader.ReadFile(name, shellcmd.MaxSumsBytes)
	if err != nil {
		return nil, false
	}
	return shellcmd.ParseSums(data)
}
