package scriptcheck

import (
	"regexp"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
)

// labelFields are env-setup payload fields that only name or locate an
// entry; they never reach a shell.
var labelFields = map[string]bool{
	"key": true, "name": true, "setting": true, "form": true,
	"runs_on": true, "job": true, "id": true,
}

// hashFilesCall is a GitHub Actions hashFiles() expression, which only
// hashes the files it names.
var hashFilesCall = regexp.MustCompile(`hashFiles\(\s*'[^']*'(?:\s*,\s*'[^']*')*\s*\)`)

// annotateFetchNotRun sets FetchNotRun on every repository env-setup
// entry with a command whose fetches only write data that nothing in
// the same configuration file runs (see shellcmd.FetchNotRun). The rest
// of the file is every other string of every entry from the same path
// (labels left out, hashFiles() expressions removed), plus the entry's
// own non-command fields. A command field elsewhere in the file that
// holds a glob character counts as naming every fetched file.
func annotateFetchNotRun(items []model.ConfigItem) {
	payloads := make([]map[string]any, len(items))
	for i, item := range items {
		payloads[i] = decode(item)
	}
	for i := range items {
		item := &items[i]
		item.FetchNotRun = false
		if item.Kind != model.ConfigKindEnvSetup || item.Scope != model.ScopeRepo || payloads[i] == nil {
			continue
		}
		var others []string
		for j, other := range items {
			if other.Path != item.Path || payloads[j] == nil {
				continue
			}
			for field, v := range payloads[j] {
				if labelFields[field] || (j == i && slices.Contains(commandFields, field)) {
					continue
				}
				for _, s := range stringLeaves(v) {
					s = hashFilesCall.ReplaceAllString(s, "")
					if slices.Contains(commandFields, field) && strings.ContainsAny(s, "*?[") {
						s = "*"
					}
					others = append(others, s)
				}
			}
		}
		if slices.Contains(others, "*") {
			continue
		}
		item.FetchNotRun = commandFetchNotRun(payloads[i], others)
	}
}

// commandFetchNotRun reports an entry with exactly one command field,
// a string or a string array, that shellcmd.FetchNotRun accepts.
func commandFetchNotRun(payload map[string]any, others []string) bool {
	found := false
	result := false
	for _, field := range commandFields {
		v, ok := payload[field]
		if !ok {
			continue
		}
		if found {
			return false
		}
		found = true
		switch v := v.(type) {
		case string:
			result = shellcmd.FetchNotRun(v, others)
		case []any:
			argv := stringsOnly(v)
			result = len(argv) > 0 && shellcmd.FetchNotRunArgv(argv, others)
		}
	}
	return result
}

// stringLeaves returns every string in v, including map keys.
func stringLeaves(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			out = append(out, stringLeaves(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for k, e := range v {
			out = append(out, k)
			out = append(out, stringLeaves(e)...)
		}
		return out
	}
	return nil
}
