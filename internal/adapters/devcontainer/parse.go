package devcontainer

import (
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// file is one devcontainer.json being normalized.
type file struct {
	*kit.Source
}

// lifecycleCommands are the commands the Dev Containers tooling runs, and
// where. initializeCommand runs on the host machine, before the container
// exists; the others run inside the container.
//
// Reviewed against https://containers.dev/implementors/json_reference/ on
// 2026-10-31.
var lifecycleCommands = map[string]string{
	"initializeCommand":    "host",
	"onCreateCommand":      "container",
	"updateContentCommand": "container",
	"postCreateCommand":    "container",
	"postStartCommand":     "container",
	"postAttachCommand":    "container",
}

// settings is the curated set of other keys that decide which image or
// build runs, what it mounts, and with which privileges or user. Each
// present key becomes one item; other keys (name, forwardPorts,
// hostRequirements, ...) are not emitted.
var settings = map[string]bool{
	"image":                       true,
	"build":                       true,
	"dockerFile":                  true,
	"context":                     true,
	"dockerComposeFile":           true,
	"service":                     true,
	"runServices":                 true,
	"runArgs":                     true,
	"mounts":                      true,
	"workspaceMount":              true,
	"workspaceFolder":             true,
	"privileged":                  true,
	"capAdd":                      true,
	"securityOpt":                 true,
	"init":                        true,
	"customizations":              true,
	"overrideFeatureInstallOrder": true,
	"remoteUser":                  true,
	"containerUser":               true,
	"updateRemoteUserUID":         true,
	"userEnvProbe":                true,
	"overrideCommand":             true,
	"shutdownAction":              true,
	"waitFor":                     true,
}

// config normalizes a devcontainer.json. The Dev Containers tooling reads
// it as JSONC (comments and trailing commas).
func (f *file) config(raw []byte) {
	tree, warnings, err := kit.DecodeJSON(raw, kit.JSONC, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		f.Warn("devcontainer.json must be a JSON object")
		return
	}
	for _, name := range kit.SortedKeys(obj) {
		value := obj[name]
		if runsOn, ok := lifecycleCommands[name]; ok {
			f.lifecycle(name, runsOn, value)
			continue
		}
		switch {
		case name == "features":
			f.features(value)
		case name == "containerEnv" || name == "remoteEnv":
			f.env(name, value)
		case name == "runArgs":
			f.Add(model.ConfigKindEnvSetup, []string{"setting", name}, map[string]any{"setting": name, "value": f.runArgs(value)})
		case settings[name]:
			f.Add(model.ConfigKindEnvSetup, []string{"setting", name}, map[string]any{"setting": name, "value": f.SafeValue(name, value)})
		}
	}
}

// lifecycle emits one item per command of a lifecycle hook. A string runs
// through a shell; an array is an argv run without one; an object runs
// each of its named string or array commands in parallel.
func (f *file) lifecycle(setting, runsOn string, value any) {
	if obj, ok := value.(map[string]any); ok {
		for _, name := range kit.SortedKeys(obj) {
			f.command(setting, runsOn, "object", name, obj[name])
		}
		return
	}
	f.command(setting, runsOn, "", "", value)
}

func (f *file) command(setting, runsOn, parent, name string, value any) {
	payload := map[string]any{"setting": setting, "runs_on": runsOn}
	if name != "" {
		payload["name"] = name
	}
	form := parent
	switch v := value.(type) {
	case string:
		payload["command"] = f.SafeString(v)
		if form == "" {
			form = "string"
		}
	case []any:
		payload["command"] = f.SafeValue("", f.SafeToolArgv(v))
		if form == "" {
			form = "array"
		}
	default:
		where := setting
		if name != "" {
			where += "." + name
		}
		f.Warn("%s must be a string or an array of strings; it is reported as written", where)
		payload["value"] = f.SafeValue("", value)
		form = "other"
	}
	payload["form"] = form
	f.Add(model.ConfigKindEnvSetup, []string{"lifecycle", setting, name}, payload)
}

// features emits one item per Feature. A Feature is an install script
// fetched from its reference (an OCI image, a tarball URL, or a local
// directory) and run as root while the image is built.
func (f *file) features(value any) {
	table, ok := value.(map[string]any)
	if !ok {
		f.Warn("features must be an object keyed by Feature reference")
		f.Add(model.ConfigKindEnvSetup, []string{"setting", "features"}, map[string]any{"setting": "features", "value": f.SafeValue("features", value)})
		return
	}
	for _, id := range kit.SortedKeys(table) {
		safe := f.SafeString(id)
		f.Add(model.ConfigKindEnvSetup, []string{"feature", safe}, map[string]any{
			"setting": "features",
			"feature": safe,
			"options": f.SafeValue("", table[id]),
		})
	}
}

// runArgs sanitizes the docker run arguments as an argv. The shared
// rules redact a credential-named NAME=VALUE element wherever it
// appears, which covers -e NAME=VALUE and --env=NAME=VALUE. docker also
// accepts the short flag glued to its value, -eNAME=VALUE, where those
// rules read the name as "eNAME". After the shared pass, an element
// that still starts with -e and contains = is sanitized again without
// that flag, so a value the first pass only partly redacted is finished.
// An element replaced entirely, such as the argument after --password,
// is [REDACTED] and no longer starts with -e, so it is left as it is.
func (f *file) runArgs(value any) any {
	args, ok := value.([]any)
	if !ok {
		return f.SafeValue("runArgs", value)
	}
	out, _ := f.SafeValue("", f.SafeToolArgv(args)).([]any)
	for i, item := range out {
		text, isString := item.(string)
		if !isString {
			continue
		}
		assignment, glued := strings.CutPrefix(text, "-e")
		if glued && strings.Contains(assignment, "=") {
			out[i] = "-e" + f.SafeString(assignment)
		}
	}
	return out
}

// env emits a containerEnv or remoteEnv map with its values redacted and
// its names in env_keys.
func (f *file) env(setting string, value any) {
	m, ok := value.(map[string]any)
	if !ok {
		f.Warn("%s must be an object", setting)
		f.Add(model.ConfigKindEnvSetup, []string{"setting", setting}, map[string]any{"setting": setting, "value": f.SafeValue(setting, value)})
		return
	}
	f.Add(model.ConfigKindEnvSetup, []string{"setting", setting}, map[string]any{
		"setting":  setting,
		"value":    f.RedactValues(m),
		"env_keys": kit.SortedKeys(m),
	})
}
