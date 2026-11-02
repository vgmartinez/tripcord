// Package mcppkg reads the argv of a stdio MCP server and reports the
// packages a known launcher would install. It does not run the launcher
// and does not expand variables. An unknown option yields no packages
// rather than a guess.
package mcppkg

import (
	"encoding/json"
	"errors"
	"path"
	"strconv"
	"strings"

	"github.com/vgmartinez/tripcord/internal/advisory"
	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
)

// ErrArgs is returned when command or args is not text a program would
// receive: an object, a nested list, or null. Callers wrap it so a scan
// stays incomplete instead of skipping the server.
var ErrArgs = errors.New("mcp args are not strings, numbers, or bools")

// ParsePayload reads payload.command and payload.args. work is the
// number of argument bytes, charged as CEL cost. A command string with
// no args is split as a shell command; a substitution makes that split
// unparsed, which is an empty result and not an error.
func ParsePayload(payload map[string]any) ([]advisory.PackageRef, int, error) {
	if payload == nil {
		return nil, 0, nil
	}
	command, ok := payload["command"]
	if !ok || command == nil {
		return nil, 0, nil
	}
	args, err := argStrings(payload["args"])
	if err != nil {
		return nil, 0, err
	}
	var argv []string
	switch c := command.(type) {
	case string:
		if len(args) == 0 && strings.ContainsAny(c, " \t") {
			words, ok := shellcmd.Words(c)
			if !ok {
				return nil, len(c) + 1, nil
			}
			argv = words
		} else {
			argv = append([]string{c}, args...)
		}
	case []any:
		for i, el := range c {
			s, ok := scalarString(el)
			if !ok {
				return nil, 0, fmtArg(i)
			}
			argv = append(argv, s)
		}
		argv = append(argv, args...)
	default:
		return nil, 0, ErrArgs
	}
	if len(argv) == 0 {
		return nil, 0, nil
	}
	refs, _ := Parse(argv)
	return refs, workOf(argv), nil
}

func argStrings(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, ErrArgs
	}
	out := make([]string, 0, len(list))
	for i, el := range list {
		s, ok := scalarString(el)
		if !ok {
			return nil, fmtArg(i)
		}
		out = append(out, s)
	}
	return out, nil
}

func fmtArg(i int) error {
	return errors.Join(ErrArgs, errors.New("argument "+strconv.Itoa(i)))
}

func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case json.Number:
		return t.String(), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	default:
		return "", false
	}
}

func workOf(argv []string) int {
	n := 0
	for _, a := range argv {
		n += len(a) + 1
	}
	return n
}

// Parse returns the packages argv would install. unparsed is true when
// a known launcher has an option this grammar does not recognize; the
// returned refs are then empty.
func Parse(argv []string) ([]advisory.PackageRef, bool) {
	if len(argv) == 0 {
		return nil, false
	}
	base := baseName(argv[0])
	switch base {
	case "npx", "bunx":
		return parseNPX(argv[1:])
	case "npm":
		return parseNPM(argv[1:])
	case "pnpm":
		return parseDLX(argv[1:], pnpmBools, pnpmValues)
	case "yarn":
		return parseDLX(argv[1:], yarnBools, yarnValues)
	case "uvx":
		return parseUV(argv[1:], true)
	case "uv":
		return parseUVCommand(argv[1:])
	case "pipx":
		return parsePipx(argv[1:])
	case "docker", "podman":
		return parseDocker(argv[1:])
	default:
		if isPython(base) {
			return parsePython(argv)
		}
		return nil, false
	}
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	b := path.Base(p)
	b = strings.ToLower(b)
	b = strings.TrimSuffix(b, ".exe")
	b = strings.TrimSuffix(b, ".cmd")
	return b
}

func isPython(b string) bool {
	if b == "python" || b == "python3" {
		return true
	}
	rest, ok := strings.CutPrefix(b, "python3.")
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type scanned struct {
	positionals []string
	values      map[string][]string
	unparsed    bool
}

func scanLong(argv []string, bools, values map[string]bool) scanned {
	out := scanned{values: map[string][]string{}}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			out.positionals = append(out.positionals, argv[i+1:]...)
			return out
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			out.positionals = append(out.positionals, argv[i:]...)
			return out
		}
		name, val, has := strings.Cut(a, "=")
		switch {
		case bools[name]:
			if has {
				out.unparsed = true
				return out
			}
		case values[name]:
			if !has {
				i++
				if i >= len(argv) {
					out.unparsed = true
					return out
				}
				val = argv[i]
			}
			out.values[name] = append(out.values[name], val)
		default:
			out.unparsed = true
			return out
		}
	}
	return out
}

var (
	npxBools = map[string]bool{
		"-y": true, "--yes": true, "--no": true, "--no-install": true,
		"-q": true, "--quiet": true, "--offline": true, "--prefer-offline": true,
		"--prefer-online": true, "--ignore-existing": true, "-n": true,
	}
	npxValues = map[string]bool{
		"-p": true, "--package": true, "-c": true, "--call": true,
		"--registry": true, "--cache": true, "--userconfig": true,
		"-w": true, "--workspace": true, "--npm": true,
		"--node-arg": true, "--node-options": true,
	}
	pnpmBools = map[string]bool{
		"--silent": true, "--prefer-offline": true, "--ignore-scripts": true,
	}
	pnpmValues = map[string]bool{"--reporter": true, "--config": true}
	yarnBools  = map[string]bool{"--silent": true, "--quiet": true}
	yarnValues = map[string]bool{"--cache-folder": true}
	uvBools    = map[string]bool{
		"--offline": true, "--no-cache": true, "--refresh": true, "--no-project": true,
		"--isolated": true, "--exact": true, "--no-index": true, "--quiet": true, "--verbose": true,
	}
	uvValues = map[string]bool{
		"--from": true, "--with": true, "--with-editable": true, "--with-requirements": true,
		"--python": true, "-p": true, "--index": true, "--index-url": true,
		"--extra-index-url": true, "--default-index": true, "-c": true, "--constraints": true,
		"--directory": true, "--project": true,
	}
	pipxBools  = map[string]bool{"--verbose": true, "--quiet": true, "--no-cache": true}
	pipxValues = map[string]bool{
		"--spec": true, "--python": true, "--pip-args": true, "--index-url": true, "--pypi-url": true,
	}
)

func parseNPX(argv []string) ([]advisory.PackageRef, bool) {
	sc := scanLong(argv, npxBools, npxValues)
	if sc.unparsed {
		return nil, true
	}
	var specs []string
	if len(sc.values["-p"])+len(sc.values["--package"]) > 0 {
		specs = append(specs, sc.values["-p"]...)
		specs = append(specs, sc.values["--package"]...)
	} else if len(sc.positionals) > 0 {
		specs = []string{sc.positionals[0]}
	}
	return npmSpecs(specs), false
}

func parseNPM(argv []string) ([]advisory.PackageRef, bool) {
	if len(argv) == 0 || (argv[0] != "exec" && argv[0] != "x") {
		return nil, false
	}
	return parseNPX(argv[1:])
}

func parseDLX(argv []string, bools, values map[string]bool) ([]advisory.PackageRef, bool) {
	if len(argv) == 0 || argv[0] != "dlx" {
		return nil, false
	}
	sc := scanLong(argv[1:], bools, values)
	if sc.unparsed {
		return nil, true
	}
	if len(sc.positionals) == 0 {
		return nil, false
	}
	return npmSpecs([]string{sc.positionals[0]}), false
}

func parseUVCommand(argv []string) ([]advisory.PackageRef, bool) {
	if len(argv) >= 2 && argv[0] == "tool" && argv[1] == "run" {
		return parseUV(argv[2:], true)
	}
	if len(argv) >= 1 && argv[0] == "run" {
		return parseUV(argv[1:], false)
	}
	return nil, false
}

func parseUV(argv []string, positional bool) ([]advisory.PackageRef, bool) {
	sc := scanLong(argv, uvBools, uvValues)
	if sc.unparsed {
		return nil, true
	}
	// -p on uv is --python, an interpreter path, not a package.
	// --from replaces the positional package.
	var specs []string
	from := sc.values["--from"]
	specs = append(specs, sc.values["--with"]...)
	if len(from) > 0 {
		specs = append(from, specs...)
	} else if positional && len(sc.positionals) > 0 {
		specs = append(specs, sc.positionals[0])
	}
	return pypiSpecs(specs), false
}

func parsePipx(argv []string) ([]advisory.PackageRef, bool) {
	if len(argv) == 0 || argv[0] != "run" {
		return nil, false
	}
	sc := scanLong(argv[1:], pipxBools, pipxValues)
	if sc.unparsed {
		return nil, true
	}
	if specs := sc.values["--spec"]; len(specs) > 0 {
		return pypiSpecs(specs), false
	}
	if len(sc.positionals) == 0 {
		return nil, false
	}
	return pypiSpecs([]string{sc.positionals[0]}), false
}

func parseDocker(argv []string) ([]advisory.PackageRef, bool) {
	if len(argv) == 0 {
		return nil, false
	}
	if argv[0] == "container" {
		argv = argv[1:]
	}
	if len(argv) == 0 || argv[0] != "run" {
		return nil, false
	}
	return parseDockerRun(argv[1:])
}

var (
	dockerBools = map[string]bool{
		"-i": true, "-t": true, "-d": true, "--rm": true, "--init": true,
		"--privileged": true, "--detach": true,
	}
	dockerValues = map[string]bool{
		"-e": true, "--env": true, "-v": true, "--volume": true, "-p": true, "--publish": true,
		"--name": true, "--network": true, "--net": true, "--env-file": true, "--entrypoint": true,
		"-w": true, "--workdir": true, "-u": true, "--user": true, "--platform": true, "--mount": true,
		"-l": true, "--label": true, "-h": true, "--hostname": true, "--memory": true, "--cpus": true,
		"--pull": true, "--restart": true, "--add-host": true, "--log-driver": true, "--log-opt": true,
	}
)

func parseDockerRun(argv []string) ([]advisory.PackageRef, bool) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			i++
			if i >= len(argv) {
				return nil, false
			}
			return []advisory.PackageRef{parseImage(argv[i])}, false
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			return []advisory.PackageRef{parseImage(a)}, false
		}
		if strings.HasPrefix(a, "--") {
			name, _, has := strings.Cut(a, "=")
			switch {
			case dockerBools[name]:
				if has {
					return nil, true
				}
			case dockerValues[name]:
				if !has {
					i++
					if i >= len(argv) {
						return nil, true
					}
				}
			default:
				return nil, true
			}
			continue
		}
		cluster := a[1:]
		for j := 0; j < len(cluster); j++ {
			flag := "-" + cluster[j:j+1]
			switch {
			case dockerBools[flag]:
			case dockerValues[flag]:
				if j+1 < len(cluster) {
					j = len(cluster)
					continue
				}
				i++
				if i >= len(argv) {
					return nil, true
				}
				j = len(cluster)
			default:
				return nil, true
			}
		}
	}
	return nil, false
}

var (
	pyBoolShort  = "bBdEIiOqsSuvx"
	pyValueShort = "WX"
)

func parsePython(argv []string) ([]advisory.PackageRef, bool) {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			i++
			return pythonPositional(argv, i), false
		case a == "-m":
			i++
			if i >= len(argv) {
				return nil, true
			}
			return []advisory.PackageRef{moduleRef(argv[i])}, false
		case a == "-c" || strings.HasPrefix(a, "-c"):
			return nil, false
		case strings.HasPrefix(a, "--"):
			return nil, true
		case strings.HasPrefix(a, "-") && a != "-":
			for j := 1; j < len(a); j++ {
				switch {
				case strings.ContainsRune(pyBoolShort, rune(a[j])):
				case strings.ContainsRune(pyValueShort, rune(a[j])):
					if j+1 < len(a) {
						j = len(a)
						continue
					}
					i++
					if i >= len(argv) {
						return nil, true
					}
					j = len(a)
				default:
					return nil, true
				}
			}
		default:
			return pythonPositional(argv, i), false
		}
	}
	return nil, false
}

func pythonPositional(argv []string, i int) []advisory.PackageRef {
	if i >= len(argv) {
		return nil
	}
	p := argv[i]
	if strings.HasSuffix(strings.ToLower(p), ".py") {
		return []advisory.PackageRef{moduleRef(p)}
	}
	return nil
}

func moduleRef(name string) advisory.PackageRef {
	name = strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "./")
	return advisory.PackageRef{
		Ecosystem: advisory.EcoModule,
		Name:      name,
		Spec:      name,
		Kind:      advisory.KindUnpinned,
	}
}

func npmSpecs(specs []string) []advisory.PackageRef {
	out := make([]advisory.PackageRef, 0, len(specs))
	for _, s := range specs {
		out = append(out, parseNPMSpec(s))
	}
	return out
}

func pypiSpecs(specs []string) []advisory.PackageRef {
	out := make([]advisory.PackageRef, 0, len(specs))
	for _, s := range specs {
		out = append(out, parsePySpec(s))
	}
	return out
}
