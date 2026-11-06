package corpus

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/jsonc"
)

// utf8BOM is the leading byte order mark JSONC callers strip before
// jsonc.Strip, matching internal/adapters/kit.DecodeJSON.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// jsonStringLiteral matches one JSON string, escapes included. It is the
// fallback for a file that parses as neither JSONC nor YAML.
var jsonStringLiteral = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)

// configStrings returns string values of data. JSON is read as JSONC:
// comments and trailing commas are stripped, then json.Unmarshal decodes
// escapes (\n, \", \uXXXX, and the rest). YAML documents are read too.
// When neither parse succeeds, every JSON string literal is decoded the
// same way, so a truncated file still yields the commands inside its
// strings. The raw text is checked separately, so a string that is the
// whole input is left out.
func configStrings(data []byte) []string {
	raw := strings.TrimSpace(string(data))
	var out []string
	seen := map[string]struct{}{}
	add := func(s string) {
		if s == "" || s == raw {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	parsed := false
	if cleaned, err := jsonc.Strip(bytes.TrimPrefix(data, utf8BOM)); err == nil {
		var j any
		if json.Unmarshal(cleaned, &j) == nil {
			collectStrings(j, add)
			parsed = true
		}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var v any
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		collectStrings(v, add)
		parsed = true
	}
	if !parsed {
		for _, lit := range jsonStringLiteral.FindAll(data, -1) {
			var s string
			if json.Unmarshal(lit, &s) != nil {
				continue
			}
			add(s)
		}
	}
	return out
}

func collectStrings(v any, add func(string)) {
	switch t := v.(type) {
	case string:
		add(t)
	case []any:
		for _, e := range t {
			collectStrings(e, add)
		}
	case map[string]any:
		for _, e := range t {
			collectStrings(e, add)
		}
	case map[any]any:
		for _, e := range t {
			collectStrings(e, add)
		}
	}
}
