package corpus

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

// configStrings returns string values of data when it is a JSON value or
// a YAML document, with standard escapes decoded (\n, \", \uXXXX, and
// the rest of each encoding). A document that does not parse contributes
// nothing. The raw text is checked separately, so a string that is the
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
	var j any
	if json.Unmarshal(data, &j) == nil {
		collectStrings(j, add)
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
