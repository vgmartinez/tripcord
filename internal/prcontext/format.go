package prcontext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// FormatText renders r for a human reader. Signals are in detection order.
func FormatText(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "agent: %t\n", r.Agent)
	fmt.Fprintf(&b, "agents: %s\n", strings.Join(r.Agents, ", "))
	b.WriteString("signals:\n")
	for _, s := range r.Signals {
		fmt.Fprintf(&b, "- type: %s\n  agent: %s\n  value: %s\n  source: %s\n", s.Type, s.Agent, s.Value, s.Source)
	}
	if len(r.Warnings) > 0 {
		b.WriteString("warnings:\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	return b.String()
}

// FormatJSON renders r as one indented JSON document with a trailing newline.
func FormatJSON(r Result) ([]byte, error) {
	if r.Agents == nil {
		r.Agents = []string{}
	}
	if r.Signals == nil {
		r.Signals = []Signal{}
	}
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// FormatOutput is the GITHUB_OUTPUT fragment: is_agent and agents.
// agents is comma-separated with no spaces, in the same order as Result.Agents.
func FormatOutput(r Result) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "is_agent=%t\n", r.Agent)
	fmt.Fprintf(&b, "agents=%s\n", strings.Join(r.Agents, ","))
	return b.String()
}
