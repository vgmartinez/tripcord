package model

import "fmt"

// Harness is a coding-agent product id, or a non-harness surface that
// rules attach findings to. Product ids are the eight agents. vscode,
// devcontainer, and generic are surfaces; IsProduct reports the split.
type Harness string

const (
	HarnessClaude   Harness = "claude"
	HarnessCodex    Harness = "codex"
	HarnessCursor   Harness = "cursor"
	HarnessCopilot  Harness = "copilot" // VS Code and Copilot share this id.
	HarnessGemini   Harness = "gemini"
	HarnessOpenCode Harness = "opencode"
	HarnessWindsurf Harness = "windsurf"
	HarnessDevin    Harness = "devin"
)

// Surfaces used by rules that are not harness products.
const (
	SurfaceVSCode       Harness = "vscode"
	SurfaceDevcontainer Harness = "devcontainer"
	SurfaceGeneric      Harness = "generic"
)

var productHarnesses = []Harness{
	HarnessClaude,
	HarnessCodex,
	HarnessCursor,
	HarnessCopilot,
	HarnessGemini,
	HarnessOpenCode,
	HarnessWindsurf,
	HarnessDevin,
}

var surfaces = []Harness{
	SurfaceVSCode,
	SurfaceDevcontainer,
	SurfaceGeneric,
}

// String returns the wire value.
func (h Harness) String() string { return string(h) }

// IsProduct reports whether h is one of the eight coding-agent harnesses.
func (h Harness) IsProduct() bool {
	return harnessListed(productHarnesses, h)
}

// Valid reports whether h is a known harness or surface.
func (h Harness) Valid() bool {
	return h.IsProduct() || harnessListed(surfaces, h)
}

// ParseHarness accepts a product harness or a surface.
func ParseHarness(s string) (Harness, error) {
	h := Harness(s)
	if !h.Valid() {
		return "", fmt.Errorf("harness %q: unknown", s)
	}
	return h, nil
}

func harnessListed(list []Harness, h Harness) bool {
	for _, item := range list {
		if item == h {
			return true
		}
	}
	return false
}
