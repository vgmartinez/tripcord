package cfg014

import (
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/devin"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/opencode"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
)

// DefaultClassifiers are the adapters that already classify repository
// paths. Classification does not read a repository.
func DefaultClassifiers() []Classifier {
	return []Classifier{
		claude.New(claude.Options{}),
		codex.New(codex.Options{}),
		copilot.New(copilot.Options{}),
		cursor.New(cursor.Options{}),
		devcontainer.New(devcontainer.Options{}),
		devin.New(devin.Options{}),
		gemini.New(gemini.Options{}),
		generic.New(generic.Options{}),
		opencode.New(opencode.Options{}),
		windsurf.New(windsurf.Options{}),
	}
}
