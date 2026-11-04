package main

import (
	"testing"

	"github.com/vgmartinez/tripcord/internal/txtar"
)

const coreRulesDir = "../../rules"

// rulesTree returns a copy of the core pack in t.TempDir, named rules,
// with every raw fixture archive <name>.txtar unpacked into its
// directory <name>.
func rulesTree(t *testing.T) string {
	t.Helper()
	return txtar.ExpandTree(t, coreRulesDir)
}
