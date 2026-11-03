package indexfiles

import "github.com/vgmartinez/tripcord/internal/adapters"

// Scan budgets. These are the repository walk limits in
// internal/adapters/kit and internal/adapters/claude, not the larger
// preopen tree budgets. A staged scan stops where a checkout scan stops.
const (
	maxDepth   = 32
	maxEntries = 200_000
	maxFiles   = 2_000
	maxBytes   = 64 << 20
	maxFile    = adapters.MaxConfigFileBytes
)

// maxSymlinkBytes bounds symlink text read while resolving the index.
// Targets longer than this are kept as symlinks and not followed here.
const maxSymlinkBytes = 4096
