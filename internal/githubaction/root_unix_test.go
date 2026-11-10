//go:build unix

package githubaction_test

import "os"

func runningAsRoot() bool {
	return os.Geteuid() == 0
}
