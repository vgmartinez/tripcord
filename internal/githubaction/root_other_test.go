//go:build !unix

package githubaction_test

func runningAsRoot() bool { return false }
