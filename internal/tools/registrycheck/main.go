// Command registrycheck fails when a rule REGISTRY edit would let a
// rule id be reused. CI runs it with the pull request base version of
// rules/REGISTRY and the head version:
//
//	go run ./internal/tools/registrycheck OLD NEW
//
// An empty or missing OLD file is a registry with no entries.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/vgmartinez/tripcord/internal/rules"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) != 2 {
		return fail(stderr, 2, errors.New("usage: registrycheck OLD NEW"))
	}
	old, err := load(args[0], true)
	if err != nil {
		return fail(stderr, 1, err)
	}
	next, err := load(args[1], false)
	if err != nil {
		return fail(stderr, 1, err)
	}
	if err := rules.CheckRegistryEvolution(old, next); err != nil {
		return fail(stderr, 1, err)
	}
	return 0
}

func fail(stderr io.Writer, code int, err error) int {
	_, _ = fmt.Fprintln(stderr, err)
	return code
}

func load(path string, missingOK bool) (*rules.Registry, error) {
	data, err := os.ReadFile(path)
	if missingOK && errors.Is(err, fs.ErrNotExist) {
		data, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	r, err := rules.ParseRegistry(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}
