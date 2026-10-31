// Command tripcord is the Tripcord command-line interface.
//
// The root command uses the standard library only, so a later hook mode
// can cold-start quickly.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// version is the build version. Override it at link time:
//
//	go build -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

const usage = `tripcord is a local coding-agent security scanner (pre-release).

Usage:
  tripcord help
  tripcord version

Only help and version are implemented in this build.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return writeString(stdout, usage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		return writeString(stdout, usage)
	case "version", "--version":
		return writeString(stdout, version+"\n")
	default:
		msg := fmt.Sprintf("tripcord: unknown command %q\n\n%s", args[0], usage)
		writeString(stderr, msg)
		return int(exitcode.Config)
	}
}

// writeString writes s and reports the exit status: OK on success, or
// Internal for a write failure (stdout or stderr closed out from under
// the process), per the CLI exit code table.
func writeString(w io.Writer, s string) int {
	if _, err := io.WriteString(w, s); err != nil {
		return int(exitcode.Internal)
	}
	return int(exitcode.OK)
}
