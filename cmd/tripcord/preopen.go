package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/preopen"
)

// preopenStopSignals are the signals that stop a fetch and remove the
// temporary clone. SIGHUP is included so a closed terminal cleans up too.
var preopenStopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

// runPreopen clones a repository into a temporary directory without
// running anything it contains, scans the clone like scan does, and
// removes the clone, also when interrupted.
func runPreopen(args []string, stdout, stderr io.Writer) int {
	opts, err := parseCommandFlags(preopenCommand, args, stdout)
	if errors.Is(err, errHelp) {
		return int(exitcode.OK)
	}
	if errors.Is(err, errHelpWrite) {
		return int(exitcode.Internal)
	}
	target := scanTarget{prog: "tripcord preopen"}
	switch {
	case err != nil:
		return target.configError(stderr, err)
	case opts.secrets || opts.all:
		return target.configError(stderr, errors.New("secret scanning lands in v1; v0 supports --config only"))
	case opts.since != "":
		return target.configError(stderr, errors.New("--since is not available: preopen fetches only the latest commit"))
	case opts.scope != "repo":
		return target.configError(stderr, errors.New("--scope must be repo: preopen scans the fetched repository only"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), preopenStopSignals...)
	defer stop()
	ws, err := preopen.Fetch(ctx, opts.path)
	var targetErr *preopen.TargetError
	switch {
	case errors.As(err, &targetErr):
		return target.configError(stderr, err)
	case errors.Is(err, context.Canceled):
		return target.internalError(stderr, errors.New("interrupted; the temporary clone was removed"))
	case err != nil:
		return target.internalError(stderr, err)
	}
	defer func() {
		if err := ws.Close(); err != nil {
			writeString(stderr, target.prog+": remove temporary clone: "+redactHomeFromError(err)+"\n")
		}
	}()
	// The clone's own .tripcord policy must not grant it exceptions or
	// relax the mode, so repository policy is read from a directory that
	// does not exist. --policy and --org-policy still apply.
	target.root = ws.Tree()
	target.policyRoot = filepath.Join(ws.Dir(), "no-repository-policy")
	code := scanTree(target, opts, stdout, stderr)
	if ctx.Err() != nil {
		return target.internalError(stderr, errors.New("interrupted; the temporary clone was removed"))
	}
	return code
}
