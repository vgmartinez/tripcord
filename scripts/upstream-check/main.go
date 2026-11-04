// Command upstream-check fetches every URL in schemas/upstream.lock and
// exits 1 when one no longer hashes to its locked SHA-256, printing a
// diff against the pinned commit's copy.
//
//	go run ./scripts/upstream-check [-lock schemas/upstream.lock]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vgmartinez/tripcord/internal/benignscan"
)

func main() {
	lockPath := flag.String("lock", filepath.Join("schemas", "upstream.lock"), "upstream.lock path")
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: upstream-check [-lock FILE]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*lockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upstream-check:", err)
		os.Exit(2)
	}
	rows, err := benignscan.ParseUpstream(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upstream-check:", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	drift := benignscan.CheckUpstream(ctx, rows, benignscan.HTTPGet)
	for _, d := range drift {
		fmt.Println(d.String())
	}
	if len(drift) > 0 {
		fmt.Fprintf(os.Stderr, "upstream-check: %d of %d upstream files changed or could not be read\n", len(drift), len(rows))
		os.Exit(1)
	}
	fmt.Printf("upstream-check: %d upstream files match\n", len(rows))
}
