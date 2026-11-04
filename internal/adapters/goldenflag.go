package adapters

import "flag"

// GoldenUpdate reports whether adapter tests should rewrite
// discover.golden. It is set by the -update flag:
//
//	go test ./internal/adapters/... -update
//
// Production code leaves it false. The adapters package does not
// register the flag from init: other test binaries already use -update.
var GoldenUpdate bool

// RegisterGoldenUpdate registers -update on the default flag set when
// that flag is not already there. Test binaries under internal/adapters
// call it from init. The flag rewrites discover.golden and nothing else.
func RegisterGoldenUpdate() {
	if flag.Lookup("update") != nil {
		return
	}
	flag.BoolVar(&GoldenUpdate, "update", false, "rewrite adapter discover.golden files")
}
