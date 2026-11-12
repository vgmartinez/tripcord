package main

import (
	"io"
	"os"
)

// textHyperlinks reports whether compact text should wrap rule ids in
// OSC 8 links. FORCE_HYPERLINK=1 forces them on and FORCE_HYPERLINK=0
// forces them off, ahead of every other condition. Otherwise links are
// off when output is a file, stdout is not a terminal, NO_COLOR is set,
// TERM is dumb, or CI is set.
func textHyperlinks(outputPath string, stdout io.Writer) bool {
	return textHyperlinksEnv(outputPath, stdout, os.Getenv)
}

func textHyperlinksEnv(outputPath string, stdout io.Writer, getenv func(string) string) bool {
	switch getenv("FORCE_HYPERLINK") {
	case "1":
		return true
	case "0":
		return false
	}
	if outputPath != "" && outputPath != "-" {
		return false
	}
	if !stdoutIsTerminal(stdout) {
		return false
	}
	if getenv("NO_COLOR") != "" {
		return false
	}
	if getenv("TERM") == "dumb" {
		return false
	}
	if getenv("CI") != "" {
		return false
	}
	return true
}

// stdoutIsTerminal reports whether w is a character device. Tests
// replace this to simulate a pty.
var stdoutIsTerminal = func(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
