//go:build race

package rules

// timingScale loosens wall-clock bounds under the race detector, which
// slows regular expression matching by about 10x.
const timingScale = 20
