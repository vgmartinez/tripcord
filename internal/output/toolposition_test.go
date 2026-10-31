package output

import (
	"slices"
	"strings"
	"testing"
)

// A path activates a tool's flags only where it names the command, not
// as another flag's argument: make -C /opt/fly -t all is make, not fly.
func TestToolPathOnlyActivatesInCommandPosition(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"make -C /opt/fly -t all",
		"make -C=/opt/fly -t all",
		"tar -C ./vercel -t -f a.tar",
		`robocopy /mir -d C:\src\fly -t 5`,
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
		if got, removed := RedactCommand(in); got != in || len(removed) != 0 {
			t.Errorf("RedactCommand(%q) = %q, %q; want unchanged", in, got, removed)
		}
	}
	for in, secret := range map[string]string{
		"/opt/fly/bin/fly deploy -t CMDPOS":          "CMDPOS",
		"sudo -E /usr/local/bin/fly deploy -t SUDOE": "SUDOE",
		"npx --yes ./node_modules/.bin/vercel -t NB": "NB",
		`runas /x C:\tools\vercel.exe -t WINEXE`:     "WINEXE",
		"make -C /opt/fly && fly deploy -t AFTER":    "AFTER",
		"npx --yes vercel -t BARENAME":               "BARENAME",
	} {
		if got := DefaultRedactor(in); strings.Contains(got, secret) {
			t.Errorf("DefaultRedactor(%q) = %q leaks %q", in, got, secret)
		}
	}
	argv := []string{"make", "-C", "/opt/fly", "-t", "all"}
	if got, removed := RedactToolArgv(argv); !slices.Equal(got, argv) || len(removed) != 0 {
		t.Errorf("RedactToolArgv(%q) = %q, %q; want unchanged", argv, got, removed)
	}
	argv = []string{"sudo", "-E", "/usr/local/bin/fly", "-t", "ARGVSUDOE"}
	if got, _ := RedactToolArgv(argv); slices.Contains(got, "ARGVSUDOE") {
		t.Errorf("RedactToolArgv(%q) = %q", argv, got)
	}
}
