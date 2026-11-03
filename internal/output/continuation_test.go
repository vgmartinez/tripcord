package output

import (
	"slices"
	"testing"
)

// A shell line continuation between a credential's name and its value
// is deleted by the shell, so the value on the next line is the secret.
// Every class that reads a value after a separator must skip it.
func TestRedactSkipsLineContinuationBeforeValue(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"curl --token \\\n  CONTA1 x":                            "curl --token \\\n  [REDACTED] x",
		"curl --token \\\r\n  CONTA2 x":                          "curl --token \\\r\n  [REDACTED] x",
		"curl --token=\\\nCONTA3 x":                              "curl --token=\\\n[REDACTED] x",
		"curl -u \\\n  admin:CONTB1 https://h":                   "curl -u \\\n  [REDACTED] https://h",
		"sshpass -p \\\n  CONTC1 ssh h":                          "sshpass -p \\\n  [REDACTED] ssh h",
		"redis-cli -a \\\n  CONTC2":                              "redis-cli -a \\\n  [REDACTED]",
		"docker login -p \\\n  CONTC3 registry":                  "docker login -p \\\n  [REDACTED] registry",
		"SECRET_KEY=\\\nCONTD1 run":                              "SECRET_KEY=\\\n[REDACTED] run",
		"api_key: \\\n  CONTD2":                                  "api_key: \\\n  [REDACTED]",
		"curl -H 'Authorization: Bearer \\\n  CONTE1' https://h": "curl -H 'Authorization: Bearer \\\n  [REDACTED]' https://h",
		"echo bearer \\\n  CONTE2aaaaaaaaaaaaaaaaaaaa":           "echo [REDACTED]",
	}
	for in, want := range cases {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
	got, removed := RedactCommand("curl --token \\\n  CONTA1 x")
	if got != "curl --token \\\n  [REDACTED] x" || !slices.Equal(removed, []string{"CONTA1"}) {
		t.Errorf("RedactCommand = %q, %q; want the value after the continuation removed", got, removed)
	}
}

// A continuation that glues the flag to the next word makes one shell
// word, and a continuation not after a separator is left alone.
func TestRedactLineContinuationKeepsShellWords(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"cli --token\\\nizer gpt2",
		"curl -fsSL https://h/x \\\n  -o out",
		"make \\\n  all",
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
}
