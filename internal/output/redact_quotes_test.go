package output

import (
	"strings"
	"testing"
)

const quoteSecret = "Zq00Lm2Nv9Rx4Kt8W"

// A value inside shell-escaped quotes is the secret, for every credential
// key and for the flag forms that share the value reader. The wrapper
// stays so the command still shows how the value was quoted.
func TestShellEscapedQuotesRedacted(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		`echo "token: \"` + quoteSecret + `\""`:              `echo "token: \"[REDACTED]\""`,
		`echo "password: \"` + quoteSecret + `\""`:           `echo "password: \"[REDACTED]\""`,
		`echo "api_key: \"` + quoteSecret + `\""`:            `echo "api_key: \"[REDACTED]\""`,
		`echo "api-key: \"` + quoteSecret + `\""`:            `echo "api-key: \"[REDACTED]\""`,
		`echo "secret: \"` + quoteSecret + `\""`:             `echo "secret: \"[REDACTED]\""`,
		`echo "passwd: \"` + quoteSecret + `\""`:             `echo "passwd: \"[REDACTED]\""`,
		`echo "credentials: \"` + quoteSecret + `\""`:        `echo "credentials: \"[REDACTED]\""`,
		`echo "client_secret: \"` + quoteSecret + `\""`:      `echo "client_secret: \"[REDACTED]\""`,
		`echo "access_token: \"` + quoteSecret + `\""`:       `echo "access_token: \"[REDACTED]\""`,
		`echo "my token: \"` + quoteSecret + `\""`:           `echo "my token: \"[REDACTED]\""`,
		`echo "token:\"` + quoteSecret + `\""`:               `echo "token:\"[REDACTED]\""`,
		`echo "token: \"` + quoteSecret + ` extra\""`:        `echo "token: \"[REDACTED]\""`,
		`TOKEN=\"` + quoteSecret + `\"`:                      `TOKEN=\"[REDACTED]\"`,
		`echo "password=\"` + quoteSecret + `\""`:            `echo "password=\"[REDACTED]\""`,
		`tool --password \"` + quoteSecret + `\"`:            `tool --password \"[REDACTED]\"`,
		`tool --password=\"` + quoteSecret + `\"`:            `tool --password=\"[REDACTED]\"`,
		`tool --token \"` + quoteSecret + `\"`:               `tool --token \"[REDACTED]\"`,
		`sshpass -p \"` + quoteSecret + `\" host`:            `sshpass -p \"[REDACTED]\" host`,
		`machine h login u password \"` + quoteSecret + `\"`: `machine h login u password \"[REDACTED]\"`,
		`regcli --user bot -p \"` + quoteSecret + `\"`:       `regcli --user bot -p \"[REDACTED]\"`,
		`sshpass -p ` + quoteSecret + ` echo "say \"hi\""`:   `sshpass -p [REDACTED] echo "say \"hi\""`,
		`{"password":"a\"b"}`:                                `{"password":"[REDACTED]"}`,
		`echo "token: \\\"` + quoteSecret + `\\\""`:          `echo "token: \\\"[REDACTED]\\\""`,
	}
	for in, want := range cases {
		got := DefaultRedactor(in)
		if got != want || strings.Contains(got, quoteSecret) {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		if again := DefaultRedactor(got); again != got {
			t.Errorf("DefaultRedactor is not idempotent: %q then %q", got, again)
		}
	}
}

// Placeholders, literal commit text, and a \" pair that is not a
// credential value stay as written.
func TestShellEscapedQuotesKeepNonSecrets(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`echo "token: \"$PW\""`,
		`echo "token: \"${TOKEN}\""`,
		`echo "token: \"\""`,
		`echo "say \"hello\""`,
		`git commit -m "fix token: \"` + quoteSecret + `\""`,
		`echo "note: \"` + quoteSecret + `\""`,
		`echo "say \\"hello\\""`,
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
}

// A quote is escaped only after an odd run of backslashes. \\\"X\\\" is
// one escaped value, so the span starts at the first backslash. \\" is
// an even run: the quote is real and no span is opened.
func TestIndexEscapedQuotesBackslashParity(t *testing.T) {
	t.Parallel()
	odd := `echo "token: \\\"X\\\""`
	spans := indexEscapedQuotes(odd)
	if len(spans) != 1 || odd[spans[0][0]:spans[0][1]] != `\\\"X\\\"` {
		t.Fatalf("indexEscapedQuotes(%q) = %#v", odd, spans)
	}
	even := `echo "say \\"hello\\""`
	if spans := indexEscapedQuotes(even); len(spans) != 0 {
		got := make([]string, len(spans))
		for i, sp := range spans {
			got[i] = even[sp[0]:sp[1]]
		}
		t.Fatalf("even run spans = %q", got)
	}
}
