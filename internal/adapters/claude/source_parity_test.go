package claude

import (
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
)

func hookSettings(t *testing.T, command string) string {
	t.Helper()
	return string(mustJSON(t, map[string]any{
		"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command}}}}},
	}))
}

// The source side and output.DefaultRedactor share one table: a hook
// command is redacted at the source exactly as the output side would
// redact it, and a command the output side leaves alone is unchanged in
// both the payload and the key, with no key discriminator.
func TestSourceRedactionMatchesOutputRedactor(t *testing.T) {
	t.Parallel()
	redacted := []string{
		"curl --proxy-user bob:PROXYPASS https://x",
		"sshpass -pSSHGLUED ssh host",
		"openssl enc -aes-256-cbc -K 0011HEXKEY -in f",
		"openssl rsa -passin pass:PASSIN -in k.pem",
		"openssl pkcs12 -pass pass:PASSPASS",
		"redis-cli --pass REDISLONG ping",
		"git clone https://user:pa/SLASHPASS@host/r",
		`cli "--token" QUOTEDFLAG`,
		"docker run --rm img vercel deploy -t DOCKERREMOTE",
		"ssh host 'openssl enc -k SSHREMOTE'",
		"x=$(openssl enc -k SUBK)",
		"x=`vercel -t TICKT`",
		"(cli --token PARENTOK)",
		"cli --token='-Q'",
		"secret: foo && run",
		"curl -H 'X-Token: HDRTOK' https://x",
		"docker run -e SECRET_KEY=ENVSK img",
		"docker run -e AWS_SECRET_ACCESS_KEY=ENVAWS img",
		"PRIVATE_KEY=ENVPK deploy",
		"docker run -e DB_PASS=ENVPASS img",
		`echo "token: PXC5" > .env`,
		"echo 'password: PXC6' >> config.yml",
		"printf 'api_key: PXC8'",
		"http example.com X-Api-Key:PXC7",
		"http example.com 'X-API-Token:PXC7B'",
		`echo "db password: PXC9" > .env`,
		`echo "my token: PXC10"`,
		"echo 'user: a password: PXC11'",
		`echo "export A=1; token: PXC12"`,
		"http h x-api-key:PXC13",
		"http h api_key:PXC14",
		"echo -e 'token: PXC15'",
		"sh -c 'echo token: PXC16'",
		"echo password: PXC17 > f",
		"echo secret: foo && run",
		"echo -e --token PXC21",
	}
	for _, command := range redacted {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			got := discoverSettings(t, hookSettings(t, command))
			payloadCommand, _ := payloadField(t, got.Items[0], "command")
			if want := output.DefaultRedactor(command); payloadCommand != want || want == command {
				t.Fatalf("source command = %q, output side = %q", payloadCommand, want)
			}
			if parts := keyParts(t, got, model.ConfigKindHook); strings.Count(strings.Join(parts, " "), "sig:") != 2 {
				t.Fatalf("key %q has no discriminator for the removed secret", parts)
			}
		})
	}
	kept := []string{
		"git commit -m 'fix token: handling'",
		"grep -e --token file",
		"cli --token=",
		"grep -e 'token: x' file",
		"make -C /opt/fly -t all",
		"docker run -e SECRET_KEY_FILE=/run/secrets/k img",
		"TOKEN_TTL=30 app",
		"gh auth login --with-token < token.txt",
		"gh auth login --with-token=true",
	}
	for _, command := range kept {
		t.Run("kept/"+command, func(t *testing.T) {
			t.Parallel()
			got := discoverSettings(t, hookSettings(t, command))
			payloadCommand, _ := payloadField(t, got.Items[0], "command")
			if payloadCommand != command || output.DefaultRedactor(command) != command {
				t.Fatalf("command changed: %q -> %q", command, payloadCommand)
			}
			parts := strings.Join(keyParts(t, got, model.ConfigKindHook), " ")
			if strings.Count(parts, "sig:") != 1 || strings.Contains(parts, "[REDACTED]") {
				t.Fatalf("key %q redacts or discriminates text nothing removed", parts)
			}
		})
	}
}

func TestRedactCommandSecretsQuotesAgree(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"cli --token='-Q'": "cli --token='[REDACTED]'",
		`cli --token="-Q"`: `cli --token="[REDACTED]"`,
		"cli --token=-Q":   "cli --token=[REDACTED]",
	} {
		got, removed := redactCommandSecrets(in)
		if got != want || !slices.Equal(removed, []string{"-Q"}) {
			t.Errorf("redactCommandSecrets(%q) = %q, %q; want %q, [-Q]", in, got, removed, want)
		}
	}
	if got, removed := redactCommandSecrets("cli --token="); got != "cli --token=" || len(removed) != 0 {
		t.Errorf("empty value: %q, %q", got, removed)
	}
}
