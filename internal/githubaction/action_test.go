package githubaction_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestTripcordActionDefaultsAndPinnedActions(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "actions", "tripcord", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}

	var action struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
		Runs struct {
			Using string `yaml:"using"`
			Steps []struct {
				Uses string `yaml:"uses"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}

	if action.Runs.Using != "composite" {
		t.Fatalf("runs.using = %q, want composite", action.Runs.Using)
	}
	if got := action.Inputs["fail-on"].Default; got != "high" {
		t.Fatalf("fail-on default = %q, want high", got)
	}
	if got := action.Inputs["upload-sarif"].Default; got != "true" {
		t.Fatalf("upload-sarif default = %q, want true", got)
	}

	const (
		uploadSARIF = "github/codeql-action/upload-sarif@4bfa242aa49c5f7c6770b98670d354a7dfac05f8"
		comment     = "actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b"
	)
	var uses []string
	var scan string
	for _, step := range action.Runs.Steps {
		if step.Uses != "" {
			uses = append(uses, step.Uses)
		}
		if step.Run != "" && strings.Contains(step.Run, "--format gha") {
			scan = step.Run
		}
	}
	if strings.Join(uses, "\n") != strings.Join([]string{uploadSARIF, comment}, "\n") {
		t.Fatalf("third-party action pins = %q, want %q and %q", uses, uploadSARIF, comment)
	}
	for _, format := range []string{"gha", "sarif", "md"} {
		if !strings.Contains(scan, "--format "+format) {
			t.Errorf("scan step does not produce %s output", format)
		}
	}
	if !strings.Contains(scan, "--fail-on") {
		t.Error("scan step does not set the failure threshold")
	}
}
