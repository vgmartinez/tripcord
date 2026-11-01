package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestGeneratedTableIsCurrent(t *testing.T) {
	data, err := os.ReadFile("emoji-data.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Generate(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../pictographic.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))) {
		t.Fatal("pictographic.go is stale: run go generate ./internal/hiddenchar")
	}
}

func TestGenerateRejects(t *testing.T) {
	for name, data := range map[string]string{
		"other version": "# Version: 16.0\n00A9 ; Extended_Pictographic\n",
		"no ranges":     "# Version: 17.0\n",
		"bad range":     "# Version: 17.0\n2000..1FFF ; Extended_Pictographic\n",
		"bad hex":       "# Version: 17.0\nZZZZ ; Extended_Pictographic\n",
	} {
		if _, err := Generate(strings.NewReader(data)); err == nil {
			t.Errorf("%s: Generate succeeded", name)
		}
	}
}
