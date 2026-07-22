package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validDocument = `{
  "schema": "pasturestack.overlay-topology/v1",
  "backend": "ipsec",
  "local_node_id": "node-a",
  "overlay_cidr": "198.51.100.0/24",
  "nodes": [
    {"id":"node-a","underlay_address":"192.0.2.10","overlay_address":"198.51.100.10"},
    {"id":"node-b","underlay_address":"192.0.2.11","overlay_address":"198.51.100.11"}
  ]
}`

func TestRunValidDocument(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(nil, strings.NewReader(validDocument), &stdout, &stderr); code != 0 {
		t.Fatalf("run returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"mode": "audit-only"`) {
		t.Fatalf("missing safety mode: %s", stdout.String())
	}
	for _, forbidden := range []string{"node-a", "192.0.2.10", "198.51.100.10"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("output leaked %q: %s", forbidden, stdout.String())
		}
	}
}

func TestRunFileAndVersion(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "topology.json")
	if err := os.WriteFile(path, []byte(validDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	if code := run([]string{"--file", path}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("file run returned %d: %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr); code != 0 || strings.TrimSpace(stdout.String()) != version {
		t.Fatalf("version run returned %d, stdout=%q, stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunFailuresDoNotEchoValuesOrPaths(t *testing.T) {
	secret := `{"schema":"pasturestack.overlay-topology/v1","psk":"hidden-value"}`
	var stdout, stderr strings.Builder
	if code := run(nil, strings.NewReader(secret), &stdout, &stderr); code != 1 {
		t.Fatalf("unknown field returned %d", code)
	}
	if strings.Contains(stderr.String(), "hidden-value") {
		t.Fatalf("error leaked field value: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	missing := filepath.Join(t.TempDir(), "private-name.json")
	if code := run([]string{"--file", missing}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Fatalf("missing file returned %d", code)
	}
	if strings.Contains(stderr.String(), missing) || strings.Contains(stderr.String(), "private-name") {
		t.Fatalf("error leaked file path: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"extra"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("positional argument returned %d", code)
	}
}

func TestRunOutputFailure(t *testing.T) {
	var stderr strings.Builder
	if code := run(nil, strings.NewReader(validDocument), errorWriter{}, &stderr); code != 1 {
		t.Fatalf("output failure returned %d", code)
	}
	if !strings.Contains(stderr.String(), "unable to encode plan") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
