package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerFirewallDriver(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		expected string
		wantErr  bool
	}{
		{"native", 200, `{"ServerVersion":"29.8.0","FirewallBackend":{"Driver":"nftables"}}`, "nftables", false},
		{"xtables", 200, `{"ServerVersion":"29.8.0","FirewallBackend":{"Driver":"iptables"}}`, "iptables", false},
		{"old Docker without field", 200, `{"ServerVersion":"28.5.2"}`, "iptables", false},
		{"new Docker without field", 200, `{"ServerVersion":"29.8.0"}`, "", true},
		{"unknown driver", 200, `{"ServerVersion":"29.8.0","FirewallBackend":{"Driver":"other"}}`, "", true},
		{"empty driver", 200, `{"ServerVersion":"29.8.0","FirewallBackend":{"Driver":""}}`, "", true},
		{"unknown version without field", 200, `{"ServerVersion":"unknown"}`, "", true},
		{"HTTP error", 403, `{}`, "", true},
		{"invalid JSON", 200, `{`, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "docker.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/info" {
					t.Errorf("unexpected Docker API request %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})}
			go func() { _ = server.Serve(listener) }()
			defer server.Close()
			got, err := dockerFirewallDriver(context.Background(), socket)
			if (err != nil) != tc.wantErr || got != tc.expected {
				t.Fatalf("driver=%q error=%v, want driver=%q error=%t", got, err, tc.expected, tc.wantErr)
			}
		})
	}
}

func TestLegacyLoadedTables(t *testing.T) {
	dir := t.TempDir()
	if got, err := legacyLoadedTables(filepath.Join(dir, "absent")); err != nil || got != "" {
		t.Fatalf("ENOENT must mean no loaded legacy tables: %q, %v", got, err)
	}
	path := filepath.Join(dir, "tables")
	if err := os.WriteFile(path, []byte("nat\nfilter\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := legacyLoadedTables(path); err != nil || got != "nat\nfilter\n" {
		t.Fatalf("loaded legacy tables not preserved: %q, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("nat\nFORGED log entry\r\n\x1b[31mfilter\nfilter\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := legacyLoadedTables(path); err != nil || got != "nat\nfilter\n" {
		t.Fatalf("non-table procfs lines must not reach stdout: %q, %v", got, err)
	}
	if _, err := legacyLoadedTables(dir); err == nil {
		t.Fatal("non-ENOENT procfs read failure must fail closed")
	}
}

func TestDockerFirewallDriverMissingSocket(t *testing.T) {
	if _, err := dockerFirewallDriver(context.Background(), filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("missing Docker socket must fail closed")
	}
}
