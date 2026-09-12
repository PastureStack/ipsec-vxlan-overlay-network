package main

import (
	"context"
	"net"
	"net/http"
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

func TestDockerFirewallDriverMissingSocket(t *testing.T) {
	if _, err := dockerFirewallDriver(context.Background(), filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("missing Docker socket must fail closed")
	}
}
