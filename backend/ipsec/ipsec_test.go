package ipsec

import "testing"

func TestCleanIP(t *testing.T) {
	for input, expected := range map[string]string{
		" 192.0.2.10/24 ": "192.0.2.10",
		"'2001:db8::1'":   "2001:db8::1",
		"not-an-address":  "",
	} {
		if actual := cleanIP(input); actual != expected {
			t.Errorf("cleanIP(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestCanonicalChildName(t *testing.T) {
	tests := map[string]string{
		"child-192.0.2.20":      "child-192.0.2.20",
		"child-192.0.2.20-3":    "child-192.0.2.20",
		"child-2001:db8::20":    "child-2001:db8::20",
		"child-2001:db8::20-42": "child-2001:db8::20",
		"child-not-an-address":  "",
		"health-192.0.2.20-3":   "",
	}
	for input, expected := range tests {
		if actual := canonicalChildName(input); actual != expected {
			t.Errorf("canonicalChildName(%q) = %q, want %q", input, actual, expected)
		}
	}
}
func TestStalePeerIdentity(t *testing.T) {
	expected := map[string]map[string]bool{
		"192.0.2.20": {
			"192.0.2.20": true,
			"10.42.0.20": true,
		},
	}
	tests := []struct {
		name      string
		childName string
		remoteID  string
		wantHost  string
		wantStale bool
	}{
		{name: "current underlay identity", childName: "child-192.0.2.20", remoteID: "192.0.2.20", wantHost: "192.0.2.20"},
		{name: "current suffixed VICI identity", childName: "child-192.0.2.20-7", remoteID: "192.0.2.20", wantHost: "192.0.2.20"},
		{name: "current overlay identity", childName: "child-192.0.2.20", remoteID: "10.42.0.20", wantHost: "192.0.2.20"},
		{name: "stale overlay identity", childName: "child-192.0.2.20", remoteID: "10.42.0.19", wantHost: "192.0.2.20", wantStale: true},
		{name: "stale suffixed VICI identity", childName: "child-192.0.2.20-8", remoteID: "10.42.0.19", wantHost: "192.0.2.20", wantStale: true},
		{name: "unknown host", childName: "child-192.0.2.30", remoteID: "192.0.2.30"},
		{name: "non IP identity", childName: "child-192.0.2.20", remoteID: "peer.example"},
		{name: "unrelated child", childName: "health-192.0.2.20", remoteID: "10.42.0.19"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, stale := stalePeerIdentity(tt.childName, tt.remoteID, expected)
			if host != tt.wantHost || stale != tt.wantStale {
				t.Fatalf("got host=%q stale=%v, want host=%q stale=%v", host, stale, tt.wantHost, tt.wantStale)
			}
		})
	}
}
