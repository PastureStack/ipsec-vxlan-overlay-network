package ipsec

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureOverlayNATBypassSkipsMissingOptionalBackend(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "pasture-overlay-iptables")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "commands.log")
	script := `#!/bin/sh
name=$(basename "$0")
echo "$name $*" >> "$IPTABLES_LOG"
case "$name $*" in
  "iptables -t nat -S CATTLE_NAT_POSTROUTING")
    exit 0
    ;;
  "iptables -t nat -C CATTLE_NAT_POSTROUTING -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT")
    exit 1
    ;;
  "iptables -t nat -I CATTLE_NAT_POSTROUTING 1 -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT")
    exit 0
    ;;
  "iptables-legacy -t nat -S CATTLE_NAT_POSTROUTING")
    exit 1
    ;;
esac
exit 1
`
	for _, name := range []string{"iptables", "iptables-legacy"} {
		if err := ioutil.WriteFile(filepath.Join(tmpDir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	oldPath := os.Getenv("PATH")
	oldLog := os.Getenv("IPTABLES_LOG")
	os.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)
	os.Setenv("IPTABLES_LOG", logFile)
	defer os.Setenv("PATH", oldPath)
	defer os.Setenv("IPTABLES_LOG", oldLog)

	if err := (&Overlay{}).ensureOverlayNATBypass(); err != nil {
		t.Fatalf("expected missing iptables-legacy chain to be skipped, got %v", err)
	}

	commandsBytes, err := ioutil.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(commandsBytes)
	if !strings.Contains(commands, "iptables -t nat -I CATTLE_NAT_POSTROUTING 1") {
		t.Fatalf("expected primary iptables insert, got commands:\n%s", commands)
	}
	if strings.Contains(commands, "iptables-legacy -t nat -I CATTLE_NAT_POSTROUTING 1") {
		t.Fatalf("expected missing iptables-legacy chain to skip insert, got commands:\n%s", commands)
	}
}

func TestEnsureOverlayNATBypassUsesExplicitNftBackend(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "pasture-overlay-iptables-nft")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "commands.log")
	script := `#!/bin/sh
name=$(basename "$0")
echo "$name $*" >> "$IPTABLES_LOG"
case "$name $*" in
  "iptables -t nat -S CATTLE_NAT_POSTROUTING")
    exit 1
    ;;
  "iptables-nft -t nat -S CATTLE_NAT_POSTROUTING")
    exit 0
    ;;
  "iptables-nft -t nat -C CATTLE_NAT_POSTROUTING -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT")
    exit 1
    ;;
  "iptables-nft -t nat -I CATTLE_NAT_POSTROUTING 1 -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT")
    exit 0
    ;;
  "iptables-legacy -t nat -S CATTLE_NAT_POSTROUTING")
    exit 1
    ;;
esac
exit 1
`
	for _, name := range []string{"iptables", "iptables-nft", "iptables-legacy"} {
		if err := ioutil.WriteFile(filepath.Join(tmpDir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	oldPath := os.Getenv("PATH")
	oldLog := os.Getenv("IPTABLES_LOG")
	os.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)
	os.Setenv("IPTABLES_LOG", logFile)
	defer os.Setenv("PATH", oldPath)
	defer os.Setenv("IPTABLES_LOG", oldLog)

	if err := (&Overlay{}).ensureOverlayNATBypass(); err != nil {
		t.Fatalf("expected explicit iptables-nft backend to handle nft-owned chain, got %v", err)
	}

	commandsBytes, err := ioutil.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(commandsBytes)
	if !strings.Contains(commands, "iptables-nft -t nat -I CATTLE_NAT_POSTROUTING 1") {
		t.Fatalf("expected explicit iptables-nft insert, got commands:\n%s", commands)
	}
	if strings.Contains(commands, "iptables -t nat -I CATTLE_NAT_POSTROUTING 1") {
		t.Fatalf("expected primary iptables backend without chain to skip insert, got commands:\n%s", commands)
	}
}

func TestEnsureOverlayForwardJumpUsesExplicitNftBackend(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "pasture-overlay-forward-nft")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "commands.log")
	script := `#!/bin/sh
name=$(basename "$0")
echo "$name $*" >> "$IPTABLES_LOG"
case "$name $*" in
  "iptables-nft -S CATTLE_FORWARD")
    exit 0
    ;;
  "iptables-nft -C CATTLE_FORWARD -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT")
    exit 0
    ;;
  "iptables-nft -C FORWARD -j CATTLE_FORWARD")
    exit 1
    ;;
  "iptables-nft -I FORWARD 1 -j CATTLE_FORWARD")
    exit 0
    ;;
  "iptables-legacy -S CATTLE_FORWARD")
    exit 1
    ;;
esac
exit 1
`
	for _, name := range []string{"iptables-nft", "iptables-legacy"} {
		if err := ioutil.WriteFile(filepath.Join(tmpDir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	oldPath := os.Getenv("PATH")
	oldLog := os.Getenv("IPTABLES_LOG")
	os.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)
	os.Setenv("IPTABLES_LOG", logFile)
	defer os.Setenv("PATH", oldPath)
	defer os.Setenv("IPTABLES_LOG", oldLog)

	if err := (&Overlay{}).ensureOverlayForwardJump(); err != nil {
		t.Fatalf("expected explicit iptables-nft backend to handle nft-owned forward chain, got %v", err)
	}

	commandsBytes, err := ioutil.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(commandsBytes)
	if !strings.Contains(commands, "iptables-nft -I FORWARD 1 -j CATTLE_FORWARD") {
		t.Fatalf("expected explicit iptables-nft forward insert, got commands:\n%s", commands)
	}
	if strings.Contains(commands, "iptables -I FORWARD 1 -j CATTLE_FORWARD") {
		t.Fatalf("expected primary iptables backend without chain to skip insert, got commands:\n%s", commands)
	}
}

func TestEnsureOverlayForwardJumpCreatesActiveBackendChain(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "pasture-overlay-forward-create")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logFile := filepath.Join(tmpDir, "commands.log")
	script := `#!/bin/sh
name=$(basename "$0")
echo "$name $*" >> "$IPTABLES_LOG"
case "$name $*" in
  "iptables -S CATTLE_FORWARD")
    exit 1
    ;;
  "iptables -N CATTLE_FORWARD")
    exit 0
    ;;
  "iptables -C CATTLE_FORWARD -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT")
    exit 1
    ;;
  "iptables -I CATTLE_FORWARD 1 -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT")
    exit 0
    ;;
  "iptables -C FORWARD -j CATTLE_FORWARD")
    exit 1
    ;;
  "iptables -I FORWARD 1 -j CATTLE_FORWARD")
    exit 0
    ;;
  "iptables-legacy -S CATTLE_FORWARD")
    exit 1
    ;;
esac
exit 1
`
	for _, name := range []string{"iptables", "iptables-legacy"} {
		if err := ioutil.WriteFile(filepath.Join(tmpDir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}

	oldPath := os.Getenv("PATH")
	oldLog := os.Getenv("IPTABLES_LOG")
	os.Setenv("PATH", tmpDir+string(os.PathListSeparator)+oldPath)
	os.Setenv("IPTABLES_LOG", logFile)
	defer os.Setenv("PATH", oldPath)
	defer os.Setenv("IPTABLES_LOG", oldLog)

	if err := (&Overlay{}).ensureOverlayForwardJump(); err != nil {
		t.Fatalf("expected missing active backend chain to be created, got %v", err)
	}

	commandsBytes, err := ioutil.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(commandsBytes)
	for _, expected := range []string{
		"iptables -N CATTLE_FORWARD",
		"iptables -I CATTLE_FORWARD 1 -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT",
		"iptables -I FORWARD 1 -j CATTLE_FORWARD",
	} {
		if !strings.Contains(commands, expected) {
			t.Fatalf("expected %q, got commands:\n%s", expected, commands)
		}
	}
	if strings.Contains(commands, "iptables-legacy -N CATTLE_FORWARD") {
		t.Fatalf("expected missing optional legacy backend to be skipped, got commands:\n%s", commands)
	}
}

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
