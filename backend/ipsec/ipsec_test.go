package ipsec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bronze1man/goStrongswanVici"
)

func TestIKEConnectionUniquenessIsSentToVICI(t *testing.T) {
	templates := Templates{ConfigDir: t.TempDir()}
	if err := templates.Reload(); err != nil {
		t.Fatal(err)
	}
	conf := templates.NewIkeConf()
	if conf.Unique != "replace" {
		t.Fatalf("default unique policy = %q, want replace", conf.Unique)
	}
	conf.RemoteAddrs = []string{"192.0.2.20"}
	conf.Children = map[string]goStrongswanVici.ChildSAConf{"child-192.0.2.20": templates.NewChildSaConf()}
	request := &map[string]interface{}{}
	if err := goStrongswanVici.ConvertToGeneral(&map[string]IKEConnectionConfig{"conn-192.0.2.20": conf}, request); err != nil {
		t.Fatal(err)
	}
	loaded := (*request)["conn-192.0.2.20"].(map[string]interface{})
	if loaded["unique"] != "replace" {
		t.Fatalf("VICI unique policy = %v, want replace", loaded["unique"])
	}
	if loaded["remote_addrs"].([]interface{})[0] != "192.0.2.20" {
		t.Fatalf("remote address was lost: %v", loaded["remote_addrs"])
	}
	if _, ok := loaded["children"].(map[string]interface{})["child-192.0.2.20"]; !ok {
		t.Fatal("CHILD_SA was lost from VICI request")
	}
}

func TestIKEConnectionCustomTemplateUniqueness(t *testing.T) {
	for _, test := range []struct {
		name string
		json string
		want string
	}{
		{name: "legacy template inherits safe default", json: `{"local":{"auth":"psk"},"remote":{"auth":"psk"}}`, want: "replace"},
		{name: "explicit policy retained", json: `{"unique":"keep","local":{"auth":"psk"},"remote":{"auth":"psk"}}`, want: "keep"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(configDir, ikeConfName), []byte(test.json), 0600); err != nil {
				t.Fatal(err)
			}
			templates := Templates{ConfigDir: configDir}
			if err := templates.Reload(); err != nil {
				t.Fatal(err)
			}
			if got := templates.NewIkeConf().Unique; got != test.want {
				t.Fatalf("unique policy = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDeletingDuplicateIKEIDsOnlyReapsReplacedPeer(t *testing.T) {
	sas := []map[string]goStrongswanVici.IkeSa{
		{"conn-192.0.2.20": {
			Uniqueid: "4", Remote_host: "192.0.2.20", State: "ESTABLISHED",
			Child_sas: map[string]goStrongswanVici.Child_sas{"child-192.0.2.20-4": {State: "INSTALLED"}},
		}},
		{"conn-192.0.2.20": {Uniqueid: "3", Remote_host: "192.0.2.20", State: "DELETING"}},
		{"conn-192.0.2.21": {Uniqueid: "5", Remote_host: "192.0.2.21", State: "DELETING"}},
		{"other-192.0.2.20": {Uniqueid: "6", Remote_host: "192.0.2.20", State: "DELETING"}},
		{"conn-192.0.2.20": {Uniqueid: "not-a-number", Remote_host: "192.0.2.20", State: "DELETING"}},
	}
	ids := deletingDuplicateIKEIDs(sas, map[string]bool{"192.0.2.20": true, "192.0.2.21": true})
	if len(ids) != 1 || ids[0] != "3" {
		t.Fatalf("stale duplicate IDs = %v, want [3]", ids)
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
