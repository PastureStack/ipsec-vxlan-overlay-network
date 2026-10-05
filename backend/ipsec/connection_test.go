package ipsec

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bronze1man/goStrongswanVici"
)

const oldLocal = "192.0.2.10"
const newLocal = "192.0.2.11"
const remotePeer = "192.0.2.20"

type mockConnectionClient struct {
	calls            []string
	requests         []map[string]interface{}
	sas              []map[string]goStrongswanVici.IkeSa
	loadErr          error
	listErr          error
	terminateOK      bool
	terminateMissing bool
}

func (m *mockConnectionClient) Request(name string, request map[string]interface{}) (map[string]interface{}, error) {
	m.calls = append(m.calls, name)
	m.requests = append(m.requests, request)
	if name == "load-conn" && m.loadErr != nil {
		return nil, m.loadErr
	}
	if name == "terminate" && m.terminateMissing {
		return map[string]interface{}{"success": "no", "matches": "0"}, nil
	}
	if name == "terminate" && !m.terminateOK {
		return map[string]interface{}{"success": "no", "matches": "1", "errmsg": "synthetic failure"}, nil
	}
	return map[string]interface{}{"success": "yes"}, nil
}

func (m *mockConnectionClient) ListSas(_, _ string) ([]map[string]goStrongswanVici.IkeSa, error) {
	m.calls = append(m.calls, "list-sas")
	return m.sas, m.listErr
}

func defaultTemplates(t *testing.T) *Templates {
	t.Helper()
	templates := &Templates{ConfigDir: t.TempDir()}
	if err := templates.Reload(); err != nil {
		t.Fatal(err)
	}
	return templates
}

func desired(t *testing.T, templates *Templates, local string, hostSource bool) (IKEConnectionConfig, string) {
	t.Helper()
	conf, fingerprint, err := hostConnectionConfig(templates, nil, local, local, remotePeer, hostSource)
	if err != nil {
		t.Fatal(err)
	}
	return conf, fingerprint
}

func ownedSA(id, state string) goStrongswanVici.IkeSa {
	return goStrongswanVici.IkeSa{Uniqueid: id, State: state, Local_host: oldLocal, Remote_host: remotePeer, Local_id: oldLocal}
}

func TestConnectionFingerprintIncludesSelfAndCompleteConfiguration(t *testing.T) {
	templates := defaultTemplates(t)
	old, first := desired(t, templates, oldLocal, true)
	current, second := desired(t, templates, newLocal, true)
	_, repeated := desired(t, templates, newLocal, true)
	if first == second || second != repeated {
		t.Fatal("local endpoint changes must invalidate an otherwise stable cache")
	}
	old.LocalAddrs = current.LocalAddrs
	if !reflect.DeepEqual(old, current) {
		t.Fatal("endpoint update changed proposals, auth, CHILD policy or uniqueness")
	}
	_, localMode := desired(t, templates, newLocal, false)
	if localMode == second {
		t.Fatal("host-tunnel mode must be bound to its fingerprint")
	}
	templates.ikeConfTemplate = []byte(`{"local":{"auth":"psk","id":"explicit.example"},"remote":{"auth":"psk"},"unique":"keep","local_port":"4500"}`)
	custom, changed := desired(t, templates, newLocal, true)
	if changed == second || custom.LocalAuth.ID != "explicit.example" || custom.Unique != "keep" || custom.LocalPort != "4500" {
		t.Fatal("complete custom configuration must invalidate cache without overriding explicit values")
	}
}

func TestConnectionGCMFilteringAndCustomChildConfigurationAreUnchanged(t *testing.T) {
	templates := defaultTemplates(t)
	templates.childSaConfTemplate = []byte(`{"esp_proposals":["aes128gcm16-modp2048","aes-modp2048"],"close_action":"start","mode":"transport","policies":"no"}`)
	conf, _, err := hostConnectionConfig(templates, []string{"aes128gcm16"}, newLocal, newLocal, remotePeer, true)
	if err != nil {
		t.Fatal(err)
	}
	child := conf.Children["child-"+remotePeer]
	if !reflect.DeepEqual(conf.Proposals, []string{"aes-sha1-modp2048"}) || !reflect.DeepEqual(child.ESPProposals, []string{"aes-modp2048"}) ||
		child.CloseAction != "start" || child.Mode != "transport" || child.InstallPolicy != "no" || child.ReqID != reqIdStr {
		t.Fatal("existing algorithm filtering or custom CHILD settings changed")
	}
}

func TestConnectionReloadQueuesOwnedPreviousEndpointThenTerminatesExactConnectingID(t *testing.T) {
	templates := defaultTemplates(t)
	hosts, stale := map[string]string{}, map[string]map[string]string{}
	client := &mockConnectionClient{terminateOK: true}
	old, oldFingerprint := desired(t, templates, oldLocal, true)
	if err := loadHostConnection(client, remotePeer, old, oldFingerprint, hosts, stale); err != nil {
		t.Fatal(err)
	}
	if len(stale) != 0 {
		t.Fatal("first successful load has no previous owned endpoint")
	}
	client.calls, client.requests = nil, nil
	current, fingerprint := desired(t, templates, newLocal, true)
	if err := loadHostConnection(client, remotePeer, current, fingerprint, hosts, stale); err != nil {
		t.Fatal(err)
	}
	connecting := ownedSA("7", "CONNECTING")
	connecting.Local_id = "" // A connecting IKE_SA need not have a child or an authenticated ID.
	client.sas = []map[string]goStrongswanVici.IkeSa{{"conn-" + remotePeer: connecting}}
	if err := reapStaleLocalSAs(client, newLocal, map[string]bool{remotePeer: true}, stale); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(client.calls, []string{"load-conn", "list-sas", "terminate"}) {
		t.Fatalf("unsafe operation order: %v", client.calls)
	}
	if !reflect.DeepEqual(client.requests[1], map[string]interface{}{"ike-id": "7", "force": "yes", "timeout": "1000"}) {
		t.Fatalf("termination was not by exact IKE ID: %v", client.requests[1])
	}
	if hosts[remotePeer] != fingerprint || len(stale) != 0 {
		t.Fatal("successful load must cache, and completed transition authority must be consumed")
	}
	client.calls = nil
	if err := loadHostConnection(client, remotePeer, current, fingerprint, hosts, stale); err != nil {
		t.Fatal(err)
	}
	if err := reapStaleLocalSAs(client, newLocal, map[string]bool{remotePeer: true}, stale); err != nil || len(client.calls) != 0 {
		t.Fatal("unchanged cache or consumed historical authority issued another request")
	}
}

func TestConnectionFailedLoadNeverUpdatesCacheQueuesOrTerminates(t *testing.T) {
	templates := defaultTemplates(t)
	old, oldFingerprint := desired(t, templates, oldLocal, true)
	hosts, stale := map[string]string{}, map[string]map[string]string{}
	client := &mockConnectionClient{}
	if err := loadHostConnection(client, remotePeer, old, oldFingerprint, hosts, stale); err != nil {
		t.Fatal(err)
	}
	client.calls = nil
	client.loadErr = errors.New("synthetic load failure")
	current, fingerprint := desired(t, templates, newLocal, true)
	if err := loadHostConnection(client, remotePeer, current, fingerprint, hosts, stale); err == nil {
		t.Fatal("failed VICI load passed")
	}
	if hosts[remotePeer] != oldFingerprint || len(stale) != 0 || !reflect.DeepEqual(client.calls, []string{"load-conn", "load-conn", "load-conn"}) {
		t.Fatalf("failure changed ownership/cache or attempted termination: %v", client.calls)
	}
}

func TestConnectionDiscoveredOrLocalModeCannotAuthorizeStaleCleanup(t *testing.T) {
	templates := defaultTemplates(t)
	for _, prior := range []string{"", templates.Revision()} {
		hosts, stale := map[string]string{remotePeer: prior}, map[string]map[string]string{}
		client := &mockConnectionClient{}
		current, fingerprint := desired(t, templates, newLocal, true)
		if err := loadHostConnection(client, remotePeer, current, fingerprint, hosts, stale); err != nil || len(stale) != 0 {
			t.Fatal("discovered/unverified conn was treated as an owned previous configuration")
		}
	}
	hosts, stale := map[string]string{}, map[string]map[string]string{}
	client := &mockConnectionClient{}
	for _, local := range []string{oldLocal, newLocal} {
		conf, fingerprint := desired(t, templates, local, false)
		if err := loadHostConnection(client, remotePeer, conf, fingerprint, hosts, stale); err != nil {
			t.Fatal(err)
		}
	}
	if len(stale) != 0 {
		t.Fatal("metadata IP is not authority over a custom local-mode endpoint")
	}
}

func TestStaleLocalIKEIDsKeepFreshForeignUnknownAndAmbiguousAssociations(t *testing.T) {
	connecting := ownedSA("7", "CONNECTING")
	established := ownedSA("8", "ESTABLISHED")
	established.Child_sas = map[string]goStrongswanVici.Child_sas{"child-" + remotePeer + "-8": {State: "INSTALLED", Reqid: reqIdStr}}
	stale := map[string]map[string]string{remotePeer: {oldLocal: oldLocal}}
	expected := map[string]bool{remotePeer: true}
	for _, sa := range []goStrongswanVici.IkeSa{connecting, established} {
		ids := staleLocalIKEIDs([]map[string]goStrongswanVici.IkeSa{{"conn-" + remotePeer: sa}}, newLocal, expected, stale)
		if !reflect.DeepEqual(ids, []string{sa.Uniqueid}) {
			t.Fatalf("owned previous endpoint was not selected: %v", ids)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*goStrongswanVici.IkeSa)
	}{
		{"fresh endpoint", func(sa *goStrongswanVici.IkeSa) { sa.Local_host = newLocal }},
		{"unproved endpoint", func(sa *goStrongswanVici.IkeSa) { sa.Local_host = "192.0.2.99" }},
		{"foreign peer", func(sa *goStrongswanVici.IkeSa) { sa.Remote_host = "192.0.2.21" }},
		{"foreign identity", func(sa *goStrongswanVici.IkeSa) { sa.Local_id = "foreign.example" }},
		{"unknown state", func(sa *goStrongswanVici.IkeSa) { sa.State = "UNKNOWN" }},
		{"invalid unique ID", func(sa *goStrongswanVici.IkeSa) { sa.Uniqueid = "not-an-id" }},
		{"zero unique ID", func(sa *goStrongswanVici.IkeSa) { sa.Uniqueid = "0" }},
		{"foreign child", func(sa *goStrongswanVici.IkeSa) {
			sa.Child_sas = map[string]goStrongswanVici.Child_sas{"foreign": {Reqid: reqIdStr}}
		}},
		{"foreign reqid", func(sa *goStrongswanVici.IkeSa) {
			sa.Child_sas = map[string]goStrongswanVici.Child_sas{"child-" + remotePeer: {Reqid: "9999"}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sa := connecting
			test.change(&sa)
			if ids := staleLocalIKEIDs([]map[string]goStrongswanVici.IkeSa{{"conn-" + remotePeer: sa}}, newLocal, expected, stale); len(ids) != 0 {
				t.Fatalf("foreign/unknown SA selected: %v", ids)
			}
		})
	}
	for _, sas := range [][]map[string]goStrongswanVici.IkeSa{
		{{"foreign-" + remotePeer: connecting}},
		{{"conn-" + remotePeer: connecting}, {"foreign": connecting}},
		{{"conn-" + remotePeer: connecting}, {"conn-192.0.2.21": {Uniqueid: connecting.Uniqueid, State: "CONNECTING", Local_host: oldLocal, Remote_host: "192.0.2.21"}}},
	} {
		if ids := staleLocalIKEIDs(sas, newLocal, expected, stale); len(ids) != 0 {
			t.Fatalf("foreign name/ambiguous ID selected: %v", ids)
		}
	}
	if len(staleLocalIKEIDs([]map[string]goStrongswanVici.IkeSa{{"conn-" + remotePeer: connecting}}, newLocal, map[string]bool{}, stale)) != 0 ||
		len(staleLocalIKEIDs([]map[string]goStrongswanVici.IkeSa{{"conn-" + remotePeer: connecting}}, "", expected, stale)) != 0 {
		t.Fatal("missing current metadata authority selected an SA")
	}
}

func TestStaleLocalCleanupFailureKeepsTransitionAuthorityAndNoBroadTermination(t *testing.T) {
	stale := map[string]map[string]string{remotePeer: {oldLocal: oldLocal}}
	client := &mockConnectionClient{listErr: errors.New("synthetic list failure")}
	if err := reapStaleLocalSAs(client, newLocal, map[string]bool{remotePeer: true}, stale); err == nil || len(stale) != 1 {
		t.Fatal("list failure consumed authority")
	}
	client.listErr, client.calls = nil, nil
	client.sas = []map[string]goStrongswanVici.IkeSa{{"conn-" + remotePeer: ownedSA("7", "CONNECTING")}}
	if err := reapStaleLocalSAs(client, newLocal, map[string]bool{remotePeer: true}, stale); err == nil || len(stale) != 1 {
		t.Fatal("termination failure consumed authority")
	}
	if !reflect.DeepEqual(client.calls, []string{"list-sas", "terminate"}) {
		t.Fatalf("unexpected recovery operation: %v", client.calls)
	}
}

func TestStaleLocalCleanupAlreadyGoneIsIdempotent(t *testing.T) {
	stale := map[string]map[string]string{remotePeer: {oldLocal: oldLocal}}
	client := &mockConnectionClient{
		terminateMissing: true,
		sas:              []map[string]goStrongswanVici.IkeSa{{"conn-" + remotePeer: ownedSA("7", "CONNECTING")}},
	}
	if err := reapStaleLocalSAs(client, newLocal, map[string]bool{remotePeer: true}, stale); err != nil {
		t.Fatalf("SA disappearing after observation must be idempotent: %v", err)
	}
	if len(stale) != 0 || !reflect.DeepEqual(client.calls, []string{"list-sas", "terminate"}) ||
		!reflect.DeepEqual(client.requests, []map[string]interface{}{{"ike-id": "7", "force": "yes", "timeout": "1000"}}) {
		t.Fatal("already-gone SA caused a retry, broad termination, or retained historical authority")
	}
}
