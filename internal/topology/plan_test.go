package topology

import (
	"encoding/json"
	"strings"
	"testing"
)

func validVXLANConfig() Config {
	return Config{
		Schema:      InputSchema,
		Backend:     "vxlan",
		LocalNodeID: "node-a",
		OverlayCIDR: "198.51.100.0/24",
		Nodes: []Node{
			{ID: "node-a", UnderlayAddress: "192.0.2.10", OverlayAddress: "198.51.100.10"},
			{ID: "node-b", UnderlayAddress: "192.0.2.11", OverlayAddress: "198.51.100.11"},
		},
		VXLAN: &VXLANConfig{VNI: 1042, UDPPort: 4789, MTU: 1400, InterfaceName: "pasture-vxlan"},
	}
}

func cloneConfig(config Config) Config {
	copy := config
	copy.Nodes = append([]Node(nil), config.Nodes...)
	if config.VXLAN != nil {
		vxlan := *config.VXLAN
		copy.VXLAN = &vxlan
	}
	return copy
}

func TestBuildPlanVXLANIsRedacted(t *testing.T) {
	config := validVXLANConfig()
	plan, err := BuildPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != PlanSchema || plan.Backend != "vxlan" || plan.NodeCount != 2 || plan.RemoteNodeCount != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.EstimatedObjects != (Estimates{PeerRelationships: 1, RouteEntries: 1, NeighborEntries: 1, ForwardingEntries: 1}) {
		t.Fatalf("unexpected estimates: %+v", plan.EstimatedObjects)
	}
	if plan.Safeguards.AppliesHostChanges || plan.Safeguards.ReadsMetadata || plan.Safeguards.AcceptsSecretMaterial || plan.Safeguards.ProductionReady {
		t.Fatalf("unsafe safeguards: %+v", plan.Safeguards)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"node-a", "node-b", "192.0.2.10", "198.51.100.10", "pasture-vxlan"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("plan leaked %q: %s", forbidden, encoded)
		}
	}
	if len(plan.NormalizedSHA256) != 64 {
		t.Fatalf("unexpected digest: %q", plan.NormalizedSHA256)
	}
}

func TestBuildPlanIsDeterministicAcrossNodeOrder(t *testing.T) {
	first := validVXLANConfig()
	second := cloneConfig(first)
	second.Nodes[0], second.Nodes[1] = second.Nodes[1], second.Nodes[0]
	firstPlan, err := BuildPlan(first)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := BuildPlan(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstPlan.NormalizedSHA256 != secondPlan.NormalizedSHA256 {
		t.Fatalf("digest changed with input order: %s != %s", firstPlan.NormalizedSHA256, secondPlan.NormalizedSHA256)
	}
}

func TestBuildPlanIPsec(t *testing.T) {
	config := validVXLANConfig()
	config.Backend = "ipsec"
	config.VXLAN = nil
	plan, err := BuildPlan(config)
	if err != nil {
		t.Fatal(err)
	}
	want := Estimates{PeerRelationships: 1, RouteEntries: 1}
	if plan.EstimatedObjects != want {
		t.Fatalf("got %+v, want %+v", plan.EstimatedObjects, want)
	}
}

func TestBuildPlanValidation(t *testing.T) {
	base := validVXLANConfig()
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "schema", mutate: func(c *Config) { c.Schema = "other" }, want: "schema"},
		{name: "backend", mutate: func(c *Config) { c.Backend = "other" }, want: "backend"},
		{name: "local id syntax", mutate: func(c *Config) { c.LocalNodeID = "Node_A" }, want: "local_node_id"},
		{name: "local missing", mutate: func(c *Config) { c.LocalNodeID = "node-c" }, want: "does not match"},
		{name: "too few nodes", mutate: func(c *Config) { c.Nodes = c.Nodes[:1] }, want: "between 2 and 4096"},
		{name: "noncanonical prefix", mutate: func(c *Config) { c.OverlayCIDR = "198.51.100.7/24" }, want: "canonical"},
		{name: "small prefix", mutate: func(c *Config) { c.OverlayCIDR = "198.51.100.0/31" }, want: "between 8 and 30"},
		{name: "node id", mutate: func(c *Config) { c.Nodes[0].ID = "node_a" }, want: "nodes[0].id"},
		{name: "duplicate id", mutate: func(c *Config) { c.Nodes[1].ID = c.Nodes[0].ID }, want: "duplicated"},
		{name: "underlay invalid", mutate: func(c *Config) { c.Nodes[0].UnderlayAddress = "not-an-address" }, want: "underlay_address"},
		{name: "underlay overlap", mutate: func(c *Config) { c.Nodes[0].UnderlayAddress = "198.51.100.20" }, want: "overlaps"},
		{name: "underlay duplicate", mutate: func(c *Config) { c.Nodes[1].UnderlayAddress = c.Nodes[0].UnderlayAddress }, want: "duplicated"},
		{name: "overlay network", mutate: func(c *Config) { c.Nodes[0].OverlayAddress = "198.51.100.0" }, want: "usable address"},
		{name: "overlay broadcast", mutate: func(c *Config) { c.Nodes[0].OverlayAddress = "198.51.100.255" }, want: "usable address"},
		{name: "overlay outside", mutate: func(c *Config) { c.Nodes[0].OverlayAddress = "203.0.113.10" }, want: "usable address"},
		{name: "overlay duplicate", mutate: func(c *Config) { c.Nodes[1].OverlayAddress = c.Nodes[0].OverlayAddress }, want: "duplicated"},
		{name: "vxlan missing", mutate: func(c *Config) { c.VXLAN = nil }, want: "required"},
		{name: "vni", mutate: func(c *Config) { c.VXLAN.VNI = 0 }, want: "vxlan.vni"},
		{name: "port", mutate: func(c *Config) { c.VXLAN.UDPPort = 80 }, want: "vxlan.udp_port"},
		{name: "mtu", mutate: func(c *Config) { c.VXLAN.MTU = 9001 }, want: "vxlan.mtu"},
		{name: "interface", mutate: func(c *Config) { c.VXLAN.InterfaceName = "vtep1042" }, want: "interface_name"},
		{name: "ipsec rejects vxlan", mutate: func(c *Config) { c.Backend = "ipsec" }, want: "must be omitted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := cloneConfig(base)
			test.mutate(&config)
			_, err := BuildPlan(config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
			if strings.Contains(err.Error(), "not-an-address") {
				t.Fatal("validation error echoed an address value")
			}
		})
	}
}
