package topology

const (
	InputSchema = "pasturestack.overlay-topology/v1"
	PlanSchema  = "pasturestack.overlay-topology-plan/v1"
)

type Config struct {
	Schema      string       `json:"schema"`
	Backend     string       `json:"backend"`
	LocalNodeID string       `json:"local_node_id"`
	OverlayCIDR string       `json:"overlay_cidr"`
	Nodes       []Node       `json:"nodes"`
	VXLAN       *VXLANConfig `json:"vxlan,omitempty"`
}

type Node struct {
	ID              string `json:"id"`
	UnderlayAddress string `json:"underlay_address"`
	OverlayAddress  string `json:"overlay_address"`
}

type VXLANConfig struct {
	VNI           int    `json:"vni"`
	UDPPort       int    `json:"udp_port"`
	MTU           int    `json:"mtu"`
	InterfaceName string `json:"interface_name"`
}

type Plan struct {
	Schema            string     `json:"schema"`
	Backend           string     `json:"backend"`
	NormalizedSHA256  string     `json:"normalized_sha256"`
	AddressFamily     string     `json:"address_family"`
	OverlayPrefixBits int        `json:"overlay_prefix_bits"`
	NodeCount         int        `json:"node_count"`
	RemoteNodeCount   int        `json:"remote_node_count"`
	EstimatedObjects  Estimates  `json:"estimated_objects"`
	Safeguards        Safeguards `json:"safeguards"`
}

type Estimates struct {
	PeerRelationships int `json:"peer_relationships"`
	RouteEntries      int `json:"route_entries"`
	NeighborEntries   int `json:"neighbor_entries"`
	ForwardingEntries int `json:"forwarding_entries"`
}

type Safeguards struct {
	Mode                  string `json:"mode"`
	AppliesHostChanges    bool   `json:"applies_host_changes"`
	ReadsMetadata         bool   `json:"reads_metadata"`
	AcceptsSecretMaterial bool   `json:"accepts_secret_material"`
	ProductionReady       bool   `json:"production_ready"`
}
