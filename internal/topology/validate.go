package topology

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

var (
	nodeIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	interfacePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)
)

type normalizedConfig struct {
	Schema      string           `json:"schema"`
	Backend     string           `json:"backend"`
	LocalNodeID string           `json:"local_node_id"`
	OverlayCIDR string           `json:"overlay_cidr"`
	Nodes       []normalizedNode `json:"nodes"`
	VXLAN       *VXLANConfig     `json:"vxlan,omitempty"`
	prefixBits  int
}

type normalizedNode struct {
	ID              string `json:"id"`
	UnderlayAddress string `json:"underlay_address"`
	OverlayAddress  string `json:"overlay_address"`
}

func normalize(config Config) (normalizedConfig, error) {
	if config.Schema != InputSchema {
		return normalizedConfig{}, fmt.Errorf("schema must be %q", InputSchema)
	}
	if config.Backend != "ipsec" && config.Backend != "vxlan" {
		return normalizedConfig{}, errors.New("backend must be ipsec or vxlan")
	}
	if !nodeIDPattern.MatchString(config.LocalNodeID) {
		return normalizedConfig{}, errors.New("local_node_id is invalid")
	}
	if len(config.Nodes) < 2 || len(config.Nodes) > 4096 {
		return normalizedConfig{}, errors.New("nodes must contain between 2 and 4096 entries")
	}

	prefix, err := netip.ParsePrefix(config.OverlayCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return normalizedConfig{}, errors.New("overlay_cidr must be a canonical IPv4 prefix")
	}
	if prefix.Bits() < 8 || prefix.Bits() > 30 {
		return normalizedConfig{}, errors.New("overlay_cidr prefix length must be between 8 and 30")
	}

	seenIDs := make(map[string]struct{}, len(config.Nodes))
	seenUnderlays := make(map[netip.Addr]struct{}, len(config.Nodes))
	seenOverlays := make(map[netip.Addr]struct{}, len(config.Nodes))
	nodes := make([]normalizedNode, 0, len(config.Nodes))
	localFound := false

	for index, node := range config.Nodes {
		if !nodeIDPattern.MatchString(node.ID) {
			return normalizedConfig{}, fmt.Errorf("nodes[%d].id is invalid", index)
		}
		if _, exists := seenIDs[node.ID]; exists {
			return normalizedConfig{}, fmt.Errorf("nodes[%d].id is duplicated", index)
		}
		seenIDs[node.ID] = struct{}{}
		if node.ID == config.LocalNodeID {
			localFound = true
		}

		underlay, err := parseUsableIPv4(node.UnderlayAddress)
		if err != nil {
			return normalizedConfig{}, fmt.Errorf("nodes[%d].underlay_address is invalid", index)
		}
		if prefix.Contains(underlay) {
			return normalizedConfig{}, fmt.Errorf("nodes[%d].underlay_address overlaps overlay_cidr", index)
		}
		if _, exists := seenUnderlays[underlay]; exists {
			return normalizedConfig{}, fmt.Errorf("nodes[%d].underlay_address is duplicated", index)
		}
		seenUnderlays[underlay] = struct{}{}

		overlay, err := parseUsableIPv4(node.OverlayAddress)
		if err != nil || !prefix.Contains(overlay) || isNetworkOrBroadcast(prefix, overlay) {
			return normalizedConfig{}, fmt.Errorf("nodes[%d].overlay_address is not a usable address in overlay_cidr", index)
		}
		if _, exists := seenOverlays[overlay]; exists {
			return normalizedConfig{}, fmt.Errorf("nodes[%d].overlay_address is duplicated", index)
		}
		seenOverlays[overlay] = struct{}{}

		nodes = append(nodes, normalizedNode{
			ID:              node.ID,
			UnderlayAddress: underlay.String(),
			OverlayAddress:  overlay.String(),
		})
	}
	if !localFound {
		return normalizedConfig{}, errors.New("local_node_id does not match a node")
	}

	var vxlan *VXLANConfig
	if config.Backend == "ipsec" {
		if config.VXLAN != nil {
			return normalizedConfig{}, errors.New("vxlan must be omitted for the ipsec backend")
		}
	} else {
		if config.VXLAN == nil {
			return normalizedConfig{}, errors.New("vxlan is required for the vxlan backend")
		}
		if err := validateVXLAN(*config.VXLAN); err != nil {
			return normalizedConfig{}, err
		}
		copy := *config.VXLAN
		vxlan = &copy
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return normalizedConfig{
		Schema:      config.Schema,
		Backend:     config.Backend,
		LocalNodeID: config.LocalNodeID,
		OverlayCIDR: prefix.String(),
		Nodes:       nodes,
		VXLAN:       vxlan,
		prefixBits:  prefix.Bits(),
	}, nil
}

func validateVXLAN(config VXLANConfig) error {
	if config.VNI < 1 || config.VNI > 16777215 {
		return errors.New("vxlan.vni must be between 1 and 16777215")
	}
	if config.UDPPort < 1024 || config.UDPPort > 65535 {
		return errors.New("vxlan.udp_port must be between 1024 and 65535")
	}
	if config.MTU < 1280 || config.MTU > 9000 {
		return errors.New("vxlan.mtu must be between 1280 and 9000")
	}
	if !interfacePattern.MatchString(config.InterfaceName) || !strings.HasPrefix(config.InterfaceName, "pasture-") {
		return errors.New("vxlan.interface_name must be a lowercase pasture- name of at most 15 characters")
	}
	return nil
}

func parseUsableIPv4(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() || !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("not a usable IPv4 address")
	}
	return addr.Unmap(), nil
}

func isNetworkOrBroadcast(prefix netip.Prefix, addr netip.Addr) bool {
	firstBytes := prefix.Masked().Addr().As4()
	addrBytes := addr.As4()
	first := binary.BigEndian.Uint32(firstBytes[:])
	current := binary.BigEndian.Uint32(addrBytes[:])
	hostBits := 32 - prefix.Bits()
	last := first | uint32((uint64(1)<<hostBits)-1)
	return current == first || current == last
}
