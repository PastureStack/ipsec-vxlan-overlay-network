package topology

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func BuildPlan(config Config) (Plan, error) {
	normalized, err := normalize(config)
	if err != nil {
		return Plan{}, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return Plan{}, fmt.Errorf("encode normalized topology: %w", err)
	}
	digest := sha256.Sum256(encoded)
	remote := len(normalized.Nodes) - 1
	estimates := Estimates{
		PeerRelationships: remote,
		RouteEntries:      remote,
	}
	if normalized.Backend == "vxlan" {
		estimates.NeighborEntries = remote
		estimates.ForwardingEntries = remote
	}
	return Plan{
		Schema:            PlanSchema,
		Backend:           normalized.Backend,
		NormalizedSHA256:  hex.EncodeToString(digest[:]),
		AddressFamily:     "ipv4",
		OverlayPrefixBits: normalized.prefixBits,
		NodeCount:         len(normalized.Nodes),
		RemoteNodeCount:   remote,
		EstimatedObjects:  estimates,
		Safeguards: Safeguards{
			Mode:                  "audit-only",
			AppliesHostChanges:    false,
			ReadsMetadata:         false,
			AcceptsSecretMaterial: false,
			ProductionReady:       false,
		},
	}, nil
}
