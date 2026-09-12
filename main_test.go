package main

import "testing"

func TestHostRouteFirewallBackendMustBeResolved(t *testing.T) {
	for _, mode := range []string{"nftables", "iptables-nft", "iptables-legacy"} {
		if err := validateFirewallBackend(true, mode); err != nil {
			t.Errorf("valid mode %s rejected: %v", mode, err)
		}
	}
	for _, mode := range []string{"", "auto", "iptables", "invalid"} {
		if err := validateFirewallBackend(true, mode); err == nil {
			t.Errorf("unresolved or ambiguous mode %q accepted", mode)
		}
	}
	if err := validateFirewallBackend(false, ""); err != nil {
		t.Errorf("non-host mode must not require host firewall access: %v", err)
	}
}
