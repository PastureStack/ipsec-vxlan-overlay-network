package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResolveConfigLiteralUnchanged(t *testing.T) {
	input := []byte(`{"name":"legacy","bridgeSubnet":"10.42.0.0/16","ipam":{"subnet":"10.42.0.0/16"}}`)
	output, err := resolveConfig(input, func() (map[string]string, error) {
		t.Fatal("literal configuration must not query metadata")
		return nil, nil
	})
	if err != nil || string(output) != string(input) {
		t.Fatalf("literal config changed: %s, %v", output, err)
	}
}

func TestResolveConfigPerHostSubnet(t *testing.T) {
	input := []byte(`{"name":"per-host","bridgeSubnet":"__host_label__: io.pasturestack.network.per-host-subnet.subnet","ipam":{"subnet":"__host_label__: io.pasturestack.network.per-host-subnet.subnet","rangeStart":"__host_label__: io.pasturestack.network.per-host-subnet.range-start","rangeEnd":"__host_label__: io.pasturestack.network.per-host-subnet.range-end"}}`)
	queries := 0
	output, err := resolveConfig(input, func() (map[string]string, error) {
		queries++
		return map[string]string{
			"io.pasturestack.network.per-host-subnet.subnet":      "10.51.1.0/24",
			"io.pasturestack.network.per-host-subnet.range-start": "10.51.1.20",
		}, nil
	})
	if err != nil || queries != 1 {
		t.Fatalf("resolve = %v; metadata queries = %d", err, queries)
	}
	var config struct {
		BridgeSubnet string            `json:"bridgeSubnet"`
		IPAM         map[string]string `json:"ipam"`
	}
	if err := json.Unmarshal(output, &config); err != nil {
		t.Fatal(err)
	}
	if config.BridgeSubnet != "10.51.1.0/24" || config.IPAM["subnet"] != "10.51.1.0/24" ||
		config.IPAM["rangeStart"] != "10.51.1.20" {
		t.Fatalf("wrong resolved configuration: %s", output)
	}
	if _, exists := config.IPAM["rangeEnd"]; exists {
		t.Fatalf("missing optional range-end must be omitted: %s", output)
	}
}

func TestResolveConfigRejectsMissingAndInvalidSubnet(t *testing.T) {
	input := []byte(`{"bridgeSubnet":"__host_label__: subnet","ipam":{"subnet":"__host_label__: subnet"}}`)
	for _, labels := range []map[string]string{{}, {"subnet": "10.51.1.5/24"}, {"subnet": "not-a-subnet"}} {
		if _, err := resolveConfig(input, func() (map[string]string, error) { return labels, nil }); err == nil {
			t.Fatalf("must reject labels %#v", labels)
		}
	}
	if _, err := resolveConfig(input, func() (map[string]string, error) { return nil, errors.New("unavailable") }); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("metadata failure must fail closed: %v", err)
	}
}

func TestResolveConfigRejectsInconsistentNetwork(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		labels map[string]string
	}{
		{"different subnets", `{"bridgeSubnet":"__host_label__: bridge","ipam":{"subnet":"__host_label__: subnet"}}`, map[string]string{"bridge": "10.51.1.0/24", "subnet": "10.51.2.0/24"}},
		{"range outside subnet", `{"bridgeSubnet":"__host_label__: subnet","ipam":{"subnet":"__host_label__: subnet","rangeStart":"__host_label__: start"}}`, map[string]string{"subnet": "10.51.1.0/24", "start": "10.51.2.20"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := resolveConfig([]byte(tt.input), func() (map[string]string, error) { return tt.labels, nil }); err == nil {
				t.Fatal("inconsistent per-host configuration must fail before executing bridge")
			}
		})
	}
}
