package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// dockerFirewallDriver reads only Docker's current /info endpoint. The socket
// itself is not read-only; the router is already privileged and this command
// must never send an API request that changes daemon state.
func dockerFirewallDriver(ctx context.Context, socket string) (string, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/info", nil)
	if err != nil {
		return "", fmt.Errorf("construct Docker info request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("read Docker firewall mode: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read Docker firewall mode: HTTP %d", response.StatusCode)
	}
	var info struct {
		ServerVersion   string `json:"ServerVersion"`
		FirewallBackend *struct {
			Driver string `json:"Driver"`
		} `json:"FirewallBackend"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&info); err != nil {
		return "", fmt.Errorf("decode Docker firewall mode: %w", err)
	}
	if info.FirewallBackend != nil {
		switch info.FirewallBackend.Driver {
		case "iptables", "nftables":
			return info.FirewallBackend.Driver, nil
		default:
			return "", fmt.Errorf("unsupported Docker firewall driver %q", info.FirewallBackend.Driver)
		}
	}
	// Docker's native nftables backend first appeared in 29. Older daemons
	// cannot select it, but a 29+ daemon omitting the field is ambiguous.
	majorText, _, found := strings.Cut(info.ServerVersion, ".")
	major, err := strconv.Atoi(majorText)
	if !found || err != nil || major < 1 || major >= 29 {
		return "", fmt.Errorf("Docker %q did not report a usable firewall driver", info.ServerVersion)
	}
	return "iptables", nil
}

// A missing procfs legacy table list means no legacy tables are loaded on a
// native nftables host. Any other read error leaves the backend ambiguous.
func legacyLoadedTables(path string) (string, error) {
	tables, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read loaded legacy netfilter tables: %w", err)
	}
	// Only nat and filter are consumed by the host firewall selector. Emit
	// canonical names rather than forwarding arbitrary procfs bytes to stdout.
	var loaded strings.Builder
	for _, name := range strings.Split(string(tables), "\n") {
		switch name {
		case "nat":
			loaded.WriteString("nat\n")
		case "filter":
			loaded.WriteString("filter\n")
		}
	}
	return loaded.String(), nil
}
