package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	bridgeBinary = "/opt/cni/bin/pasture-bridge-core"
	metadataURL  = "http://169.254.169.250/2016-07-29/self/host/labels/"
	labelPrefix  = "__host_label__:"
	maxConfig    = 1 << 20
)

func main() {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, maxConfig+1))
	if err != nil || len(input) > maxConfig {
		fmt.Fprintln(os.Stderr, "pasture-bridge: invalid CNI config size")
		os.Exit(1)
	}
	resolved, err := resolveConfig(input, readHostLabel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pasture-bridge:", err)
		os.Exit(1)
	}
	command := exec.Command(bridgeBinary, os.Args[1:]...)
	command.Stdin = bytes.NewReader(resolved)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "pasture-bridge: launch bridge plugin:", err)
		os.Exit(1)
	}
}

// resolveConfig keeps literal CNI documents byte-for-byte compatible. Only
// the per-host subnet fields explicitly used by this network driver expand
// host-label references before the bridge and its IPAM child receive stdin.
func resolveConfig(input []byte, getLabel func(string) (string, error)) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(input, &root); err != nil || root == nil {
		return nil, fmt.Errorf("invalid CNI JSON")
	}
	var ipam map[string]json.RawMessage
	if raw := root["ipam"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &ipam); err != nil {
			return nil, fmt.Errorf("invalid CNI IPAM JSON")
		}
	}
	type field struct {
		object   map[string]json.RawMessage
		name     string
		optional bool
	}
	fields := []field{{root, "bridgeSubnet", false}, {ipam, "subnet", false}, {ipam, "rangeStart", true}, {ipam, "rangeEnd", true}}
	labels := make(map[string]string)
	changed := false
	for _, target := range fields {
		if target.object == nil {
			continue
		}
		raw, ok := target.object[target.name]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || !strings.HasPrefix(value, labelPrefix) {
			continue
		}
		key := strings.TrimSpace(strings.TrimPrefix(value, labelPrefix))
		if key == "" || strings.ContainsAny(key, " \t\r\n/\\?#") {
			return nil, fmt.Errorf("invalid host-label reference in %s", target.name)
		}
		resolved, cached := labels[key]
		if !cached {
			var err error
			resolved, err = getLabel(key)
			if err != nil {
				return nil, fmt.Errorf("read local host label %q: %w", key, err)
			}
			labels[key] = resolved
		}
		resolved = strings.TrimSpace(resolved)
		if resolved == "" {
			if target.optional {
				delete(target.object, target.name)
				changed = true
				continue
			}
			return nil, fmt.Errorf("required local host label %q is missing", key)
		}
		if target.name == "subnet" || target.name == "bridgeSubnet" {
			ip, cidr, err := net.ParseCIDR(resolved)
			if err != nil || ip.To4() == nil || !ip.Equal(cidr.IP) {
				return nil, fmt.Errorf("host label %q must be a canonical IPv4 subnet", key)
			}
		} else if ip := net.ParseIP(resolved); ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("host label %q must be an IPv4 address", key)
		}
		encoded, _ := json.Marshal(resolved)
		target.object[target.name] = encoded
		changed = true
	}
	if !changed {
		return input, nil
	}
	var bridgeSubnet, ipamSubnet string
	if raw := root["bridgeSubnet"]; len(raw) > 0 {
		_ = json.Unmarshal(raw, &bridgeSubnet)
	}
	if ipam != nil {
		_ = json.Unmarshal(ipam["subnet"], &ipamSubnet)
	}
	if bridgeSubnet != "" && ipamSubnet != "" && bridgeSubnet != ipamSubnet {
		return nil, fmt.Errorf("bridge and IPAM subnets must match")
	}
	if _, subnet, err := net.ParseCIDR(ipamSubnet); err == nil {
		for _, name := range []string{"rangeStart", "rangeEnd"} {
			if raw := ipam[name]; len(raw) > 0 {
				var address string
				if json.Unmarshal(raw, &address) == nil {
					if ip := net.ParseIP(address); ip != nil && !subnet.Contains(ip) {
						return nil, fmt.Errorf("%s must be inside IPAM subnet", name)
					}
				}
			}
		}
	}
	if ipam != nil {
		encoded, err := json.Marshal(ipam)
		if err != nil {
			return nil, err
		}
		root["ipam"] = encoded
	}
	return json.Marshal(root)
}

func readHostLabel(key string) (string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{
		Timeout:       3 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return fetchHostLabel(client, metadataURL, key)
}

func fetchHostLabel(client *http.Client, baseURL, key string) (string, error) {
	response, err := client.Get(baseURL + url.PathEscape(key))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(data) > 1024 {
		return "", fmt.Errorf("invalid local host label size")
	}
	return strings.TrimSpace(string(data)), nil
}
