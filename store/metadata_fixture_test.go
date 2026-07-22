//go:build integration
// +build integration

package store

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

// newMetadataFixture serves the preserved metadata answer documents through
// the same HTTP interface used by the production metadata client. Keeping the
// fixture in this repository avoids importing an obsolete metadata server and
// its unrelated cloud HTTP transport into the product source tree.
func newMetadataFixture(t *testing.T, answersPath string) *httptest.Server {
	t.Helper()

	contents, err := os.ReadFile(answersPath)
	if err != nil {
		t.Fatalf("read metadata fixture %s: %v", answersPath, err)
	}

	var raw interface{}
	if err := yaml.Unmarshal(contents, &raw); err != nil {
		t.Fatalf("parse metadata fixture %s: %v", answersPath, err)
	}
	versions, ok := stringMap(raw)
	if !ok {
		t.Fatalf("metadata fixture %s has an invalid root", answersPath)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		segments := splitMetadataPath(req.URL.Path)
		if len(segments) < 2 {
			http.NotFound(w, req)
			return
		}
		version, ok := stringMap(versions[segments[0]])
		if !ok {
			http.NotFound(w, req)
			return
		}

		answers, ok := mergedMetadataAnswers(version, requestClientIP(req))
		if !ok {
			http.NotFound(w, req)
			return
		}
		value, ok := metadataValue(answers, segments[1:])
		if !ok {
			http.NotFound(w, req)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodHead {
			return
		}
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Errorf("encode metadata response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func splitMetadataPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func requestClientIP(req *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(req.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
		if net.ParseIP(forwarded) != nil {
			return forwarded
		}
		return ""
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func mergedMetadataAnswers(version map[string]interface{}, clientIP string) (map[string]interface{}, bool) {
	defaults, ok := stringMap(version["default"])
	if !ok {
		return nil, false
	}
	merged := make(map[string]interface{}, len(defaults))
	for key, value := range defaults {
		merged[key] = value
	}
	if client, ok := stringMap(version[clientIP]); ok {
		for key, value := range client {
			merged[key] = value
		}
	}
	normalizeLegacyNetworkFixture(merged)
	return merged, true
}

// The preserved 2015 answer documents predate the network UUID fields now
// required by MetadataStore. The production control plane adds those fields;
// the fixture mirrors that compatibility adapter with one managed network.
func normalizeLegacyNetworkFixture(answers map[string]interface{}) {
	const networkUUID = "fixture-managed-network"
	if _, exists := answers["networks"]; !exists {
		answers["networks"] = []interface{}{map[string]interface{}{
			"name":       "managed",
			"uuid":       networkUUID,
			"is_default": true,
		}}
	}
	addFixtureNetworkUUID(answers, networkUUID)
}

func addFixtureNetworkUUID(value interface{}, networkUUID string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		if _, hasPrimaryIP := typed["primary_ip"]; hasPrimaryIP {
			if _, hasHostUUID := typed["host_uuid"]; hasHostUUID {
				if _, exists := typed["network_uuid"]; !exists {
					typed["network_uuid"] = networkUUID
				}
			}
		}
		for _, item := range typed {
			addFixtureNetworkUUID(item, networkUUID)
		}
	case []interface{}:
		for _, item := range typed {
			addFixtureNetworkUUID(item, networkUUID)
		}
	}
}

func metadataValue(root interface{}, path []string) (interface{}, bool) {
	value := root
	for _, segment := range path {
		switch current := value.(type) {
		case map[string]interface{}:
			var ok bool
			value, ok = current[segment]
			if !ok {
				return nil, false
			}
		case []interface{}:
			index, err := strconv.Atoi(segment)
			if err == nil {
				if index < 0 || index >= len(current) {
					return nil, false
				}
				value = current[index]
				continue
			}
			found := false
			for _, item := range current {
				candidate, ok := item.(map[string]interface{})
				if ok && fmt.Sprint(candidate["name"]) == segment {
					value = item
					found = true
					break
				}
			}
			if !found {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return value, true
}

func stringMap(value interface{}) (map[string]interface{}, bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		return typed, true
	case map[interface{}]interface{}:
		converted := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			stringKey, ok := key.(string)
			if !ok {
				return nil, false
			}
			converted[stringKey] = convertMetadataValue(item)
		}
		return converted, true
	default:
		return nil, false
	}
}

func convertMetadataValue(value interface{}) interface{} {
	if converted, ok := stringMap(value); ok {
		return converted
	}
	if array, ok := value.([]interface{}); ok {
		converted := make([]interface{}, len(array))
		for index, item := range array {
			converted[index] = convertMetadataValue(item)
		}
		return converted
	}
	return value
}
