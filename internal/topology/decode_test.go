package topology

import (
	"strings"
	"testing"
)

func TestDecodeRejectsUnknownField(t *testing.T) {
	document := `{"schema":"pasturestack.overlay-topology/v1","backend":"ipsec","local_node_id":"node-a","overlay_cidr":"198.51.100.0/24","nodes":[],"psk":"must-not-be-accepted"}`
	_, err := Decode(strings.NewReader(document))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
	if strings.Contains(err.Error(), "must-not-be-accepted") {
		t.Fatal("decoder echoed an unknown field value")
	}
}

func TestDecodeRejectsDuplicateField(t *testing.T) {
	document := `{"schema":"pasturestack.overlay-topology/v1","schema":"shadow-value"}`
	_, err := Decode(strings.NewReader(document))
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("expected duplicate-field error, got %v", err)
	}
	if strings.Contains(err.Error(), "shadow-value") {
		t.Fatal("decoder echoed a duplicate field value")
	}
}

func TestDecodeRejectsMultipleDocuments(t *testing.T) {
	_, err := Decode(strings.NewReader(`{} {}`))
	if err == nil || !strings.Contains(err.Error(), "multiple JSON documents") {
		t.Fatalf("expected multiple-document error, got %v", err)
	}
}

func TestDecodeRejectsOversizedDocument(t *testing.T) {
	_, err := Decode(strings.NewReader(strings.Repeat("x", MaxInputBytes+1)))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestDecodeRejectsMalformedDocument(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"schema":`))
	if err == nil || !strings.Contains(err.Error(), "decode input") {
		t.Fatalf("expected decode error, got %v", err)
	}
}
