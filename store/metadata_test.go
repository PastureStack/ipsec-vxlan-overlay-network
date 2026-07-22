//go:build integration
// +build integration

package store

import (
	"reflect"
	"testing"

	"github.com/rancher/go-rancher-metadata/metadata"
	"github.com/sirupsen/logrus"
)

const (
	mdVersion = "2015-12-19"

	answers1 = "./metadata_test_data/answers.host1.yml"
	answers2 = "./metadata_test_data/answers.host2.yml"
	answers3 = "./metadata_test_data/answers.host3.yml"

	simpleFile1 = "./metadata_test_data/ipsec.host1.json"
	simpleFile2 = "./metadata_test_data/ipsec.host2.json"
	simpleFile3 = "./metadata_test_data/ipsec.host3.json"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

//func TestGet

func TestMetadataStoreVsSimpleStore(t *testing.T) {
	tests := []struct {
		name        string
		answersFile string
		simpleFile  string
		clientIP    string
		localIP     string
		remoteIP    string
	}{
		{"host1", answers1, simpleFile1, "10.42.231.44", "10.42.114.70", "10.42.223.250"},
		{"host2", answers2, simpleFile2, "10.42.151.49", "10.42.128.187", "10.42.231.44"},
		{"host3", answers3, simpleFile3, "10.42.119.156", "10.42.223.250", "10.42.151.49"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newMetadataFixture(t, test.answersFile)
			metadataURL := server.URL + "/" + mdVersion

			simpleStore := NewSimpleStore(test.simpleFile, "")
			if err := simpleStore.Reload(); err != nil {
				t.Fatalf("reload simple store: %v", err)
			}

			metadataStore, err := NewMetadataStoreWithClientIP(metadataURL, test.clientIP)
			if err != nil {
				t.Fatalf("create metadata store: %v", err)
			}
			if err := metadataStore.Reload(); err != nil {
				t.Fatalf("reload metadata store: %v", err)
			}

			if !reflect.DeepEqual(simpleStore.Entries(), metadataStore.Entries()) {
				t.Error("expected Entries() to be equal")
			}
			if !reflect.DeepEqual(simpleStore.PeerEntriesMap(), metadataStore.PeerEntriesMap()) {
				t.Error("expected PeerEntriesMap() to be equal")
			}
			if !reflect.DeepEqual(simpleStore.RemoteEntriesMap(), metadataStore.RemoteEntriesMap()) {
				t.Error("expected RemoteEntriesMap() to be equal")
			}
			if simpleStore.LocalHostIpAddress() != metadataStore.LocalHostIpAddress() {
				t.Error("expected LocalHostIpAddress() to be equal")
			}
			if simpleStore.LocalIpAddress() != metadataStore.LocalIpAddress() {
				t.Error("expected LocalIpAddress() to be equal")
			}
			if simpleStore.IsRemote(test.localIP) != metadataStore.IsRemote(test.localIP) {
				t.Errorf("expected lookup result for local IP %s to be equal", test.localIP)
			}
			if simpleStore.IsRemote(test.remoteIP) != metadataStore.IsRemote(test.remoteIP) {
				t.Errorf("expected lookup result for remote IP %s to be equal", test.remoteIP)
			}
		})
	}
}

func TestGetHostsMapFromHostsArray(t *testing.T) {
	server := newMetadataFixture(t, answers1)
	mc, err := metadata.NewClientAndWait(server.URL + "/" + mdVersion)
	logrus.Debugf("mc: %v", mc)
	if err != nil {
		t.Fatalf("couldn't create metadata client: %v", err)
	}

	hosts, err := mc.GetHosts()
	if err != nil {
		t.Errorf("not expecting error, got: %v", err)
	}

	hostsMap := getHostsMapFromHostsArray(hosts)

	testUUID := "ce5d0147-8f2d-4e87-86ea-977dd61f83df"
	actual := hostsMap[testUUID].UUID

	if actual != testUUID {
		t.Errorf("expected ce5d0147-8f2d-4e87-86ea-977dd61f83df, got: %v", actual)
	}
}
