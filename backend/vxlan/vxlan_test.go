package vxlan

import (
	"fmt"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/store"
	"github.com/rancher/go-rancher-metadata/metadata"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// NewTestOverlay is used to create a new VXLAN Overlay network
// for testing purposes
func NewTestOverlay(v *vxlanIntfInfo, db store.Store) (*Overlay, error) {
	logrus.Debugf("vxlan: creating new overlay: %+v", v)
	mc, err := metadata.NewClientAndWait(store.DefaultMetadataURL)
	if err != nil {
		return nil, err
	}

	return &Overlay{
		m:  mc,
		db: db,
		v:  v,
	}, nil
}

func newNetlinkTestOverlay(v *vxlanIntfInfo) *Overlay {
	return &Overlay{v: v}
}

func skipIfNetlinkUnavailable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not supported") || strings.Contains(msg, "address family not supported") {
		t.Skipf("requires privileged netlink/VXLAN support: %v", err)
	}
}

func getRandomVxlanInterface() *vxlanIntfInfo {
	vni := 10000 + rand.Intn(50000)
	name := fmt.Sprintf("vtep%v", vni)

	vtepMAC1, _ := net.ParseMAC("00:00:00:00:01:01")

	vx := &vxlanIntfInfo{
		name: name,
		vni:  vni,
		port: vni,
		mac:  vtepMAC1,
		mtu:  vxlanMTU,
	}
	logrus.Debugf("vx: %+v", vx)
	return vx
}

func TestABCD(t *testing.T) {
	getRandomVxlanInterface()
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Some of the tests which involve the actual interfaces, need to
// run either in a privileged container or using sudo.
// Easy way would be to mount the source code inside a go container
// and build/run/test.

func TestCreateDeleteVTEP(t *testing.T) {
	vx := getRandomVxlanInterface()
	o := newNetlinkTestOverlay(vx)

	err := o.checkAndCreateVTEP()
	skipIfNetlinkUnavailable(t, err)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = o.checkAndDeleteVTEP()
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}
}

func TestAddDeleteVxlanStaticRoute(t *testing.T) {
	vx := getRandomVxlanInterface()
	o := newNetlinkTestOverlay(vx)

	ip := net.ParseIP("1.1.1.1")
	mac, _ := net.ParseMAC("00:00:11:11:11:11")

	err := o.checkAndCreateVTEP()
	skipIfNetlinkUnavailable(t, err)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = addVxlanForwardingEntry(vx.name, mac, ip)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = deleteVxlanForwardingEntry(vx.name, mac, ip)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = o.checkAndDeleteVTEP()
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

}

func TestGetMACAddressForVxlanIP(t *testing.T) {
	inputVxlanIP := "10.42.29.78"
	macprefix := "00:ab:00:00:00:00"
	expected := "00:ab:0a:2a:1d:4e"

	actual, _ := getMACAddressForVxlanIP(macprefix, net.ParseIP(inputVxlanIP))
	if actual.String() != expected {
		t.Errorf("expected: %v, actual: %v", expected, actual)
	}
}

func TestAddDelRoute(t *testing.T) {
	vxlanContainerIP := "10.42.2.2"
	vtepMAC1, _ := net.ParseMAC("00:00:00:00:01:01")
	intfName := randSeq(8)

	v := &vxlanIntfInfo{
		name: intfName,
		vni:  vxlanVni,
		port: vxlanPort,
		mac:  vtepMAC1,
		mtu:  vxlanMTU,
	}

	err := createVxlanInterface(v)
	skipIfNetlinkUnavailable(t, err)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	ip, _ := netlink.ParseIPNet("10.1.1.1/32")

	via1 := net.ParseIP(vxlanContainerIP)
	//via2 := net.ParseIP(vtepIPStr3)

	err = addRoute(ip, via1, "")
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = delRoute(ip, via1, "")
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = addRoute(ip, nil, v.name)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = delRoute(ip, nil, v.name)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = deleteVxlanInterface(intfName)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

}

func TestAddDelARPEntry(t *testing.T) {
	vx := getRandomVxlanInterface()
	o := newNetlinkTestOverlay(vx)

	err := o.checkAndCreateVTEP()
	skipIfNetlinkUnavailable(t, err)

	ip := net.ParseIP("1.1.1.1")
	mac, _ := net.ParseMAC("00:00:11:11:11:11")

	err = addARPEntry(vx.name, ip, mac)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = delARPEntry(vx.name, ip, mac)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	o.checkAndDeleteVTEP()
}

func waitForFile(file string) string {
	for i := 0; i < 60; i++ {
		if _, err := os.Stat(file); err == nil {
			return file
		}

		logrus.Infof("Waiting for file %s", file)
		time.Sleep(1 * time.Second)
	}
	logrus.Fatalf("Failed to find %s", file)
	return ""
}

func TestDiffEntries(t *testing.T) {
	oldDB := store.NewSimpleStore(waitForFile("oldEntries.json"), "")
	oldDB.Reload()

	newDB := store.NewSimpleStore(waitForFile("newEntries.json"), "")
	newDB.Reload()

	oldMap := oldDB.RemoteEntriesMap()
	newMap := newDB.RemoteEntriesMap()
	diff := calculateDiffOfEntries(oldMap, newMap)

	logrus.Debugf("After oldMap: %+v", oldMap)

	logrus.Debugf("diff: %+v", diff)
	if len(diff.toAdd) != 1 || len(diff.toDel) != 1 || len(diff.toUpd) != 1 {
		t.Errorf("not expected lengths")
	}
}

func TestDBEntries(t *testing.T) {
	db := store.NewSimpleStore(waitForFile("entries.json"), "")
	db.Reload()

	m := buildPeersMapping(db.PeerEntriesMap())

	expectedLength := 1
	actualLength := len(m)
	if actualLength != expectedLength {
		t.Errorf("expected length: %v got: %v", expectedLength, actualLength)
	}

	expectedIP := "10.42.100.17"
	actualIP := m["172.22.101.101"].String()
	if actualIP != expectedIP {
		t.Errorf("expected: %v got: %v", expectedIP, actualIP)
	}
}

func TestFindVxlanInterace(t *testing.T) {
	_, err := findVxlanInterface("vtep123")
	if err == nil {
		t.Errorf("Expecting error, but got no error")
	}

	_, err = findVxlanInterface("eth0")
	if err != nil {
		t.Errorf("Not expecting error, but got %v", err)
	}
}

func TestPeerVxlanEntryOperations(t *testing.T) {
	var err error

	vtepMAC1, _ := net.ParseMAC("00:00:00:00:01:01")
	intfName := randSeq(8)

	vx := &vxlanIntfInfo{
		name: intfName,
		vni:  vxlanVni,
		port: vxlanPort,
		mac:  vtepMAC1,
		mtu:  vxlanMTU,
	}

	err = createVxlanInterface(vx)
	skipIfNetlinkUnavailable(t, err)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}
	e := store.Entry{
		IpAddress:     "10.42.1.1/16",
		HostIpAddress: "52.1.1.1",
	}

	v, err := newPeerVxlanEntry(intfName, e)
	if err != nil {
		t.Errorf("Error creating new peer entry: %v", err)
	}
	if v == nil {
		t.Errorf("Not expecting nil")
	}

	err = v.add()
	if err != nil {
		t.Errorf("Not expecting error, got: %v", err)
	}

	err = v.del()
	if err != nil {
		t.Errorf("Not expecting error, got: %v", err)
	}

	err = deleteVxlanInterface(intfName)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

}

func TestRemoteVxlanEntryOperations(t *testing.T) {
	var err error

	vx := getRandomVxlanInterface()
	err = createVxlanInterface(vx)
	skipIfNetlinkUnavailable(t, err)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}
	db := store.NewSimpleStore(waitForFile("entries.json"), "")
	db.Reload()

	m := buildPeersMapping(db.PeerEntriesMap())

	e := store.Entry{
		IpAddress:     "10.42.13.108/16",
		HostIpAddress: "172.22.101.101",
	}

	v, err := newRemoteVxlanEntry(vx.name, e, m)
	if err != nil {
		t.Errorf("Error creating new remote entry: %v", err)
	}
	if v == nil {
		t.Errorf("Not expecting nil")
	}

	expectedVia := "10.42.100.17"
	actualVia := v.via.String()
	if actualVia != expectedVia {
		t.Errorf("expected: %v actual: %v", expectedVia, actualVia)
	}

	err = v.add()
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	v.via = nil
	err = v.del()
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}

	err = deleteVxlanInterface(vx.name)
	if err != nil {
		t.Errorf("No error expected, got: %v", err)
	}
}

func TestVxlanFunctionality(t *testing.T) {
	db, err := store.NewMetadataStore("")
	if err != nil || db == nil {
		t.Skipf("requires the platform metadata service: %v", err)
	}
	logrus.Infof("db: %+v", db)
	if err := db.Reload(); err != nil {
		t.Skipf("requires usable platform metadata: %v", err)
	}

	o, err := NewOverlay("", db)
	if err != nil || o == nil {
		t.Skipf("requires a metadata-backed VXLAN overlay: %v", err)
	}
	logrus.Infof("o=%+v", o)
	o.configure()
	o.Reload()
	o.cleanup()
}

func TestGetMyVtepInfo(t *testing.T) {
	vx := getRandomVxlanInterface()
	db, err := store.NewMetadataStore("")
	if err != nil || db == nil {
		t.Skipf("requires the platform metadata service: %v", err)
	}
	if err := db.Reload(); err != nil {
		t.Skipf("requires usable platform metadata: %v", err)
	}
	o, err := NewTestOverlay(vx, db)
	if err != nil || o == nil {
		t.Skipf("requires a metadata-backed VXLAN overlay: %v", err)
	}

	mac, err := o.GetMyVTEPInfo()
	if err != nil {
		t.Fatalf("unexpected VTEP info error: %v", err)
	}

	if mac.String() == "" {
		t.Error("Expecting a MAC address")
	}
}
