package ipsec

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PastureStack/ipsec-vxlan-overlay-network/store"
	"github.com/bronze1man/goStrongswanVici"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	reqId    = 1234
	reqIdStr = "1234"
	pskFile  = "psk.txt"
	pidFile  = "/var/run/charon.pid"

	ipsecHealthCheckInterval = 30 * time.Second
	ipsecInitiateDelay       = 5 * time.Second
	ipsecInitiateAttempts    = 3
	ipsecInitiateTimeout     = "12"
	hostRouteProtocol        = 186
)

type Overlay struct {
	sync.Mutex

	keyAttempt    map[string]bool
	hostAttempt   map[string]bool
	initiating    map[string]bool
	keys          map[string]string
	hosts         map[string]string
	templates     Templates
	db            store.Store
	psk           string
	netlinkHandle *netlink.Handle
	Blacklist     []string
	NetnsPath     string

	// UseHostTunnelSource keeps the metadata identity unchanged while allowing
	// the tunnel endpoints to be the host agent IP in host-netns XFRM mode.
	UseHostTunnelSource bool
	SyncHostRoutes      bool
}

func NewOverlay(configDir string, db store.Store) *Overlay {
	return &Overlay{
		db: db,
		templates: Templates{
			ConfigDir: configDir,
		},
		keys:       map[string]string{},
		hosts:      map[string]string{},
		initiating: map[string]bool{},
	}
}

func (o *Overlay) localTunnelAddress() string {
	if o.UseHostTunnelSource {
		return o.db.LocalHostIpAddress()
	}
	return o.db.LocalIpAddress()
}

func (o *Overlay) Start(launch bool, logFile string) {
	if launch {
		go runCharon(logFile, o.NetnsPath)
	} else {
		go o.monitorCharon()
	}

	if err := o.loadConns(); err != nil {
		logrus.Fatalf("Failed to load connections from charon: %v", err)
	}

	go o.monitorIpsecHealth()
}

func Test() error {
	client, err := getClient()
	if err != nil {
		return err
	}
	defer client.Close()

	if _, err := client.ListConns(""); err != nil {
		return err
	}

	return nil
}

func (o *Overlay) loadConns() error {
	o.Lock()
	defer o.Unlock()

	client, err := getClient()
	if err != nil {
		return err
	}
	defer client.Close()

	conns, err := client.ListConns("")
	if err != nil {
		return err
	}

	o.hosts = map[string]string{}

	for _, conn := range conns {
		for k := range conn {
			if strings.HasPrefix(k, "conn-") {
				logrus.Infof("Found existing connection: %s", k)
				o.hosts[strings.TrimPrefix(k, "conn-")] = o.templates.Revision()
			}
		}
	}

	return nil
}

func (o *Overlay) Reload() error {
	if err := o.db.Reload(); err != nil {
		return err
	}

	content, err := ioutil.ReadFile(path.Join(o.templates.ConfigDir, pskFile))
	if err != nil {
		return err
	}
	o.psk = strings.TrimSpace(string(content))

	return o.configure()
}

func (o *Overlay) monitorCharon() {
	pid := ""
	for {
		newPidBytes, err := ioutil.ReadFile(pidFile)
		if err != nil {
			logrus.Fatalf("Failed to read %s", pidFile)
		}
		newPid := strings.TrimSpace(string(newPidBytes))
		if pid == "" {
			pid = newPid
			logrus.Infof("Charon running PID: %s", pid)
		} else if pid != newPid {
			logrus.Fatalf("Charon restarted, old PID: %s, new PID: %s", pid, newPid)
		} else {
			o.Lock()
			if err := Test(); err != nil {
				logrus.Errorf("Killing charon due to: %v", err)
				o.killCharon(pid)
			}
			o.Unlock()
		}
		time.Sleep(2 * time.Second)
	}
}

func runCharon(logFile string, netnsPath string) {
	// Ignore error
	os.Remove("/var/run/charon.vici")

	args := []string{}
	for _, i := range strings.Split("dmn|mgr|ike|chd|cfg|knl|net|asn|tnc|imc|imv|pts|tls|esp|lib", "|") {
		args = append(args, "--debug-"+i)
		if logrus.GetLevel() == logrus.DebugLevel {
			args = append(args, "3")
		} else {
			args = append(args, "1")
		}
	}

	cmd := commandInNetns(netnsPath, "charon", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if logFile != "" {
		output, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			logrus.Fatalf("Failed to log to file %s: %v", logFile, err)
		}
		defer output.Close()
		cmd.Stdout = output
		cmd.Stderr = output
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	logrus.Fatalf("charon exited: %v", cmd.Run())
}

func commandInNetns(netnsPath, name string, args ...string) *exec.Cmd {
	if netnsPath == "" {
		return exec.Command(name, args...)
	}
	nsArgs := append([]string{"--net=" + netnsPath, name}, args...)
	return exec.Command("nsenter", nsArgs...)
}

func handleErr(firstErr, err error, fmt string, args ...interface{}) error {
	logrus.Errorf(fmt, args...)
	if firstErr != nil {
		return firstErr
	}
	return err
}

func (o *Overlay) configure() error {
	o.Lock()
	defer o.Unlock()
	logrus.Infof("Reconfiguring")

	if err := o.templates.Reload(); err != nil {
		return err
	}

	o.keyAttempt = map[string]bool{}
	o.hostAttempt = map[string]bool{}

	var firstErr error
	localHostIp := o.db.LocalHostIpAddress()
	hosts := map[string]bool{}
	hostRoutes := map[string]store.Entry{}

	policiesToAdd := map[string]netlink.XfrmPolicy{}
	existingPolicies, err := o.getRules()
	if err != nil {
		firstErr = handleErr(firstErr, err, "Failed to list rules for: %v", err)
	}

	if err := o.loadSharedKey(""); err != nil {
		firstErr = handleErr(firstErr, err, "Failed to load key for all peers: %v", err)
	}

	for _, entry := range o.db.Entries() {
		if entry.Peer {
			if err := o.loadSharedKey(entry.IpAddress); err != nil {
				firstErr = handleErr(firstErr, err, "Failed to set PSK for peer agent %s: %v", entry.IpAddress, err)
			}
		}

		if localHostIp == entry.HostIpAddress {
			continue
		}
		ipNoCidr := strings.Split(entry.IpAddress, "/")[0]
		hostRoutes[ipNoCidr] = entry
		if !hosts[entry.HostIpAddress] {
			if err := o.addHost(entry); err == nil {
				hosts[entry.HostIpAddress] = true
			} else {
				firstErr = handleErr(firstErr, err, "Failed to setup host %s: %v", entry.HostIpAddress, err)
			}
		}

		if err := o.addRules(entry, existingPolicies, policiesToAdd); err != nil {
			firstErr = handleErr(firstErr, err, "Failed to add rules for host %s, ip %s : %v", entry.HostIpAddress, entry.IpAddress, err)
		}
	}

	if firstErr == nil {
		firstErr = o.deletePolicies(existingPolicies)
	}

	if firstErr == nil {
		firstErr = o.addPolicies(policiesToAdd)
	}

	if firstErr == nil {
		firstErr = o.syncHostRoutes(hostRoutes)
	}

	if firstErr == nil {
		firstErr = o.restartForStalePeerIdentities()
	}

	if firstErr == nil {
		firstErr = o.removeHosts()
		// Currently VICI doesn't support unloading keys
	}

	if firstErr == nil {
		o.scheduleInitiatesLocked(hosts, ipsecInitiateDelay)
	}

	return firstErr
}

func cleanIP(value string) string {
	value = strings.Trim(value, " \t\r\n'\"")
	if strings.Contains(value, "/") {
		value = strings.SplitN(value, "/", 2)[0]
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (o *Overlay) expectedPeerIdentitiesByHost() map[string]map[string]bool {
	localHostIP := cleanIP(o.db.LocalHostIpAddress())
	expected := map[string]map[string]bool{}
	for _, entry := range o.db.PeerEntriesMap() {
		hostIP := cleanIP(entry.HostIpAddress)
		if hostIP == "" || hostIP == localHostIP {
			continue
		}

		identities := expected[hostIP]
		if identities == nil {
			identities = map[string]bool{}
			expected[hostIP] = identities
		}
		identities[hostIP] = true
		if overlayIP := cleanIP(entry.IpAddress); overlayIP != "" {
			identities[overlayIP] = true
		}
	}
	return expected
}

func stalePeerIdentity(childName, remoteID string, expected map[string]map[string]bool) (string, bool) {
	if !strings.HasPrefix(childName, "child-") {
		return "", false
	}
	hostIP := cleanIP(strings.TrimPrefix(childName, "child-"))
	remoteIP := cleanIP(remoteID)
	if hostIP == "" || remoteIP == "" {
		return "", false
	}
	identities, ok := expected[hostIP]
	if !ok {
		return "", false
	}
	return hostIP, !identities[remoteIP]
}

func (o *Overlay) restartForStalePeerIdentities() error {
	expected := o.expectedPeerIdentitiesByHost()
	if len(expected) == 0 {
		return nil
	}

	client, err := getClient()
	if err != nil {
		return err
	}
	defer client.Close()

	sas, err := client.ListSas("", "")
	if err != nil {
		return err
	}
	for _, saMap := range sas {
		for ikeName, sa := range saMap {
			for childName, childSA := range sa.Child_sas {
				if childSA.State != "INSTALLED" {
					continue
				}
				hostIP, stale := stalePeerIdentity(childName, sa.Remote_id, expected)
				if !stale {
					continue
				}
				logrus.Warnf("Detected stale IPsec peer identity in %s for host %s; restarting charon", ikeName, hostIP)
				o.restartCharonForRecovery(hostIP)
				return fmt.Errorf("stale IPsec peer identity for host %s", hostIP)
			}
		}
	}
	return nil
}

func (o *Overlay) scheduleInitiatesLocked(hosts map[string]bool, delay time.Duration) {
	if len(hosts) == 0 {
		return
	}

	targets := make([]string, 0, len(hosts))
	for host := range hosts {
		if host == "" || o.initiating[host] {
			continue
		}
		o.initiating[host] = true
		targets = append(targets, host)
	}
	sort.Strings(targets)

	if len(targets) == 0 {
		return
	}

	go func() {
		if delay > 0 {
			time.Sleep(delay)
		}
		for _, host := range targets {
			o.initiateHostWithRetry(host)
			o.Lock()
			delete(o.initiating, host)
			o.Unlock()
		}
	}()
}

func (o *Overlay) monitorIpsecHealth() {
	ticker := time.NewTicker(ipsecHealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := o.reconcileIpsecHealth(); err != nil {
			logrus.Warnf("IPsec health reconciliation failed: %v", err)
		}
	}
}

func (o *Overlay) reconcileIpsecHealth() error {
	localHostIp := o.db.LocalHostIpAddress()
	expectedHosts := map[string]bool{}
	for _, entry := range o.db.Entries() {
		if entry.HostIpAddress == "" || entry.HostIpAddress == localHostIp {
			continue
		}
		expectedHosts[entry.HostIpAddress] = true
	}
	if len(expectedHosts) == 0 {
		return nil
	}

	installedChildren, err := o.installedChildren()
	if err != nil {
		return err
	}

	missingHosts := map[string]bool{}
	for host := range expectedHosts {
		if !installedChildren["child-"+host] {
			missingHosts[host] = true
		}
	}
	if len(missingHosts) == 0 {
		return nil
	}

	logrus.Warnf("Detected %d missing IPsec CHILD_SA(s), scheduling recovery", len(missingHosts))
	o.Lock()
	o.scheduleInitiatesLocked(missingHosts, 0)
	o.Unlock()
	return nil
}

func (o *Overlay) initiateHostWithRetry(host string) {
	child := "child-" + host
	for i := 0; i < ipsecInitiateAttempts; i++ {
		if o.childInstalled(child) {
			logrus.Infof("CHILD_SA %s already installed", child)
			return
		}

		o.cleanupConntrack(host)
		cmd := exec.Command("swanctl", "--initiate", "--child", child, "--timeout", ipsecInitiateTimeout)
		out, err := cmd.CombinedOutput()
		if err == nil {
			logrus.Infof("Initiated CHILD_SA %s", child)
			return
		}

		logrus.Warnf("Failed to initiate CHILD_SA %s attempt %d: %v: %s", child, i+1, err, strings.TrimSpace(string(out)))
		time.Sleep(time.Duration(i+1) * 5 * time.Second)
	}

	logrus.Errorf("Failed to recover CHILD_SA %s after %d attempts, restarting charon", child, ipsecInitiateAttempts)
	o.restartCharonForRecovery(host)
}

func (o *Overlay) childInstalled(child string) bool {
	installed, err := o.installedChildren()
	if err != nil {
		logrus.Debugf("Unable to list SAs for %s: %v", child, err)
		return false
	}
	return installed[child]
}

func (o *Overlay) installedChildren() (map[string]bool, error) {
	client, err := getClient()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	sas, err := client.ListSas("", "")
	if err != nil {
		return nil, err
	}

	installed := map[string]bool{}
	for _, saMap := range sas {
		for _, sa := range saMap {
			for childName, childSA := range sa.Child_sas {
				if childSA.State == "INSTALLED" {
					installed[childName] = true
				}
			}
		}
	}

	return installed, nil
}

func (o *Overlay) cleanupConntrack(host string) {
	host = strings.Split(host, "/")[0]
	if net.ParseIP(host) == nil {
		return
	}

	filters := [][]string{
		{"-D", "-p", "udp", "-d", host},
		{"-D", "-p", "udp", "-s", host},
		{"-D", "-p", "udp", "-r", host},
		{"-D", "-p", "udp", "-q", host},
	}

	for _, filter := range filters {
		out, err := commandInNetns(o.NetnsPath, "conntrack", filter...).CombinedOutput()
		trimmed := strings.TrimSpace(string(out))
		if err == nil {
			if trimmed != "" {
				logrus.Infof("Cleared IPsec conntrack for host %s: %s", host, trimmed)
			}
			continue
		}
		if trimmed != "" {
			logrus.Debugf("Conntrack cleanup for host %s with args %v: %v: %s", host, filter, err, trimmed)
		} else {
			logrus.Debugf("Conntrack cleanup for host %s with args %v: %v", host, filter, err)
		}
	}
}

func (o *Overlay) restartCharonForRecovery(host string) {
	pidBytes, err := ioutil.ReadFile(pidFile)
	if err != nil {
		logrus.Errorf("Unable to restart charon for host %s recovery, failed to read %s: %v", host, pidFile, err)
		return
	}

	pid := strings.TrimSpace(string(pidBytes))
	logrus.Warnf("Killing charon PID %s to force IPsec recovery for host %s", pid, host)
	o.killCharon(pid)
}

func (o *Overlay) killCharon(pid string) {
	pidNum, err := strconv.Atoi(pid)
	if err == nil {
		err = syscall.Kill(pidNum, syscall.SIGKILL)
	}

	if err != nil {
		logrus.Errorf("Can't kill %s: %v", pid, err)
	}
}

func (o *Overlay) deletePolicies(policies map[string]netlink.XfrmPolicy) error {
	var lastErr error
	handle, err := o.xfrmHandle()
	if err != nil {
		return err
	}
	for _, policy := range policies {
		if err := handle.XfrmPolicyDel(&policy); err != nil {
			logrus.Errorf("Failed to delete policy: %+v, %v", policy, err)
			lastErr = err
		} else {
			logrus.Infof("Deleted policy: %+v", policy)
		}
	}
	return lastErr
}

func (o *Overlay) addPolicies(policies map[string]netlink.XfrmPolicy) error {
	var lastErr error
	handle, err := o.xfrmHandle()
	if err != nil {
		return err
	}
	for _, policy := range policies {
		if err := handle.XfrmPolicyAdd(&policy); err != nil {
			logrus.Errorf("Failed to add policy: %+v, %v", policy, err)
			lastErr = err
		} else {
			logrus.Infof("Added policy: %+v", policy)
		}
	}
	return lastErr
}

func (o *Overlay) getRules() (map[string]netlink.XfrmPolicy, error) {
	policies := map[string]netlink.XfrmPolicy{}
	handle, err := o.xfrmHandle()
	if err != nil {
		return nil, err
	}
	existing, err := handle.XfrmPolicyList(0)
	if err != nil {
		return nil, err
	}

	for _, policy := range existing {
		if policy.Dir != netlink.XFRM_DIR_IN && policy.Dir != netlink.XFRM_DIR_FWD && policy.Dir != netlink.XFRM_DIR_OUT {
			continue
		}
		policies[toKey(&policy)] = policy
	}

	return policies, nil
}

func (o *Overlay) xfrmHandle() (*netlink.Handle, error) {
	if o.netlinkHandle != nil {
		return o.netlinkHandle, nil
	}
	if o.NetnsPath == "" {
		handle, err := netlink.NewHandle()
		if err != nil {
			return nil, err
		}
		o.netlinkHandle = handle
		return o.netlinkHandle, nil
	}
	ns, err := netns.GetFromPath(o.NetnsPath)
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return nil, err
	}
	o.netlinkHandle = handle
	return o.netlinkHandle, nil
}

func (o *Overlay) runIP(args ...string) error {
	return o.runCommand("ip", args...)
}

func (o *Overlay) runCommand(name string, args ...string) error {
	cmd := commandInNetns(o.NetnsPath, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (o *Overlay) ensureOverlayNATBypass() error {
	chainArgs := []string{"-t", "nat", "-S", "CATTLE_NAT_POSTROUTING"}
	args := []string{"-t", "nat", "-C", "CATTLE_NAT_POSTROUTING", "-s", "10.42.0.0/16", "-d", "10.42.0.0/16", "-j", "ACCEPT"}
	insertArgs := []string{"-t", "nat", "-I", "CATTLE_NAT_POSTROUTING", "1", "-s", "10.42.0.0/16", "-d", "10.42.0.0/16", "-j", "ACCEPT"}

	var firstErr error
	for _, binary := range []string{"iptables", "iptables-nft", "iptables-legacy"} {
		if _, err := exec.LookPath(binary); err != nil {
			continue
		}
		if err := o.runCommand(binary, chainArgs...); err != nil {
			logrus.Debugf("Skipping overlay NAT bypass for %s because CATTLE_NAT_POSTROUTING is unavailable: %v", binary, err)
			continue
		}
		if err := o.runCommand(binary, args...); err == nil {
			continue
		}
		if err := o.runCommand(binary, insertArgs...); err != nil {
			firstErr = handleErr(firstErr, err, "Failed to ensure overlay NAT bypass with %s: %v", binary, err)
		}
	}

	return firstErr
}

func (o *Overlay) ensureOverlayForwardJump() error {
	chainArgs := []string{"-S", "CATTLE_FORWARD"}
	createChainArgs := []string{"-N", "CATTLE_FORWARD"}
	acceptArgs := []string{"-C", "CATTLE_FORWARD", "-s", "10.42.0.0/16", "-d", "10.42.0.0/16", "-j", "ACCEPT"}
	insertAcceptArgs := []string{"-I", "CATTLE_FORWARD", "1", "-s", "10.42.0.0/16", "-d", "10.42.0.0/16", "-j", "ACCEPT"}
	jumpArgs := []string{"-C", "FORWARD", "-j", "CATTLE_FORWARD"}
	insertJumpArgs := []string{"-I", "FORWARD", "1", "-j", "CATTLE_FORWARD"}

	var firstErr error
	for _, backend := range []struct {
		binary          string
		createIfMissing bool
	}{
		{binary: "iptables", createIfMissing: true},
		{binary: "iptables-nft", createIfMissing: true},
		{binary: "iptables-legacy"},
	} {
		binary := backend.binary
		if _, err := exec.LookPath(binary); err != nil {
			continue
		}
		if err := o.runCommand(binary, chainArgs...); err != nil {
			if !backend.createIfMissing {
				logrus.Debugf("Skipping overlay forward jump for %s because CATTLE_FORWARD is unavailable: %v", binary, err)
				continue
			}
			if err := o.runCommand(binary, createChainArgs...); err != nil {
				firstErr = handleErr(firstErr, err, "Failed to create overlay forward chain with %s: %v", binary, err)
				continue
			}
		}
		if err := o.runCommand(binary, acceptArgs...); err != nil {
			if err := o.runCommand(binary, insertAcceptArgs...); err != nil {
				firstErr = handleErr(firstErr, err, "Failed to ensure overlay forward accept with %s: %v", binary, err)
			}
		}
		if err := o.runCommand(binary, jumpArgs...); err == nil {
			continue
		}
		if err := o.runCommand(binary, insertJumpArgs...); err != nil {
			firstErr = handleErr(firstErr, err, "Failed to ensure overlay forward jump with %s: %v", binary, err)
		}
	}

	return firstErr
}

func (o *Overlay) routeDevice(remoteHostIP net.IP) (string, error) {
	handle, err := o.xfrmHandle()
	if err != nil {
		return "", err
	}
	routes, err := handle.RouteGet(remoteHostIP)
	if err != nil {
		return "", err
	}
	if len(routes) == 0 || routes[0].LinkIndex == 0 {
		return "", fmt.Errorf("no route device found for host %s", remoteHostIP)
	}
	link, err := handle.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", err
	}
	return link.Attrs().Name, nil
}

func (o *Overlay) syncHostRoutes(desired map[string]store.Entry) error {
	if !o.SyncHostRoutes {
		return nil
	}

	var firstErr error
	if err := o.ensureOverlayNATBypass(); err != nil {
		firstErr = handleErr(firstErr, err, "Failed to sync IPsec overlay NAT bypass: %v", err)
	}
	if err := o.ensureOverlayForwardJump(); err != nil {
		firstErr = handleErr(firstErr, err, "Failed to sync IPsec overlay forward jump: %v", err)
	}

	desiredIPs := map[string]bool{}
	for ipAddress, entry := range desired {
		overlayIP := net.ParseIP(ipAddress)
		remoteHostIP := net.ParseIP(entry.HostIpAddress)
		if overlayIP == nil || remoteHostIP == nil {
			firstErr = handleErr(firstErr, fmt.Errorf("invalid route entry ip=%q host=%q", ipAddress, entry.HostIpAddress), "Invalid IPsec host route entry ip=%q host=%q", ipAddress, entry.HostIpAddress)
			continue
		}
		desiredIPs[ipAddress] = true

		dev, err := o.routeDevice(remoteHostIP)
		if err != nil {
			firstErr = handleErr(firstErr, err, "Failed to resolve route device for remote host %s: %v", entry.HostIpAddress, err)
			continue
		}

		dst := fmt.Sprintf("%s/32", ipAddress)
		if err := o.runIP("route", "replace", dst, "via", entry.HostIpAddress, "dev", dev, "proto", strconv.Itoa(hostRouteProtocol)); err != nil {
			firstErr = handleErr(firstErr, err, "Failed to sync IPsec host route %s via %s dev %s: %v", dst, entry.HostIpAddress, dev, err)
			continue
		}
		logrus.Debugf("Synced IPsec host route %s via %s dev %s", dst, entry.HostIpAddress, dev)
	}

	handle, err := o.xfrmHandle()
	if err != nil {
		return handleErr(firstErr, err, "Failed to create netlink handle for stale IPsec route cleanup: %v", err)
	}
	routes, err := handle.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return handleErr(firstErr, err, "Failed to list host routes for stale IPsec route cleanup: %v", err)
	}
	for _, route := range routes {
		if route.Protocol != hostRouteProtocol || route.Dst == nil || route.Dst.IP == nil {
			continue
		}
		ipAddress := route.Dst.IP.String()
		if desiredIPs[ipAddress] {
			continue
		}
		if err := o.runIP("route", "del", route.Dst.String(), "proto", strconv.Itoa(hostRouteProtocol)); err != nil {
			firstErr = handleErr(firstErr, err, "Failed to delete stale IPsec host route %s: %v", route.Dst.String(), err)
			continue
		}
		logrus.Infof("Deleted stale IPsec host route %s", route.Dst.String())
	}

	return firstErr
}

func (o *Overlay) removeHosts() error {
	var firstErr error

	for k, _ := range o.hosts {
		if !o.hostAttempt[k] {
			if err := o.removeHost(k); err != nil {
				firstErr = handleErr(firstErr, err, "Failed to add remove connection for host %s: %v", k, err)
			} else {
				logrus.Infof("Removed connection for %s", k)
				delete(o.hosts, k)
			}
		}
	}

	return firstErr
}

func (o *Overlay) removeHost(host string) error {
	client, err := getClient()
	if err != nil {
		return err
	}
	defer client.Close()

	name := "conn-" + strings.Split(host, "/")[0]
	logrus.Infof("Removing connection for %s", name)
	return client.UnloadConn(&goStrongswanVici.UnloadConnRequest{
		Name: name,
	})
}

func getClient() (*goStrongswanVici.ClientConn, error) {
	var err error
	for i := 0; i < 3; i++ {
		var client *goStrongswanVici.ClientConn
		client, err = goStrongswanVici.NewClientConnFromDefaultSocket()
		if err == nil {
			return client, nil
		}

		if i > 0 {
			logrus.Errorf("Failed to connect to charon: %v", err)
		}
		time.Sleep(1 * time.Second)
	}

	return nil, err
}

func (o *Overlay) addHost(entry store.Entry) error {
	if err := o.loadSharedKey(entry.HostIpAddress); err != nil {
		return err
	}

	return o.addHostConnection(entry)
}

func (o *Overlay) loadSharedKey(ipAddress string) error {
	ipAddress = strings.Split(ipAddress, "/")[0]
	key := o.getPsk(ipAddress)

	o.keyAttempt[ipAddress] = true
	if o.keys[ipAddress] == key {
		logrus.Debugf("Key for %s already loaded", ipAddress)
		return nil
	}

	client, err := getClient()
	if err != nil {
		return err
	}
	defer client.Close()

	sharedKey := &goStrongswanVici.Key{
		Typ:    "IKE",
		Data:   key,
		Owners: []string{ipAddress},
	}

	err = client.LoadShared(sharedKey)
	if err != nil {
		logrus.Infof("Failed to load pre-shared key for %s: %v", ipAddress, err)
		return err
	}

	o.keys[ipAddress] = key
	logrus.Infof("Loaded pre-shared key for %s", ipAddress)
	return nil
}

func (o *Overlay) filterAlgos(algos []string) []string {
	ret := []string{}
	for _, algo := range algos {
		add := true
		for _, ignore := range o.Blacklist {
			if strings.HasPrefix(algo, ignore) {
				add = false
				break
			}
		}
		if add {
			ret = append(ret, algo)
		}
	}

	return ret
}

func (o *Overlay) addHostConnection(entry store.Entry) error {
	o.hostAttempt[entry.HostIpAddress] = true
	if o.hosts[entry.HostIpAddress] == o.templates.Revision() {
		logrus.Debugf("Connection already loaded for host %s", entry.HostIpAddress)
		return nil
	}

	client, err := getClient()
	if err != nil {
		return err
	}
	defer client.Close()

	childSAConf := o.templates.NewChildSaConf()
	childSAConf.ESPProposals = o.filterAlgos(childSAConf.ESPProposals)
	childSAConf.ReqID = reqIdStr
	if strings.Compare(entry.HostIpAddress, o.db.LocalHostIpAddress()) < 0 {
		childSAConf.RekeyTime = "8760h"
	}

	ikeConf := o.templates.NewIkeConf()
	ikeConf.Proposals = o.filterAlgos(ikeConf.Proposals)
	if o.UseHostTunnelSource {
		ikeConf.LocalAddrs = []string{o.localTunnelAddress()}
	}
	ikeConf.RemoteAddrs = []string{entry.HostIpAddress}
	ikeConf.Children = map[string]goStrongswanVici.ChildSAConf{
		"child-" + entry.HostIpAddress: childSAConf,
	}

	name := fmt.Sprintf("conn-%s", entry.HostIpAddress)
	// Loading connections doesn't seem to be very reliable, can't get info
	// why it's failing though.
	for i := 0; i < 3; i++ {
		err = client.LoadConn(&map[string]goStrongswanVici.IKEConf{
			name: ikeConf,
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		logrus.Errorf("Failed loading connection %s: %v", name, err)
		return err
	}

	o.hosts[entry.HostIpAddress] = o.templates.Revision()
	logrus.Infof("Loaded connection: %v, %v, %v", name, ikeConf.Proposals, childSAConf.ESPProposals)

	return nil
}

func toKey(p *netlink.XfrmPolicy) string {
	buffer := bytes.Buffer{}
	buffer.WriteString(p.Dir.String())
	buffer.WriteRune('-')
	if p.Src != nil {
		buffer.WriteString(p.Src.String())
	}
	buffer.WriteRune('-')
	if p.Dst != nil {
		buffer.WriteString(p.Dst.String())
	}
	buffer.WriteRune('-')
	if len(p.Tmpls) > 0 {
		buffer.WriteString(p.Tmpls[0].Src.String())
		buffer.WriteRune('-')
		buffer.WriteString(p.Tmpls[0].Dst.String())
		buffer.WriteRune('-')
		buffer.WriteString(strconv.Itoa(p.Tmpls[0].Reqid))
	}

	return buffer.String()
}

func (o *Overlay) addRules(entry store.Entry, existingPolicies map[string]netlink.XfrmPolicy, policiesToAdd map[string]netlink.XfrmPolicy) error {
	localIp := net.ParseIP(o.localTunnelAddress())
	remoteHostIp := net.ParseIP(entry.HostIpAddress)

	ip, ipNet, err := net.ParseCIDR(entry.IpAddress)
	if err != nil {
		return err
	}

	_, ipDirectNet, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		return err
	}

	outPolicy := netlink.XfrmPolicy{
		Src:      ipNet,
		Dst:      ipDirectNet,
		Dir:      netlink.XFRM_DIR_OUT,
		Priority: 10000,
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   localIp,
				Dst:   remoteHostIp,
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TUNNEL,
				Reqid: reqId,
			},
		},
	}
	inPolicy := netlink.XfrmPolicy{
		Src:      ipDirectNet,
		Dst:      ipNet,
		Dir:      netlink.XFRM_DIR_IN,
		Priority: 10000,
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   remoteHostIp,
				Dst:   localIp,
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TUNNEL,
				Reqid: reqId,
			},
		},
	}
	fwdPolicy := netlink.XfrmPolicy{
		Src:      ipDirectNet,
		Dst:      ipNet,
		Dir:      netlink.XFRM_DIR_FWD,
		Priority: 10000,
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   remoteHostIp,
				Dst:   localIp,
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TUNNEL,
				Reqid: reqId,
			},
		},
	}

	var lastErr error
	for _, policy := range []netlink.XfrmPolicy{outPolicy, inPolicy, fwdPolicy} {
		key := toKey(&policy)
		if _, ok := existingPolicies[key]; ok {
			delete(existingPolicies, key)
		} else {
			policiesToAdd[key] = policy
		}
	}

	return lastErr
}

func (o *Overlay) getPsk(hostIp string) string {
	return o.psk
}
