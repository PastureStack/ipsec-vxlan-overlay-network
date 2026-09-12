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

	"github.com/PastureStack/ipsec-vxlan-overlay-network/internal/logsafe"
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
		logrus.Fatalf("Failed to load connections from charon: %s", logsafe.Value(err))
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
				logrus.Infof("Found existing connection: %s", logsafe.Value(k))
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
			logrus.Infof("Charon running PID: %s", logsafe.Value(pid))
		} else if pid != newPid {
			logrus.Fatalf("Charon restarted, old PID: %s, new PID: %s", logsafe.Value(pid), logsafe.Value(newPid))
		} else {
			o.Lock()
			if err := Test(); err != nil {
				logrus.Errorf("Killing charon due to: %s", logsafe.Value(err))
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
			logrus.Fatalf("Failed to log to file %s: %s", logsafe.Value(logFile), logsafe.Value(err))
		}
		defer output.Close()
		cmd.Stdout = output
		cmd.Stderr = output
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}

	logrus.Fatalf("charon exited: %s", logsafe.Value(cmd.Run()))
}

func commandInNetns(netnsPath, name string, args ...string) *exec.Cmd {
	if netnsPath == "" {
		return exec.Command(name, args...)
	}
	nsArgs := append([]string{"--net=" + netnsPath, name}, args...)
	return exec.Command("nsenter", nsArgs...)
}

func handleErr(firstErr, err error, format string, args ...interface{}) error {
	logrus.Error(logsafe.Value(fmt.Sprintf(format, args...)))
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

// childHostIP returns the peer IP encoded in a configured CHILD_SA name.
// strongSwan appends the CHILD_SA unique ID to names reported by VICI (for
// example, child-192.0.2.20-3).  Health reconciliation must compare the
// configured name, not the unique runtime instance name, or it will
// repeatedly initiate a duplicate SA and eventually restart charon.
func childHostIP(childName string) string {
	if !strings.HasPrefix(childName, "child-") {
		return ""
	}

	value := strings.TrimPrefix(childName, "child-")
	if hostIP := cleanIP(value); hostIP != "" {
		return hostIP
	}

	separator := strings.LastIndex(value, "-")
	if separator <= 0 {
		return ""
	}
	if _, err := strconv.ParseUint(value[separator+1:], 10, 64); err != nil {
		return ""
	}
	return cleanIP(value[:separator])
}

func canonicalChildName(childName string) string {
	hostIP := childHostIP(childName)
	if hostIP == "" {
		return ""
	}
	return "child-" + hostIP
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
	hostIP := childHostIP(childName)
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
				logrus.Warnf("Detected stale IPsec peer identity in %s for host %s; restarting charon", logsafe.Value(ikeName), logsafe.Value(hostIP))
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
			logrus.Warnf("IPsec health reconciliation failed: %s", logsafe.Value(err))
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
			logrus.Infof("CHILD_SA %s already installed", logsafe.Value(child))
			return
		}

		o.cleanupConntrack(host)
		cmd := exec.Command("swanctl", "--initiate", "--child", child, "--timeout", ipsecInitiateTimeout)
		out, err := cmd.CombinedOutput()
		if err == nil {
			logrus.Infof("Initiated CHILD_SA %s", logsafe.Value(child))
			return
		}

		logrus.Warnf("Failed to initiate CHILD_SA %s attempt %d: %s: %s", logsafe.Value(child), i+1, logsafe.Value(err), logsafe.Value(strings.TrimSpace(string(out))))
		time.Sleep(time.Duration(i+1) * 5 * time.Second)
	}

	// A peer can be unavailable during a normal host or Docker restart. Killing
	// charon here also drops healthy associations with unrelated peers. The
	// periodic health reconciliation will schedule another attempt if this
	// CHILD_SA is still missing; reserve a charon restart for stale local peer
	// identity, where retrying the same state cannot repair it.
	logrus.Warnf("CHILD_SA %s is unavailable after %d attempts; periodic health reconciliation will retry", logsafe.Value(child), ipsecInitiateAttempts)
}

func (o *Overlay) childInstalled(child string) bool {
	installed, err := o.installedChildren()
	if err != nil {
		logrus.Debugf("Unable to list SAs for %s: %s", logsafe.Value(child), logsafe.Value(err))
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
					canonical := canonicalChildName(childName)
					if canonical == "" {
						canonical = childName
					}
					installed[canonical] = true
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
				logrus.Infof("Cleared IPsec conntrack for host %s: %s", logsafe.Value(host), logsafe.Value(trimmed))
			}
			continue
		}
		if trimmed != "" {
			logrus.Debugf("Conntrack cleanup for host %s with args %s: %s: %s", logsafe.Value(host), logsafe.Value(filter), logsafe.Value(err), logsafe.Value(trimmed))
		} else {
			logrus.Debugf("Conntrack cleanup for host %s with args %s: %s", logsafe.Value(host), logsafe.Value(filter), logsafe.Value(err))
		}
	}
}

func (o *Overlay) restartCharonForRecovery(host string) {
	pidBytes, err := ioutil.ReadFile(pidFile)
	if err != nil {
		logrus.Errorf("Unable to restart charon for host %s recovery, failed to read %s: %s", logsafe.Value(host), pidFile, logsafe.Value(err))
		return
	}

	pid := strings.TrimSpace(string(pidBytes))
	logrus.Warnf("Killing charon PID %s to force IPsec recovery for host %s", logsafe.Value(pid), logsafe.Value(host))
	o.killCharon(pid)
}

func (o *Overlay) killCharon(pid string) {
	pidNum, err := strconv.Atoi(pid)
	if err == nil {
		err = syscall.Kill(pidNum, syscall.SIGKILL)
	}

	if err != nil {
		logrus.Errorf("Can't kill %s: %s", logsafe.Value(pid), logsafe.Value(err))
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
			logrus.Errorf("Failed to delete policy: %s, %s", logsafe.Value(policy), logsafe.Value(err))
			lastErr = err
		} else {
			logrus.Infof("Deleted policy: %s", logsafe.Value(policy))
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
			logrus.Errorf("Failed to add policy: %s, %s", logsafe.Value(policy), logsafe.Value(err))
			lastErr = err
		} else {
			logrus.Infof("Added policy: %s", logsafe.Value(policy))
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
		logrus.Debugf("Synced IPsec host route %s via %s dev %s", logsafe.Value(dst), logsafe.Value(entry.HostIpAddress), logsafe.Value(dev))
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
		logrus.Infof("Deleted stale IPsec host route %s", logsafe.Value(route.Dst.String()))
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
				logrus.Infof("Removed connection for %s", logsafe.Value(k))
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
	logrus.Infof("Removing connection for %s", logsafe.Value(name))
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
			logrus.Errorf("Failed to connect to charon: %s", logsafe.Value(err))
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
		logrus.Debugf("Key for %s already loaded", logsafe.Value(ipAddress))
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
		logrus.Infof("Failed to load pre-shared key for %s: %s", logsafe.Value(ipAddress), logsafe.Value(err))
		return err
	}

	o.keys[ipAddress] = key
	logrus.Infof("Loaded pre-shared key for %s", logsafe.Value(ipAddress))
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
		logrus.Debugf("Connection already loaded for host %s", logsafe.Value(entry.HostIpAddress))
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
		logrus.Errorf("Failed loading connection %s: %s", logsafe.Value(name), logsafe.Value(err))
		return err
	}

	o.hosts[entry.HostIpAddress] = o.templates.Revision()
	logrus.Infof("Loaded connection %s with %d IKE and %d ESP proposals", logsafe.Value(name), len(ikeConf.Proposals), len(childSAConf.ESPProposals))

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
