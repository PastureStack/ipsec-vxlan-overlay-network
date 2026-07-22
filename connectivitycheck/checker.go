package connectivitycheck

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rancher/go-rancher-metadata/metadata"
	"github.com/sirupsen/logrus"
)

const (
	defaultMetadataAddress = "169.254.169.250"
	defaultCheckInterval   = 5000
	defaultPeerTimeout     = 1000
	defaultServerPort      = 80

	metadataURLTemplate           = "http://%s/2016-07-29"
	connectivityCheckServiceName  = "connectivity-check"
	ipsecServiceHealthcheckFlag   = "ipsec.service.enable.healthcheck"
	expectedPeerPingResponse      = "pong"
	connectivityHealthyResponse   = "OK"
	connectivityUnhealthyResponse = "NOT OK"
)

// Version is set by main so the sidecar command reports the same build tag as
// the primary overlay binary.
var Version = "v0.0.0-dev"

type host struct {
	UUID       string `json:"uuid"`
	AgentIP    string `json:"agent_ip"`
	State      string `json:"state"`
	AgentState string `json:"agent_state"`
}

type container struct {
	UUID      string `json:"uuid"`
	HostUUID  string `json:"host_uuid"`
	PrimaryIP string `json:"primary_ip"`
	State     string `json:"state"`
}

type service struct {
	Name       string                 `json:"name"`
	State      string                 `json:"state"`
	Metadata   map[string]interface{} `json:"metadata"`
	Containers []container            `json:"containers"`
}

type metadataClient interface {
	SendRequest(string) ([]byte, error)
}

type metadataSnapshot struct {
	ipsecState         string
	connCheckState     string
	healthcheckEnabled bool
	hosts              map[string]*host
	peerContainers     map[string]*container
	checkContainers    map[string]*container
}

type peer struct {
	sync.Mutex
	uuid              string
	host              *host
	container         *container
	checkContainer    *container
	stop              chan struct{}
	count             int
	checkInterval     time.Duration
	connectionTimeout time.Duration
	lastChecked       time.Time
	randomOffset      time.Duration
}

type checker struct {
	sync.Mutex
	client            metadataClient
	port              int
	checkInterval     time.Duration
	connectionTimeout time.Duration
	peers             map[string]*peer
	peersByIP         map[string]*peer
	ok                bool
	server            *http.Server
	listener          net.Listener
	stop              chan struct{}
}

// Run starts the IPsec connectivity-check sidecar command. It preserves the
// compatibility command-line and HTTP contract: /ping returns
// "pong", /connectivity returns 200 "OK" only when peer checks are healthy,
// and the default listen port is 80.
func Run(args []string) error {
	var metadataAddress string
	var intervalMillis int
	var peerTimeoutMillis int
	var port int
	var debug bool
	var showVersion bool

	fs := flag.NewFlagSet("connectivity-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&metadataAddress, "metadata-address", envString("PASTURESTACK_METADATA_ADDRESS", envString("RANCHER_METADATA_ADDRESS", defaultMetadataAddress)), "platform metadata address")
	fs.IntVar(&intervalMillis, "connectivity-check-interval", envInt("CONNECTIVITY_CHECK_INTERVAL", defaultCheckInterval), "peer check interval in milliseconds")
	fs.IntVar(&peerTimeoutMillis, "peer-connection-timeout", envInt("PEER_CONNECTION_TIMEOUT", defaultPeerTimeout), "peer connection timeout in milliseconds")
	fs.IntVar(&port, "port", defaultServerPort, "listen port")
	fs.BoolVar(&debug, "debug", envBool("PASTURESTACK_DEBUG") || envBool("RANCHER_DEBUG"), "enable debug logging")
	fs.BoolVar(&showVersion, "version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Println(Version)
		return nil
	}
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if !validPort(port) {
		logrus.Warnf("Invalid port %d, using default %d", port, defaultServerPort)
		port = defaultServerPort
	}
	if intervalMillis <= 0 {
		intervalMillis = defaultCheckInterval
	}
	if peerTimeoutMillis <= 0 {
		peerTimeoutMillis = defaultPeerTimeout
	}

	metadataURL := fmt.Sprintf(metadataURLTemplate, metadataAddress)
	logrus.Infof("Waiting for metadata at %s", metadataURL)
	client, err := metadata.NewClientAndWait(metadataURL)
	if err != nil {
		return fmt.Errorf("create metadata client: %w", err)
	}
	logrus.Infof("Successfully connected to metadata")

	cc := newChecker(client, port, time.Duration(intervalMillis)*time.Millisecond, time.Duration(peerTimeoutMillis)*time.Millisecond)
	return cc.run()
}

func newChecker(client metadataClient, port int, checkInterval, connectionTimeout time.Duration) *checker {
	return &checker{
		client:            client,
		port:              port,
		checkInterval:     checkInterval,
		connectionTimeout: connectionTimeout,
		peers:             map[string]*peer{},
		peersByIP:         map[string]*peer{},
		ok:                true,
		stop:              make(chan struct{}),
	}
}

func (c *checker) run() error {
	if err := c.startServer(); err != nil {
		return err
	}
	go c.watch()
	select {}
}

func (c *checker) startServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", c.ping)
	mux.HandleFunc("/connectivity", c.connectivity)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", c.port))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", c.port, err)
	}
	c.listener = listener
	c.server = &http.Server{Handler: mux}
	logrus.Infof("Starting connectivity-check webserver on port %d", c.port)
	go func() {
		if err := c.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Errorf("connectivity-check webserver failed: %v", err)
		}
	}()
	return nil
}

func (c *checker) watch() {
	for {
		select {
		case <-c.stop:
			return
		default:
			c.doWork()
			time.Sleep(c.checkInterval)
		}
	}
}

func (c *checker) doWork() {
	snapshot, err := getMetadataSnapshot(c.client)
	if err != nil {
		logrus.Errorf("Failed to read connectivity metadata: %v", err)
		return
	}

	c.Lock()
	defer c.Unlock()

	nextPeers := map[string]*peer{}
	nextPeersByIP := map[string]*peer{}
	for uuid, peerContainer := range snapshot.peerContainers {
		current := c.peers[uuid]
		if current == nil {
			current = &peer{
				uuid:              uuid,
				stop:              make(chan struct{}),
				checkInterval:     c.checkInterval,
				connectionTimeout: c.connectionTimeout,
				randomOffset:      randomOffset(peerContainer.HostUUID),
			}
			go current.run()
		}
		current.Lock()
		current.container = peerContainer
		current.host = snapshot.hosts[peerContainer.HostUUID]
		current.checkContainer = snapshot.checkContainers[peerContainer.HostUUID]
		current.Unlock()
		nextPeers[uuid] = current
		nextPeersByIP[peerContainer.PrimaryIP] = current
		delete(c.peers, uuid)
	}

	for uuid, stale := range c.peers {
		logrus.Infof("Peer container deleted: %s", uuid)
		close(stale.stop)
	}

	c.peers = nextPeers
	c.peersByIP = nextPeersByIP
	c.ok = c.computeOK(snapshot)
	logrus.Debugf("connectivity-check state=%v peers=%d", c.ok, len(c.peers))
}

func (c *checker) computeOK(snapshot *metadataSnapshot) bool {
	if !shouldConsider(snapshot) {
		return true
	}
	for peerIP, p := range c.peersByIP {
		p.Lock()
		consider := p.consider()
		count := p.count
		p.Unlock()
		if consider && count == 0 {
			logrus.Debugf("Peer %s is not reachable", peerIP)
			return false
		}
	}
	return true
}

func (c *checker) ping(w http.ResponseWriter, r *http.Request) {
	sourceIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		sourceIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	c.Lock()
	p := c.peersByIP[sourceIP]
	c.Unlock()
	if p != nil {
		p.UpdateSuccess()
	}
	_, _ = w.Write([]byte(expectedPeerPingResponse))
}

func (c *checker) connectivity(w http.ResponseWriter, _ *http.Request) {
	c.Lock()
	ok := c.ok
	c.Unlock()
	if ok {
		_, _ = w.Write([]byte(connectivityHealthyResponse))
		return
	}
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(connectivityUnhealthyResponse))
}

func (p *peer) run() {
	for {
		select {
		case <-p.stop:
			return
		default:
			p.doWork()
			time.Sleep(p.sleepDuration())
		}
	}
}

func (p *peer) doWork() {
	p.Lock()
	if !p.consider() || time.Since(p.lastChecked) < p.checkInterval {
		p.Unlock()
		return
	}
	primaryIP := p.container.PrimaryIP
	timeout := p.connectionTimeout
	p.Unlock()

	ok, err := isReachable(fmt.Sprintf("http://%s/ping", primaryIP), expectedPeerPingResponse, timeout)
	p.Lock()
	defer p.Unlock()
	if ok {
		p.updateSuccess()
		return
	}
	p.updateFailure()
	if err != nil {
		logrus.Debugf("Peer %s reachability check failed: %v", p.uuid, err)
	}
}

func (p *peer) consider() bool {
	if p.host == nil || p.container == nil || p.checkContainer == nil {
		return false
	}
	if p.host.State != "active" {
		return false
	}
	if p.host.AgentState != "" && p.host.AgentState != "active" {
		return false
	}
	return p.container.State == "running" && p.checkContainer.State == "running"
}

func (p *peer) UpdateSuccess() {
	p.Lock()
	defer p.Unlock()
	p.updateSuccess()
}

func (p *peer) updateSuccess() {
	if p.count < 3 {
		p.count++
		if p.count == 1 {
			logrus.Infof("Peer %s became reachable", p.uuid)
		}
	}
	p.lastChecked = time.Now()
}

func (p *peer) updateFailure() {
	if p.count > 0 {
		p.count--
		if p.count == 0 {
			logrus.Errorf("Peer %s became unreachable", p.uuid)
		}
	}
	p.lastChecked = time.Now()
}

func (p *peer) sleepDuration() time.Duration {
	if p.checkInterval <= p.randomOffset {
		return p.checkInterval
	}
	return p.checkInterval - p.randomOffset
}

func getMetadataSnapshot(client metadataClient) (*metadataSnapshot, error) {
	selfHost, err := getOne[host](client, "/self/host")
	if err != nil {
		return nil, err
	}
	hosts, err := getMany[host](client, "/hosts")
	if err != nil {
		return nil, err
	}
	selfService, err := getOne[service](client, "/self/service")
	if err != nil {
		return nil, err
	}
	services, err := getMany[service](client, "/services")
	if err != nil {
		return nil, err
	}

	snapshot := &metadataSnapshot{
		ipsecState:      selfService.State,
		hosts:           map[string]*host{},
		peerContainers:  map[string]*container{},
		checkContainers: map[string]*container{},
	}
	if enabled, ok := selfService.Metadata[ipsecServiceHealthcheckFlag].(bool); ok {
		snapshot.healthcheckEnabled = enabled
	}
	for i := range hosts {
		if hosts[i].UUID != selfHost.UUID {
			snapshot.hosts[hosts[i].UUID] = &hosts[i]
		}
	}
	for i := range selfService.Containers {
		if selfService.Containers[i].HostUUID != selfHost.UUID {
			snapshot.peerContainers[selfService.Containers[i].UUID] = &selfService.Containers[i]
		}
	}
	for i := range services {
		if services[i].Name != connectivityCheckServiceName {
			continue
		}
		snapshot.connCheckState = services[i].State
		for j := range services[i].Containers {
			if services[i].Containers[j].HostUUID != selfHost.UUID {
				snapshot.checkContainers[services[i].Containers[j].HostUUID] = &services[i].Containers[j]
			}
		}
	}
	return snapshot, nil
}

func getOne[T any](client metadataClient, path string) (T, error) {
	var result T
	body, err := client.SendRequest(path)
	if err != nil {
		return result, err
	}
	return result, json.Unmarshal(body, &result)
}

func getMany[T any](client metadataClient, path string) ([]T, error) {
	var result []T
	body, err := client.SendRequest(path)
	if err != nil {
		return result, err
	}
	return result, json.Unmarshal(body, &result)
}

func shouldConsider(snapshot *metadataSnapshot) bool {
	return snapshot.healthcheckEnabled &&
		snapshot.ipsecState == "active" &&
		snapshot.connCheckState == "active"
}

func isReachable(url, expected string, timeout time.Duration) (bool, error) {
	client := http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("status code %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if string(body) != expected {
		return false, fmt.Errorf("unexpected response %q", string(body))
	}
	return true, nil
}

func randomOffset(hostUUID string) time.Duration {
	if hostUUID == "" {
		return 0
	}
	var sum int
	for _, c := range hostUUID {
		sum += int(c)
	}
	return time.Duration(sum%1000) * time.Millisecond
}

func validPort(port int) bool {
	return port > 0 && port <= 65535
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string) bool {
	value := strings.ToLower(os.Getenv(key))
	return value == "true" || value == "1" || value == "yes"
}
