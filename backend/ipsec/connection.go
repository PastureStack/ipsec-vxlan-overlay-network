package ipsec

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/bronze1man/goStrongswanVici"
)

const reqIdStr = "1234"

type viciRequester interface {
	Request(string, map[string]interface{}) (map[string]interface{}, error)
}

type viciSAClient interface {
	viciRequester
	ListSas(string, string) ([]map[string]goStrongswanVici.IkeSa, error)
}

// A nonempty fingerprint is written only after this process loads the complete
// connection. Merely discovering a connection name is not ownership evidence.
type connectionIdentity struct {
	TemplateRevision string
	LocalAgentIP     string
	LocalTunnelIP    string
	HostTunnelSource bool
	Connection       IKEConnectionConfig
}

func hostConnectionConfig(templates *Templates, blacklist []string, localAgentIP, localTunnelIP, remoteIP string, hostTunnelSource bool) (IKEConnectionConfig, string, error) {
	filter := func(algos []string) []string {
		result := []string{}
		for _, algo := range algos {
			ignored := false
			for _, prefix := range blacklist {
				if strings.HasPrefix(algo, prefix) {
					ignored = true
					break
				}
			}
			if !ignored {
				result = append(result, algo)
			}
		}
		return result
	}
	child := templates.NewChildSaConf()
	child.ESPProposals = filter(child.ESPProposals)
	child.ReqID = reqIdStr
	if strings.Compare(remoteIP, localAgentIP) < 0 {
		child.RekeyTime = "8760h"
	}
	conf := templates.NewIkeConf()
	conf.Proposals = filter(conf.Proposals)
	if hostTunnelSource {
		conf.LocalAddrs = []string{localTunnelIP}
	}
	conf.RemoteAddrs = []string{remoteIP}
	conf.Children = map[string]goStrongswanVici.ChildSAConf{"child-" + remoteIP: child}
	encoded, err := json.Marshal(connectionIdentity{
		TemplateRevision: templates.Revision(), LocalAgentIP: localAgentIP, LocalTunnelIP: localTunnelIP,
		HostTunnelSource: hostTunnelSource, Connection: conf,
	})
	return conf, string(encoded), err
}

func loadHostConnection(client viciRequester, remoteIP string, conf IKEConnectionConfig, fingerprint string, hosts map[string]string, staleLocal map[string]map[string]string) error {
	if hosts[remoteIP] == fingerprint {
		return nil
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = loadIKEConnection(client, "conn-"+remoteIP, conf)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	// Queue only an endpoint anchored in our previous successful load. Imported
	// connections and arbitrary stale-local SAs never acquire this authority.
	var previous, current connectionIdentity
	if json.Unmarshal([]byte(hosts[remoteIP]), &previous) == nil && json.Unmarshal([]byte(fingerprint), &current) == nil &&
		previous.HostTunnelSource && current.HostTunnelSource && previous.LocalAgentIP != current.LocalAgentIP &&
		net.ParseIP(previous.LocalAgentIP) != nil && net.ParseIP(current.LocalAgentIP) != nil &&
		len(previous.Connection.LocalAddrs) == 1 && previous.Connection.LocalAddrs[0] == previous.LocalAgentIP &&
		len(previous.Connection.RemoteAddrs) == 1 && previous.Connection.RemoteAddrs[0] == remoteIP &&
		previous.Connection.LocalAuth.AuthMethod == "psk" && len(previous.Connection.Children) == 1 &&
		previous.Connection.Children["child-"+remoteIP].ReqID == reqIdStr {
		identity := previous.Connection.LocalAuth.ID
		if identity == "" {
			identity = previous.LocalAgentIP
		}
		// strongSwan identity expressions cannot be safely inferred from an SA.
		if !strings.HasPrefix(identity, "%") {
			if staleLocal[remoteIP] == nil {
				staleLocal[remoteIP] = map[string]string{}
			}
			staleLocal[remoteIP][previous.LocalAgentIP] = identity
		}
	}
	hosts[remoteIP] = fingerprint
	return nil
}

func loadIKEConnection(client viciRequester, name string, conf IKEConnectionConfig) error {
	request := &map[string]interface{}{}
	if err := goStrongswanVici.ConvertToGeneral(&map[string]IKEConnectionConfig{name: conf}, request); err != nil {
		return fmt.Errorf("encode IKE connection: %w", err)
	}
	response, err := client.Request("load-conn", *request)
	if err != nil {
		return err
	}
	if response["success"] != "yes" {
		return fmt.Errorf("load IKE connection: %v", response["errmsg"])
	}
	return nil
}

func staleLocalIKEIDs(sas []map[string]goStrongswanVici.IkeSa, currentLocalIP string, expectedHosts map[string]bool, staleLocal map[string]map[string]string) []string {
	if net.ParseIP(currentLocalIP) == nil {
		return nil
	}
	counts := map[string]int{}
	for _, saMap := range sas {
		for _, sa := range saMap {
			counts[sa.Uniqueid]++
		}
	}
	ids := []string{}
	for _, saMap := range sas {
		for name, sa := range saMap {
			identity, known := staleLocal[sa.Remote_host][sa.Local_host]
			if !known || !expectedHosts[sa.Remote_host] || name != "conn-"+sa.Remote_host || sa.Local_host == currentLocalIP || counts[sa.Uniqueid] != 1 {
				continue
			}
			if sa.State != "CONNECTING" && sa.State != "ESTABLISHED" && sa.State != "REKEYING" {
				continue
			}
			if sa.Local_id != identity && !(sa.State == "CONNECTING" && sa.Local_id == "") {
				continue
			}
			id, err := strconv.ParseUint(sa.Uniqueid, 10, 32)
			if err != nil || id == 0 {
				continue
			}
			ownedChildren := true
			for childName, child := range sa.Child_sas {
				prefix := "child-" + sa.Remote_host
				ownedName := childName == prefix
				if strings.HasPrefix(childName, prefix+"-") {
					childID, err := strconv.ParseUint(strings.TrimPrefix(childName, prefix+"-"), 10, 64)
					ownedName = err == nil && childID > 0
				}
				if !ownedName || child.Reqid != reqIdStr {
					ownedChildren = false
				}
			}
			if ownedChildren {
				ids = append(ids, sa.Uniqueid)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func terminateIKEID(client viciRequester, id string) error {
	response, err := client.Request("terminate", map[string]interface{}{"ike-id": id, "force": "yes", "timeout": "1000"})
	if err != nil {
		return err
	}
	if response["success"] != "yes" && response["matches"] != "0" {
		return fmt.Errorf("terminate stale IKE_SA %s: %v", id, response["errmsg"])
	}
	return nil
}

func reapStaleLocalSAs(client viciSAClient, currentLocalIP string, expectedHosts map[string]bool, staleLocal map[string]map[string]string) error {
	if len(staleLocal) == 0 {
		return nil
	}
	sas, err := client.ListSas("", "")
	if err != nil {
		return err
	}
	for _, id := range staleLocalIKEIDs(sas, currentLocalIP, expectedHosts, staleLocal) {
		if err := terminateIKEID(client, id); err != nil {
			return err
		}
	}
	// Consume transition authority after successful observation/termination;
	// later unrelated SAs cannot borrow a historical local-address proof.
	for host := range staleLocal {
		if expectedHosts[host] {
			delete(staleLocal, host)
		}
	}
	return nil
}
