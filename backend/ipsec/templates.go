package ipsec

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	"github.com/PastureStack/ipsec-vxlan-overlay-network/internal/logsafe"
	"github.com/bronze1man/goStrongswanVici"
	"github.com/sirupsen/logrus"
)

const (
	ikeConfName     = "ike.conf"
	childSaConfName = "childsa.conf"
)

var (
	defaultIkeConf = []byte(`{
		"local_addrs": [],
		"proposals": ["aes128gcm16-sha256-modp2048", "aes-sha1-modp2048"],
		"encap": "yes",
		"unique": "replace",
		"local": {
			"auth": "psk"
		},
		"remote": {
			"auth": "psk"
		}
	}`)
	defaultChildSaConf = []byte(`{
		"local_ts": ["0.0.0.0/0"],
		"remote_ts": ["0.0.0.0/0"],
		"esp_proposals":  ["aes128gcm16-modp2048", "aes-modp2048"],
		"start_action": "none",
		"close_action": "start",
		"mode": "tunnel",
		"policies": "no"
	}`)
)

type Templates struct {
	ConfigDir           string
	ikeConfTemplate     []byte
	childSaConfTemplate []byte
	revision            string
}

// IKEConnectionConfig extends the VICI library's typed config with strongSwan's
// per-connection uniqueness policy. The library does not expose this option;
// embedding preserves its existing field conversion and custom IKE templates.
type IKEConnectionConfig struct {
	goStrongswanVici.IKEConf
	Unique string `json:"unique,omitempty"`
}

func (t *Templates) Reload() error {
	var err error
	t.ikeConfTemplate, err = t.loadBytes(ikeConfName, defaultIkeConf)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(t.ikeConfTemplate, &IKEConnectionConfig{}); err != nil {
		logrus.Errorf("Failed to unmarshal IKE config: %s", logsafe.Value(err))
		return err
	}

	t.childSaConfTemplate, err = t.loadBytes(childSaConfName, defaultChildSaConf)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(t.childSaConfTemplate, &goStrongswanVici.ChildSAConf{}); err != nil {
		logrus.Errorf("Failed to unmarshal CHILD_SA config: %s", logsafe.Value(err))
		return err
	}

	digest := sha1.New()
	digest.Write(t.ikeConfTemplate)
	digest.Write(t.childSaConfTemplate)
	t.revision = hex.EncodeToString(digest.Sum(nil))

	return nil
}

func (t *Templates) Revision() string {
	return t.revision
}

func (t *Templates) NewIkeConf() IKEConnectionConfig {
	var resp IKEConnectionConfig
	// Should never fail because we checked this in Reload()
	json.Unmarshal(t.ikeConfTemplate, &resp)
	// Existing custom ike.conf files may predate this option. Keep the safe
	// per-peer default unless the operator explicitly selected another policy.
	if resp.Unique == "" {
		resp.Unique = "replace"
	}
	return resp
}

func (t *Templates) NewChildSaConf() goStrongswanVici.ChildSAConf {
	var resp goStrongswanVici.ChildSAConf
	// Should never fail because we checked this in Reload()
	json.Unmarshal(t.childSaConfTemplate, &resp)
	return resp
}

func (t *Templates) loadBytes(file string, defaultBytes []byte) ([]byte, error) {
	bytes, err := ioutil.ReadFile(path.Join(t.ConfigDir, file))
	if os.IsNotExist(err) {
		return defaultBytes, nil
	}
	return bytes, err
}
