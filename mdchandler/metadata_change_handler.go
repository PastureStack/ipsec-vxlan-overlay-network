package mdchandler

import (
	"github.com/PastureStack/ipsec-vxlan-overlay-network/backend"
	"github.com/rancher/go-rancher-metadata/metadata"
	"github.com/sirupsen/logrus"
)

var (
	changeCheckInterval = 2
)

// MetadataChangeHandler listens for version changes of metadata
// and triggers appropriate handlers in the current application
type MetadataChangeHandler struct {
	Backend backend.Backend
	mc      metadata.Client
}

// NewMetadataChangeHandler creates a metadata change handler using the same
// endpoint as the overlay store.
func NewMetadataChangeHandler(b backend.Backend, metadataURL string) (*MetadataChangeHandler, error) {
	mc, err := metadata.NewClientAndWait(metadataURL)
	if err != nil {
		return nil, err
	}
	return &MetadataChangeHandler{
		Backend: b,
		mc:      mc,
	}, nil
}

// OnChangeHandler is the actual callback function called when
// the metadata changes
func (mdch *MetadataChangeHandler) OnChangeHandler(version string) {
	logrus.Infof("Metadata OnChange received, version: %v", version)
	err := mdch.Backend.Reload()
	if err != nil {
		logrus.Errorf("Error reloading backend after receiving the db change: %v", err)
	} else {
		logrus.Debugf("Reload successful")
	}
}

// Start is used to begin the OnChange handling
func (mdch *MetadataChangeHandler) Start() error {
	logrus.Debugf("Starting the MetadataChangeHandler")
	mdch.mc.OnChange(changeCheckInterval, mdch.OnChangeHandler)

	return nil
}
