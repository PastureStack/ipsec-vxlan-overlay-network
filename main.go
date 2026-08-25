package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/PastureStack/ipsec-vxlan-overlay-network/arp"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/backend"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/backend/ipsec"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/backend/vxlan"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/connectivitycheck"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/mdchandler"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/server"
	"github.com/PastureStack/ipsec-vxlan-overlay-network/store"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var (
	// VERSION Of the binary
	VERSION = "0.0.0-dev"
)

const (
	backendFlag           = "backend"
	backendNameIpsec      = "ipsec"
	backendNameVxlan      = "vxlan"
	metadataFlag          = "use-metadata"
	metadataURLFlag       = "metadata-url"
	metadataClientIPFlag  = "metadata-client-ip"
	arpInterfaceFlag      = "arp-interface"
	xfrmTunnelSourceFlag  = "xfrm-tunnel-source"
	xfrmNetnsPathFlag     = "xfrm-netns-path"
	syncHostRoutesFlag    = "sync-host-routes"
	xfrmTunnelSourceHost  = "host"
	xfrmTunnelSourceLocal = "local"
)

func main() {
	commandName := filepath.Base(os.Args[0])
	if commandName == "connectivity-check" || commandName == "ipsec-vxlan-connectivity-check" {
		connectivitycheck.Version = VERSION
		if err := connectivitycheck.Run(os.Args[1:]); err != nil {
			logrus.Fatal(err)
		}
		return
	}

	app := &cli.Command{
		Name:    "ipsec-vxlan-overlay-network",
		Usage:   "manage the PastureStack IPsec or VXLAN overlay data plane",
		Version: VERSION,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: "log",
			},
			&cli.StringFlag{
				Name: "pid-file",
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Value:   "config.json",
			},
			&cli.StringFlag{
				Name:    "ipsec-config",
				Aliases: []string{"c"},
				Value:   ".",
				Usage:   "Configuration directory",
			},
			&cli.BoolFlag{
				Name:  "gcm",
				Value: true,
				Usage: "GCM mode Supported",
			},
			&cli.StringFlag{
				Name: "charon-log",
			},
			&cli.BoolFlag{
				Name: "charon-launch",
			},
			&cli.BoolFlag{
				Name: "test-charon",
			},
			&cli.BoolFlag{
				Name: "debug",
			},
			&cli.StringFlag{
				Name:  "listen",
				Value: ":8111",
			},
			&cli.StringFlag{
				Name:    "local-ip",
				Aliases: []string{"i"},
			},
			&cli.StringFlag{
				Name:    metadataURLFlag,
				Usage:   "Metadata URL override",
				Sources: cli.EnvVars("PASTURESTACK_METADATA_URL", "RANCHER_METADATA_URL"),
			},
			&cli.StringFlag{
				Name:    metadataClientIPFlag,
				Usage:   "Client IP to send to metadata through X-Forwarded-For",
				Sources: cli.EnvVars("PASTURESTACK_METADATA_CLIENT_IP", "RANCHER_METADATA_CLIENT_IP"),
			},
			&cli.StringFlag{
				Name:    arpInterfaceFlag,
				Value:   "eth0",
				Usage:   "Interface used by the ARP synchronization server",
				Sources: cli.EnvVars("PASTURESTACK_NETWORK_ARP_INTERFACE", "RANCHER_NET_ARP_INTERFACE"),
			},
			&cli.StringFlag{
				Name:    xfrmTunnelSourceFlag,
				Value:   xfrmTunnelSourceLocal,
				Usage:   "XFRM tunnel endpoint source: local or host",
				Sources: cli.EnvVars("PASTURESTACK_NETWORK_XFRM_TUNNEL_SOURCE", "RANCHER_NET_XFRM_TUNNEL_SOURCE"),
			},
			&cli.StringFlag{
				Name:    xfrmNetnsPathFlag,
				Usage:   "Network namespace path used for charon and XFRM operations",
				Sources: cli.EnvVars("PASTURESTACK_NETWORK_XFRM_NETNS_PATH", "RANCHER_NET_XFRM_NETNS_PATH"),
			},
			&cli.BoolFlag{
				Name:    syncHostRoutesFlag,
				Usage:   "Sync remote overlay container routes into the host namespace",
				Sources: cli.EnvVars("PASTURESTACK_NETWORK_SYNC_HOST_ROUTES", "RANCHER_NET_SYNC_HOST_ROUTES"),
			},
			&cli.StringFlag{
				Name:    backendFlag,
				Value:   backendNameIpsec,
				Usage:   "backend to use: ipsec/vxlan",
				Sources: cli.EnvVars("PASTURESTACK_NETWORK_BACKEND", "RANCHER_NET_BACKEND"),
			},
			&cli.BoolFlag{
				Name:    metadataFlag,
				Usage:   "Use metadata instead of config file",
				Sources: cli.EnvVars("PASTURESTACK_NETWORK_USE_METADATA", "RANCHER_NET_USE_METADATA"),
			},
		},
		Action: func(_ context.Context, command *cli.Command) error {
			return appMain(command)
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		logrus.Fatal(err)
	}
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

func appMain(ctx *cli.Command) error {
	if ctx.Bool("test-charon") {
		if err := ipsec.Test(); err != nil {
			log.Fatalf("Failed to talk to charon: %v", err)
		}
		os.Exit(0)
	}

	logFile := ctx.String("log")
	if logFile != "" {
		if output, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
			logrus.Fatalf("Failed to log to file %s: %v", logFile, err)
		} else {
			logrus.SetOutput(output)
		}
	}

	pidFile := ctx.String("pid-file")
	if pidFile != "" {
		logrus.Infof("Writing pid %d to %s", os.Getpid(), pidFile)
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
			logrus.Fatalf("Failed to write pid file %s: %v", pidFile, err)
		}
	}

	if ctx.Bool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}

	backendToUse := ctx.String(backendFlag)
	validBackend := backendToUse == backendNameIpsec || backendToUse == backendNameVxlan
	if !validBackend {
		logrus.Fatalf("Invalid backend specified")
	}
	logrus.Infof("Using backend: %v", backendToUse)

	useMetadata := ctx.Bool(metadataFlag)
	logrus.Infof("Using metadata: %v", useMetadata)

	var db store.Store
	var err error
	metadataURL := ctx.String(metadataURLFlag)
	if useMetadata {
		logrus.Infof("Reading info from metadata")
		metadataClientIP := ctx.String(metadataClientIPFlag)
		if metadataClientIP != "" {
			db, err = store.NewMetadataStoreWithClientIP(metadataURL, metadataClientIP)
		} else {
			db, err = store.NewMetadataStore(metadataURL)
		}
		if err != nil {
			logrus.Errorf("Error creating metadata store: %v", err)
			return err
		}

	} else {
		logrus.Infof("Reading info from config file")
		db = store.NewSimpleStore(waitForFile(ctx.String("file")), ctx.String("local-ip"))
	}
	if err := db.Reload(); err != nil {
		return err
	}

	var overlay backend.Backend
	if backendToUse == backendNameVxlan {
		overlay, err = vxlan.NewOverlay("", db)
		if err != nil {
			return err
		}
		overlay.Start(true, "")
	} else {
		ipsecOverlay := ipsec.NewOverlay(ctx.String("ipsec-config"), db)
		ipsecOverlay.NetnsPath = ctx.String(xfrmNetnsPathFlag)
		ipsecOverlay.SyncHostRoutes = ctx.Bool(syncHostRoutesFlag)
		switch ctx.String(xfrmTunnelSourceFlag) {
		case xfrmTunnelSourceLocal:
			ipsecOverlay.UseHostTunnelSource = false
		case xfrmTunnelSourceHost:
			ipsecOverlay.UseHostTunnelSource = true
		default:
			logrus.Fatalf("Invalid %s value %q", xfrmTunnelSourceFlag, ctx.String(xfrmTunnelSourceFlag))
		}
		if !ctx.Bool("gcm") {
			ipsecOverlay.Blacklist = []string{"aes128gcm16"}
		}
		overlay = ipsecOverlay
		overlay.Start(ctx.Bool("charon-launch"), ctx.String("charon-log"))
	}

	done := make(chan error)
	go func() {
		done <- arp.ListenAndServe(db, ctx.String(arpInterfaceFlag))
	}()

	listenPort := ctx.String("listen")
	logrus.Debugf("About to start server and listen on port: %v", listenPort)
	go func() {
		s := server.Server{
			Backend: overlay,
		}
		done <- s.ListenAndServe(listenPort)
	}()

	if err := overlay.Reload(); err != nil {
		logrus.Errorf("couldn't reload the overlay: %v", err)
		return err
	}

	if useMetadata {
		if metadataURL == "" {
			metadataURL = store.DefaultMetadataURL
		}
		mdch, err := mdchandler.NewMetadataChangeHandler(overlay, metadataURL)
		if err != nil {
			return err
		}
		go func() {
			done <- mdch.Start()
		}()
	}

	return <-done
}
