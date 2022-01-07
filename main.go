package main

import (
	"flag"
	"fmt"
	"os"
	oidcclient "vdbulcke/oidc-client-demo/oidc-client"

	"github.com/hashicorp/go-hclog"
)

// GitCommit the current git commit
// will be injected during build
var GitCommit string

// Version
var Version string

// HumanVersion version with commit
var HumanVersion = fmt.Sprintf("%s-(%s)", Version, GitCommit)

func main() {
	// Parse argument
	configFilenamePtr := flag.String("config", "config.yaml", "Config file")
	debugMode := flag.Bool("debug", false, "Enable Debug Mode")
	displayVersion := flag.Bool("version", false, "Display version")
	flag.Parse()

	// Version Flag
	if *displayVersion {
		if GitCommit != "" {
			fmt.Println(HumanVersion)
		} else {
			fmt.Println(Version)
		}

		os.Exit(0)
	}

	// Create Logger
	var appLogger hclog.Logger

	logLevel := hclog.LevelFromString("INFO")

	if *debugMode {
		logLevel = hclog.LevelFromString("DEBUG")
	}

	appLogger = hclog.New(&hclog.LoggerOptions{
		Name:  "oidc-client",
		Level: logLevel,
		Color: hclog.AutoColor,
	})

	// Parse Config
	config, err := oidcclient.ParseConfig(*configFilenamePtr)
	if err != nil {
		appLogger.Error("Could not parse config", "err", err)
		os.Exit(1)
	}

	client := oidcclient.NewOIDCClient(config, appLogger)

	var v string
	if GitCommit != "" {

		v = HumanVersion

	} else {
		v = Version
	}
	appLogger.Info("Starting OIDC Client", "version", v)
	client.Info()

	err = client.OIDCAuthorizationCodeFlow()
	if err != nil {
		appLogger.Error("Error initializing client", "error", err)
		os.Exit(1)
	}

}
