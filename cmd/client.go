package cmd

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
	oidcclient "github.com/vdbulcke/oidc-client-demo/oidc-client"
)

// args var
var configFilename string
var port int

// default
var DefaultListeningAddress = "127.0.0.1"
var DefaultListeningPost = 5556

func init() {
	// bind to root command
	rootCmd.AddCommand(clientCmd)
	// add flags to sub command
	clientCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	clientCmd.Flags().IntVarP(&port, "port", "p", DefaultListeningPost, "oidc client call back port")

	// required flags
	//nolint
	clientCmd.MarkFlagRequired("config")

}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Starts the oidc client",
	// Long: "",
	Run: runClient,
}

// startServer cobra server handler
func runClient(cmd *cobra.Command, args []string) {

	appLogger := genLogger()

	// Parse Config
	config, err := oidcclient.ParseConfig(configFilename)
	if err != nil {
		appLogger.Error("Could not parse config", "err", err)
		os.Exit(1)
	}

	// validate config
	if !oidcclient.ValidateConfig(config) {
		appLogger.Error("Could not validate config")
		os.Exit(1)
	}

	// setting the redirect URI
	config.ListenAddress = DefaultListeningAddress
	config.ListenPort = port
	config.RedirectUri = fmt.Sprintf("http://%s:%d/auth/callback", DefaultListeningAddress, port)

	// Make a new OIDC Client
	client := oidcclient.NewOIDCClient(config, appLogger)
	// display info about the current client
	client.Info()

	err = client.OIDCAuthorizationCodeFlow()
	if err != nil {
		appLogger.Error("Error initializing client", "error", err)
		os.Exit(1)
	}

}

// genLogger generate logger
func genLogger() hclog.Logger {
	// Create Logger
	var appLogger hclog.Logger

	logLevel := hclog.LevelFromString("INFO")

	// from arg
	if Debug {
		logLevel = hclog.LevelFromString("DEBUG")
	}

	if noColor {
		appLogger = hclog.New(&hclog.LoggerOptions{
			Name:  "oidc-client",
			Level: logLevel,
		})
	} else {
		appLogger = hclog.New(&hclog.LoggerOptions{
			Name:  "oidc-client",
			Level: logLevel,
			Color: hclog.AutoColor,
		})
	}

	return appLogger
}
