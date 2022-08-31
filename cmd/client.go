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
var useLocalhost bool
var acrValueOverride string
var fakePKCEVerifier bool

// default
var DefaultListeningAddress = "127.0.0.1"
var DefaultListeningPost = 5556

func init() {
	// bind to root command
	rootCmd.AddCommand(clientCmd)
	// add flags to sub command
	clientCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	clientCmd.Flags().IntVarP(&port, "port", "p", DefaultListeningPost, "oidc client call back port")
	clientCmd.Flags().BoolVarP(&useLocalhost, "localhost", "", false, "use localhost instead of 127.0.0.1")
	clientCmd.Flags().StringVarP(&acrValueOverride, "acr-values", "a", "", "override 'acr_values' from config")
	clientCmd.Flags().BoolVarP(&fakePKCEVerifier, "fake-pkce-verifier", "", false, "send a dummy pkce 'code_verifier'")

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
	if useLocalhost {
		config.ListenAddress = "localhost"
	} else {
		config.ListenAddress = DefaultListeningAddress
	}

	config.ListenPort = port
	config.RedirectUri = fmt.Sprintf("http://%s:%d/auth/callback", config.ListenAddress, port)

	// override config if flag is passed as args
	if skipUserinfo {
		appLogger.Warn("Skipping Userinfo")
		config.SkipUserinfo = skipUserinfo
	}

	// override acr_values
	if acrValueOverride != "" {
		config.AcrValues = acrValueOverride
	}

	// fail PKCE
	if fakePKCEVerifier {
		config.FakePKCEVerifier = true
	}

	// set output flag
	config.OutputEnabled = output
	config.OutputDir = outputDir

	// Make a new OIDC Client
	client, err := oidcclient.NewOIDCClient(config, appLogger)
	if err != nil {
		appLogger.Error("Error creating client", "error", err)
		os.Exit(1)
	}

	// set default output
	client.SetDefaultOutput()

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
