package cmd

import (
	"os"

	"github.com/spf13/cobra"
	oidcclient "github.com/vdbulcke/oidc-client-demo/oidc-client"
)

// args var
var token string

func init() {
	// bind to root command
	rootCmd.AddCommand(introspectCmd)
	// add flags to sub command
	introspectCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	introspectCmd.Flags().StringVarP(&token, "token", "", "", "Token to introspect")

	// required flags
	//nolint
	introspectCmd.MarkFlagRequired("config")

	//nolint
	introspectCmd.MarkFlagRequired("token")

}

var introspectCmd = &cobra.Command{
	Use:   "introspect",
	Short: "Introspect token",
	// Long: "",
	Run: runIntrospectToken,
}

// startServer cobra server handler
func runIntrospectToken(cmd *cobra.Command, args []string) {

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

	// Validate introspect url
	if config.IntrospectEndpoint == "" {
		appLogger.Error("introspect_endpoint not found")
		os.Exit(1)
	}

	// Make a new OIDC Client
	client, err := oidcclient.NewOIDCClient(config, appLogger)
	if err != nil {
		appLogger.Error("Error creating client", "error", err)
		os.Exit(1)
	}

	err = client.IntrospectToken(token)
	if err != nil {
		appLogger.Error("Error during introspect Token", "error", err)
		os.Exit(1)
	}

}
