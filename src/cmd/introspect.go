package cmd

import (
	"os"

	"github.com/spf13/cobra"
	oidcclient "github.com/vdbulcke/oidc-client-demo/src/client"
	"github.com/vdbulcke/oidc-client-demo/src/client/jwt/signer"
)

// args var
var token string

func init() {
	// bind to root command
	rootCmd.AddCommand(introspectCmd)
	// add flags to sub command
	introspectCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	introspectCmd.Flags().StringVarP(&token, "token", "", "", "Token to introspect")
	introspectCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature")
	introspectCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

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

	var jwtsigner signer.JwtSigner

	if privateKey != "" {
		key, err := signer.ParsePrivateKey(privateKey)
		if err != nil {
			appLogger.Error("error parsing private key", "key", privateKey, "err", err)
			os.Exit(1)
		}

		jwtsigner, err = signer.NewJwtSigner(key, config.JwtSigningAlg, mockKid)
		if err != nil {
			appLogger.Error("error generating jwt signer", "err", err)
			os.Exit(1)
		}

	}
	// Validate introspect url
	if config.IntrospectEndpoint == "" {
		appLogger.Error("introspect_endpoint not found")
		os.Exit(1)
	}

	// set output flag
	config.OutputEnabled = output
	config.OutputDir = outputDir

	// Make a new OIDC Client
	client, err := oidcclient.NewOIDCClient(config, jwtsigner, appLogger)
	if err != nil {
		appLogger.Error("Error creating client", "error", err)
		os.Exit(1)
	}

	// set default output
	client.SetDefaultOutput()

	err = client.IntrospectToken(token)
	if err != nil {
		appLogger.Error("Error during introspect Token", "error", err)
		os.Exit(1)
	}

}
