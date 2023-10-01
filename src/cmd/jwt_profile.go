package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	oidcclient "github.com/vdbulcke/oidc-client-demo/src/client"
	"github.com/vdbulcke/oidc-client-demo/src/client/jwt/signer"
)

// args var
var endpoint string

func init() {
	// bind to root command
	jwtCmd.AddCommand(jwtProfileCmd)
	// add flags to sub command
	jwtProfileCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	jwtProfileCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature")
	jwtProfileCmd.Flags().StringVarP(&endpoint, "endpoint", "", "", "OAuth endpoint for 'aud' audiance claims")
	jwtProfileCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

	// required flags
	//nolint
	jwtProfileCmd.MarkFlagRequired("config")

	//nolint
	jwtProfileCmd.MarkFlagRequired("pem-key")

}

var jwtProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Generate jwt profile (client_assertion)",
	// Long: "",
	Run: jwtProfile,
}

// startServer cobra server handler
func jwtProfile(cmd *cobra.Command, args []string) {

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

	// Make a new OIDC Client
	client, err := oidcclient.NewOIDCClient(config, jwtsigner, appLogger)
	if err != nil {
		appLogger.Error("Error creating client", "error", err)
		os.Exit(1)
	}

	if endpoint == "" {
		endpoint = client.Wellknown.TokenEndpoint
	}

	signedJwt, err := client.GenerateJwtProfile(endpoint)
	if err != nil {
		appLogger.Error("Error generating signed jwt ", "error", err)
		os.Exit(1)
	}

	fmt.Println(signedJwt)
}
