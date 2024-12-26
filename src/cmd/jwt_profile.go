package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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

	client := initClient()

	signedJwt, err := client.GenerateJwtProfile(endpoint)
	if err != nil {
		client.GetLogger().Error("Error generating signed jwt ", "error", err)
		os.Exit(1)
	}

	fmt.Println(signedJwt)
}
