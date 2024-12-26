package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// args var
var token string

func init() {
	// bind to root command
	rootCmd.AddCommand(introspectCmd)
	// add flags to sub command
	introspectCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	introspectCmd.Flags().StringVarP(&token, "token", "", "", "Token to introspect")
	introspectCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature or mTLS")
	introspectCmd.Flags().StringVarP(&clientCertificate, "pem-cert", "", "", "client certificate (pem format) mTLS")
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

	client := initClient()

	// set default output
	client.SetDefaultOutput()

	err := client.IntrospectToken(token)
	if err != nil {
		client.GetLogger().Error("Error during introspect Token", "error", err)
		os.Exit(1)
	}

}
