package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

func init() {
	// bind to root command
	rootCmd.AddCommand(clientCredentialsCmd)
	// add flags to sub command
	clientCredentialsCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	clientCredentialsCmd.Flags().BoolVarP(&skipIdTokenVerification, "skip-id-token-verification", "", false, "Skip validation of id_token after renewing tokens")
	clientCredentialsCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature or mTLS")
	clientCredentialsCmd.Flags().StringVarP(&clientCertificate, "pem-cert", "", "", "client certificate (pem format) mTLS")
	clientCredentialsCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

	// required flags
	//nolint
	clientCredentialsCmd.MarkFlagRequired("config")

}

var clientCredentialsCmd = &cobra.Command{
	Use:   "client-credentials",
	Short: "Client Credentials Grant Flow",
	// Long: "",
	Run: func(cmd *cobra.Command, args []string) {
		client := initClient()
		// set default output
		client.SetDefaultOutput()

		// display info about the current client
		client.Info()

		err := client.ClientCredentialsFlow()
		if err != nil {
			client.GetLogger().Error("Error during Client Credentials grant", "error", err)
			os.Exit(1)
		}
	},
}
