package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

func init() {
	// bind to root command
	rootCmd.AddCommand(revokeCmd)
	// add flags to sub command
	revokeCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	revokeCmd.Flags().StringVarP(&token, "token", "", "", "token to revoke ")
	revokeCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature or mTLS")
	revokeCmd.Flags().StringVarP(&clientCertificate, "pem-cert", "", "", "client certificate (pem format) mTLS")
	revokeCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

	// required flags
	//nolint
	revokeCmd.MarkFlagRequired("config")

	//nolint
	revokeCmd.MarkFlagRequired("token")

}

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "rfc7009 token revocation",
	// Long: "",
	Run: func(cmd *cobra.Command, args []string) {

		client := initClient()

		// set default output
		client.SetDefaultOutput()

		err := client.Revoke(token)
		if err != nil {
			client.GetLogger().Error("Error during token revocation", "error", err)
			os.Exit(1)
		}

	},
}
