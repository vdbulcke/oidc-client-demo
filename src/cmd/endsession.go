package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var postLogout string

func init() {
	// bind to root command
	rootCmd.AddCommand(endSessionCmd)
	// add flags to sub command
	endSessionCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	endSessionCmd.Flags().StringVarP(&token, "token", "", "", "IDToken ")
	endSessionCmd.Flags().StringVarP(&postLogout, "post-logout-redirect-uri", "", "", "post_logout_redirect_uri")
	endSessionCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature or mTLS")
	endSessionCmd.Flags().StringVarP(&clientCertificate, "pem-cert", "", "", "client certificate (pem format) mTLS")
	endSessionCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

	// required flags
	//nolint
	endSessionCmd.MarkFlagRequired("config")

	//nolint
	endSessionCmd.MarkFlagRequired("token")

}

var endSessionCmd = &cobra.Command{
	Use:   "end-session",
	Short: "oidc RP initiated logout",
	// Long: "",
	Run: func(cmd *cobra.Command, args []string) {

		client := initClient()

		// set default output
		client.SetDefaultOutput()

		err := client.EndSession(token, postLogout)
		if err != nil {
			client.GetLogger().Error("Error during RP initiated logout", "error", err)
			os.Exit(1)
		}

	},
}
