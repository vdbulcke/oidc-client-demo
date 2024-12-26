package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// args var
var refreshToken string

var skipIdTokenVerification bool

func init() {
	// bind to root command
	rootCmd.AddCommand(refreshTokenCmd)
	// add flags to sub command
	refreshTokenCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	refreshTokenCmd.Flags().StringVarP(&refreshToken, "refresh-token", "", "", "Refresh Token")
	refreshTokenCmd.Flags().BoolVarP(&skipIdTokenVerification, "skip-id-token-verification", "", false, "Skip validation of id_token after renewing tokens")
	refreshTokenCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature or mTLS")
	refreshTokenCmd.Flags().StringVarP(&clientCertificate, "pem-cert", "", "", "client certificate (pem format) mTLS")
	refreshTokenCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

	// required flags
	//nolint
	refreshTokenCmd.MarkFlagRequired("config")

	//nolint
	refreshTokenCmd.MarkFlagRequired("refresh-token")

}

var refreshTokenCmd = &cobra.Command{
	Use:   "refresh-token",
	Short: "Renew tokens with Refresh Token",
	// Long: "",
	Run: runRefreshToken,
}

// startServer cobra server handler
func runRefreshToken(cmd *cobra.Command, args []string) {
	client := initClient()
	// set default output
	client.SetDefaultOutput()

	// display info about the current client
	client.Info()

	err := client.RefreshTokenFlow(refreshToken, skipIdTokenVerification)
	if err != nil {
		client.GetLogger().Error("Error during Refresh Token", "error", err)
		os.Exit(1)
	}

}
