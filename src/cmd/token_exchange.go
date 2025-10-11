package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var requestedTokenType string

var subjectToken string
var subjectTokenType string

var actorToken string
var actorTokenType string

func init() {
	// bind to root command
	rootCmd.AddCommand(tokenExchangeCmd)
	// add flags to sub command
	tokenExchangeCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	tokenExchangeCmd.Flags().StringVarP(&subjectToken, "subject-token", "", "", "subject Token")
	tokenExchangeCmd.Flags().StringVarP(&subjectTokenType, "subject-token-type", "", "", "subject Token type")
	tokenExchangeCmd.Flags().StringVarP(&requestedTokenType, "requested-token-type", "", "", "requested Token type")
	tokenExchangeCmd.Flags().StringVarP(&actorToken, "actor-token", "", "", "actor Token")
	tokenExchangeCmd.Flags().StringVarP(&actorTokenType, "actor-token-type", "", "", "actor Token type")

	tokenExchangeCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature or mTLS")
	tokenExchangeCmd.Flags().StringVarP(&clientCertificate, "pem-cert", "", "", "client certificate (pem format) mTLS")
	tokenExchangeCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

	// required flags
	//nolint
	tokenExchangeCmd.MarkFlagRequired("config")

	//nolint
	tokenExchangeCmd.MarkFlagRequired("subject-token")
	//nolint
	tokenExchangeCmd.MarkFlagRequired("subject-token-type")

}

var tokenExchangeCmd = &cobra.Command{
	Use:   "token-exchange",
	Short: "Renew tokens with rfc8693 token exchange",
	// Long: "",
	Run: runTokenExchange,
}

// startServer cobra server handler
func runTokenExchange(cmd *cobra.Command, args []string) {
	client := initClient()
	// set default output
	client.SetDefaultOutput()

	// display info about the current client
	client.Info()

	err := client.TokenExchangeFlow(
		subjectToken,
		subjectTokenType,
		requestedTokenType,
		actorToken,
		actorTokenType,
	)
	if err != nil {
		client.GetLogger().Error("Error during token exchange", "error", err)
		os.Exit(1)
	}

}
