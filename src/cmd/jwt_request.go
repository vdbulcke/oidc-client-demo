package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// args var

func init() {
	// bind to root command
	jwtCmd.AddCommand(jwtRequestCmd)
	// add flags to sub command
	jwtRequestCmd.Flags().StringVarP(&configFilename, "config", "c", "", "oidc client config file")
	jwtRequestCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature")
	jwtRequestCmd.Flags().IntVarP(&port, "port", "p", DefaultListeningPost, "oidc jwtRequest call back port")
	jwtRequestCmd.Flags().BoolVarP(&useLocalhost, "localhost", "", false, "use localhost instead of 127.0.0.1")
	jwtRequestCmd.Flags().StringVarP(&acrValueOverride, "acr-values", "a", "", "override 'acr_values' from config")
	jwtRequestCmd.Flags().StringVarP(&mockNonce, "mock-nonce", "", "", "Use static 'nonce' value")
	jwtRequestCmd.Flags().StringVarP(&mockState, "mock-state", "", "", "Use static 'state' value")
	jwtRequestCmd.Flags().StringVarP(&mockCodeVerifier, "mock-code-verifier", "", "", "Use static pkce 'code_verifier' value")
	jwtRequestCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

	// required flags
	//nolint
	jwtRequestCmd.MarkFlagRequired("config")

	//nolint
	jwtRequestCmd.MarkFlagRequired("pem-key")

}

var jwtRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Generate jwt request parameter",
	// Long: "",
	Run: jwtRequest,
}

// startServer cobra server handler
func jwtRequest(cmd *cobra.Command, args []string) {

	client := initClient()
	signedJwt, err := client.GenerateRequestJwt()
	if err != nil {
		client.GetLogger().Error("Error generating signed jwt ", "error", err)
		os.Exit(1)
	}

	fmt.Println(signedJwt)
}
