package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vdbulcke/oidc-client-demo/src/client/jwt/signer"
)

// args var
var jwtAlg string

func init() {
	// bind to root command
	jwtCmd.AddCommand(jwksCmd)
	// add flags to sub command
	jwksCmd.Flags().StringVarP(&privateKey, "pem-key", "", "", "private key (pem format) for jwt signature")
	jwksCmd.Flags().StringVarP(&jwtAlg, "alg", "", "RS256", "signing alg to use in jwks")

	//nolint
	jwksCmd.MarkFlagRequired("pem-key")

}

var jwksCmd = &cobra.Command{
	Use:   "jwks",
	Short: "Generate jwks for key",
	// Long: "",
	Run: jwks,
}

// startServer cobra server handler
func jwks(cmd *cobra.Command, args []string) {

	appLogger := genLogger()

	var jwtsigner signer.JwtSigner

	key, err := signer.ParsePrivateKey(privateKey)
	if err != nil {
		appLogger.Error("error parsing private key", "key", privateKey, "err", err)
		os.Exit(1)
	}

	jwtsigner, err = signer.NewJwtSigner(key, jwtAlg)
	if err != nil {
		appLogger.Error("error generating jwt signer", "err", err)
		os.Exit(1)
	}

	jwks, err := jwtsigner.JWKS()
	if err != nil {
		appLogger.Error("Error generating  jwks ", "error", err)
		os.Exit(1)
	}

	fmt.Println(string(jwks))
}
