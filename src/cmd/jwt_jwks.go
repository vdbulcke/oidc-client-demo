package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vdbulcke/oauthx"
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
	jwksCmd.Flags().StringVarP(&mockKid, "mock-jwt-kid", "", "", "Use static jwt 'kid' value")

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

	var oauthkey oauthx.OAuthPrivateKey

	key, err := signer.ParsePrivateKey(privateKey)
	if err != nil {
		appLogger.Error("error parsing private key", "key", privateKey, "err", err)
		os.Exit(1)
	}

	oauthkey, err = oauthx.NewOAuthPrivateKey(key, jwtAlg, mockKid)

	if err != nil {
		appLogger.Error("error parsing private key", "key", privateKey, "err", err)
		os.Exit(1)
	}

	jwtSigner, ok := oauthkey.(oauthx.JwtAdvertiser)
	if !ok {
		appLogger.Error("Error invalid type oauthx.JwtAdvertiser ")
		os.Exit(1)
	}

	jwks, err := jwtSigner.JWKS()
	if err != nil {
		appLogger.Error("Error generating  jwks ", "error", err)
		os.Exit(1)
	}

	fmt.Println(string(jwks))
}
