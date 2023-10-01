package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	oidcclient "github.com/vdbulcke/oidc-client-demo/src/client"
	"github.com/vdbulcke/oidc-client-demo/src/client/jwt/signer"
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

	appLogger := genLogger()

	// Parse Config
	config, err := oidcclient.ParseConfig(configFilename)
	if err != nil {
		appLogger.Error("Could not parse config", "err", err)
		os.Exit(1)
	}
	// validate config
	if !oidcclient.ValidateConfig(config) {
		appLogger.Error("Could not validate config")
		os.Exit(1)
	}

	if useLocalhost {
		config.ListenAddress = "localhost"
	} else {
		config.ListenAddress = DefaultListeningAddress
	}

	config.ListenPort = port
	if config.RedirectUri == "" {
		config.RedirectUri = fmt.Sprintf("http://%s:%d/auth/callback", config.ListenAddress, port)
	}

	// override acr_values
	if acrValueOverride != "" {
		config.AcrValues = acrValueOverride
	}

	var jwtsigner signer.JwtSigner

	key, err := signer.ParsePrivateKey(privateKey)
	if err != nil {
		appLogger.Error("error parsing private key", "key", privateKey, "err", err)
		os.Exit(1)
	}

	jwtsigner, err = signer.NewJwtSigner(key, config.JwtSigningAlg, mockKid)
	if err != nil {
		appLogger.Error("error generating jwt signer", "err", err)
		os.Exit(1)
	}

	// Make a new OIDC Client
	client, err := oidcclient.NewOIDCClient(config, jwtsigner, appLogger)
	if err != nil {
		appLogger.Error("Error creating client", "error", err)
		os.Exit(1)
	}

	claims := map[string]interface{}{}
	state, err := client.NewState(6)
	if err != nil {
		appLogger.Error("Could not generate state", "err", err)
		os.Exit(1)
	}
	claims["state"] = state

	nonce, err := client.NewNonce(6)
	if err != nil {
		appLogger.Error("Could not generate nonce", "err", err)
		os.Exit(1)
	}
	claims["nonce"] = nonce

	if config.UsePKCE {

		// generate new code
		codeVerifier, err := client.NewCodeVerifier(config.PKCECodeLength)
		if err != nil {
			appLogger.Error("Could not generate pkce code verifier", "err", err)
			os.Exit(1)
		}

		// generate challenge
		challenge, err := client.NewCodeChallenge(codeVerifier)
		if err != nil {
			appLogger.Error("Could not generate pkce code challenge", "err", err)
			os.Exit(1)
		}

		claims["code_challenge"] = challenge
		claims["code_challenge_method"] = config.PKCEChallengeMethod

	}
	signedJwt, err := client.GenerateRequestJwt(claims)
	if err != nil {
		appLogger.Error("Error generating signed jwt ", "error", err)
		os.Exit(1)
	}

	fmt.Println(signedJwt)
}
