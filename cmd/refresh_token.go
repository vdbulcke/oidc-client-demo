package cmd

import (
	"os"

	"github.com/spf13/cobra"
	oidcclient "github.com/vdbulcke/oidc-client-demo/oidc-client"
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

	// NOTE: Redirect URI is not need for refresh token grant

	// override config if flag is passed as args
	if skipUserinfo {
		appLogger.Warn("Skipping Userinfo")
		config.SkipUserinfo = skipUserinfo
	}

	// set output flag
	config.OutputEnabled = output
	config.OutputDir = outputDir

	// Make a new OIDC Client
	client, err := oidcclient.NewOIDCClient(config, appLogger)
	if err != nil {
		appLogger.Error("Error creating client", "error", err)
		os.Exit(1)
	}

	// set default output
	client.SetDefaultOutput()

	// display info about the current client
	client.Info()

	err = client.RefreshTokenFlow(refreshToken, skipIdTokenVerification)
	if err != nil {
		appLogger.Error("Error during Refresh Token", "error", err)
		os.Exit(1)
	}

}
