package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	// bind to root command
	rootCmd.AddCommand(jwtCmd)

}

var jwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Commands for generating request or client_assertion jwt or jwks",
	// Long: "",
	Run: func(cmd *cobra.Command, args []string) {

		// command does nothing
		err := cmd.Help()
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(1)
	},
}
