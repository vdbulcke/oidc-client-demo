package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var Debug bool
var noColor bool
var skipUserinfo bool
var output bool
var outputDir string

func init() {

	// add global("persistent") flag
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "debug mode enabled")
	rootCmd.PersistentFlags().BoolVarP(&noColor, "no-color", "", false, "disable color output")
	rootCmd.PersistentFlags().BoolVarP(&skipUserinfo, "skip-userinfo", "", false, "Skip fetching Userinfo")
	rootCmd.PersistentFlags().BoolVarP(&output, "output", "o", false, "Output results to files")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "", ".", "Output directory")

}

var rootCmd = &cobra.Command{
	Use:   "oidc-client",
	Short: "oidc-client is a demo CLI OIDC client",
	Long:  `A tool to test and validate OIDC integration`,
	Run: func(cmd *cobra.Command, args []string) {

		// Root command does nothing
		err := cmd.Help()
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(1)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
