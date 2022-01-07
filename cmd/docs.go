package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var docDir string

func init() {
	rootCmd.AddCommand(mdGenCmd)
	// add flags to sub command
	mdGenCmd.Flags().StringVarP(&docDir, "dir", "", "./doc", "Directory where to generate the doc")
	//nolint
	mdGenCmd.MarkFlagRequired("dir")

	// rootCmd.DisableSuggestions = true
}

var mdGenCmd = &cobra.Command{
	Use:   "documentation",
	Short: "Generate Markdown doc for oidc-client",
	Long:  `Generate Markdown in ./doc`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("generating doc...")

		err := doc.GenMarkdownTree(rootCmd, docDir)
		if err != nil {
			log.Fatal(err)
		}

	},
}
