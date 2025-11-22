package cmd

import (
	"os"
	"path/filepath"

	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
)

var docgenCommand = &cobra.Command{
	Use:   "docgen",
	Short: "Generate documentation for cert",
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		msg.Qprintln("generating man pages...")
		manPath := filepath.Join(viper.GetString(flagOutput), "man1")
		err := os.MkdirAll(manPath, 0755)
		die.If(err)

		header := &doc.GenManHeader{
			Title:   "CERT",
			Section: "1",
			Source:  "github.com/kisom/cert",
		}

		err = doc.GenManTree(rootCommand, header, manPath)
		die.If(err)

		msg.Qprintln("generating markdown...")
		mdPath := filepath.Join(viper.GetString(flagOutput), "md")
		err = os.MkdirAll(mdPath, 0755)
		die.If(err)

		err = doc.GenMarkdownTree(rootCommand, mdPath)
		die.If(err)
	},
}
