package cmd

import (
	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
)

var fileTypeCommand = &cobra.Command{
	Use:   "filetype",
	Short: "Display the file type of an X.509 file",
	Long:  `Display the file type of an X.509 file.`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		for _, fileName := range args {
			msg.Printf("%s: ", fileName)

			fileKind, err := certlib.FileKind(fileName)
			if err != nil {
				msg.Println(err)
			}

			msg.Println(fileKind)
		}
	},
}
