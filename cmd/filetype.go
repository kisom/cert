package cmd

import (
	"fmt"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"github.com/spf13/cobra"
)

var fileTypeCommand = &cobra.Command{
	Use:   "filetype",
	Short: "Display the file type of an X.509 file",
	Long:  `Display the file type of an X.509 file.`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, fileName := range args {
			fmt.Printf("%s: ", fileName)

			fileKind, err := certlib.FileKind(fileName)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println(fileKind)
		}
	},
}
