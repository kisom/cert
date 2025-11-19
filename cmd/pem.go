package cmd

import (
	"encoding/pem"
	"os"

	"git.wntrmute.dev/kyle/goutils/die"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var pemCommand = &cobra.Command{
	Use:   "pem",
	Short: "Encode or decode PEM files",
	Long: `Encode data to a PEM file by specifying the PEM type with -t.

Alternatively, dump the binary data in a PEM file by specifying the file name
with -b.
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			die.With("expected exactly one filename")
		}

		path := args[0]
		fileData, err := os.ReadFile(path)
		die.If(err)

		if viper.IsSet("pem-type") && viper.GetString("pem-output") != "" {
			block := &pem.Block{
				Type:  viper.GetString("pem-type"),
				Bytes: fileData,
			}

			err = pem.Encode(os.Stdout, block)
			die.If(err)

			return
		}

		block, _ := pem.Decode(fileData)
		err = os.WriteFile(viper.GetString("binary-out"), block.Bytes, 0644)
		die.If(err)
	},
}
