package cmd

import (
	"encoding/pem"
	"os"

	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/msg"
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
		setMsg()

		if len(args) != 1 {
			die.With("expected exactly one filename")
		}

		path := args[0]
		fileData, err := os.ReadFile(path)
		die.If(err)

		if viper.IsSet(flagPEMType) {
			if viper.GetString("pem-output") != "" {
				die.With("no PEM type specified")
			}

			msg.Vprintf("encoding %s as PEM...\n", path)
			block := &pem.Block{
				Type:  viper.GetString(flagPEMType),
				Bytes: fileData,
			}

			err = pem.Encode(os.Stdout, block)
			die.If(err)

			return
		}

		msg.Vprintf("dumping binary data from %s to in %s...\n", path, viper.GetString(flagBinaryOut))

		block, _ := pem.Decode(fileData)
		err = os.WriteFile(viper.GetString(flagBinaryOut), block.Bytes, 0644)
		die.If(err)

		msg.Qprintln("OK.")
	},
}
