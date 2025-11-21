package cmd

import (
	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/certgen"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var genKeyCommand = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a private key",
	Long:  `Generate a private key.`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		keyAlgo := certgen.KeySpec{
			Algorithm: viper.GetString("key-algo"),
			Size:      viper.GetInt("key-size"),
		}

		msg.Vprintf("generating %s private key\n", printKeySpec(keyAlgo))

		_, priv, err := keyAlgo.Generate()
		die.If(err)

		out, err := certlib.ExportPrivateKeyPEM(priv)
		die.If(err)

		msg.Println(string(out))
		msg.Qprintln("OK.")
	},
}
