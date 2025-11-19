package cmd

import (
	"fmt"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/certgen"
	"git.wntrmute.dev/kyle/goutils/die"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var genKeyCommand = &cobra.Command{
	Use:   "genkey",
	Short: "Generate a private key",
	Long:  `Generate a private key.`,
	Run: func(cmd *cobra.Command, args []string) {
		keyAlgo := certgen.KeySpec{
			Algorithm: viper.GetString("key-algo"),
			Size:      viper.GetInt("key-size"),
		}

		_, priv, err := keyAlgo.Generate()
		die.If(err)

		out, err := certlib.ExportPrivateKeyPEM(priv)
		die.If(err)

		fmt.Println(string(out))
	},
}
