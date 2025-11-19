package cmd

import (
	"crypto"
	"fmt"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/die"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var genCSRCommand = &cobra.Command{
	Use:   "gencsr",
	Short: "Generate a certificate signing request",
	Long:  `Generate a certificate signing request.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := loadCertificateRequest(viper.GetString("gencsr-request"))
		die.If(err)

		var priv crypto.PrivateKey
		fmt.Printf("private key: %s\n", viper.GetString("gencsr-key-file"))
		if viper.IsSet("gencsr-key-file") {
			priv, err = certlib.LoadPrivateKey(viper.GetString("gencsr-key-file"))
			die.If(err)
		} else {
			var out []byte

			_, priv, err = cfg.KeySpec.Generate()
			die.If(err)

			out, err = certlib.ExportPrivateKeyPEM(priv)
			die.If(err)
			fmt.Println(string(out))
		}

		req, err := cfg.Request(priv)
		die.If(err)

		fmt.Println(string(certlib.ExportCSRAsPEM(req)))
	},
}
