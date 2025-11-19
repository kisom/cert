package cmd

import (
	"fmt"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/die"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var matchKeyCommand = &cobra.Command{
	Use:   "matchkey -c cert.pem -k key.pem",
	Short: "Check whether a certificate and private key match",
	Long: `Load a certificate and a private key and determine whether they
correspond to each other. Returns non-zero on mismatch unless --verbose is set
and a match is found.`,
	Run: func(cmd *cobra.Command, args []string) {
		cert, err := certlib.LoadCertificate(viper.GetString("ca-file"))
		die.If(err)

		priv, err := certlib.LoadPrivateKey(viper.GetString("key-file"))
		die.If(err)

		matched, reason := certlib.MatchKeys(cert, priv)
		if matched {
			if viper.GetBool("verbose") {
				fmt.Println("OK.")
				return
			}
		}
		fmt.Printf("No match (%s).\n", reason)
		os.Exit(1)
	},
}
