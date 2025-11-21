package cmd

import (
	"crypto/x509"

	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/lib/fetch"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serialCommand = &cobra.Command{
	Use:   "serial",
	Short: "Display serial number for a certificate",
	Long:  `Display the serial number for a certificate.`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		tcfg, err := tlsConfig()
		die.If(err)

		numeric := viper.GetBool("numeric")
		mode := displayMode()

		for _, arg := range args {
			var cert *x509.Certificate

			cert, err = fetch.GetCertificate(arg, tcfg)
			if err != nil {
				lib.Warn(err, "while parsing certificate from %s", arg)
				continue
			}

			msg.Printf("%s: ", arg)

			if numeric {
				msg.Printf("%s\n", cert.SerialNumber)
				continue
			}

			msg.Printf("%s\n", lib.HexEncode(cert.SerialNumber.Bytes(), mode))
			msg.Qprintln("OK.")
		}
	},
}
