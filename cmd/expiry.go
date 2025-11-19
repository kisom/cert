package cmd

import (
	"crypto/x509"
	"fmt"

	"git.wntrmute.dev/kyle/goutils/certlib/verify"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var expiryCommand = &cobra.Command{
	Use:   "expiry <cert.pem>",
	Short: "Display certificate expiry date",
	Long:  `Display the expiry date of a certificate file.`,
	Run: func(cmd *cobra.Command, args []string) {
		tcfg, err := tlsConfig()
		die.If(err)

		for _, target := range args {
			var certs []*x509.Certificate

			certs, err = lib.GetCertificateChain(target, tcfg)
			if err != nil {
				lib.Warn(err, "while parsing certificates")
				continue
			}

			for _, cert := range certs {
				check := verify.NewCertCheck(cert, viper.GetDuration("leeway"))

				if viper.GetBool("expiring-only") {
					if err = check.Err(); err != nil {
						lib.Warn(err, "certificate is expiring")
					}
				} else {
					fmt.Printf("%s expires on %s (in %s)\n", check.Name(),
						cert.NotAfter, check.Expiry())
				}
			}
		}
	},
}
