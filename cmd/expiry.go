package cmd

import (
	"crypto/x509"

	"git.wntrmute.dev/kyle/goutils/certlib/verify"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/lib/fetch"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var expiryCommand = &cobra.Command{
	Use:   "expiry <cert.pem>",
	Short: "Display certificate expiry date",
	Long: `Display the expiry date of a certificate file. If quiet mode is enabled,
only certificates expiring within the window are displayed.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmdInit(cmd, flagLeeway)
	},
	Run: func(cmd *cobra.Command, args []string) {
		tcfg, err := tlsConfig()
		die.If(err)

		for _, target := range args {
			var certs []*x509.Certificate

			certs, err = fetch.GetCertificateChain(target, tcfg)
			if err != nil {
				lib.Warn(err, "while parsing certificates")
				continue
			}

			for _, cert := range certs {
				check := verify.NewCertCheck(cert, viper.GetDuration(flagLeeway))

				if viper.GetBool("expiring-only") {
					if err = check.Err(); err != nil {
						lib.Warn(err, "certificate is expiring")
					}
				} else {
					name := check.Name()
					if viper.GetBool(flagShort) {
						name = cert.Subject.CommonName
						if name == "" {
							name = target
						}
					}
					msg.Printf("%s expires on %s (in %s)\n", name,
						cert.NotAfter, check.Expiry())
				}
			}
		}
	},
}
