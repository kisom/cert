package cmd

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/verify"
	"git.wntrmute.dev/kyle/goutils/dbg"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func isSelfSigned(cert *x509.Certificate, caCert *x509.Certificate) bool {
	if len(cert.AuthorityKeyId) == 0 {
		return true
	}

	return bytes.Equal(cert.AuthorityKeyId, caCert.AuthorityKeyId)
}

var caSignedCommand = &cobra.Command{
	Use:   "ca-signed",
	Short: "Check whether a certificate is signed by a CA",
	Long: `Check whether a certificate is signed by a CA. The file pointed to by the 
--ca is used as the CA certificate, and should contain only one CA
certificate.

Results will be output as one of:
+ SELF-SIGNED
+ INVALID
+ OK (expires <date>)`,
	Run: func(cmd *cobra.Command, args []string) {
		debug := dbg.NewFromEnv()

		if len(args) == 0 {
			fmt.Println("No certificates to check.")
			os.Exit(1)
		}

		tcfg, err := tlsConfig()
		die.If(err)

		if viper.GetString("ca") == "" {
			die.With("CA certificate file must be specified.")
		}

		caCert, err := certlib.LoadCertificates(viper.GetString("ca"))
		die.If(err)

		if len(caCert) != 1 {
			debug.Printf("CA certificate count: %d\n", len(caCert))
			die.With("only one CA certificate should be presented.")
		}

		roots := x509.NewCertPool()
		roots.AddCert(caCert[0])

		for _, arg := range args {
			var cert *x509.Certificate

			cert, err = lib.GetCertificate(arg, tcfg)
			if err != nil {
				lib.Warn(err, "while parsing certificate from %s", arg)
				continue
			}

			if isSelfSigned(cert, caCert[0]) {
				fmt.Printf("%s: SELF-SIGNED\n", arg)
				continue
			}

			if _, err := verify.CertWith(cert, roots, nil, false); err != nil {
				fmt.Printf("%s: INVALID\n", arg)
			} else {
				fmt.Printf("%s: OK (expires %s)\n", arg, cert.NotAfter.Format(lib.DateShortFormat))
			}
		}
	},
}
