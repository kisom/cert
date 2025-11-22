package cmd

import (
	"crypto"
	"crypto/x509"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/certgen"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func signCSR(
	cert *x509.Certificate,
	priv crypto.PrivateKey,
	cfg *certgen.CertificateRequest,
	path string,
) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	req, _, err := certlib.ParseCSR(data)
	if err != nil {
		return nil, err
	}

	return cfg.Profile.SignRequest(cert, req, priv)
}

var signCSRCommand = &cobra.Command{
	Use:   "signcsr",
	Short: "Sign a certificate signing request (CSR)",
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		msg.Vprintf("loading ca cert: %s\n", viper.GetString(flagCertFile))

		caCert, err := certlib.LoadCertificate(viper.GetString(flagCertFile))
		die.If(err)

		msg.Vprintf("loading key: %s\n", viper.GetString(flagKeyFile))

		priv, err := certlib.LoadPrivateKey(viper.GetString(flagKeyFile))
		die.If(err)

		msg.Vprintf("loading config: %s\n", viper.GetString(flagRequest))

		cfg, err := loadCertificateRequest(viper.GetString(flagRequest))
		die.If(err)

		var cert *x509.Certificate
		for _, arg := range args {
			msg.Vprintf("signing csr from %s...\n", arg)

			cert, err = signCSR(caCert, priv, cfg, arg)
			if err != nil {
				lib.Warn(err, "while signing CSR from %s", arg)
				continue
			}

			pemCert := certlib.EncodeCertificatePEM(cert)
			msg.Println(string(pemCert))

			msg.Qprintln("OK.")
		}
	},
}
