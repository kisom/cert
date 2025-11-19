package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/certgen"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func signCSR(cert *x509.Certificate, priv crypto.PrivateKey, cfg *certgen.CertificateRequest, path string) (*x509.Certificate, error) {
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
		verbose := viper.GetBool("verbose")

		if verbose {
			fmt.Printf("loading ca cert: %s\n", viper.GetString("signing-cert-file"))
		}
		caCert, err := certlib.LoadCertificate(viper.GetString("signing-cert-file"))
		die.If(err)

		if verbose {
			fmt.Printf("loading key: %s\n", viper.GetString("signing-key-file"))
		}
		priv, err := certlib.LoadPrivateKey(viper.GetString("signing-key-file"))
		die.If(err)

		if verbose {
			fmt.Printf("loading config: %s\n", viper.GetString("signing-request"))
		}
		cfg, err := loadCertificateRequest(viper.GetString("signing-request"))
		die.If(err)

		var cert *x509.Certificate
		for _, arg := range args {
			if verbose {
				fmt.Printf("signing csr from %s...\n", arg)
			}

			cert, err = signCSR(caCert, priv, cfg, arg)
			if err != nil {
				lib.Warn(err, "while signing CSR from %s", arg)
				continue
			}

			pemCert := certlib.EncodeCertificatePEM(cert)
			fmt.Println(string(pemCert))
		}
	},
}
