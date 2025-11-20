package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/die"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var selfSignCommand = &cobra.Command{
	Use:   "selfsign",
	Short: "Generate a self-signed certificate",
	Long:  `Generate a self-signed certificate.`,
	Run: func(cmd *cobra.Command, args []string) {
		configFile := viper.GetString("request")
		if configFile == "" {
			die.With("no request file specified.")
		}

		reqConfig, err := loadCertificateRequest(configFile)
		die.If(err)

		var (
			priv crypto.PrivateKey
			req  *x509.CertificateRequest
		)

		if viper.IsSet("selfsign-key-file") {
			if viper.GetBool("verbose") {
				fmt.Printf("loading key: %s\n", viper.GetString("selfsign-key-file"))
			}

			priv, err = certlib.LoadPrivateKey(viper.GetString("selfsign-key-file"))
			die.If(err)

			if viper.IsSet("selfsign-csr-file") {
				if viper.GetBool("verbose") {
					fmt.Printf("loading csr: %s\n", viper.GetString("selfsign-csr-file"))
				}

				req, err = certlib.LoadCSR(viper.GetString("selfsign-csr-file"))
				die.If(err)
			}
		}

		if priv == nil {
			if viper.IsSet("selfsign-csr-file") {
				die.With("cannot selfsign a CSR without a key.")
			}

			priv, req, err = reqConfig.Generate()
			die.If(err)
		}

		if req == nil {
			req, err = reqConfig.Request(priv)
			die.If(err)
		}

		cert, err := reqConfig.Profile.SelfSign(req, priv)
		die.If(err)

		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		die.If(err)

		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

		certPEM := certlib.EncodeCertificatePEM(cert)

		fmt.Println(string(privPEM))
		fmt.Println(string(certPEM))

	},
}
