package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var selfSignCommand = &cobra.Command{
	Use:   "selfsign",
	Short: "Generate a self-signed certificate",
	Long:  `Generate a self-signed certificate.`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		configFile := viper.GetString("request")
		msg.Vprintf("loading request from %s\n", configFile)
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
			msg.Vprintf("loading key: %s\n", viper.GetString("selfsign-key-file"))

			priv, err = certlib.LoadPrivateKey(viper.GetString("selfsign-key-file"))
			die.If(err)

			if viper.IsSet("selfsign-csr-file") {
				msg.Vprintf("loading csr: %s\n", viper.GetString("selfsign-csr-file"))

				req, err = certlib.LoadCSR(viper.GetString("selfsign-csr-file"))
				die.If(err)
			}
		}

		if priv == nil {
			if viper.IsSet("selfsign-csr-file") {
				die.With("cannot selfsign a CSR without a key.")
			}

			msg.Vprintf("generating %s key...\n", printKeySpec(reqConfig.KeySpec))
			priv, req, err = reqConfig.Generate()
			die.If(err)
		}

		if req == nil {
			msg.Vprintln("generating certificate signing request...")
			req, err = reqConfig.Request(priv)
			die.If(err)
		}

		msg.Dprintln("signing certificate...")
		cert, err := reqConfig.Profile.SelfSign(req, priv)
		die.If(err)

		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		die.If(err)

		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

		certPEM := certlib.EncodeCertificatePEM(cert)

		fmt.Println(string(privPEM))
		fmt.Println(string(certPEM))

		msg.Qprintln("OK.")
	},
}
