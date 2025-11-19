package cmd

import (
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

		priv, req, err := reqConfig.Generate()
		die.If(err)

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
