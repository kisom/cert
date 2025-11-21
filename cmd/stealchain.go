package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"os"

	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib/fetch"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var stealchainCommand = &cobra.Command{
	Use:   "stealchain <host:port> [more ...]",
	Short: "Retrieve and save the full certificate chain from a TLS host",
	Long: `Connect to one or more TLS endpoints and write the presented
certificate chain to a local PEM file named <host>.pem.

Use --sni-name to override the SNI name used for the TLS handshake. Root CAs
are taken from --ca if provided, otherwise from the system pool.`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		var roots *x509.CertPool

		tcfg, err := tlsConfig()
		die.If(err)

		if viper.GetString("ca") != "" {
			roots, err = getPool()
			die.If(err)
		} else {
			roots, err = x509.SystemCertPool()
			die.If(err)
		}

		tcfg.RootCAs = roots

		if viper.GetString("sni-name") != "" {
			tcfg.ServerName = viper.GetString("sni-name")
		}

		for _, site := range args {
			var chains []*x509.Certificate

			msg.Vprintf("[+] fetching chain for %s...\n", site)

			chains, err = fetch.GetCertificateChain(site, tcfg)
			die.If(err)

			var chain []byte

			for _, cert := range chains {
				p := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				}
				chain = append(chain, pem.EncodeToMemory(p)...)
			}

			err = os.WriteFile(site+".pem", chain, 0644)
			die.If(err)

			msg.Vprintf("[+] wrote %s.pem.\n", site)
			msg.Qprintln("OK.")
		}
	},
}
