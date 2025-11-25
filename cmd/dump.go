package cmd

import (
	"crypto/x509"
	"os"

	"git.wntrmute.dev/kyle/goutils/lib/fetch"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"git.wntrmute.dev/kyle/goutils/certlib/dump"
	"git.wntrmute.dev/kyle/goutils/lib"
)

var dumpCommand = &cobra.Command{
	Use:   "dump [host:port|cert.pem]...",
	Short: "Fetch and display certificates for a host or PEM file(s)",
	Long: `Fetch and display certificates for one or more targets.

Targets may be:
- A TLS endpoint in host:port form (e.g., example.com:443) — the peer chain is
  retrieved and displayed.
- A path to a PEM/DER certificate file — the certificate is displayed.

Use --leaf-only to print only the leaf certificate when connecting to a host.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmdInit(cmd, flagLeafOnly, flagShowHashes)
	},
	Run: func(cmd *cobra.Command, args []string) {
		tcfg, err := tlsConfig()
		cobra.CheckErr(err)

		for _, arg := range args {
			var certs []*x509.Certificate

			msg.Printf("--%s ---\n", arg)

			certs, err = fetch.GetCertificateChain(arg, tcfg)
			if err != nil {
				lib.Warn(err, "couldn't read certificate")
				continue
			}

			if viper.GetBool(flagLeafOnly) {
				dump.DisplayCert(os.Stdout, certs[0], viper.GetBool(flagShowHashes))
				continue
			}

			for i := range certs {
				dump.DisplayCert(os.Stdout, certs[i], viper.GetBool(flagShowHashes))
			}
		}
	},
}
