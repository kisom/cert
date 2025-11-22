package cmd

import (
	"context"
	"crypto/tls"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib/hosts"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/lib/dialer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/kisom/cert/tlsinfo"
)

var tlsInfoCommand = &cobra.Command{
	Use:   "tlsinfo <host:port> [more ...]",
	Short: "Connect and print TLS connection details",
	Long: `Connects to one or more TLS endpoints (proxy‑aware dialer) and prints
TLS version, cipher suite, and peer certificate subjects/issuers. Note: the
connection is made with InsecureSkipVerify=true to retrieve details; this does
not validate the peer.`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		for _, target := range args {
			host, err := hosts.ParseHost(target)
			if err != nil {
				lib.Warn(err, "couldn't parse host %s", target)
				continue
			}

			// Use proxy-aware TLS dialer; skip verification as before
			conn, err := dialer.DialTLS(
				context.Background(),
				host.String(),
				dialer.Opts{TLSConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         viper.GetString(flagSNIName),
				}}, // #nosec G402
			) // #nosec G402
			die.If(err)

			state := conn.ConnectionState()
			tlsinfo.PrintConnectionDetails(os.Stdout, state)
			conn.Close()
		}

	},
}
