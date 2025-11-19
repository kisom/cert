package cmd

import (
	"cert/tlsinfo"
	"context"
	"crypto/tls"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib/hosts"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"github.com/spf13/cobra"
)

var tlsInfoCommand = &cobra.Command{
	Use:   "tlsinfo <host:port> [more ...]",
	Short: "Connect and print TLS connection details",
	Long: `Connects to one or more TLS endpoints (proxy‑aware dialer) and prints
TLS version, cipher suite, and peer certificate subjects/issuers. Note: the
connection is made with InsecureSkipVerify=true to retrieve details; this does
not validate the peer.`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, target := range args {
			host, err := hosts.ParseHost(target)
			if err != nil {
				lib.Warn(err, "couldn't parse host %s", target)
				continue
			}

			// Use proxy-aware TLS dialer; skip verification as before
			conn, err := lib.DialTLS(
				context.Background(),
				host.String(),
				lib.DialerOpts{TLSConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402
			) // #nosec G402
			die.If(err)

			defer conn.Close()

			state := conn.ConnectionState()
			tlsinfo.PrintConnectionDetails(os.Stdout, state)
		}

	},
}
