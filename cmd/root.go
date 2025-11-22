package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

// rootCommand represents the base command when called without any subcommands.
var rootCommand = &cobra.Command{
	Use:   "cert",
	Short: "A certificate swiss‑army knife",
	Long: `cert is a small command‑line tool for inspecting and working with X.509/TLS
certificates and connections. It consolidates several utilities from kisom/goutils
into a single binary using the Cobra CLI framework. Use --help on any subcommand
to see details and examples.

A note on targets: most commands accept a list of targets, which can be either
remote hosts or local files. cert will first check whether the target is a file
on disk; if it is not, it will attempt to treat the target as a remote host.
Valid formats for remote hosts are:

- host[:port] (defaulting to port 443)
- https URLs, including host:port
- tls://host[:port]

Generally, the tools will not proceed past the handshake state when connecting to
a remote host.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCommand.
func Execute() {
	err := rootCommand.Execute()
	if err != nil {
		os.Exit(1)
	}
}
