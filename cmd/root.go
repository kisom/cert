// Package cmd contains the Cobra CLI commands.
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

The display modes for hex-encoded data can be controlled with the 
--display-mode flag. Valid settings are:
  + lower (default)
  + upper
  + lcolon (display as colon-separated lowercase hex pairs)
  + uccolon (display as colon-separated uppercase hex pairs)
  + bytes (display as a Go byte slice)
  + base64 (display as base64)"
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
