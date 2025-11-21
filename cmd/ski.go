package cmd

import (
	"flag"

	"git.wntrmute.dev/kyle/goutils/certlib/ski"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/viper"

	"github.com/spf13/cobra"
)

var skiCommand = &cobra.Command{
	Use:   "ski <key-or-cert> [more ...]",
	Short: "Display Subject Key Identifier (SKI) for keys/certs",
	Long: `Display the Subject Key Identifier (SKI) for one or more keys or
certificates. When multiple files are provided with --should-match, all SKIs
are compared and a warning is printed if any differ. The output includes the
input path, SKI, key type, and file type.

Use --display-mode to control hex formatting of the SKI (default: lower).`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		var matchSKI string
		for _, path := range flag.Args() {
			keyInfo, err := ski.ParsePEM(path)
			die.If(err)

			keySKI, err := keyInfo.SKI(displayMode())
			die.If(err)

			if matchSKI == "" {
				matchSKI = keySKI
			}

			if viper.GetBool("should-match") && matchSKI != keySKI {
				_, _ = lib.Warnx("%s: SKI mismatch (%s != %s)",
					path, matchSKI, keySKI)
			}

			msg.Printf("%s  %s (%s %s)\n", path, keySKI, keyInfo.KeyType, keyInfo.FileType)
			msg.Qprintln("OK")
		}
	},
}
