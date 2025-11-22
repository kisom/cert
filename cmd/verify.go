package cmd

import (
	"crypto/x509"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/verify"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verifyCommand = &cobra.Command{
	Use:   "verify <host:port|cert.pem> [more ...]",
	Short: "Verify certificate chains for hosts or certificate files",
	Long: `Verify certificate chains for one or more targets. Targets can be
TLS endpoints (host:port) or certificate files. You can supply custom root CA
and intermediate bundles. Optionally check revocation.
`,
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		var (
			roots, ints *x509.CertPool
			err         error
			failed      bool
		)

		opts := &verify.Opts{
			CheckRevocation:    viper.GetBool(flagCheckRevocation),
			ForceIntermediates: viper.GetBool(flagForceIntBundle),
			Verbose:            viper.GetBool(flagVerbose),
		}

		caFile := viper.GetString(flagCA)
		if caFile != "" {
			msg.Vprintf("loading CA certificates from %s\n", caFile)

			roots, err = certlib.LoadPEMCertPool(caFile)
			die.If(err)
		}

		intFile := viper.GetString(flagIntermediatesFile)
		if intFile != "" {

			msg.Vprintf("loading intermediate certificates from %s\n", intFile)

			ints, err = certlib.LoadPEMCertPool(intFile)
			die.If(err)
		}

		opts.Config, err = tlsConfig()
		die.If(err)

		opts.Config.RootCAs = roots
		opts.Intermediates = ints

		for _, arg := range args {
			msg.Vprintf("verifying %s...\n", arg)

			_, err = verify.Chain(os.Stdout, arg, opts)
			if err != nil {
				lib.Warn(err, "while verifying %s", arg)
				failed = true
			} else {
				msg.Vprintf("%s: OK\n", arg)

			}
		}

		if failed {
			os.Exit(1)
		}
	},
}
