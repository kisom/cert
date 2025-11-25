package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var csrPubCommand = &cobra.Command{
	Use:   "csrpub",
	Short: "Display public key from a CSR",
	Long:  `Extract the public key from a CSR and write it to a PEM file.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmdInit(cmd, flagStdout)
	},
	Run: func(cmd *cobra.Command, args []string) {
		for _, fileName := range args {
			in, err := os.ReadFile(fileName)
			die.If(err)

			csr, _, err := certlib.ParseCSR(in)
			die.If(err)

			out, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
			die.If(err)

			var t string
			switch pub := csr.PublicKey.(type) {
			case *rsa.PublicKey:
				t = "RSA PUBLIC KEY"
			case *ecdsa.PublicKey:
				t = "EC PUBLIC KEY"
			case *ed25519.PublicKey:
				t = "ED25519 PUBLIC KEY"
			default:
				die.With("unrecognised public key type %T", pub)
			}

			p := &pem.Block{
				Type:  t,
				Bytes: out,
			}

			if viper.GetBool(flagStdout) {
				err = pem.Encode(os.Stdout, p)
				die.If(err)

				continue
			}

			err = os.WriteFile(fileName+".pub", pem.EncodeToMemory(p), 0o644) // #nosec G306
			die.If(err)

			msg.Qprintf("[+] wrote %s.\n", fileName+".pub")
			msg.Qprintln("OK.")
		}
	},
}
