// Package cmd contains the Cobra CLI framework for cert.
//
// The doc command contains documentation for specific areas.
package cmd

import (
	"os"
	"sort"

	"git.wntrmute.dev/kyle/goutils/die"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
)

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	return keys
}

type docTopic struct {
	Short string
	Long  string
}

var docCommand = &cobra.Command{
	Use:   "doc",
	Short: "Display documentation for specific features",
	Run: func(cmd *cobra.Command, args []string) {
		setMsg()

		if len(args) == 0 {
			msg.Println("doc provides additional documentation for specific features.")
			msg.Println()
			msg.Println("Available topics:")
			for _, key := range sortedKeys(docSubcommands) {
				msg.Printf("\t%s - %s\n", key, docSubcommands[key].Short)
			}

			return
		}

		if len(args) > 1 {
			die.With("Additional arguments not supported.")
		}

		docs, ok := docSubcommands[args[0]]
		if !ok {
			msg.Printf("Unknown topic: %s\n\n", args[0])
			msg.Println("Available topics:")
			for _, key := range sortedKeys(docSubcommands) {
				msg.Printf("\t%s - %s\n", key, docSubcommands[key].Short)
			}

			os.Exit(1)
		}

		msg.Printf("%s", docs.Long)
	},
}

var docSubcommands = map[string]*docTopic{
	"certgen": {
		Short: "certificate generation configuration files",
		Long: `Many of the subcommands of cert that are related to certificate generation,
such as gencsr, selfsign, and signcsr, use a YAML configuration file. This
file contains key generation parameters, certificate subject information,
and basic signing profile information. Certificate generation in cert
is intended to be a basic set of tools, and if more complex certificate
generation is required, it is recommended to use a different tool.

An example file is:

key:
  algorithm: ecdsa
  size: 521
subject:
  common_name: Example Web Server
  country: US
  locality: Golden
  province: CO
  organization: Acme Certificate Authority
  organizational_unit: Cryptographic Services
  dns:
    - example.com
	- www.example.com
	- mail.example.com
  ips:
	- 192.168.1.64
profile:
  is_ca: false
  path_len: 0
  key_uses: digital signature
  ext_key_usages:
    - server auth
  expiry: 30d

KEY SECTION

The supported algorithms are ed25519, ecdsa, and rsa. For ecdsa, the size
selects the relevant NIST curve (e.g. 256 for P-256; options are 256, 384,
and 521). For ed25519, the size is ignored.

SUBJECT SECTION

The subject section contains information about the certificate subject, and
is used to both build the subject information and fill in SANs.

PROFILE SECTION

The profile section contains information about the certificate signing.

If the profile is for a certificate authority, the is_ca field should be set
as well as the path_len field.

Generally for server certificates, the key_uses field should be set to
digital signature and ext_key_usages should include server auth. The list
of strings for these fields is documented in the goutils/certlib/certgen
package, but is provided below.

KEY USES
	
	- signing
	- digital signature
	- content commitment
	- key encipherment
	- key agreement
	- data encipherment
	- cert sign
	- crl sign
	- encipher only
	- decipher only

EXTENDED KEY USAGES
	- any
	- server auth
	- client auth
	- code signing
	- email protection
	- s/mime
	- ipsec end system
	- ipsec tunnel
	- ipsec user
	- timestamping
	- ocsp signing
	- microsoft sgc
	- netscape sgc
`,
	},
}
