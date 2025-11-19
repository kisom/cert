package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/certgen"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/lib/dialer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func getPool() (*x509.CertPool, error) {
	return certlib.LoadFullCertPool(viper.GetString("ca"), viper.GetString("intermediates-file"))
}

func tlsConfig() (*tls.Config, error) {
	tcfg, err := dialer.BaselineTLSConfig(viper.GetBool("skip-verify"), viper.GetBool("strict-tls"))
	if err != nil {
		return nil, fmt.Errorf("couldn't create TLS config: %w", err)
	}

	pool, err := getPool()
	if err != nil {
		return nil, fmt.Errorf("couldn't load certificate pool: %w", err)
	}

	tcfg.RootCAs = pool
	return tcfg, nil
}

func displayMode() lib.HexEncodeMode {
	return lib.ParseHexEncodeMode(viper.GetString("display-mode"))
}

func loadCertificateRequest(path string) (*certgen.CertificateRequest, error) {
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't read certificate request file: %w", err)
	}

	req := &certgen.CertificateRequest{}

	err = yaml.Unmarshal(fileData, req)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse certificate request file: %w", err)
	}

	return req, nil
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		path := filepath.Join(home, ".config", "goutils")

		viper.AddConfigPath(path)
		viper.SetConfigType("yaml")
		viper.SetConfigName("cert")
	}

	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func initRootFlags() {
	// Persistent flags follow.
	rootCommand.PersistentFlags().StringVar(&cfgFile,
		"config", "",
		"config file (default is $HOME/.config/goutils/cert.yaml)")
	rootCommand.PersistentFlags().String("ca", "", "CA certificate bundle file")
	rootCommand.PersistentFlags().StringP("display-mode", "d", "lower", "hex display mode for SKI")
	rootCommand.PersistentFlags().StringP("intermediates-file", "i", "",
		"intermediate certificate bundle")
	rootCommand.PersistentFlags().BoolP("skip-verify", "k", false, "skip certificate verification")
	rootCommand.PersistentFlags().Bool("strict-tls", false, "use strict TLS settings")
	rootCommand.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	// Bind persistent flags.
	viper.BindPFlag("ca", rootCommand.PersistentFlags().Lookup("ca"))
	viper.BindPFlag("display-mode", rootCommand.PersistentFlags().Lookup("display-mode"))
	viper.BindPFlag("intermediates-file", rootCommand.PersistentFlags().Lookup("intermediates-file"))
	viper.BindPFlag("skip-verify", rootCommand.PersistentFlags().Lookup("skip-verify"))
	viper.BindPFlag("strict-tls", rootCommand.PersistentFlags().Lookup("strict-tls"))
	viper.BindPFlag("verbose", rootCommand.PersistentFlags().Lookup("verbose"))

	rootCommand.MarkFlagsMutuallyExclusive("skip-verify", "strict-tls")
}

func initLocalFlags() {
	bundlerCommand.Flags().
		StringP("config-file", "f", "bundle.yaml", "config file for bundler (default: bundle.yaml in current directory")
	bundlerCommand.Flags().StringP("output", "o", "pkg", "output directory for generated files")
	csrPubCommand.Flags().Bool("stdout", false, "write PEM-encoded CSR to stdout instead of a file")
	dumpCommand.Flags().BoolP("leaf-only", "l", false, "only display the leaf certificate")
	dumpCommand.Flags().BoolP("show-hashes", "s", false, "show hashes of all certificates in the chain")
	expiryCommand.Flags().DurationP("leeway", "p", 0, "leeway for certificate expiry checks (e.g. 1h30m")
	expiryCommand.Flags().BoolP("expiring-only", "q", false, "only display certificates expiring soon")
	genCSRCommand.Flags().StringP("request", "f", "request.yaml", "YAML config file to use for self-signing")
	genCSRCommand.Flags().StringP("key-file", "p", "", "key file to match")
	genKeyCommand.Flags().StringP("key-algo", "a", "ecdsa", "key type to generate (rsa or ec)")
	genKeyCommand.Flags().IntP("key-size", "s", 521, "key size to generate (in bits)")
	matchKeyCommand.Flags().StringP("cert-file", "c", "", "certificate file to match (PEM or DER format")
	matchKeyCommand.Flags().StringP("key-file", "p", "", "key file to match")
	pemCommand.Flags().StringP("binary-out", "b", "", "file to write extracted binary data from a PEM file")
	pemCommand.Flags().StringP("pem-type", "t", "CERTIFICATE", "PEM type for output")
	selfSignCommand.Flags().StringP("request", "f", "request.yaml", "YAML config file to use for self-signing")
	serialCommand.Flags().BoolP("numeric", "n", false, "display serial numbers as integers")
	signCSRCommand.Flags().StringP("cert-file", "c", "", "certificate file to match (PEM or DER format")
	signCSRCommand.Flags().StringP("request", "f", "request.yaml", "YAML config file to use for certificate signing")
	signCSRCommand.Flags().StringP("key-file", "p", "", "key file to match")
	skiCommand.Flags().BoolP("should-match", "m", false, "all SKIs should match")
	stealchainCommand.Flags().StringP("sni-name", "s", "", "SNI name to use when connecting")
	verifyCommand.Flags().BoolP("force-intermediate-bundle", "f", false, "force loading of intermediate bundle")
	verifyCommand.Flags().BoolP("check-revocation", "r", false, "check revocation status")
}

func bindLocalFlags() {
	viper.BindPFlag("config-file", bundlerCommand.Flags().Lookup("config-file"))
	viper.BindPFlag("output", bundlerCommand.Flags().Lookup("output"))
	viper.BindPFlag("stdout", csrPubCommand.Flags().Lookup("stdout"))
	viper.BindPFlag("leaf-only", dumpCommand.Flags().Lookup("leaf-only"))
	viper.BindPFlag("show-hashes", dumpCommand.Flags().Lookup("show-hashes"))
	viper.BindPFlag("leeway", expiryCommand.Flags().Lookup("leeway"))
	viper.BindPFlag("expiring-only", expiryCommand.Flags().Lookup("expiring-only"))
	viper.BindPFlag("gencsr-request", genCSRCommand.Flags().Lookup("request"))
	viper.BindPFlag("gencsr-key-file", genCSRCommand.Flags().Lookup("key-file"))
	viper.BindPFlag("key-algo", genKeyCommand.Flags().Lookup("key-algo"))
	viper.BindPFlag("key-size", genKeyCommand.Flags().Lookup("key-size"))
	viper.BindPFlag("cert-file", matchKeyCommand.Flags().Lookup("cert-file"))
	viper.BindPFlag("key-file", matchKeyCommand.Flags().Lookup("key-file"))
	viper.BindPFlag("binary-out", pemCommand.Flags().Lookup("binary-out"))
	viper.BindPFlag("pem-type", pemCommand.Flags().Lookup("pem-type"))
	viper.BindPFlag("request", selfSignCommand.Flags().Lookup("request"))
	viper.BindPFlag("numeric", serialCommand.Flags().Lookup("numeric"))
	viper.BindPFlag("signing-cert-file", signCSRCommand.Flags().Lookup("cert-file"))
	viper.BindPFlag("signing-request", signCSRCommand.Flags().Lookup("request"))
	viper.BindPFlag("signing-key-file", signCSRCommand.Flags().Lookup("key-file"))
	viper.BindPFlag("should-match", skiCommand.Flags().Lookup("should-match"))
	viper.BindPFlag("sni-name", stealchainCommand.Flags().Lookup("sni-name"))
	viper.BindPFlag("force-intermediate-bundle", verifyCommand.Flags().Lookup("force-intermediate-bundle"))
	viper.BindPFlag("check-revocation", verifyCommand.Flags().Lookup("check-revocation"))

	pemCommand.MarkFlagsMutuallyExclusive("binary-out", "pem-type")
	pemCommand.MarkFlagsOneRequired("binary-out", "pem-type")

	caSignedCommand.MarkFlagRequired("ca")
	genCSRCommand.MarkFlagRequired("request")
	matchKeyCommand.MarkFlagRequired("cert-file")
	matchKeyCommand.MarkFlagRequired("key-file")
	selfSignCommand.MarkFlagRequired("request")
	signCSRCommand.MarkFlagRequired("signing-cert-file")
	signCSRCommand.MarkFlagRequired("signing-request")
	signCSRCommand.MarkFlagRequired("signing-key-file")
}

func init() {
	cobra.OnInitialize(initConfig)

	initRootFlags()
	initLocalFlags()
	bindLocalFlags()
}

func init() {
	rootCommand.AddCommand(bundlerCommand)
	rootCommand.AddCommand(caSignedCommand)
	rootCommand.AddCommand(csrPubCommand)
	rootCommand.AddCommand(dumpCommand)
	rootCommand.AddCommand(expiryCommand)
	rootCommand.AddCommand(genCSRCommand)
	rootCommand.AddCommand(genKeyCommand)
	rootCommand.AddCommand(matchKeyCommand)
	rootCommand.AddCommand(pemCommand)
	rootCommand.AddCommand(selfSignCommand)
	rootCommand.AddCommand(serialCommand)
	rootCommand.AddCommand(signCSRCommand)
	rootCommand.AddCommand(skiCommand)
	rootCommand.AddCommand(stealchainCommand)
	rootCommand.AddCommand(tlsInfoCommand)
	rootCommand.AddCommand(verifyCommand)
	rootCommand.AddCommand(versionCommand)
}
