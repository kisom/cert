package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/certlib/certgen"
	"git.wntrmute.dev/kyle/goutils/certlib/verify"
	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/lib/dialer"
	"git.wntrmute.dev/kyle/goutils/msg"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func getPool() (*x509.CertPool, error) {
	return certlib.LoadFullCertPool(viper.GetString(flagCA), viper.GetString(flagIntermediatesFile))
}

func tlsConfig() (*tls.Config, error) {
	tcfg, err := dialer.BaselineTLSConfig(viper.GetBool(flagSkipVerify), viper.GetBool(flagStrictTLS))
	if err != nil {
		return nil, fmt.Errorf("couldn't create TLS config: %w", err)
	}

	pool, err := getPool()
	if err != nil {
		return nil, fmt.Errorf("couldn't load certificate pool: %w", err)
	}

	tcfg.RootCAs = pool
	tcfg.ServerName = viper.GetString(flagSNIName)

	return tcfg, nil
}

func displayMode() lib.HexEncodeMode {
	return lib.ParseHexEncodeMode(viper.GetString(flagDisplayMode))
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

func setMsg() {
	msg.Reset()

	msg.Set(
		viper.GetBool(flagQuiet),
		viper.GetBool(flagVerbose),
		viper.GetBool(flagDebug),
	)
}

func printKeySpec(ks certgen.KeySpec) string {
	if strings.ToLower(ks.Algorithm) == "ed25519" {
		return "ed25519"
	}

	return fmt.Sprintf("%s-%d", ks.Algorithm, ks.Size)
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
	rootCommand.PersistentFlags().String(flagCA, "", "CA certificate bundle file")
	rootCommand.PersistentFlags().Bool(flagDebug, false, "enable debug mode")
	rootCommand.PersistentFlags().StringP(flagDisplayMode, "d", "lower", "hex display mode for SKI")
	rootCommand.PersistentFlags().StringP(flagIntermediatesFile, "i", "",
		"intermediate certificate bundle")
	rootCommand.PersistentFlags().BoolP(flagSkipVerify, "k", false, "skip certificate verification")
	rootCommand.PersistentFlags().Bool(flagStrictTLS, false, "use strict TLS settings")
	rootCommand.PersistentFlags().BoolP(flagQuiet, "q", false, "enable quiet mode")
	rootCommand.PersistentFlags().BoolP(flagVerbose, "v", false, "verbose output")

	// Bind persistent flags.
	viper.BindPFlag(flagCA, rootCommand.PersistentFlags().Lookup(flagCA))
	viper.BindPFlag(flagDebug, rootCommand.PersistentFlags().Lookup(flagDebug))
	viper.BindPFlag(flagDisplayMode, rootCommand.PersistentFlags().Lookup(flagDisplayMode))
	viper.BindPFlag(flagIntermediatesFile, rootCommand.PersistentFlags().Lookup(flagIntermediatesFile))
	viper.BindPFlag(flagSkipVerify, rootCommand.PersistentFlags().Lookup(flagSkipVerify))
	viper.BindPFlag(flagStrictTLS, rootCommand.PersistentFlags().Lookup(flagStrictTLS))
	viper.BindPFlag(flagQuiet, rootCommand.PersistentFlags().Lookup(flagQuiet))
	viper.BindPFlag(flagVerbose, rootCommand.PersistentFlags().Lookup(flagVerbose))

	rootCommand.MarkFlagsMutuallyExclusive(flagSkipVerify, flagStrictTLS)
	rootCommand.MarkFlagsMutuallyExclusive(flagQuiet, flagVerbose)
}

func initLocalFlags() {
	bundlerCommand.Flags().
		StringP(flagConfigFile, "f", "bundle.yaml", "config file for bundler (default: bundle.yaml in current directory")
	bundlerCommand.Flags().StringP(flagOutput, "o", "pkg", "output directory for generated files")
	csrPubCommand.Flags().Bool(flagStdout, false, "write PEM-encoded CSR to stdout instead of a file")
	dumpCommand.Flags().BoolP(flagLeafOnly, "l", false, "only display the leaf certificate")
	dumpCommand.Flags().BoolP(flagShowHashes, "s", false, "show hashes of all certificates in the chain")
	expiryCommand.Flags().
		DurationP(flagLeeway, "p", verify.DefaultLeeway, "leeway for certificate expiry checks (e.g. 1h30m")
	genCSRCommand.Flags().StringP(flagRequest, "f", "request.yaml", "YAML config file to use for self-signing")
	genCSRCommand.Flags().StringP(flagKeyFile, "p", "", "optional private key for the CSR")
	genKeyCommand.Flags().StringP(flagKeyAlgo, "a", "ecdsa", "key type to generate (rsa or ec)")
	genKeyCommand.Flags().IntP(flagKeySize, "s", 521, "key size to generate (in bits)")
	matchKeyCommand.Flags().StringP(flagCertFile, "c", "", "certificate file to match (PEM or DER format")
	matchKeyCommand.Flags().StringP(flagKeyFile, "p", "", "key file to match")
	pemCommand.Flags().StringP(flagBinaryOut, "b", "", "file to write extracted binary data from a PEM file")
	pemCommand.Flags().StringP(flagPEMType, "t", "CERTIFICATE", "PEM type for output")
	selfSignCommand.Flags().StringP(flagRequest, "f", "request.yaml", "YAML config file to use for self-signing")
	selfSignCommand.Flags().StringP(flagCSRFile, "c", "", "CSR file to use for self-signing")
	selfSignCommand.Flags().StringP(flagKeyFile, "p", "", "key file to use for self-signing")
	serialCommand.Flags().BoolP(flagNumeric, "n", false, "display serial numbers as integers")
	signCSRCommand.Flags().StringP(flagCertFile, "c", "", "certificate file to use for signing")
	signCSRCommand.Flags().StringP(flagRequest, "f", "request.yaml", "YAML config file to use for certificate signing")
	signCSRCommand.Flags().StringP(flagKeyFile, "p", "", "key file to match")
	skiCommand.Flags().BoolP(flagShouldMatch, "m", false, "all SKIs should match")
	stealchainCommand.Flags().StringP(flagSNIName, "s", "", "SNI name to use when connecting")
	tlsInfoCommand.Flags().StringP(flagSNIName, "s", "", "SNI name to use when connecting")

	verifyCommand.Flags().BoolP(flagForceIntBundle, "f", false, "force loading of intermediate bundle")
	verifyCommand.Flags().BoolP(flagCheckRevocation, "r", false, "check revocation status")
}

func bindLocalFlags() {
	viper.BindPFlag(flagConfigFile, bundlerCommand.Flags().Lookup(flagConfigFile))
	viper.BindPFlag(flagOutput, bundlerCommand.Flags().Lookup(flagOutput))
	viper.BindPFlag(flagStdout, csrPubCommand.Flags().Lookup(flagStdout))
	viper.BindPFlag(flagLeafOnly, dumpCommand.Flags().Lookup(flagLeafOnly))
	viper.BindPFlag(flagShowHashes, dumpCommand.Flags().Lookup(flagShowHashes))
	viper.BindPFlag(flagLeeway, expiryCommand.Flags().Lookup(flagLeeway))
	viper.BindPFlag(flagRequest, genCSRCommand.Flags().Lookup(flagRequest))
	viper.BindPFlag(flagKeyFile, genCSRCommand.Flags().Lookup(flagKeyFile))
	viper.BindPFlag(flagKeyAlgo, genKeyCommand.Flags().Lookup(flagKeyAlgo))
	viper.BindPFlag(flagKeySize, genKeyCommand.Flags().Lookup(flagKeySize))
	viper.BindPFlag(flagCertFile, matchKeyCommand.Flags().Lookup(flagCertFile))
	viper.BindPFlag(flagKeyFile, matchKeyCommand.Flags().Lookup(flagKeyFile))
	viper.BindPFlag(flagBinaryOut, pemCommand.Flags().Lookup(flagBinaryOut))
	viper.BindPFlag(flagPEMType, pemCommand.Flags().Lookup(flagPEMType))
	viper.BindPFlag(flagRequest, selfSignCommand.Flags().Lookup(flagRequest))
	viper.BindPFlag(flagCSRFile, selfSignCommand.Flags().Lookup(flagCSRFile))
	viper.BindPFlag(flagKeyFile, selfSignCommand.Flags().Lookup(flagKeyFile))
	viper.BindPFlag(flagNumeric, serialCommand.Flags().Lookup(flagNumeric))
	viper.BindPFlag(flagCertFile, signCSRCommand.Flags().Lookup(flagCertFile))
	viper.BindPFlag(flagRequest, signCSRCommand.Flags().Lookup(flagRequest))
	viper.BindPFlag(flagKeyFile, signCSRCommand.Flags().Lookup(flagKeyFile))
	viper.BindPFlag(flagShouldMatch, skiCommand.Flags().Lookup(flagShouldMatch))
	viper.BindPFlag(flagSNIName, stealchainCommand.Flags().Lookup(flagSNIName))
	viper.BindPFlag(flagSNIName, tlsInfoCommand.Flags().Lookup(flagSNIName))
	viper.BindPFlag(flagForceIntBundle, verifyCommand.Flags().Lookup(flagForceIntBundle))
	viper.BindPFlag(flagCheckRevocation, verifyCommand.Flags().Lookup(flagCheckRevocation))

	pemCommand.MarkFlagsMutuallyExclusive(flagBinaryOut, flagPEMType)
	pemCommand.MarkFlagsOneRequired(flagBinaryOut, flagPEMType)

	caSignedCommand.MarkFlagRequired(flagCA)
	genCSRCommand.MarkFlagRequired(flagRequest)
	matchKeyCommand.MarkFlagRequired(flagCertFile)
	matchKeyCommand.MarkFlagRequired(flagKeyFile)
	selfSignCommand.MarkFlagRequired(flagRequest)
	signCSRCommand.MarkFlagRequired(flagCertFile)
	signCSRCommand.MarkFlagRequired(flagRequest)
	signCSRCommand.MarkFlagRequired(flagKeyFile)
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
	rootCommand.AddCommand(docCommand)
	rootCommand.AddCommand(dumpCommand)
	rootCommand.AddCommand(expiryCommand)
	rootCommand.AddCommand(fileTypeCommand)
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
