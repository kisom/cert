package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"git.wntrmute.dev/kyle/goutils/certlib"
	"git.wntrmute.dev/kyle/goutils/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getPool() (*x509.CertPool, error) {
	return certlib.LoadFullCertPool(viper.GetString("ca-file"), viper.GetString("intermediates-file"))
}

func tlsConfig() (*tls.Config, error) {
	tcfg, err := lib.BaselineTLSConfig(viper.GetBool("skip-verify"), viper.GetBool("strict-tls"))
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

func init() {
	cobra.OnInitialize(initConfig)

	// Persistent flags follow.
	rootCommand.PersistentFlags().StringVar(&cfgFile,
		"config", "",
		"config file (default is $HOME/.config/goutils/cert.yaml)")
	rootCommand.PersistentFlags().StringP("ca-file", "c", "", "CA certificate bundle file")
	rootCommand.PersistentFlags().StringP("display-mode", "d", "lower", "hex display mode for SKI (default: lower)")
	rootCommand.PersistentFlags().StringP("intermediates-file", "i", "",
		"intermediate certificate bundle")
	rootCommand.PersistentFlags().BoolP("skip-verify", "k", false, "skip certificate verification")
	rootCommand.PersistentFlags().BoolP("strict-tls", "t", false, "use strict TLS settings")
	rootCommand.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	// Bind persistent flags.
	viper.BindPFlag("ca-file", rootCommand.PersistentFlags().Lookup("ca-file"))
	viper.BindPFlag("display-mode", rootCommand.PersistentFlags().Lookup("display-mode"))
	viper.BindPFlag("intermediates-file", rootCommand.PersistentFlags().Lookup("intermediates-file"))
	viper.BindPFlag("skip-verify", rootCommand.PersistentFlags().Lookup("skip-verify"))
	viper.BindPFlag("strict-tls", rootCommand.PersistentFlags().Lookup("strict-tls"))
	viper.BindPFlag("verbose", rootCommand.PersistentFlags().Lookup("verbose"))

	// Local flags follow.
	dumpCommand.Flags().BoolP("leaf-only", "l", false, "only display the leaf certificate")
	matchKeyCommand.Flags().StringP("key-file", "k", "", "key file to match")
	skiCommand.Flags().BoolP("should-match", "m", false, "all SKIs should match")
	stealchainCommand.Flags().StringP("sni-name", "s", "", "SNI name to use when connecting")
	verifyCommand.Flags().BoolP("force-intermediate-bundle", "f", false, "force loading of intermediate bundle")
	verifyCommand.Flags().BoolP("check-revocation", "r", false, "check revocation status")

	// Bind local flags.
	viper.BindPFlag("leaf-only", dumpCommand.Flags().Lookup("leaf-only"))
	viper.BindPFlag("should-match", skiCommand.Flags().Lookup("should-match"))
	viper.BindPFlag("sni-name", stealchainCommand.Flags().Lookup("sni-name"))
	viper.BindPFlag("force-intermediate-bundle", verifyCommand.Flags().Lookup("force-intermediate-bundle"))
	viper.BindPFlag("check-revocation", verifyCommand.Flags().Lookup("check-revocation"))
}

func init() {
	rootCommand.AddCommand(dumpCommand)
	rootCommand.AddCommand(matchKeyCommand)
	rootCommand.AddCommand(skiCommand)
	rootCommand.AddCommand(stealchainCommand)
	rootCommand.AddCommand(tlsInfoCommand)
	rootCommand.AddCommand(verifyCommand)
	rootCommand.AddCommand(versionCommand)
}
