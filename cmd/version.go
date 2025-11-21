package cmd

import (
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
)

// Version holds the version string for the binary. It is intended to be
// overridden at build time using:
//
//	go build -ldflags "-X cert/cmd.Version=v1.2.3"
//
// Default is "dev" when not provided.
var Version = "dev"

// versionCommand prints the version of the tool. The value is embedded at
// build time via -ldflags; no runtime calls to git are made.
var versionCommand = &cobra.Command{
	Use:   "version",
	Short: "Print the embedded version",
	Run: func(cmd *cobra.Command, args []string) {
		msg.Println(Version)
	},
}
