package cmd

import (
	"encoding/hex"
	"math/big"
	"strings"

	"git.wntrmute.dev/kyle/goutils/lib"
	"git.wntrmute.dev/kyle/goutils/msg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func parseHex(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ToLower(s)

	return hex.DecodeString(s)
}

func showHexAsNumber(arg string) {
	bs, err := parseHex(arg)
	if err != nil {
		lib.Warn(err, "while parsing hex string %s", arg)
	}

	var n = big.NewInt(0)
	n.SetBytes(bs)

	msg.Printf("%s: %s\n", arg, n.String())
}

func showNumberAsHex(arg string) {
	var n = big.NewInt(0)
	n.SetString(arg, 10)

	msg.Printf("%s: %s\n", arg, lib.HexEncode(n.Bytes(), displayMode()))
}

var hexNumCommand = &cobra.Command{
	Use:   "hexnum",
	Short: "Display a hex string as a number or vice versa",
	PreRun: func(cmd *cobra.Command, args []string) {
		cmdInit(cmd, flagNumeric)
	},
	Run: func(cmd *cobra.Command, args []string) {

		for _, arg := range args {
			if viper.GetBool(flagNumeric) {
				showHexAsNumber(arg)
			} else {
				showNumberAsHex(arg)
			}
		}
	},
}
