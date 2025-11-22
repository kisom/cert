package cmd

// Contains the constants for flag names to avoid typos and provide
// consistency across commands.

// Root flags.
const (
	flagCA                = "ca"
	flagDebug             = "debug"
	flagDisplayMode       = "display-mode"
	flagIntermediatesFile = "intermediates-file"
	flagSkipVerify        = "skip-verify"
	flagStrictTLS         = "strict-tls"
	flagQuiet             = "quiet"
	flagVerbose           = "verbose"
)

// Local flags.
const (
	flagConfigFile      = "config-file"
	flagOutput          = "output"
	flagStdout          = "stdout"
	flagLeafOnly        = "leaf-only"
	flagShowHashes      = "show-hashes"
	flagLeeway          = "leeway"
	flagRequest         = "request"
	flagKeyFile         = "key-file"
	flagKeyAlgo         = "key-algo"
	flagKeySize         = "key-size"
	flagCertFile        = "cert-file"
	flagBinaryOut       = "binary-out"
	flagPEMType         = "pem-type"
	flagCSRFile         = "csr-file"
	flagNumeric         = "numeric"
	flagShouldMatch     = "should-match"
	flagSNIName         = "sni-name"
	flagForceIntBundle  = "force-intermediate-bundle"
	flagCheckRevocation = "check-revocation"
)
