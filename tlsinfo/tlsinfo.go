package tlsinfo

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
)

// PrintConnectionDetails prints the TLS connection details to the given writer.
func PrintConnectionDetails(w io.Writer, state tls.ConnectionState) {
	version := tlsVersion(state.Version)
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)
	fmt.Fprintf(w, "TLS Version: %s\n", version)
	fmt.Fprintf(w, "Cipher Suite: %s\n", cipherSuite)
	printPeerCertificates(w, state.PeerCertificates)
}

func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:

		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}

func printPeerCertificates(w io.Writer, certificates []*x509.Certificate) {
	for i, cert := range certificates {
		fmt.Fprintf(w, "Certificate %d\n", i+1)
		fmt.Fprintf(w, "\tSubject: %s\n", cert.Subject)
		fmt.Fprintf(w, "\tIssuer: %s\n", cert.Issuer)
		fmt.Fprintf(w, "\tDNS Names:	%v\n", cert.DNSNames)
		fmt.Fprintf(w, "\tNot Before: %s\n:", cert.NotBefore)
		fmt.Fprintf(w, "\tNot After: %s\n", cert.NotAfter)
	}
}
