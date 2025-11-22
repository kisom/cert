cert-request(5) "" "CSR/signing Request Format"

# NAME

cert-requests - configuration format for certificate signing

# OVERVIEW

Many of the subcommands of cert that are related to certificate generation,
such as gencsr, selfsign, and signcsr, use a YAML configuration file. This
file contains key generation parameters, certificate subject information,
and basic signing profile information. Certificate generation in cert
is intended to be a basic set of tools, and if more complex certificate
generation is required, it is recommended to use a different tool.

# SYNTAX

An example file is:

```
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
  key_uses:
    - digital signature
  ext_key_usages:
    - server auth
  expiry: 30d
```

# KEY SECTION

The supported algorithms are ed25519, ecdsa, and rsa. For ecdsa, the
size selects the relevant NIST curve (e.g. 256 for P-256; options are
256, 384, and 521). For ed25519, the size is ignored.

# SUBJECT SECTION

The subject section contains information about the certificate
subject, and is used to both build the subject information and fill in
SANs. The allowed fields are

- common_name
- country
- locality
- province
- organization
- organizational_unit
- email: a list of email SANs to include in a cert
- dns: a list of DNS SANs to include in a cert
- ips: a list of IP SANs to include in a cert

# PROFILE SECTION

The profile section contains information about the certificate
signing.

- is_ca: true if this is a CA certificate
- path_len: max path length for a CA certificate
- key_use: the key use for this certificate (see below)
- ext_key_usages: a list of extended key usages (see below)
- expiry: how long the cert is valid for.

If the profile is for a certificate authority, the is_ca field should
be set as well as the path_len field. The key use should be "cert
sign".

The expiry field supports "y" for year, "m" for month, "d" for day, in
addition to the standard Go time duration formats.

Generally for server certificates, the key_use field should be set to
digital signature and ext_key_usages should include server auth. The
list of strings for these fields is documented in the
goutils/certlib/certgen package, but is provided below.

# KEY USES

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

# EXTENDED KEY USAGES

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

# SEE ALSO

- RFC 5280 describes many of these parameters, including key uses and
  extended key uses.