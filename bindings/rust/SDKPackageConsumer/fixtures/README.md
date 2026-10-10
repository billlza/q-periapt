# Public TLS test identities

These four DER files are deliberately public regression fixtures, including the
private keys. They are not credentials for any deployed service and must not be
used outside tests. The client identity is `client.test`; the server identity is
`localhost`. Each identity has its own ECDSA P-256 key and self-signed certificate.

The fixtures were generated once using the package's `standard_peer fixtures`
command (rcgen 0.14.10) for this purpose. The SDK consumer reads these bytes to
perform real TLS 1.3/X25519MLKEM768 authentication, application-policy confirmation
and fragmented request/response exchanges. Ephemeral key exchange and the SDK's
operating-system entropy remain live. Only certificate generation is outside
the consumer, so testing public APIs on Rust 1.90 does not import a generator
whose own minimum Rust version is newer.

The package driver supplies the separate signed-policy fixtures into this
same directory before compilation. The private-key copies owned by the test
identity are still wiped on drop; the public fixture files themselves remain.
