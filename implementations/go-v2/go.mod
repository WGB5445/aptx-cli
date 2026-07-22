module aptx-go-v2

go 1.25.0

require (
	github.com/aptos-labs/aptos-go-sdk v1.13.0
	github.com/aptos-labs/aptos-go-sdk/v2 v2.0.0-20260530180423-d8b8cb32c5a9
)

// TODO(confidential-asset): points at a local checkout of the
// logan/v2-confidential-asset branch (adds v2/confidentialasset, not yet merged
// upstream). Replace with a pseudo-version once that branch/commit is pushed, or
// drop once the confidentialasset package lands on the v2 main line.
replace github.com/aptos-labs/aptos-go-sdk/v2 => /Users/logan/code/github/aptos-labs/aptos-go-sdk/v2

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/aptos-labs/confidential-asset-bindings/bindings/go v1.1.2 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gtank/ristretto255 v0.1.2 // indirect
	github.com/hasura/go-graphql-client v0.15.1 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)
