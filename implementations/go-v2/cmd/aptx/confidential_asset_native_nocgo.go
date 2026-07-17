//go:build !cgo

package main

import (
	"context"
	"fmt"

	aptos "github.com/aptos-labs/aptos-go-sdk/v2"
	"github.com/aptos-labs/aptos-go-sdk/v2/confidentialasset"
)

// buildConfidentialAssetNativePayload: withdraw/transfer/normalize need real ZK proof generation
// (range proofs + discrete-log balance decryption) via the confidential-asset-bindings Rust FFI,
// which requires a CGO-enabled build. This binary was built with CGO_ENABLED=0.
func buildConfidentialAssetNativePayload(_ context.Context, _ *confidentialasset.Client, _ State, spec InputSpec, _, _ aptos.AccountAddress) (*aptos.EntryFunctionPayload, error) {
	return nil, fmt.Errorf(
		"confidential-asset %s requires a CGO-enabled build (CGO_ENABLED=1) with the confidential-asset-bindings FFI static library linked; this binary was built without CGO",
		spec.ConfidentialAction,
	)
}
