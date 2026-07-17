//go:build cgo

package main

import (
	"context"
	"fmt"
	"strconv"

	aptos "github.com/aptos-labs/aptos-go-sdk/v2"
	"github.com/aptos-labs/aptos-go-sdk/v2/confidentialasset"
	"github.com/aptos-labs/aptos-go-sdk/v2/confidentialasset/native"
)

// buildConfidentialAssetNativePayload builds the withdraw/transfer/normalize payload, which needs
// real ZK proof generation (range proofs + discrete-log balance decryption) via the
// confidential-asset-bindings Rust FFI, only available in a CGO-enabled build.
func buildConfidentialAssetNativePayload(ctx context.Context, caClient *confidentialasset.Client, state State, spec InputSpec, tokenAddress, senderAddress aptos.AccountAddress) (*aptos.EntryFunctionPayload, error) {
	acct, err := buildConfidentialAssetAccount(state)
	if err != nil {
		return nil, err
	}
	nc := native.Wrap(caClient)
	switch spec.ConfidentialAction {
	case "withdraw":
		amount, err := strconv.ParseUint(spec.ConfidentialAmount, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid --confidential-amount: %v", err)
		}
		recipient := senderAddress
		if spec.ConfidentialRecipient != "" {
			recipient, err = parseV2Address(spec.ConfidentialRecipient)
			if err != nil {
				return nil, err
			}
		}
		return nc.BuildWithdrawPayload(ctx, acct, tokenAddress, amount, recipient, spec.ConfidentialDecryptionKey)
	case "transfer":
		amount, err := strconv.ParseUint(spec.ConfidentialAmount, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid --confidential-amount: %v", err)
		}
		if spec.ConfidentialRecipient == "" {
			return nil, fmt.Errorf("confidential-asset transfer requires --confidential-recipient")
		}
		recipient, err := parseV2Address(spec.ConfidentialRecipient)
		if err != nil {
			return nil, err
		}
		return nc.BuildTransferPayload(ctx, acct, tokenAddress, amount, recipient, spec.ConfidentialDecryptionKey, spec.ConfidentialMemo)
	case "normalize":
		return nc.BuildNormalizeBalancePayload(ctx, acct, tokenAddress, spec.ConfidentialDecryptionKey)
	default:
		return nil, fmt.Errorf("unsupported confidential-asset action: %s", spec.ConfidentialAction)
	}
}
