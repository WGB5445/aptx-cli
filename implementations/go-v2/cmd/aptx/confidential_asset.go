package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	aptos "github.com/aptos-labs/aptos-go-sdk/v2"
	"github.com/aptos-labs/aptos-go-sdk/v2/account"
	"github.com/aptos-labs/aptos-go-sdk/v2/confidentialasset"
)

// buildConfidentialAssetAccount builds a *account.Account from the CLI's private key. Needed for
// confidentialasset actions that type-assert their signer to *account.Account (register, rotate,
// normalize, withdraw, transfer) -- deposit and rollover take a plain token/amount and don't need
// this at all. The account's private key itself is never used cryptographically here (we always
// pass an explicit --confidential-decryption-key, so the package's "derive from account signature"
// fallback path never triggers) -- only its address matters, but building one requires real key
// bytes.
func buildConfidentialAssetAccount(state State) (*account.Account, error) {
	privKeyHex, err := readPrivateKey(state)
	if err != nil {
		return nil, err
	}
	if privKeyHex == "" {
		return nil, fmt.Errorf("confidential-asset %s requires --private-key (or --private-key-env/--private-key-file)", state.Action)
	}
	keyHex := strings.TrimPrefix(strings.TrimPrefix(privKeyHex, "ed25519-priv-"), "0x")
	return account.FromPrivateKeyHex(keyHex)
}

// buildConfidentialAssetPayload builds the unsigned entry-function payload for the requested
// --confidential-action, mirroring the TS ConfidentialAssetTransactionBuilder split (build once,
// then let the caller's own simulate/sign/submit pipeline take over).
func buildConfidentialAssetPayload(ctx context.Context, caClient *confidentialasset.Client, state State, spec InputSpec, tokenAddress, senderAddress aptos.AccountAddress) (*aptos.EntryFunctionPayload, error) {
	switch spec.ConfidentialAction {
	case "register":
		acct, err := buildConfidentialAssetAccount(state)
		if err != nil {
			return nil, err
		}
		return caClient.BuildRegisterBalancePayload(ctx, acct, tokenAddress, spec.ConfidentialDecryptionKey)
	case "deposit":
		amount, err := strconv.ParseUint(spec.ConfidentialAmount, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid --confidential-amount: %v", err)
		}
		return caClient.BuildDepositPayload(tokenAddress, amount)
	case "rollover":
		return caClient.BuildRolloverPendingBalancePayload(tokenAddress, spec.ConfidentialWithPauseIncoming)
	case "rotate":
		acct, err := buildConfidentialAssetAccount(state)
		if err != nil {
			return nil, err
		}
		return caClient.BuildRotateEncryptionKeyPayload(ctx, acct, tokenAddress, spec.ConfidentialDecryptionKey, spec.ConfidentialNewDecryptionKey)
	case "withdraw", "transfer", "normalize":
		return buildConfidentialAssetNativePayload(ctx, caClient, state, spec, tokenAddress, senderAddress)
	default:
		return nil, fmt.Errorf("unsupported confidential-asset action: %s", spec.ConfidentialAction)
	}
}

func runRealConfidentialAsset(ctx context.Context, client aptos.Client, state State, spec InputSpec) (map[string]any, error) {
	senderAddress, err := parseV2Address(spec.SenderAddress)
	if err != nil {
		return nil, err
	}
	tokenAddress, err := parseV2Address(spec.ConfidentialTokenAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid --confidential-token-address: %v", err)
	}

	caClient := confidentialasset.NewClient(client)
	entryPayload, err := buildConfidentialAssetPayload(ctx, caClient, state, spec, tokenAddress, senderAddress)
	if err != nil {
		return nil, err
	}

	buildOpts := []aptos.TransactionOption{aptos.WithMaxGas(state.MaxGasAmount)}
	rawTxn, err := client.BuildTransaction(ctx, senderAddress, entryPayload, buildOpts...)
	if err != nil {
		return nil, err
	}

	payload := map[string]any{
		"cli":            "aptx",
		"implementation": "go-v2",
		"sdk_backend":    "github.com/aptos-labs/aptos-go-sdk/v2",
		"sdk_mode":       "sdk",
		"action":         state.Action,
		"txn_type":       state.TxnType,
		"abi_enabled":    false,
		"input": map[string]any{
			"network":                          spec.Network,
			"sender_address":                   spec.SenderAddress,
			"confidential_action":              spec.ConfidentialAction,
			"confidential_token_address":       spec.ConfidentialTokenAddress,
			"confidential_amount":              spec.ConfidentialAmount,
			"confidential_recipient":           spec.ConfidentialRecipient,
			"confidential_with_pause_incoming": spec.ConfidentialWithPauseIncoming,
			"confidential_memo":                spec.ConfidentialMemo,
			"fullnode":                         spec.Fullnode,
			"sequence_number":                  rawTxn.SequenceNumber,
			"max_gas_amount":                   rawTxn.MaxGasAmount,
			"gas_unit_price":                   rawTxn.GasUnitPrice,
			"expiration_timestamp_secs":        rawTxn.ExpirationTimestampSeconds,
		},
		"signing": map[string]any{
			"mode":     signingMode(state),
			"provided": signingMode(state) != "none",
			"redacted": true,
		},
		"abi": AbiSummary{Fetched: false},
		"result": map[string]any{
			"mode":      state.Action,
			"success":   true,
			"vm_status": "built",
			"tx_hash":   "-",
			"notes":     []string{"real SDK v2 backend active"},
		},
	}
	result := payload["result"].(map[string]any)

	if state.Action == "simulate" || (state.Action == "run" && spec.NoSign) {
		signer, err := buildV2Signer(state, spec)
		if err != nil {
			return nil, err
		}
		simResult, err := client.SimulateTransaction(ctx, rawTxn, signer)
		if err != nil {
			return nil, err
		}
		result["mode"] = "simulate"
		result["success"] = simResult.Success
		result["vm_status"] = simResult.VMStatus
		result["tx_hash"] = "-"
		result["gas_used"] = simResult.GasUsed
		result["notes"] = []string{"simulated transaction"}
		result["response"] = simResult
		return payload, nil
	}

	privKeyHex, err := readPrivateKey(state)
	if err != nil {
		return nil, err
	}
	if privKeyHex == "" {
		return nil, errors.New("missing signer for submit path")
	}
	senderKey, err := buildV2PrivateKey(privKeyHex)
	if err != nil {
		return nil, err
	}
	signedTxn, err := aptos.SignTransaction(senderKey, rawTxn)
	if err != nil {
		return nil, err
	}

	if state.Action == "submit" {
		submitResult, err := client.SubmitTransaction(ctx, signedTxn)
		if err != nil {
			return nil, err
		}
		result["mode"] = "submit"
		result["success"] = true
		result["vm_status"] = "pending"
		result["tx_hash"] = submitResult.Hash
		result["notes"] = []string{"submitted transaction"}
		return payload, nil
	}

	// run: simulate first (for a reported gas_used/vm_status), then submit and wait.
	signer, err := buildV2Signer(state, spec)
	if err != nil {
		return nil, err
	}
	simResult, err := client.SimulateTransaction(ctx, rawTxn, signer)
	if err != nil {
		return nil, err
	}
	submitResult, err := client.SubmitTransaction(ctx, signedTxn)
	if err != nil {
		return nil, err
	}
	executed, err := client.WaitForTransaction(ctx, submitResult.Hash)
	if err != nil {
		return nil, err
	}

	result["mode"] = "run"
	result["success"] = executed.Success
	result["vm_status"] = executed.VMStatus
	result["tx_hash"] = executed.Hash
	result["gas_used"] = executed.GasUsed
	result["notes"] = []string{"simulated transaction", "submitted transaction", "waited for execution"}
	result["response"] = map[string]any{
		"simulation": simResult,
		"submission": submitResult,
		"execution":  executed,
	}
	return payload, nil
}
