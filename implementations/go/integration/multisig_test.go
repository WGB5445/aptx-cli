package integration_test

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	aptos "github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
)

const (
	multisigFundingAmount  = uint64(100_000_000)
	multisigTransferAmount = uint64(1_000_000)
)

func TestOnChainMultisig(t *testing.T) {
	client := newLocalClient(t)

	owners := []*aptos.Account{
		newAccount(t),
		newAccount(t),
		newAccount(t),
	}
	recipient := newAccount(t)

	for _, owner := range owners {
		fundAccount(t, client, owner.Address, multisigFundingAmount)
	}

	multisigAddress, err := client.FetchNextMultisigAddress(owners[0].Address)
	if err != nil {
		t.Fatalf("fetch next multisig address: %v", err)
	}

	createMultisigAccount(t, client, owners[0], []aptos.AccountAddress{owners[1].Address, owners[2].Address})
	threshold, ownerList := multisigResource(t, client, multisigAddress)
	if threshold != 2 {
		t.Fatalf("unexpected threshold: got %d want 2", threshold)
	}
	if len(ownerList) != 3 {
		t.Fatalf("unexpected owner count: got %d want 3", len(ownerList))
	}

	fundAccount(t, client, *multisigAddress, multisigFundingAmount)

	fullPayload := createTransferProposal(t, client, owners[1], *multisigAddress, recipient.Address, false)
	approveProposal(t, client, owners[2], *multisigAddress, 1)
	executeProposal(t, client, owners[0], *multisigAddress, fullPayload)
	assertBalance(t, client, recipient.Address, multisigTransferAmount)

	hashPayload := createTransferProposal(t, client, owners[0], *multisigAddress, recipient.Address, true)
	approveProposal(t, client, owners[2], *multisigAddress, 2)
	executeProposal(t, client, owners[1], *multisigAddress, hashPayload)
	assertBalance(t, client, recipient.Address, multisigTransferAmount*2)
}

func newLocalClient(t *testing.T) *aptos.Client {
	t.Helper()
	fullnode := os.Getenv("APTX_TEST_FULLNODE")
	if fullnode == "" {
		fullnode = "http://127.0.0.1:8080/v1"
	}
	faucet := os.Getenv("APTX_TEST_FAUCET")
	if faucet == "" {
		faucet = "http://127.0.0.1:8081"
	}
	waitForEndpoint(t, fullnode)
	waitForEndpoint(t, faucet)
	client, err := aptos.NewClient(aptos.NetworkConfig{
		Name:      "localnet",
		NodeUrl:   fullnode,
		FaucetUrl: faucet,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func waitForEndpoint(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("endpoint not ready: %s", url)
}

func newAccount(t *testing.T) *aptos.Account {
	t.Helper()
	account, err := aptos.NewEd25519Account()
	if err != nil {
		t.Fatalf("new ed25519 account: %v", err)
	}
	return account
}

func fundAccount(t *testing.T, client *aptos.Client, address aptos.AccountAddress, amount uint64) {
	t.Helper()
	if err := client.Fund(address, amount); err != nil {
		t.Fatalf("fund %s: %v", address.String(), err)
	}
}

func createMultisigAccount(t *testing.T, client *aptos.Client, owner *aptos.Account, additionalOwners []aptos.AccountAddress) {
	t.Helper()
	metadataValue, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		bcs.SerializeSequenceWithFunction([]string{"integration"}, ser, func(ser *bcs.Serializer, item string) {
			ser.WriteString(item)
		})
	})
	if err != nil {
		t.Fatalf("serialize metadata: %v", err)
	}
	payload, err := aptos.MultisigCreateAccountPayload(2, additionalOwners, []string{"integration"}, metadataValue)
	if err != nil {
		t.Fatalf("multisig create payload: %v", err)
	}
	submitAndWait(t, client, owner, payload)
}

func createTransferProposal(
	t *testing.T,
	client *aptos.Client,
	sender *aptos.Account,
	multisigAddress aptos.AccountAddress,
	recipient aptos.AccountAddress,
	hashOnly bool,
) *aptos.MultisigTransactionPayload {
	t.Helper()
	entryFunctionPayload, err := aptos.CoinTransferPayload(nil, recipient, multisigTransferAmount)
	if err != nil {
		t.Fatalf("coin transfer payload: %v", err)
	}
	multisigPayload := &aptos.MultisigTransactionPayload{
		Variant: aptos.MultisigTransactionPayloadVariantEntryFunction,
		Payload: entryFunctionPayload,
	}

	var createPayload *aptos.EntryFunction
	if hashOnly {
		createPayload, err = aptos.MultisigCreateTransactionPayloadWithHash(multisigAddress, multisigPayload)
	} else {
		createPayload, err = aptos.MultisigCreateTransactionPayload(multisigAddress, multisigPayload)
	}
	if err != nil {
		t.Fatalf("multisig create transaction payload: %v", err)
	}
	submitAndWait(t, client, sender, createPayload)
	return multisigPayload
}

func approveProposal(t *testing.T, client *aptos.Client, approver *aptos.Account, multisigAddress aptos.AccountAddress, sequence uint64) {
	t.Helper()
	payload, err := aptos.MultisigApprovePayload(multisigAddress, sequence)
	if err != nil {
		t.Fatalf("approve payload: %v", err)
	}
	submitAndWait(t, client, approver, payload)
}

func executeProposal(
	t *testing.T,
	client *aptos.Client,
	sender *aptos.Account,
	multisigAddress aptos.AccountAddress,
	payload *aptos.MultisigTransactionPayload,
) {
	t.Helper()
	execPayload := &aptos.Multisig{
		MultisigAddress: multisigAddress,
		Payload:         payload,
	}
	submitAndWait(t, client, sender, execPayload)
}

func multisigResource(t *testing.T, client *aptos.Client, multisigAddress *aptos.AccountAddress) (uint64, []any) {
	t.Helper()
	resource, err := client.AccountResource(*multisigAddress, "0x1::multisig_account::MultisigAccount")
	if err != nil {
		t.Fatalf("account resource: %v", err)
	}
	resourceData, ok := resource["data"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected resource data: %#v", resource["data"])
	}
	thresholdStr, ok := resourceData["num_signatures_required"].(string)
	if !ok {
		t.Fatalf("unexpected threshold data: %#v", resourceData["num_signatures_required"])
	}
	threshold, err := aptos.StrToUint64(thresholdStr)
	if err != nil {
		t.Fatalf("parse threshold: %v", err)
	}
	owners, ok := resourceData["owners"].([]any)
	if !ok {
		t.Fatalf("unexpected owners data: %#v", resourceData["owners"])
	}
	return threshold, owners
}

func assertBalance(t *testing.T, client *aptos.Client, address aptos.AccountAddress, expected uint64) {
	t.Helper()
	balance, err := client.AccountAPTBalance(address)
	if err != nil {
		t.Fatalf("balance for %s: %v", address.String(), err)
	}
	if balance != expected {
		t.Fatalf("unexpected balance for %s: got %d want %d", address.String(), balance, expected)
	}
}

func submitAndWait(t *testing.T, client *aptos.Client, sender *aptos.Account, payload aptos.TransactionPayloadImpl) *api.UserTransaction {
	t.Helper()
	submitResponse, err := client.BuildSignAndSubmitTransaction(sender, aptos.TransactionPayload{Payload: payload}, aptos.MaxGasAmount(200_000))
	if err != nil {
		t.Fatalf("submit transaction: %v", err)
	}
	txn, err := client.WaitForTransaction(submitResponse.Hash)
	if err != nil {
		t.Fatalf("wait for transaction %s: %v", submitResponse.Hash, err)
	}
	if !txn.Success {
		t.Fatalf("transaction failed: %s (%s)", submitResponse.Hash, txn.VmStatus)
	}
	for _, event := range txn.Events {
		if event.Type == "0x1::multisig_account::TransactionExecutionFailed" {
			t.Fatalf("multisig failure event emitted: %s", fmt.Sprint(event.Data))
		}
	}
	return txn
}
