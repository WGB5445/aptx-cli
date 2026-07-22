// get-confidential-balance independently decrypts a confidential-asset balance using the Go v2
// SDK, so cross-SDK interop tests can verify plaintext amounts without trusting either CLI's own
// reported success. Mirrors how implementations/typescript/scripts/live-confidential-asset.ts
// calls @aptos-labs/confidential-asset's ConfidentialAsset.getBalance directly.
//
// Usage: get-confidential-balance <address> <decryption-key-hex> <token-address> <fullnode-url>
// Requires CGO_ENABLED=1 and the confidential-asset-bindings FFI static library linked (see
// implementations/go-v2/README.md).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	aptos "github.com/aptos-labs/aptos-go-sdk/v2"
	"github.com/aptos-labs/aptos-go-sdk/v2/account"
	"github.com/aptos-labs/aptos-go-sdk/v2/confidentialasset"
	"github.com/aptos-labs/aptos-go-sdk/v2/confidentialasset/native"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: get-confidential-balance <address> <decryption-key-hex> <token-address> <fullnode-url>")
		os.Exit(2)
	}
	address, decryptionKey, tokenAddressHex, fullnode := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	config := aptos.Localnet
	config.NodeURL = fullnode
	client, err := aptos.NewClient(config)
	if err != nil {
		fail(err)
	}
	acctAddr, err := aptos.ParseAddress(address)
	if err != nil {
		fail(err)
	}
	tokenAddr, err := aptos.ParseAddress(tokenAddressHex)
	if err != nil {
		fail(err)
	}

	// GetBalance only reads Address() off the signer and uses the explicit decryptionKey we pass
	// -- it never signs anything, so a freshly generated dummy key bound to the real address is
	// sufficient (we don't have or need the account's actual private key here).
	dummy, err := account.NewEd25519()
	if err != nil {
		fail(err)
	}
	acct := account.FromSignerWithAddress(dummy.Signer(), acctAddr)

	caClient := confidentialasset.NewClient(client)
	nc := native.Wrap(caClient)
	bal, err := nc.GetBalance(context.Background(), acct, tokenAddr, decryptionKey)
	if err != nil {
		fail(err)
	}

	out, _ := json.Marshal(map[string]uint64{
		"available": bal.AvailableOctas,
		"pending":   bal.PendingOctas,
	})
	fmt.Println(string(out))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
