package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	aptos "github.com/aptos-labs/aptos-go-sdk/v2"
)

// Multi-agent script payload used by the test suite (matches live_multi_agent.py)
const multiAgentScriptHex = "0xa11ceb0b0700000a0601000403040d04110405151b07302f085f2000000001010203040001000306020100010105010704060c" +
	"060c03030205050001060c010501090003060c05030109010d6170746f735f6163636f756e74067369676e65720a61646472657373" +
	"5f6f660e7472616e736665725f636f696e730000000000000000000000000000000000000000000000000000000000000001020000" +
	"00010f0a0011000c040a0111000c050b000b050b0238000b010b040b03380102"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fullnodeURL() string {
	if v := os.Getenv("APTX_TEST_FULLNODE"); v != "" {
		return v
	}
	return "http://127.0.0.1:8080/v1"
}

func faucetURL() string {
	if v := os.Getenv("APTX_TEST_FAUCET"); v != "" {
		return v
	}
	return "http://127.0.0.1:8081"
}

func testNetwork() string {
	if v := os.Getenv("APTX_TEST_NETWORK"); v != "" {
		return v
	}
	return "local"
}

func newClient(t *testing.T) aptos.Client {
	t.Helper()
	config := aptos.NetworkConfig{NodeURL: fullnodeURL()}
	client, err := aptos.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func newAccount(t *testing.T) *aptos.Ed25519PrivateKey {
	t.Helper()
	key, err := aptos.GenerateEd25519PrivateKey()
	if err != nil {
		t.Fatalf("GenerateEd25519PrivateKey: %v", err)
	}
	return key
}

func fundAccount(t *testing.T, addr aptos.AccountAddress, repeat int) {
	t.Helper()
	type fundReq struct {
		Address string `json:"address"`
		Amount  int    `json:"amount"`
	}
	type fundResp struct {
		TxnHashes []string `json:"txn_hashes"`
	}
	for i := 0; i < repeat; i++ {
		body, _ := json.Marshal(fundReq{Address: addr.String(), Amount: 100_000_000})
		resp, err := doHTTPPost(faucetURL()+"/fund", body)
		if err != nil {
			t.Fatalf("fund[%d]: %v", i, err)
		}
		var fr fundResp
		if err := json.Unmarshal(resp, &fr); err != nil {
			t.Fatalf("fund decode[%d]: %v", i, err)
		}
		ctx := context.Background()
		client := newClient(t)
		for _, hash := range fr.TxnHashes {
			if _, err := client.WaitForTransaction(ctx, hash); err != nil {
				t.Fatalf("wait fund tx %s: %v", hash, err)
			}
		}
	}
}

func doHTTPPost(url string, body []byte) ([]byte, error) {
	resp, err := http.Post(url, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read POST %s: %w", url, err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("POST %s status %d: %s", url, resp.StatusCode, out)
	}
	return out, nil
}

// repoRoot returns the repository root directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	// thisFile = .../implementations/go-v2/integration/multi_agent_test.go
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

func buildCLI(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	implDir := filepath.Join(root, "implementations", "go-v2")
	bin := filepath.Join(t.TempDir(), "aptx-v2")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/aptx")
	cmd.Dir = implDir
	cmd.Env = append(os.Environ(),
		"GOCACHE="+filepath.Join(root, ".cache", "go-build"),
		"GOMODCACHE="+filepath.Join(root, ".cache", "go-mod"),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin string, args ...string) map[string]any {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI failed: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("parse CLI output: %v\nraw: %s", err, stdout.String())
	}
	return result
}

func assertCLIResult(t *testing.T, payload map[string]any, wantImpl string) {
	t.Helper()
	if payload["implementation"] != wantImpl {
		t.Errorf("implementation: got %v, want %s", payload["implementation"], wantImpl)
	}
	result, _ := payload["result"].(map[string]any)
	if result == nil {
		t.Fatalf("missing result field")
	}
	if result["success"] != true {
		t.Errorf("success=false, vm_status=%v", result["vm_status"])
	}
	if result["vm_status"] != "Executed successfully" {
		t.Errorf("vm_status=%v", result["vm_status"])
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCLIMultiAgentSimulate(t *testing.T) {
	if os.Getenv("APTX_SKIP_LIVE") == "1" {
		t.Skip("APTX_SKIP_LIVE=1")
	}

	client := newClient(t)
	ctx := context.Background()

	senderKey := newAccount(t)
	secondaryKey := newAccount(t)

	senderAuth := senderKey.AuthKey()
	secondaryAuth := secondaryKey.AuthKey()
	senderAddr := aptos.AccountAddress(*senderAuth)
	secondaryAddr := aptos.AccountAddress(*secondaryAuth)

	fundAccount(t, senderAddr, 3)
	fundAccount(t, secondaryAddr, 3)

	// Verify accounts exist
	if _, err := client.Account(ctx, senderAddr); err != nil {
		t.Fatalf("sender account not found: %v", err)
	}

	bin := buildCLI(t)
	network := testNetwork()
	fullnode := fullnodeURL()

	result := runCLI(t, bin,
		"simulate", "multi-agent",
		"--network", network,
		"--fullnode", fullnode,
		"--script-hex", multiAgentScriptHex,
		"--type-arg", "0x1::aptos_coin::AptosCoin",
		"--type-arg", "0x1::aptos_coin::AptosCoin",
		"--sender-address", senderAddr.String(),
		"--secondary-signer-address", secondaryAddr.String(),
		"--arg", "u64:1000",
		"--arg", "u64:1200",
		"--public-key", "0x"+fmt.Sprintf("%x", senderKey.PubKey().Bytes()),
		"--output-format", "json",
	)
	assertCLIResult(t, result, "go-v2")
}

func TestCLIMultiAgentRun(t *testing.T) {
	if os.Getenv("APTX_SKIP_LIVE") == "1" {
		t.Skip("APTX_SKIP_LIVE=1")
	}

	senderKey := newAccount(t)
	secondaryKey := newAccount(t)

	senderAuth := senderKey.AuthKey()
	secondaryAuth := secondaryKey.AuthKey()
	senderAddr := aptos.AccountAddress(*senderAuth)
	secondaryAddr := aptos.AccountAddress(*secondaryAuth)

	fundAccount(t, senderAddr, 3)
	fundAccount(t, secondaryAddr, 3)

	bin := buildCLI(t)
	network := testNetwork()
	fullnode := fullnodeURL()

	senderPrivHex := "0x" + fmt.Sprintf("%x", senderKey.Bytes())
	secondaryPrivHex := "0x" + fmt.Sprintf("%x", secondaryKey.Bytes())

	result := runCLI(t, bin,
		"run", "multi-agent",
		"--network", network,
		"--fullnode", fullnode,
		"--script-hex", multiAgentScriptHex,
		"--type-arg", "0x1::aptos_coin::AptosCoin",
		"--type-arg", "0x1::aptos_coin::AptosCoin",
		"--sender-address", senderAddr.String(),
		"--secondary-signer-address", secondaryAddr.String(),
		"--arg", "u64:1000",
		"--arg", "u64:1200",
		"--private-key", senderPrivHex,
		"--secondary-private-key", secondaryPrivHex,
		"--output-format", "json",
	)
	assertCLIResult(t, result, "go-v2")
}

func TestCLISingleSimulate(t *testing.T) {
	if os.Getenv("APTX_SKIP_LIVE") == "1" {
		t.Skip("APTX_SKIP_LIVE=1")
	}

	senderKey := newAccount(t)
	senderAuth := senderKey.AuthKey()
	senderAddr := aptos.AccountAddress(*senderAuth)

	fundAccount(t, senderAddr, 2)

	bin := buildCLI(t)
	network := testNetwork()
	fullnode := fullnodeURL()

	result := runCLI(t, bin,
		"simulate", "single",
		"--network", network,
		"--fullnode", fullnode,
		"--function", "0x1::aptos_account::transfer",
		"--sender-address", senderAddr.String(),
		"--arg", "address:"+senderAddr.String(),
		"--arg", "u64:1000",
		"--public-key", "0x"+fmt.Sprintf("%x", senderKey.PubKey().Bytes()),
		"--output-format", "json",
	)
	assertCLIResult(t, result, "go-v2")
}

func TestCLIMockConformance(t *testing.T) {
	bin := buildCLI(t)

	// Verify mock mode works for all transaction types without network
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "single-mock",
			args: []string{
				"simulate", "single",
				"--network", "testnet",
				"--function", "0x1::coin::transfer",
				"--sender-address", "0x1",
				"--arg", "address:0x2", "--arg", "u64:100",
				"--sdk-mode", "mock",
			},
		},
		{
			name: "multi-agent-mock",
			args: []string{
				"simulate", "multi-agent",
				"--network", "testnet",
				"--function", "0x1::coin::transfer",
				"--sender-address", "0x1",
				"--secondary-signer-address", "0x2",
				"--arg", "address:0x3", "--arg", "u64:100",
				"--sdk-mode", "mock",
			},
		},
		{
			name: "multi-sig-mock",
			args: []string{
				"simulate", "multi-sig",
				"--network", "testnet",
				"--function", "0x1::coin::transfer",
				"--multisig-action", "propose",
				"--multisig-address", "0xabc",
				"--sender-address", "0x1",
				"--arg", "address:0x2", "--arg", "u64:100",
				"--sdk-mode", "mock",
			},
		},
		{
			name: "multi-key-mock",
			args: []string{
				"simulate", "multi-key",
				"--network", "testnet",
				"--function", "0x1::coin::transfer",
				"--sender-address", "0x1",
				"--multi-key-threshold", "2",
				"--multi-key-public-key", "0xaaa",
				"--multi-key-public-key", "0xbbb",
				"--arg", "address:0x2", "--arg", "u64:100",
				"--sdk-mode", "mock",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(tc.args, "--output-format", "json")
			result := runCLI(t, bin, args...)
			if result["implementation"] != "go-v2" {
				t.Errorf("implementation: got %v", result["implementation"])
			}
			if result["sdk_mode"] != "mock" {
				t.Errorf("sdk_mode: got %v", result["sdk_mode"])
			}
			res, _ := result["result"].(map[string]any)
			if res == nil || res["success"] != true {
				t.Errorf("result.success false: %v", res)
			}
		})
	}
}

func TestOfflineEncodeDecode(t *testing.T) {
	bin := buildCLI(t)

	// Encode a transaction
	encResult := runCLI(t, bin,
		"encode", "single",
		"--function", "0x1::aptos_account::transfer",
		"--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
		"--arg", "address:0x2222222222222222222222222222222222222222222222222222222222222222",
		"--arg", "u64:1000",
		"--sequence-number", "0",
		"--chain-id", "4",
		"--max-gas-amount", "200000",
		"--gas-unit-price", "100",
		"--expiration-timestamp", "9999999999",
		"--output-format", "json",
	)
	bcsHex, _ := encResult["bcs"].(string)
	if bcsHex == "" {
		t.Fatalf("encode produced empty bcs")
	}

	// Known-good BCS from conformance test suite
	const expectedBCS = "0x111111111111111111111111111111111111111111111111111111111111111100000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220222222222222222222222222222222222222222222222222222222222222222208e803000000000000400d0300000000006400000000000000ffe30b540200000004"
	if bcsHex != expectedBCS {
		t.Errorf("encode BCS mismatch\ngot:  %s\nwant: %s", bcsHex, expectedBCS)
	}

	// Decode it back
	decResult := runCLI(t, bin,
		"decode",
		"--input-bcs", bcsHex,
		"--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
		"--output-format", "json",
	)
	if decResult["action"] != "decode" {
		t.Errorf("decode action: got %v", decResult["action"])
	}
	// The v1 BCS library returns the short-form address (0x1 not 0x0000...0001)
	fn, _ := decResult["function"].(string)
	if fn != "0x1::aptos_account::transfer" {
		t.Errorf("decode function: got %v", fn)
	}
}

func TestOfflineSign(t *testing.T) {
	bin := buildCLI(t)

	const inputBCS = "0x111111111111111111111111111111111111111111111111111111111111111100000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220222222222222222222222222222222222222222222222222222222222222222208e803000000000000400d0300000000006400000000000000ffe30b540200000004"
	const privKey = "0x0101010101010101010101010101010101010101010101010101010101010101"

	result := runCLI(t, bin,
		"sign",
		"--input-bcs", inputBCS,
		"--private-key", privKey,
		"--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
		"--output-format", "json",
	)
	if result["action"] != "sign" {
		t.Errorf("sign action: got %v", result["action"])
	}
	if result["public_key"] == nil || result["public_key"] == "" {
		t.Errorf("sign missing public_key")
	}
	if result["signature"] == nil || result["signature"] == "" {
		t.Errorf("sign missing signature")
	}
	if result["signed_bcs"] == nil || result["signed_bcs"] == "" {
		t.Errorf("sign missing signed_bcs")
	}
}
