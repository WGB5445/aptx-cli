package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	aptos "github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
)

type ParsedArg struct {
	Mode    string `json:"mode"`
	Raw     string `json:"raw"`
	ArgType string `json:"argType"`
	Value   string `json:"value"`
}

type RawArg struct {
	Mode string `json:"mode"`
	Raw  string `json:"raw"`
	Hex  string `json:"hex"`
}

type State struct {
	Action                   string
	TxnType                  string
	Input                    string
	InputFormat              string
	Output                   string
	OutputFormat             string
	ArtifactsDir             string
	Network                  string
	Function                 string
	ScriptHex                string
	Args                     []string
	TypeArgs                 []string
	SecondarySignerAddresses []string
	SecondaryPrivateKeys     []string
	SecondaryPublicKeys      []string
	SenderAddress            string
	PrivateKey               string
	PrivateKeyEnv            string
	PrivateKeyFile           string
	PublicKey                string
	PublicKeyEnv             string
	PublicKeyFile            string
	Profile                  string
	Hash                     string
	Fullnode                 string
	MultisigAction           string
	MultisigAddress          string
	MultisigOwnerAddresses   []string
	MultisigThreshold        int
	MultisigSequence         int
	MultisigHashOnly         bool
	NoSign                   bool
	ABIEnabled               bool
	Verbose                  bool
	Quiet                    bool
	SDKMode                  string
	SequenceNumber           uint64
	ChainID                  uint8
	MaxGasAmount             uint64
	GasUnitPrice             uint64
	ExpirationTimestamp      uint64
	Nonce                    string
	InputBcs                 string
	FeePayerAddress          string
}

type InputSpec struct {
	Network                  string   `json:"network"`
	Function                 string   `json:"function"`
	ScriptHex                string   `json:"script_hex"`
	SenderAddress            string   `json:"sender_address"`
	Args                     []string `json:"args"`
	TypeArgs                 []string `json:"type_args"`
	SecondarySignerAddresses []string `json:"secondary_signer_addresses"`
	ABIEnabled               bool     `json:"abi_enabled"`
	NoSign                   bool     `json:"no_sign"`
	Hash                     string   `json:"hash"`
	Fullnode                 string   `json:"fullnode"`
	MultisigAction           string   `json:"multisig_action"`
	MultisigAddress          string   `json:"multisig_address"`
	MultisigOwnerAddresses   []string `json:"multisig_owner_addresses"`
	MultisigThreshold        int      `json:"multisig_threshold"`
	MultisigSequence         int      `json:"multisig_sequence"`
	MultisigHashOnly         bool     `json:"multisig_hash_only"`
}

type AbiSummary struct {
	Fetched            bool   `json:"fetched"`
	Module             string `json:"module,omitempty"`
	Function           string `json:"function,omitempty"`
	ParameterCount     int    `json:"parameter_count,omitempty"`
	TypeParameterCount int    `json:"type_parameter_count,omitempty"`
}

type simulationOnlySigner struct {
	publicKey *crypto.Ed25519PublicKey
}

func (s *simulationOnlySigner) Sign(msg []byte) (*crypto.AccountAuthenticator, error) {
	return nil, errors.New("simulation-only signer cannot sign transactions")
}

func (s *simulationOnlySigner) SignMessage(msg []byte) (crypto.Signature, error) {
	return nil, errors.New("simulation-only signer cannot sign messages")
}

func (s *simulationOnlySigner) SimulationAuthenticator() *crypto.AccountAuthenticator {
	return &crypto.AccountAuthenticator{
		Variant: crypto.AccountAuthenticatorEd25519,
		Auth: &crypto.Ed25519Authenticator{
			PubKey: s.publicKey,
			Sig:    &crypto.Ed25519Signature{},
		},
	}
}

func (s *simulationOnlySigner) AuthKey() *crypto.AuthenticationKey {
	return s.publicKey.AuthKey()
}

func (s *simulationOnlySigner) PubKey() crypto.PublicKey {
	return s.publicKey
}

// buildEntryFunctionArgs converts ["type:value", ...] arg strings to BCS-encoded [][]byte
func buildEntryFunctionArgs(args []string) ([][]byte, error) {
	result := make([][]byte, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "raw:") {
			hexStr := arg[4:]
			b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
			if err != nil {
				return nil, fmt.Errorf("invalid raw arg hex: %v", err)
			}
			result = append(result, b)
			continue
		}
		idx := strings.Index(arg, ":")
		if idx == -1 {
			return nil, fmt.Errorf("invalid arg format: %s", arg)
		}
		kind := arg[:idx]
		val := arg[idx+1:]
		switch kind {
		case "u8":
			n, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("bad u8: %v", err)
			}
			b, err := bcs.SerializeU8(uint8(n))
			if err != nil {
				return nil, err
			}
			result = append(result, b)
		case "u16":
			n, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("bad u16: %v", err)
			}
			b, err := bcs.SerializeU16(uint16(n))
			if err != nil {
				return nil, err
			}
			result = append(result, b)
		case "u32":
			n, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("bad u32: %v", err)
			}
			b, err := bcs.SerializeU32(uint32(n))
			if err != nil {
				return nil, err
			}
			result = append(result, b)
		case "u64":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("bad u64: %v", err)
			}
			b, err := bcs.SerializeU64(n)
			if err != nil {
				return nil, err
			}
			result = append(result, b)
		case "u128":
			n := new(big.Int)
			if _, ok := n.SetString(val, 10); !ok {
				return nil, fmt.Errorf("bad u128: %s", val)
			}
			b, err := bcs.SerializeU128(*n)
			if err != nil {
				return nil, err
			}
			result = append(result, b)
		case "bool":
			b, err := bcs.SerializeBool(val == "true")
			if err != nil {
				return nil, err
			}
			result = append(result, b)
		case "address":
			addr, err := parseAddress(val)
			if err != nil {
				return nil, fmt.Errorf("bad address: %v", err)
			}
			b, err := bcs.Serialize(&addr)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize address: %v", err)
			}
			result = append(result, b)
		case "string":
			b, err := bcs.SerializeBytes([]byte(val))
			if err != nil {
				return nil, err
			}
			result = append(result, b)
		default:
			return nil, fmt.Errorf("unsupported arg type: %s", kind)
		}
	}
	return result, nil
}

func runEncode(state State, spec InputSpec) (map[string]any, error) {
	funcParts := strings.SplitN(spec.Function, "::", 3)
	if len(funcParts) != 3 {
		return nil, fmt.Errorf("invalid function: %s", spec.Function)
	}
	moduleAddr, err := parseAddress(funcParts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid module address: %v", err)
	}

	argBytes, err := buildEntryFunctionArgs(spec.Args)
	if err != nil {
		return nil, fmt.Errorf("failed to encode args: %v", err)
	}

	typeArgs := make([]aptos.TypeTag, len(spec.TypeArgs))
	for i, ta := range spec.TypeArgs {
		tag, err := aptos.ParseTypeTag(ta)
		if err != nil {
			return nil, fmt.Errorf("invalid type arg %s: %v", ta, err)
		}
		typeArgs[i] = *tag
	}

	ef := &aptos.EntryFunction{
		Module:   aptos.ModuleId{Address: moduleAddr, Name: funcParts[1]},
		Function: funcParts[2],
		ArgTypes: typeArgs,
		Args:     argBytes,
	}

	senderAddr, err := parseAddress(spec.SenderAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid sender address: %v", err)
	}

	rawTxn := &aptos.RawTransaction{
		Sender:                     senderAddr,
		SequenceNumber:             state.SequenceNumber,
		Payload:                    aptos.TransactionPayload{Payload: ef},
		MaxGasAmount:               state.MaxGasAmount,
		GasUnitPrice:               state.GasUnitPrice,
		ExpirationTimestampSeconds: state.ExpirationTimestamp,
		ChainId:                    state.ChainID,
	}

	bcsBytes, err := bcs.Serialize(rawTxn)
	if err != nil {
		return nil, fmt.Errorf("BCS serialize failed: %v", err)
	}

	return map[string]any{
		"action":               "encode",
		"txn_type":             state.TxnType,
		"bcs":                  "0x" + hex.EncodeToString(bcsBytes),
		"sender":               spec.SenderAddress,
		"function":             spec.Function,
		"chain_id":             state.ChainID,
		"sequence_number":      state.SequenceNumber,
		"max_gas_amount":       state.MaxGasAmount,
		"gas_unit_price":       state.GasUnitPrice,
		"expiration_timestamp": state.ExpirationTimestamp,
	}, nil
}

func runDecode(state State) (map[string]any, error) {
	if state.InputBcs == "" {
		return nil, fmt.Errorf("decode requires --input-bcs <hex>")
	}
	hexStr := strings.TrimPrefix(state.InputBcs, "0x")
	bcsBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid BCS hex: %v", err)
	}
	rawTxn := &aptos.RawTransaction{}
	if err := bcs.Deserialize(rawTxn, bcsBytes); err != nil {
		return nil, fmt.Errorf("BCS deserialize failed: %v", err)
	}

	const maxU64 = ^uint64(0)
	isOrderless := rawTxn.SequenceNumber == maxU64
	seqStr := fmt.Sprintf("%d", rawTxn.SequenceNumber)
	if isOrderless {
		seqStr = "max_u64"
	}

	fn := ""
	switch p := rawTxn.Payload.Payload.(type) {
	case *aptos.EntryFunction:
		fn = p.Module.Address.String() + "::" + p.Module.Name + "::" + p.Function
	}

	txnTypeStr := "single"
	if isOrderless {
		txnTypeStr = "orderless"
	}

	return map[string]any{
		"action":               "decode",
		"txn_type":             txnTypeStr,
		"sender":               rawTxn.Sender.String(),
		"function":             fn,
		"chain_id":             rawTxn.ChainId,
		"sequence_number":      seqStr,
		"max_gas_amount":       rawTxn.MaxGasAmount,
		"gas_unit_price":       rawTxn.GasUnitPrice,
		"expiration_timestamp": rawTxn.ExpirationTimestampSeconds,
		"is_orderless":         isOrderless,
	}, nil
}

func runSign(state State) (map[string]any, error) {
	if state.InputBcs == "" {
		return nil, fmt.Errorf("sign requires --input-bcs <hex>")
	}
	privKeyStr := state.PrivateKey
	if privKeyStr == "" {
		return nil, fmt.Errorf("sign requires --private-key <hex>")
	}

	hexStr := strings.TrimPrefix(state.InputBcs, "0x")
	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid BCS hex: %v", err)
	}
	rawTxn := &aptos.RawTransaction{}
	if err := bcs.Deserialize(rawTxn, rawBytes); err != nil {
		return nil, fmt.Errorf("BCS deserialize failed: %v", err)
	}

	keyHex := strings.TrimPrefix(strings.TrimPrefix(privKeyStr, "ed25519-priv-"), "0x")
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %v", err)
	}
	privKey := &crypto.Ed25519PrivateKey{}
	if err := privKey.FromBytes(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	auth, err := rawTxn.Sign(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %v", err)
	}

	sigHex := ""
	pubKeyHex := ""
	if ed, ok := auth.Auth.(*crypto.Ed25519Authenticator); ok {
		sigHex = "0x" + hex.EncodeToString(ed.Sig.Bytes())
		pubKeyHex = "0x" + hex.EncodeToString(ed.PubKey.Bytes())
	}

	signedTxn, err := rawTxn.SignedTransactionWithAuthenticator(auth)
	if err != nil {
		return nil, fmt.Errorf("failed to build signed transaction: %v", err)
	}
	signedBytes, err := bcs.Serialize(signedTxn)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed txn: %v", err)
	}

	return map[string]any{
		"action":     "sign",
		"txn_type":   state.TxnType,
		"public_key": pubKeyHex,
		"signature":  sigHex,
		"signed_bcs": "0x" + hex.EncodeToString(signedBytes),
	}, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}

func run(argv []string) error {
	state, err := parseCLI(argv)
	if err != nil {
		return err
	}

	inputFormat := detectFormat(state.Input, state.InputFormat, "json")
	fileInput, err := loadInput(state.Input, inputFormat)
	if err != nil {
		return err
	}

	spec := InputSpec{
		Network:                  firstNonEmpty(state.Network, asString(fileInput["network"], "testnet")),
		Function:                 firstNonEmpty(state.Function, asString(fileInput["function"], "")),
		ScriptHex:                firstNonEmpty(state.ScriptHex, asString(fileInput["script_hex"], "")),
		SenderAddress:            firstNonEmpty(state.SenderAddress, asString(fileInput["sender_address"], "0x0")),
		Args:                     firstNonEmptySlice(state.Args, asStringSlice(fileInput["args"])),
		TypeArgs:                 firstNonEmptySlice(state.TypeArgs, asStringSlice(fileInput["type_args"])),
		SecondarySignerAddresses: firstNonEmptySlice(state.SecondarySignerAddresses, asStringSlice(fileInput["secondary_signer_addresses"])),
		ABIEnabled:               state.ABIEnabled && asBool(fileInput["abi_enabled"], true),
		NoSign:                   state.NoSign || asBool(fileInput["no_sign"], false),
		Hash:                     firstNonEmpty(state.Hash, asString(fileInput["hash"], "")),
		Fullnode:                 firstNonEmpty(state.Fullnode, asString(fileInput["fullnode"], "")),
		MultisigAction:           firstNonEmpty(state.MultisigAction, asString(fileInput["multisig_action"], "")),
		MultisigAddress:          firstNonEmpty(state.MultisigAddress, asString(fileInput["multisig_address"], "")),
		MultisigOwnerAddresses:   firstNonEmptySlice(state.MultisigOwnerAddresses, asStringSlice(fileInput["multisig_owner_addresses"])),
		MultisigThreshold:        firstNonZero(state.MultisigThreshold, asInt(fileInput["multisig_threshold"], 0)),
		MultisigSequence:         firstNonZero(state.MultisigSequence, asInt(fileInput["multisig_sequence"], 0)),
		MultisigHashOnly:         state.MultisigHashOnly || asBool(fileInput["multisig_hash_only"], false),
	}

	if err := requireValidState(state, spec); err != nil {
		return err
	}

	var payload map[string]any
	switch state.Action {
	case "encode":
		payload, err = runEncode(state, spec)
	case "decode":
		payload, err = runDecode(state)
	case "sign":
		payload, err = runSign(state)
	default:
		if state.SDKMode == "mock" {
			payload, err = runMock(state, spec)
		} else {
			payload, err = runReal(state, spec)
		}
	}
	if err != nil {
		return err
	}

	if state.ArtifactsDir != "" {
		if err := os.MkdirAll(state.ArtifactsDir, 0o755); err != nil {
			return err
		}
		outBytes, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(state.ArtifactsDir, "result.json"), outBytes, 0o644); err != nil {
			return err
		}
	}

	effectiveOutputFormat := state.OutputFormat
	if effectiveOutputFormat == "" && (state.Action == "encode" || state.Action == "decode" || state.Action == "sign") {
		effectiveOutputFormat = "json"
	}
	outputFormat := detectFormat(state.Output, effectiveOutputFormat, fallbackOutputFormat(state.Output))
	rendered, err := renderOutput(payload, outputFormat)
	if err != nil {
		return err
	}
	if state.Output != "" && state.Output != "-" {
		return os.WriteFile(state.Output, []byte(rendered+"\n"), 0o644)
	}
	if !state.Quiet {
		fmt.Println(rendered)
	}
	return nil
}

func parseCLI(argv []string) (State, error) {
	if len(argv) < 1 {
		return State{}, errors.New("usage: aptx <simulate|submit|run|inspect> <txn-type> [flags]")
	}
	action := argv[0]
	txnType := "single"
	start := 1
	if action != "inspect" && action != "decode" && action != "sign" {
		if len(argv) < 2 {
			return State{}, errors.New("usage: aptx <simulate|submit|run|inspect|encode> <txn-type> [flags]")
		}
		txnType = argv[1]
		start = 2
	}
	state := State{
		Action:                   action,
		TxnType:                  txnType,
		Args:                     []string{},
		TypeArgs:                 []string{},
		SecondarySignerAddresses: []string{},
		SecondaryPrivateKeys:     []string{},
		SecondaryPublicKeys:      []string{},
		MultisigOwnerAddresses:   []string{},
		ABIEnabled:               true,
		SDKMode:                  "sdk",
	}
	for i := start; i < len(argv); i++ {
		arg := argv[i]
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}
		switch arg {
		case "--input":
			state.Input = next
			i++
		case "--input-format":
			state.InputFormat = next
			i++
		case "--output":
			state.Output = next
			i++
		case "--output-format":
			state.OutputFormat = next
			i++
		case "--artifacts-dir":
			state.ArtifactsDir = next
			i++
		case "--network":
			state.Network = next
			i++
		case "--function":
			state.Function = next
			i++
		case "--script-hex":
			state.ScriptHex = next
			i++
		case "--arg":
			state.Args = append(state.Args, next)
			i++
		case "--type-arg":
			state.TypeArgs = append(state.TypeArgs, next)
			i++
		case "--secondary-signer-address":
			state.SecondarySignerAddresses = append(state.SecondarySignerAddresses, splitMultiValue(next)...)
			i++
		case "--secondary-private-key":
			state.SecondaryPrivateKeys = append(state.SecondaryPrivateKeys, next)
			i++
		case "--secondary-public-key":
			state.SecondaryPublicKeys = append(state.SecondaryPublicKeys, next)
			i++
		case "--sender-address":
			state.SenderAddress = next
			i++
		case "--private-key":
			state.PrivateKey = next
			i++
		case "--private-key-env":
			state.PrivateKeyEnv = next
			i++
		case "--private-key-file":
			state.PrivateKeyFile = next
			i++
		case "--public-key":
			state.PublicKey = next
			i++
		case "--public-key-env":
			state.PublicKeyEnv = next
			i++
		case "--public-key-file":
			state.PublicKeyFile = next
			i++
		case "--profile":
			state.Profile = next
			i++
		case "--hash":
			state.Hash = next
			i++
		case "--fullnode":
			state.Fullnode = next
			i++
		case "--multisig-action":
			state.MultisigAction = next
			i++
		case "--multisig-address":
			state.MultisigAddress = next
			i++
		case "--multisig-owner-address":
			state.MultisigOwnerAddresses = append(state.MultisigOwnerAddresses, splitMultiValue(next)...)
			i++
		case "--multisig-threshold":
			value, err := strconv.Atoi(next)
			if err != nil {
				return State{}, fmt.Errorf("invalid --multisig-threshold: %w", err)
			}
			state.MultisigThreshold = value
			i++
		case "--multisig-sequence":
			value, err := strconv.Atoi(next)
			if err != nil {
				return State{}, fmt.Errorf("invalid --multisig-sequence: %w", err)
			}
			state.MultisigSequence = value
			i++
		case "--multisig-hash-only":
			state.MultisigHashOnly = true
		case "--sdk-mode":
			state.SDKMode = next
			i++
		case "--sequence-number":
			n, _ := strconv.ParseUint(next, 10, 64)
			state.SequenceNumber = n
			i++
		case "--chain-id":
			n, _ := strconv.ParseUint(next, 10, 8)
			state.ChainID = uint8(n)
			i++
		case "--max-gas-amount":
			n, _ := strconv.ParseUint(next, 10, 64)
			state.MaxGasAmount = n
			i++
		case "--gas-unit-price":
			n, _ := strconv.ParseUint(next, 10, 64)
			state.GasUnitPrice = n
			i++
		case "--expiration-timestamp":
			n, _ := strconv.ParseUint(next, 10, 64)
			state.ExpirationTimestamp = n
			i++
		case "--nonce":
			state.Nonce = next
			i++
		case "--input-bcs":
			state.InputBcs = next
			i++
		case "--fee-payer-address":
			state.FeePayerAddress = next
			i++
		case "--no-sign":
			state.NoSign = true
		case "--no-abi":
			state.ABIEnabled = false
		case "--verbose":
			state.Verbose = true
		case "--quiet":
			state.Quiet = true
		default:
			return State{}, fmt.Errorf("unknown argument: %s", arg)
		}
	}
	if state.MaxGasAmount == 0 {
		state.MaxGasAmount = 200_000
	}
	if state.GasUnitPrice == 0 {
		state.GasUnitPrice = 100
	}
	if state.ExpirationTimestamp == 0 {
		state.ExpirationTimestamp = 9_999_999_999
	}
	if state.ChainID == 0 {
		state.ChainID = 4
	}
	return state, nil
}

func requireValidState(state State, spec InputSpec) error {
	if state.Action == "inspect" || state.Action == "encode" || state.Action == "decode" || state.Action == "sign" {
		return nil
	}
	if state.TxnType == "multi-sig" {
		if spec.MultisigAction == "" {
			return errors.New("multi-sig requires --multisig-action")
		}
		if spec.ScriptHex != "" {
			return errors.New("multi-sig currently supports entry-function payloads only")
		}
		switch spec.MultisigAction {
		case "create-account":
			if len(spec.MultisigOwnerAddresses) == 0 {
				return errors.New("multi-sig create-account requires at least one --multisig-owner-address")
			}
			if spec.MultisigThreshold < 1 {
				return errors.New("multi-sig create-account requires --multisig-threshold >= 1")
			}
			if spec.Function != "" || len(spec.Args) > 0 || len(spec.TypeArgs) > 0 {
				return errors.New("multi-sig create-account does not accept --function, --arg, or --type-arg")
			}
		case "propose":
			if spec.MultisigAddress == "" {
				return errors.New("multi-sig propose requires --multisig-address")
			}
			if spec.Function == "" {
				return errors.New("multi-sig propose requires --function")
			}
		case "approve":
			if spec.MultisigAddress == "" {
				return errors.New("multi-sig approve requires --multisig-address")
			}
			if spec.MultisigSequence < 1 {
				return errors.New("multi-sig approve requires --multisig-sequence")
			}
			if spec.Function != "" || len(spec.Args) > 0 || len(spec.TypeArgs) > 0 {
				return errors.New("multi-sig approve does not accept --function, --arg, or --type-arg")
			}
		case "execute":
			if spec.MultisigAddress == "" {
				return errors.New("multi-sig execute requires --multisig-address")
			}
			if spec.Function == "" && (len(spec.Args) > 0 || len(spec.TypeArgs) > 0) {
				return errors.New("multi-sig execute requires --function when --arg or --type-arg is provided")
			}
		default:
			return fmt.Errorf("unsupported multi-sig action: %s", spec.MultisigAction)
		}
	} else if spec.Function == "" && spec.ScriptHex == "" {
		return errors.New("missing function or --script-hex")
	}
	if state.TxnType != "single" && state.TxnType != "multi-agent" && state.TxnType != "multi-sig" {
		return fmt.Errorf("%s is not implemented yet in the real Go backend", state.TxnType)
	}
	if state.TxnType == "multi-agent" && len(spec.SecondarySignerAddresses) == 0 {
		return errors.New("multi-agent requires at least one --secondary-signer-address")
	}
	if !spec.ABIEnabled && spec.ScriptHex == "" {
		for _, item := range spec.Args {
			if strings.HasPrefix(item, "raw:") {
				return errors.New("raw:<hex> requires ABI mode")
			}
		}
	}
	signMode := signingMode(state)
	if (state.Action == "submit" || (state.Action == "run" && !spec.NoSign)) && signMode == "none" {
		return errors.New("submit requires signing material")
	}
	return nil
}

func detectFormat(path string, explicit string, fallback string) string {
	if explicit != "" && explicit != "auto" {
		return explicit
	}
	if path == "" || path == "-" {
		return fallback
	}
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		return "yaml"
	}
	return "json"
}

func fallbackOutputFormat(path string) string {
	if path != "" {
		return "json"
	}
	return "table"
}

func loadInput(path string, format string) (map[string]any, error) {
	if path == "" {
		return map[string]any{}, nil
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = os.ReadFile("/dev/stdin")
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if format == "yaml" {
		return parseSimpleYAML(string(data))
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func parseSimpleYAML(text string) (map[string]any, error) {
	obj := map[string]any{}
	currentKey := ""
	for _, rawLine := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if currentKey == "" {
				return nil, errors.New("invalid yaml list item without key")
			}
			list, _ := obj[currentKey].([]any)
			obj[currentKey] = append(list, parseScalar(strings.TrimSpace(trimmed[2:])))
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid yaml line")
		}
		key := strings.TrimSpace(parts[0])
		rest := strings.TrimSpace(parts[1])
		if rest == "" {
			obj[key] = []any{}
			currentKey = key
		} else {
			obj[key] = parseScalar(rest)
			currentKey = ""
		}
	}
	return obj, nil
}

func parseScalar(value string) any {
	switch value {
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.Atoi(value); err == nil {
		return n
	}
	return value
}

func splitMultiValue(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseArg(raw string) (any, error) {
	if strings.HasPrefix(raw, "raw:") {
		return RawArg{Mode: "raw", Raw: raw, Hex: strings.TrimPrefix(raw, "raw:")}, nil
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid --arg syntax: %s", raw)
	}
	return ParsedArg{Mode: "parsed", Raw: raw, ArgType: parts[0], Value: parts[1]}, nil
}

func signingMode(state State) string {
	if state.NoSign {
		return "none"
	}
	if state.PrivateKey != "" {
		return "private_key"
	}
	if state.PrivateKeyEnv != "" {
		return "private_key_env"
	}
	if state.PrivateKeyFile != "" {
		return "private_key_file"
	}
	if state.Profile != "" {
		return "profile"
	}
	return "none"
}

func stableDigest(seed string) string {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	hash := new(big.Int).SetUint64(0xcbf29ce484222325)
	multiplier := big.NewInt(0x100000001b3)
	for _, b := range []byte(seed) {
		hash.Xor(hash, big.NewInt(int64(b)))
		hash.Mul(hash, multiplier)
		hash.And(hash, mask)
		hash.Xor(hash, new(big.Int).Rsh(new(big.Int).Set(hash), 13))
	}
	out := hash.Text(16)
	if len(out) < 32 {
		out = strings.Repeat("0", 32-len(out)) + out
	}
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func runMock(state State, spec InputSpec) (map[string]any, error) {
	parsedArgs := make([]any, 0, len(spec.Args))
	for _, item := range spec.Args {
		arg, err := parseArg(item)
		if err != nil {
			return nil, err
		}
		parsedArgs = append(parsedArgs, arg)
	}
	signMode := signingMode(state)
	seed := strings.Join([]string{
		state.Action,
		state.TxnType,
		spec.Network,
		spec.Function,
		spec.SenderAddress,
		strings.Join(spec.Args, ","),
		strings.Join(spec.TypeArgs, ","),
		spec.MultisigAction,
		spec.MultisigAddress,
		strings.Join(spec.MultisigOwnerAddresses, ","),
		strconv.Itoa(spec.MultisigThreshold),
		strconv.Itoa(spec.MultisigSequence),
		strconv.FormatBool(spec.MultisigHashOnly),
		strconv.FormatBool(spec.ABIEnabled),
		signMode,
	}, "|")
	digest := stableDigest(seed)
	payload := map[string]any{
		"cli":            "aptx",
		"implementation": "go",
		"sdk_backend":    "github.com/aptos-labs/aptos-go-sdk",
		"sdk_mode":       "mock",
		"action":         state.Action,
		"txn_type":       state.TxnType,
		"abi_enabled":    spec.ABIEnabled,
		"input": map[string]any{
			"network":                  spec.Network,
			"function":                 spec.Function,
			"script_hex":               spec.ScriptHex,
			"sender_address":           spec.SenderAddress,
			"args":                     spec.Args,
			"parsed_args":              parsedArgs,
			"type_args":                spec.TypeArgs,
			"secondary_signer_addresses": spec.SecondarySignerAddresses,
			"multisig_action":          spec.MultisigAction,
			"multisig_address":         spec.MultisigAddress,
			"multisig_owner_addresses": spec.MultisigOwnerAddresses,
			"multisig_threshold":       spec.MultisigThreshold,
			"multisig_sequence":        spec.MultisigSequence,
			"multisig_hash_only":       spec.MultisigHashOnly,
			"hash":                     spec.Hash,
			"fullnode":                 spec.Fullnode,
		},
		"signing": map[string]any{
			"mode":     signMode,
			"provided": signMode != "none",
			"redacted": true,
		},
		"abi": map[string]any{"fetched": false},
		"result": map[string]any{
			"mode":      state.Action,
			"success":   true,
			"vm_status": "Executed successfully",
			"tx_hash":   "0x" + digest,
			"gas_used":  len(spec.Function) + len(spec.Args)*111 + len(spec.TypeArgs)*37,
			"notes":     []string{"mock backend active", "sdk integration point reserved"},
		},
	}
	if state.Action == "run" && spec.NoSign {
		payload["result"].(map[string]any)["mode"] = "simulate"
	}
	return payload, nil
}

func buildEntryFunctionPayload(spec InputSpec, typeArgs []aptos.TypeTag, entryArgs [][]byte) (*aptos.EntryFunction, error) {
	moduleAddress, moduleName, functionName, err := parseFunctionID(spec.Function)
	if err != nil {
		return nil, err
	}
	return &aptos.EntryFunction{
		Module: aptos.ModuleId{
			Address: moduleAddress,
			Name:    moduleName,
		},
		Function: functionName,
		ArgTypes: typeArgs,
		Args:     entryArgs,
	}, nil
}

func emptyMultisigMetadataValues() ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		bcs.SerializeSequenceWithFunction([][]byte{}, ser, func(ser *bcs.Serializer, item []byte) {
			ser.WriteBytes(item)
		})
	})
}

func buildMultisigPayload(
	client *aptos.Client,
	spec InputSpec,
	typeArgs []aptos.TypeTag,
	entryArgs [][]byte,
) (aptos.TransactionPayloadImpl, string, error) {
	switch spec.MultisigAction {
	case "create-account":
		senderAddress, err := parseAddress(spec.SenderAddress)
		if err != nil {
			return nil, "", err
		}
		expectedAddress, err := client.FetchNextMultisigAddress(senderAddress)
		if err != nil {
			return nil, "", err
		}
		additionalOwners, err := parseAddresses(spec.MultisigOwnerAddresses)
		if err != nil {
			return nil, "", err
		}
		metadataValues, err := emptyMultisigMetadataValues()
		if err != nil {
			return nil, "", err
		}
		payload, err := aptos.MultisigCreateAccountPayload(uint64(spec.MultisigThreshold), additionalOwners, []string{}, metadataValues)
		if err != nil {
			return nil, "", err
		}
		return payload, expectedAddress.String(), nil
	case "propose":
		multisigAddress, err := parseAddress(spec.MultisigAddress)
		if err != nil {
			return nil, "", err
		}
		entryFunction, err := buildEntryFunctionPayload(spec, typeArgs, entryArgs)
		if err != nil {
			return nil, "", err
		}
		multisigPayload := &aptos.MultisigTransactionPayload{
			Variant: aptos.MultisigTransactionPayloadVariantEntryFunction,
			Payload: entryFunction,
		}
		if spec.MultisigHashOnly {
			payload, err := aptos.MultisigCreateTransactionPayloadWithHash(multisigAddress, multisigPayload)
			return payload, "", err
		}
		payload, err := aptos.MultisigCreateTransactionPayload(multisigAddress, multisigPayload)
		return payload, "", err
	case "approve":
		multisigAddress, err := parseAddress(spec.MultisigAddress)
		if err != nil {
			return nil, "", err
		}
		payload, err := aptos.MultisigApprovePayload(multisigAddress, uint64(spec.MultisigSequence))
		return payload, "", err
	case "execute":
		multisigAddress, err := parseAddress(spec.MultisigAddress)
		if err != nil {
			return nil, "", err
		}
		var multisigPayload *aptos.MultisigTransactionPayload
		if spec.Function != "" {
			entryFunction, err := buildEntryFunctionPayload(spec, typeArgs, entryArgs)
			if err != nil {
				return nil, "", err
			}
			multisigPayload = &aptos.MultisigTransactionPayload{
				Variant: aptos.MultisigTransactionPayloadVariantEntryFunction,
				Payload: entryFunction,
			}
		}
		return &aptos.Multisig{
			MultisigAddress: multisigAddress,
			Payload:         multisigPayload,
		}, "", nil
	default:
		return nil, "", fmt.Errorf("unsupported multi-sig action: %s", spec.MultisigAction)
	}
}

func runReal(state State, spec InputSpec) (map[string]any, error) {
	client, err := newClient(spec)
	if err != nil {
		return nil, err
	}
	if state.Action == "inspect" {
		return inspectReal(client, state, spec)
	}

	abi, err := resolveABISummary(client, spec)
	if err != nil {
		return nil, err
	}
	rawArgs := make([]any, 0, len(spec.Args))
	entryArgs := make([][]byte, 0, len(spec.Args))
	scriptArgs := make([]aptos.ScriptArgument, 0, len(spec.Args))
	for _, item := range spec.Args {
		arg, err := parseArg(item)
		if err != nil {
			return nil, err
		}
		rawArgs = append(rawArgs, arg)
		if spec.ScriptHex != "" {
			scriptArg, err := scriptArgument(arg)
			if err != nil {
				return nil, err
			}
			scriptArgs = append(scriptArgs, scriptArg)
		} else {
			serialized, err := serializeArgument(arg)
			if err != nil {
				return nil, err
			}
			entryArgs = append(entryArgs, serialized)
		}
	}
	typeArgs := make([]aptos.TypeTag, 0, len(spec.TypeArgs))
	for _, item := range spec.TypeArgs {
		tag, err := aptos.ParseTypeTag(item)
		if err != nil {
			return nil, err
		}
		typeArgs = append(typeArgs, *tag)
	}
	senderAddress, err := parseAddress(spec.SenderAddress)
	if err != nil {
		return nil, err
	}
	secondaryAddresses, err := parseAddresses(spec.SecondarySignerAddresses)
	if err != nil {
		return nil, err
	}
	var (
		txnPayload              aptos.TransactionPayload
		expectedMultisigAddress string
	)
	if state.TxnType == "multi-sig" {
		payloadImpl, multisigAddress, err := buildMultisigPayload(client, spec, typeArgs, entryArgs)
		if err != nil {
			return nil, err
		}
		expectedMultisigAddress = multisigAddress
		txnPayload = aptos.TransactionPayload{Payload: payloadImpl}
	} else if spec.ScriptHex != "" {
		scriptCode, err := decodeHex(spec.ScriptHex)
		if err != nil {
			return nil, err
		}
		txnPayload = aptos.TransactionPayload{
			Payload: &aptos.Script{
				Code:     scriptCode,
				ArgTypes: typeArgs,
				Args:     scriptArgs,
			},
		}
	} else {
		entryFunction, err := buildEntryFunctionPayload(spec, typeArgs, entryArgs)
		if err != nil {
			return nil, err
		}
		txnPayload = aptos.TransactionPayload{
			Payload: entryFunction,
		}
	}

	var (
		rawTxn                  *aptos.RawTransaction
		rawTxnWithData          *aptos.RawTransactionWithData
		sequenceNumber          uint64
		maxGasAmount            uint64
		gasUnitPrice            uint64
		expirationTimestampSecs uint64
	)
	if state.TxnType == "multi-agent" {
		rawTxnWithData, err = client.BuildTransactionMultiAgent(
			senderAddress,
			txnPayload,
			aptos.AdditionalSigners(secondaryAddresses),
			aptos.MaxGasAmount(state.MaxGasAmount),
		)
		if err != nil {
			return nil, err
		}
		sequenceNumber, maxGasAmount, gasUnitPrice, expirationTimestampSecs, err = rawTxnWithDataMetadata(rawTxnWithData)
		if err != nil {
			return nil, err
		}
	} else {
		rawTxn, err = client.BuildTransaction(senderAddress, txnPayload, aptos.MaxGasAmount(state.MaxGasAmount))
		if err != nil {
			return nil, err
		}
		sequenceNumber = rawTxn.SequenceNumber
		maxGasAmount = rawTxn.MaxGasAmount
		gasUnitPrice = rawTxn.GasUnitPrice
		expirationTimestampSecs = rawTxn.ExpirationTimestampSeconds
	}
	if err != nil {
		return nil, err
	}

	payload := map[string]any{
		"cli":            "aptx",
		"implementation": "go",
		"sdk_backend":    "github.com/aptos-labs/aptos-go-sdk",
		"sdk_mode":       "sdk",
		"action":         state.Action,
		"txn_type":       state.TxnType,
		"abi_enabled":    spec.ABIEnabled,
		"input": map[string]any{
			"network":                    spec.Network,
			"function":                   spec.Function,
			"script_hex":                 spec.ScriptHex,
			"sender_address":             spec.SenderAddress,
			"args":                       spec.Args,
			"parsed_args":                rawArgs,
			"type_args":                  spec.TypeArgs,
			"secondary_signer_addresses": spec.SecondarySignerAddresses,
			"multisig_action":            spec.MultisigAction,
			"multisig_address":           spec.MultisigAddress,
			"multisig_owner_addresses":   spec.MultisigOwnerAddresses,
			"multisig_threshold":         spec.MultisigThreshold,
			"multisig_sequence":          spec.MultisigSequence,
			"multisig_hash_only":         spec.MultisigHashOnly,
			"fullnode":                   spec.Fullnode,
			"sequence_number":            sequenceNumber,
			"max_gas_amount":             maxGasAmount,
			"gas_unit_price":             gasUnitPrice,
			"expiration_timestamp_secs":  expirationTimestampSecs,
		},
		"signing": map[string]any{
			"mode":     signingMode(state),
			"provided": signingMode(state) != "none",
			"redacted": true,
		},
		"abi": abi,
		"result": map[string]any{
			"mode":      state.Action,
			"success":   true,
			"vm_status": "built",
			"tx_hash":   "-",
			"notes":     []string{"real SDK backend active"},
		},
	}
	result := payload["result"].(map[string]any)
	if expectedMultisigAddress != "" {
		payload["input"].(map[string]any)["expected_multisig_address"] = expectedMultisigAddress
	}

	if state.Action == "simulate" || (state.Action == "run" && spec.NoSign) {
		signer, err := simulationSigner(state, spec)
		if err != nil {
			return nil, err
		}
		var simulated []*api.UserTransaction
		if state.TxnType == "multi-agent" {
			simulated, err = client.SimulateTransactionMultiAgent(rawTxnWithData, signer, aptos.AdditionalSigners(secondaryAddresses))
		} else {
			simulated, err = client.SimulateTransaction(rawTxn, signer)
		}
		if err != nil {
			return nil, err
		}
		first := simulated[0]
		result["mode"] = "simulate"
		result["success"] = first.Success
		result["vm_status"] = first.VmStatus
		result["tx_hash"] = first.Hash
		result["gas_used"] = first.GasUsed
		result["notes"] = []string{"simulated transaction"}
		result["response"] = first
		if expectedMultisigAddress != "" {
			result["multisig_address"] = expectedMultisigAddress
		}
		return payload, nil
	}

	account, err := signerAccount(state, spec)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, errors.New("missing signer for submit path")
	}
	secondaryAccounts, err := secondarySignerAccounts(state, spec)
	if err != nil {
		return nil, err
	}

	if state.Action == "submit" {
		signedTxn, err := signTransaction(state, rawTxn, rawTxnWithData, account, secondaryAccounts)
		if err != nil {
			return nil, err
		}
		submitted, err := client.SubmitTransaction(signedTxn)
		if err != nil {
			return nil, err
		}
		result["mode"] = "submit"
		result["success"] = true
		result["vm_status"] = "pending"
		result["tx_hash"] = submitted.Hash
		result["notes"] = []string{"submitted transaction"}
		result["response"] = submitted
		if expectedMultisigAddress != "" {
			result["multisig_address"] = expectedMultisigAddress
		}
		return payload, nil
	}

	var simulated []*api.UserTransaction
	if state.TxnType == "multi-agent" {
		simulated, err = client.SimulateTransactionMultiAgent(rawTxnWithData, account, aptos.AdditionalSigners(secondaryAddresses))
	} else {
		simulated, err = client.SimulateTransaction(rawTxn, account)
	}
	if err != nil {
		return nil, err
	}
	signedTxn, err := signTransaction(state, rawTxn, rawTxnWithData, account, secondaryAccounts)
	if err != nil {
		return nil, err
	}
	submitted, err := client.SubmitTransaction(signedTxn)
	if err != nil {
		return nil, err
	}
	executed, err := client.WaitForTransaction(submitted.Hash)
	if err != nil {
		return nil, err
	}
	result["mode"] = "run"
	result["success"] = executed.Success
	result["vm_status"] = executed.VmStatus
	result["tx_hash"] = executed.Hash
	result["gas_used"] = executed.GasUsed
	result["notes"] = []string{"simulated transaction", "submitted transaction", "waited for execution"}
	result["response"] = map[string]any{
		"simulation": simulated[0],
		"submission": submitted,
		"execution":  executed,
	}
	if expectedMultisigAddress != "" {
		result["multisig_address"] = expectedMultisigAddress
	}
	return payload, nil
}

func parseAddresses(values []string) ([]aptos.AccountAddress, error) {
	addresses := make([]aptos.AccountAddress, 0, len(values))
	for _, value := range values {
		address, err := parseAddress(value)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func rawTxnWithDataMetadata(rawTxnWithData *aptos.RawTransactionWithData) (uint64, uint64, uint64, uint64, error) {
	switch inner := rawTxnWithData.Inner.(type) {
	case *aptos.MultiAgentRawTransactionWithData:
		return inner.RawTxn.SequenceNumber, inner.RawTxn.MaxGasAmount, inner.RawTxn.GasUnitPrice, inner.RawTxn.ExpirationTimestampSeconds, nil
	case *aptos.MultiAgentWithFeePayerRawTransactionWithData:
		return inner.RawTxn.SequenceNumber, inner.RawTxn.MaxGasAmount, inner.RawTxn.GasUnitPrice, inner.RawTxn.ExpirationTimestampSeconds, nil
	default:
		return 0, 0, 0, 0, fmt.Errorf("unsupported raw transaction with data type %T", rawTxnWithData.Inner)
	}
}

func signTransaction(
	state State,
	rawTxn *aptos.RawTransaction,
	rawTxnWithData *aptos.RawTransactionWithData,
	account *aptos.Account,
	secondaryAccounts []*aptos.Account,
) (*aptos.SignedTransaction, error) {
	if state.TxnType != "multi-agent" {
		return rawTxn.SignedTransaction(account)
	}
	senderAuthenticator, err := rawTxnWithData.Sign(account)
	if err != nil {
		return nil, err
	}
	secondaryAuthenticators := make([]crypto.AccountAuthenticator, 0, len(secondaryAccounts))
	for _, secondaryAccount := range secondaryAccounts {
		authenticator, err := rawTxnWithData.Sign(secondaryAccount)
		if err != nil {
			return nil, err
		}
		secondaryAuthenticators = append(secondaryAuthenticators, *authenticator)
	}
	signedTxn, ok := rawTxnWithData.ToMultiAgentSignedTransaction(senderAuthenticator, secondaryAuthenticators)
	if !ok {
		return nil, errors.New("failed to build multi-agent signed transaction")
	}
	return signedTxn, nil
}

func inspectReal(client *aptos.Client, state State, spec InputSpec) (map[string]any, error) {
	if spec.Hash != "" {
		transaction, err := client.TransactionByHash(spec.Hash)
		if err != nil {
			return nil, err
		}
		success := true
		vmStatus := "pending"
		if transaction.Success() != nil {
			success = *transaction.Success()
		}
		if userTxn, err := transaction.UserTransaction(); err == nil {
			vmStatus = userTxn.VmStatus
		}
		return map[string]any{
			"cli":            "aptx",
			"implementation": "go",
			"sdk_backend":    "github.com/aptos-labs/aptos-go-sdk",
			"sdk_mode":       "sdk",
			"action":         "inspect",
			"txn_type":       "single",
			"abi_enabled":    spec.ABIEnabled,
			"input": map[string]any{
				"network":  spec.Network,
				"hash":     spec.Hash,
				"fullnode": spec.Fullnode,
			},
			"signing": map[string]any{
				"mode":     signingMode(state),
				"provided": false,
				"redacted": true,
			},
			"abi": map[string]any{"fetched": false},
			"result": map[string]any{
				"mode":      "inspect",
				"success":   success,
				"vm_status": vmStatus,
				"tx_hash":   transaction.Hash(),
				"notes":     []string{"fetched transaction by hash"},
				"response":  transaction,
			},
		}, nil
	}

	info, err := client.Info()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"cli":            "aptx",
		"implementation": "go",
		"sdk_backend":    "github.com/aptos-labs/aptos-go-sdk",
		"sdk_mode":       "sdk",
		"action":         "inspect",
		"txn_type":       "single",
		"abi_enabled":    spec.ABIEnabled,
		"input": map[string]any{
			"network":  spec.Network,
			"fullnode": spec.Fullnode,
		},
		"signing": map[string]any{
			"mode":     "none",
			"provided": false,
			"redacted": true,
		},
		"abi": map[string]any{"fetched": false},
		"result": map[string]any{
			"mode":      "inspect",
			"success":   true,
			"vm_status": "ledger_info",
			"tx_hash":   "-",
			"notes":     []string{"fetched ledger info"},
			"response":  info,
		},
	}, nil
}

func newClient(spec InputSpec) (*aptos.Client, error) {
	config := networkConfig(spec.Network, spec.Fullnode)
	return aptos.NewClient(config)
}

func networkConfig(network string, fullnode string) aptos.NetworkConfig {
	normalized := strings.ToLower(network)
	config, ok := aptos.NamedNetworks[normalized]
	if !ok {
		config = aptos.NetworkConfig{Name: normalized, NodeUrl: fullnode}
	}
	if fullnode != "" {
		config.NodeUrl = fullnode
	}
	return config
}

func resolveABISummary(client *aptos.Client, spec InputSpec) (AbiSummary, error) {
	if !spec.ABIEnabled || spec.Function == "" || spec.ScriptHex != "" {
		return AbiSummary{Fetched: false}, nil
	}
	moduleAddress, moduleName, functionName, err := parseFunctionID(spec.Function)
	if err != nil {
		return AbiSummary{}, err
	}
	module, err := client.AccountModule(moduleAddress, moduleName)
	if err != nil {
		return AbiSummary{}, err
	}
	if module.Abi == nil {
		return AbiSummary{}, fmt.Errorf("module ABI unavailable for %s::%s", moduleAddress.String(), moduleName)
	}
	for _, function := range module.Abi.ExposedFunctions {
		if function.Name == functionName {
			return AbiSummary{
				Fetched:            true,
				Module:             fmt.Sprintf("%s::%s", moduleAddress.String(), moduleName),
				Function:           functionName,
				ParameterCount:     len(function.Params),
				TypeParameterCount: len(function.GenericTypeParams),
			}, nil
		}
	}
	return AbiSummary{}, fmt.Errorf("function %s not found in remote ABI", spec.Function)
}

func parseFunctionID(value string) (aptos.AccountAddress, string, string, error) {
	parts := strings.Split(value, "::")
	if len(parts) != 3 {
		return aptos.AccountAddress{}, "", "", fmt.Errorf("invalid function id: %s", value)
	}
	address, err := parseAddress(parts[0])
	if err != nil {
		return aptos.AccountAddress{}, "", "", err
	}
	return address, parts[1], parts[2], nil
}

func parseAddress(value string) (aptos.AccountAddress, error) {
	var out aptos.AccountAddress
	err := out.ParseStringRelaxed(value)
	return out, err
}

func serializeArgument(arg any) ([]byte, error) {
	switch typed := arg.(type) {
	case RawArg:
		return decodeHex(typed.Hex)
	case ParsedArg:
		switch typed.ArgType {
		case "address":
			address, err := parseAddress(typed.Value)
			if err != nil {
				return nil, err
			}
			return bcs.Serialize(&address)
		case "u8":
			value, err := strconv.ParseUint(typed.Value, 10, 8)
			if err != nil {
				return nil, err
			}
			return bcs.SerializeU8(uint8(value))
		case "u64":
			value, err := strconv.ParseUint(typed.Value, 10, 64)
			if err != nil {
				return nil, err
			}
			return bcs.SerializeU64(value)
		case "u128":
			value, ok := new(big.Int).SetString(typed.Value, 10)
			if !ok {
				return nil, fmt.Errorf("invalid u128 value: %s", typed.Value)
			}
			return bcs.SerializeU128(*value)
		case "bool":
			return bcs.SerializeBool(typed.Value == "true")
		case "string":
			return bcs.SerializeBytes([]byte(typed.Value))
		case "hex":
			bytes, err := decodeHex(typed.Value)
			if err != nil {
				return nil, err
			}
			return bcs.SerializeBytes(bytes)
		case "vector<u8>":
			bytes, err := parseVectorU8(typed.Value)
			if err != nil {
				return nil, err
			}
			return bcs.SerializeBytes(bytes)
		default:
			return nil, fmt.Errorf("unsupported argument type: %s", typed.ArgType)
		}
	default:
		return nil, fmt.Errorf("unsupported argument variant: %T", arg)
	}
}

func scriptArgument(arg any) (aptos.ScriptArgument, error) {
	switch typed := arg.(type) {
	case RawArg:
		bytes, err := decodeHex(typed.Hex)
		if err != nil {
			return aptos.ScriptArgument{}, err
		}
		return aptos.ScriptArgument{Variant: aptos.ScriptArgumentSerialized, Value: bcs.NewSerialized(bytes)}, nil
	case ParsedArg:
		switch typed.ArgType {
		case "address":
			address, err := parseAddress(typed.Value)
			if err != nil {
				return aptos.ScriptArgument{}, err
			}
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentAddress, Value: address}, nil
		case "u8":
			value, err := strconv.ParseUint(typed.Value, 10, 8)
			if err != nil {
				return aptos.ScriptArgument{}, err
			}
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentU8, Value: uint8(value)}, nil
		case "u64":
			value, err := strconv.ParseUint(typed.Value, 10, 64)
			if err != nil {
				return aptos.ScriptArgument{}, err
			}
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentU64, Value: value}, nil
		case "u128":
			value, ok := new(big.Int).SetString(typed.Value, 10)
			if !ok {
				return aptos.ScriptArgument{}, fmt.Errorf("invalid u128 value: %s", typed.Value)
			}
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentU128, Value: *value}, nil
		case "bool":
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentBool, Value: typed.Value == "true"}, nil
		case "string":
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentU8Vector, Value: []byte(typed.Value)}, nil
		case "hex":
			bytes, err := decodeHex(typed.Value)
			if err != nil {
				return aptos.ScriptArgument{}, err
			}
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentU8Vector, Value: bytes}, nil
		case "vector<u8>":
			bytes, err := parseVectorU8(typed.Value)
			if err != nil {
				return aptos.ScriptArgument{}, err
			}
			return aptos.ScriptArgument{Variant: aptos.ScriptArgumentU8Vector, Value: bytes}, nil
		default:
			return aptos.ScriptArgument{}, fmt.Errorf("unsupported script argument type: %s", typed.ArgType)
		}
	default:
		return aptos.ScriptArgument{}, fmt.Errorf("unsupported script argument variant: %T", arg)
	}
}

func parseVectorU8(value string) ([]byte, error) {
	var items []uint8
	if err := json.Unmarshal([]byte(value), &items); err != nil {
		return nil, fmt.Errorf("invalid vector<u8> value: %w", err)
	}
	return items, nil
}

func decodeHex(value string) ([]byte, error) {
	normalized := strings.TrimPrefix(normalizeKeyHex(value), "0x")
	if len(normalized)%2 != 0 {
		return nil, fmt.Errorf("invalid hex value: %s", value)
	}
	return hex.DecodeString(normalized)
}

func normalizeKeyHex(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "ed25519-priv-")
	trimmed = strings.TrimPrefix(trimmed, "ed25519-pub-")
	return trimmed
}

func signerAccount(state State, spec InputSpec) (*aptos.Account, error) {
	privateKey, err := readPrivateKey(state)
	if err != nil || privateKey == "" {
		return nil, err
	}
	key := &crypto.Ed25519PrivateKey{}
	if err := key.FromHex(strings.TrimSpace(privateKey)); err != nil {
		return nil, err
	}
	address, err := parseAddress(spec.SenderAddress)
	if err != nil {
		return nil, err
	}
	return aptos.NewAccountFromSigner(key, address)
}

func secondarySignerAccounts(state State, spec InputSpec) ([]*aptos.Account, error) {
	if state.TxnType != "multi-agent" {
		return nil, nil
	}
	if len(state.SecondaryPrivateKeys) == 0 {
		return nil, errors.New("multi-agent submit requires --secondary-private-key for each secondary signer")
	}
	if len(state.SecondaryPrivateKeys) != len(spec.SecondarySignerAddresses) {
		return nil, errors.New("secondary private key count must match secondary signer address count")
	}
	accounts := make([]*aptos.Account, 0, len(state.SecondaryPrivateKeys))
	for index, privateKey := range state.SecondaryPrivateKeys {
		key := &crypto.Ed25519PrivateKey{}
		if err := key.FromHex(strings.TrimSpace(privateKey)); err != nil {
			return nil, err
		}
		address, err := parseAddress(spec.SecondarySignerAddresses[index])
		if err != nil {
			return nil, err
		}
		account, err := aptos.NewAccountFromSigner(key, address)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func simulationSigner(state State, spec InputSpec) (*aptos.Account, error) {
	account, err := signerAccount(state, spec)
	if err != nil || account != nil {
		return account, err
	}
	publicKey, err := readPublicKey(state)
	if err != nil {
		return nil, err
	}
	if publicKey != nil {
		address, err := parseAddress(spec.SenderAddress)
		if err != nil {
			return nil, err
		}
		return aptos.NewAccountFromSigner(&simulationOnlySigner{publicKey: publicKey}, address)
	}
	key, err := crypto.GenerateEd25519PrivateKey()
	if err != nil {
		return nil, err
	}
	address, err := parseAddress(spec.SenderAddress)
	if err != nil {
		return nil, err
	}
	return aptos.NewAccountFromSigner(key, address)
}

func readPrivateKey(state State) (string, error) {
	if state.PrivateKey != "" {
		return state.PrivateKey, nil
	}
	if state.PrivateKeyEnv != "" {
		value := os.Getenv(state.PrivateKeyEnv)
		if value == "" {
			return "", fmt.Errorf("environment variable %s is not set", state.PrivateKeyEnv)
		}
		return value, nil
	}
	if state.PrivateKeyFile != "" {
		data, err := os.ReadFile(state.PrivateKeyFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}

func readPublicKey(state State) (*crypto.Ed25519PublicKey, error) {
	value := ""
	switch {
	case state.PublicKey != "":
		value = state.PublicKey
	case state.PublicKeyEnv != "":
		value = os.Getenv(state.PublicKeyEnv)
		if value == "" {
			return nil, fmt.Errorf("environment variable %s is not set", state.PublicKeyEnv)
		}
	case state.PublicKeyFile != "":
		data, err := os.ReadFile(state.PublicKeyFile)
		if err != nil {
			return nil, err
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return nil, nil
	}
	key := &crypto.Ed25519PublicKey{}
	if err := key.FromHex(normalizeKeyHex(value)); err != nil {
		return nil, err
	}
	return key, nil
}

func renderOutput(payload map[string]any, format string) (string, error) {
	switch format {
	case "json":
		data, err := json.MarshalIndent(payload, "", "  ")
		return string(data), err
	case "yaml":
		return renderYAML(payload, 0), nil
	case "ascii":
		return renderASCII(payload), nil
	default:
		return renderTable(payload), nil
	}
}

func renderTable(payload map[string]any) string {
	input := payload["input"].(map[string]any)
	result := payload["result"].(map[string]any)
	target := ""
	if multisigAction := asString(input["multisig_action"], ""); multisigAction != "" {
		target = "multisig:" + multisigAction
	} else {
		target = asString(input["function"], "")
	}
	if target == "" {
		scriptHex := asString(input["script_hex"], "")
		if scriptHex != "" {
			if len(scriptHex) > 18 {
				target = "script:" + scriptHex[:18] + "..."
			} else {
				target = "script:" + scriptHex
			}
		} else {
			target = "-"
		}
	}
	rows := [][2]string{
		{"implementation", asString(payload["implementation"], "")},
		{"sdk_backend", asString(payload["sdk_backend"], "")},
		{"action", asString(payload["action"], "")},
		{"txn_type", asString(payload["txn_type"], "")},
		{"target", target},
		{"sender", asString(input["sender_address"], "-")},
		{"vm_status", asString(result["vm_status"], "-")},
		{"tx_hash", asString(result["tx_hash"], "-")},
	}
	width := 0
	for _, row := range rows {
		if len(row[0]) > width {
			width = len(row[0])
		}
	}
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		lines = append(lines, fmt.Sprintf("%-*s | %s", width, row[0], row[1]))
	}
	return strings.Join(lines, "\n")
}

func renderASCII(payload map[string]any) string {
	input := payload["input"].(map[string]any)
	result := payload["result"].(map[string]any)
	target := ""
	if multisigAction := asString(input["multisig_action"], ""); multisigAction != "" {
		target = "multisig:" + multisigAction
	} else {
		target = asString(input["function"], "")
	}
	if target == "" {
		scriptHex := asString(input["script_hex"], "")
		if scriptHex != "" {
			if len(scriptHex) > 18 {
				target = "script:" + scriptHex[:18] + "..."
			} else {
				target = "script:" + scriptHex
			}
		} else {
			target = "-"
		}
	}
	lines := []string{
		"+----------------------------------------------+",
		"| Aptos Transaction CLI                        |",
		"+----------------------------------------------+",
		fmt.Sprintf("| action        | %-28s|", asString(payload["action"], "")),
		fmt.Sprintf("| txn_type      | %-28s|", asString(payload["txn_type"], "")),
		fmt.Sprintf("| target        | %-28s|", target),
		fmt.Sprintf("| sender        | %-28s|", asString(input["sender_address"], "-")),
		fmt.Sprintf("| vm_status     | %-28s|", asString(result["vm_status"], "-")),
		fmt.Sprintf("| tx_hash       | %-28s|", asString(result["tx_hash"], "-")),
		"+----------------------------------------------+",
	}
	return strings.Join(lines, "\n")
}

func renderYAML(value any, indent int) string {
	pad := strings.Repeat(" ", indent)
	switch typed := value.(type) {
	case map[string]any:
		lines := []string{}
		for key, child := range typed {
			switch child.(type) {
			case map[string]any, []any:
				lines = append(lines, fmt.Sprintf("%s%s:", pad, key))
				lines = append(lines, renderYAML(child, indent+2))
			default:
				lines = append(lines, fmt.Sprintf("%s%s: %s", pad, key, yamlScalar(child)))
			}
		}
		return strings.Join(lines, "\n")
	case []any:
		lines := []string{}
		for _, child := range typed {
			switch child.(type) {
			case map[string]any, []any:
				lines = append(lines, fmt.Sprintf("%s-", pad))
				lines = append(lines, renderYAML(child, indent+2))
			default:
				lines = append(lines, fmt.Sprintf("%s- %s", pad, yamlScalar(child)))
			}
		}
		return strings.Join(lines, "\n")
	default:
		return pad + yamlScalar(value)
	}
}

func yamlScalar(value any) string {
	switch typed := value.(type) {
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func asString(value any, fallback string) string {
	if value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func asBool(value any, fallback bool) bool {
	if value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		return fallback
	}
}

func asInt(value any, fallback int) int {
	if value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed)
		}
	}
	return fallback
}

func asStringSlice(value any) []string {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, asString(item, ""))
		}
		return out
	default:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, item := range values {
		if item != "" {
			return item
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, item := range values {
		if item != 0 {
			return item
		}
	}
	return 0
}

func firstNonEmptySlice(primary []string, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

var _ = api.TransactionVariantPending
