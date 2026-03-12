import json
import sys
from pathlib import Path


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def parse_simple_yaml(text: str):
    obj = {}
    current_key = None
    for raw_line in text.splitlines():
        trimmed = raw_line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if trimmed.startswith("- "):
            if current_key is None:
                raise ValueError("invalid yaml list item without key")
            obj[current_key].append(parse_scalar(trimmed[2:]))
            continue
        idx = trimmed.find(":")
        if idx == -1:
            raise ValueError("invalid yaml line")
        key = trimmed[:idx].strip()
        rest = trimmed[idx + 1 :].strip()
        if rest == "":
            obj[key] = []
            current_key = key
        else:
            obj[key] = parse_scalar(rest)
            current_key = None
    return obj


def parse_scalar(value: str):
    if value == "true":
        return True
    if value == "false":
        return False
    if value.isdigit():
        return int(value)
    return value


def detect_format(path: str, explicit: str, fallback: str) -> str:
    if explicit and explicit != "auto":
        return explicit
    if not path or path == "-":
        return fallback
    if path.endswith(".yaml") or path.endswith(".yml"):
        return "yaml"
    return "json"


def load_input(path: str, file_format: str):
    if not path:
        return {}
    text = sys.stdin.read() if path == "-" else Path(path).read_text()
    if file_format == "yaml":
        return parse_simple_yaml(text)
    return json.loads(text)


def parse_arg(raw: str):
    if raw.startswith("raw:"):
        return {"mode": "raw", "raw": raw, "hex": raw[4:]}
    idx = raw.find(":")
    if idx == -1:
        raise ValueError(f"invalid --arg syntax: {raw}")
    return {"mode": "parsed", "raw": raw, "argType": raw[:idx], "value": raw[idx + 1 :]}


def sign_mode(state):
    if state["no_sign"]:
        return "none"
    if state["private_key"]:
        return "private_key"
    if state["private_key_env"]:
        return "private_key_env"
    if state["private_key_file"]:
        return "private_key_file"
    if state["profile"]:
        return "profile"
    return "none"


def stable_digest(seed: str) -> str:
    mask = (1 << 128) - 1
    value = 0xCBF29CE484222325
    for byte in seed.encode("utf-8"):
        value ^= byte
        value = (value * 0x100000001B3) & mask
        value ^= value >> 13
    return f"{value:032x}"[:32]


def render_yaml(value, indent=0):
    pad = " " * indent
    if isinstance(value, dict):
        lines = []
        for key, child in value.items():
          if isinstance(child, (dict, list)):
              lines.append(f"{pad}{key}:")
              lines.append(render_yaml(child, indent + 2))
          else:
              lines.append(f"{pad}{key}: {render_yaml_scalar(child)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{pad}-")
                lines.append(render_yaml(child, indent + 2))
            else:
                lines.append(f"{pad}- {render_yaml_scalar(child)}")
        return "\n".join(lines)
    return f"{pad}{render_yaml_scalar(value)}"


def render_yaml_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def render_table(payload):
    rows = [
        ("implementation", payload["implementation"]),
        ("sdk_backend", payload["sdk_backend"]),
        ("action", payload["action"]),
        ("txn_type", payload["txn_type"]),
        ("function", payload["input"]["function"]),
        ("sender", payload["input"]["sender_address"]),
        ("vm_status", payload["result"]["vm_status"]),
        ("tx_hash", payload["result"]["tx_hash"]),
    ]
    width = max(len(key) for key, _ in rows)
    return "\n".join(f"{key.ljust(width)} | {value}" for key, value in rows)


def render_ascii(payload):
    rows = [
        "+----------------------------------------------+",
        "| Aptos Transaction CLI                        |",
        "+----------------------------------------------+",
        f"| action        | {payload['action']:<28}|",
        f"| txn_type      | {payload['txn_type']:<28}|",
        f"| function      | {payload['input']['function']:<28}|",
        f"| sender        | {payload['input']['sender_address']:<28}|",
        f"| vm_status     | {payload['result']['vm_status']:<28}|",
        f"| tx_hash       | {payload['result']['tx_hash']:<28}|",
        "+----------------------------------------------+",
    ]
    return "\n".join(rows)


def parse_cli(argv):
    if len(argv) < 1:
        raise ValueError("usage: aptx <simulate|submit|run|inspect> <txn-type> [flags]")
    action = argv[0]
    if action == "inspect":
        txn_type = "single"
    elif len(argv) >= 2:
        txn_type = argv[1]
    else:
        raise ValueError("usage: aptx <simulate|submit|run|inspect> <txn-type> [flags]")
    start = 1 if action == "inspect" else 2
    state = {
        "action": action,
        "txn_type": txn_type,
        "input": None,
        "input_format": None,
        "output": None,
        "output_format": None,
        "artifacts_dir": None,
        "network": None,
        "function": None,
        "script_hex": None,
        "args": [],
        "type_args": [],
        "secondary_signer_addresses": [],
        "secondary_private_keys": [],
        "secondary_public_keys": [],
        "sender_address": None,
        "private_key": None,
        "private_key_env": None,
        "private_key_file": None,
        "public_key": None,
        "public_key_env": None,
        "public_key_file": None,
        "profile": None,
        "hash": None,
        "fullnode": None,
        "multisig_action": None,
        "multisig_address": None,
        "multisig_owner_addresses": [],
        "multisig_threshold": None,
        "multisig_sequence": None,
        "multisig_hash_only": False,
        "multi_key_public_keys": [],
        "multi_key_signers": [],
        "multi_key_threshold": None,
        "no_sign": False,
        "abi_enabled": True,
        "verbose": False,
        "quiet": False,
        "sdk_mode": "mock",
    }
    i = start
    while i < len(argv):
        arg = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if arg == "--input":
            state["input"] = nxt
            i += 2
        elif arg == "--input-format":
            state["input_format"] = nxt
            i += 2
        elif arg == "--output":
            state["output"] = nxt
            i += 2
        elif arg == "--output-format":
            state["output_format"] = nxt
            i += 2
        elif arg == "--artifacts-dir":
            state["artifacts_dir"] = nxt
            i += 2
        elif arg == "--network":
            state["network"] = nxt
            i += 2
        elif arg == "--function":
            state["function"] = nxt
            i += 2
        elif arg == "--script-hex":
            state["script_hex"] = nxt
            i += 2
        elif arg == "--arg":
            state["args"].append(nxt)
            i += 2
        elif arg == "--type-arg":
            state["type_args"].append(nxt)
            i += 2
        elif arg == "--secondary-signer-address":
            state["secondary_signer_addresses"].append(nxt)
            i += 2
        elif arg == "--secondary-private-key":
            state["secondary_private_keys"].append(nxt)
            i += 2
        elif arg == "--secondary-public-key":
            state["secondary_public_keys"].append(nxt)
            i += 2
        elif arg == "--sender-address":
            state["sender_address"] = nxt
            i += 2
        elif arg == "--private-key":
            state["private_key"] = nxt
            i += 2
        elif arg == "--private-key-env":
            state["private_key_env"] = nxt
            i += 2
        elif arg == "--private-key-file":
            state["private_key_file"] = nxt
            i += 2
        elif arg == "--public-key":
            state["public_key"] = nxt
            i += 2
        elif arg == "--public-key-env":
            state["public_key_env"] = nxt
            i += 2
        elif arg == "--public-key-file":
            state["public_key_file"] = nxt
            i += 2
        elif arg == "--profile":
            state["profile"] = nxt
            i += 2
        elif arg == "--hash":
            state["hash"] = nxt
            i += 2
        elif arg == "--fullnode":
            state["fullnode"] = nxt
            i += 2
        elif arg == "--multisig-action":
            state["multisig_action"] = nxt
            i += 2
        elif arg == "--multisig-address":
            state["multisig_address"] = nxt
            i += 2
        elif arg == "--multisig-owner-address":
            state["multisig_owner_addresses"].append(nxt)
            i += 2
        elif arg == "--multisig-threshold":
            state["multisig_threshold"] = int(nxt)
            i += 2
        elif arg == "--multisig-sequence":
            state["multisig_sequence"] = int(nxt)
            i += 2
        elif arg == "--multisig-hash-only":
            state["multisig_hash_only"] = True
            i += 1
        elif arg == "--multi-key-public-key":
            state["multi_key_public_keys"].append(nxt)
            i += 2
        elif arg == "--multi-key-signer":
            state["multi_key_signers"].append(nxt)
            i += 2
        elif arg == "--multi-key-threshold":
            state["multi_key_threshold"] = int(nxt)
            i += 2
        elif arg == "--sdk-mode":
            state["sdk_mode"] = nxt or "mock"
            i += 2
        elif arg == "--no-sign":
            state["no_sign"] = True
            i += 1
        elif arg == "--no-abi":
            state["abi_enabled"] = False
            i += 1
        elif arg == "--verbose":
            state["verbose"] = True
            i += 1
        elif arg == "--quiet":
            state["quiet"] = True
            i += 1
        else:
            raise ValueError(f"unknown argument: {arg}")
    return state


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        state = parse_cli(argv)
        input_format = detect_format(state["input"], state["input_format"], "json")
        file_input = load_input(state["input"], input_format)
        spec = {
            "network": state["network"] or file_input.get("network", "testnet"),
            "function": state["function"] or file_input.get("function", ""),
            "script_hex": state["script_hex"] or file_input.get("script_hex", ""),
            "sender_address": state["sender_address"] or file_input.get("sender_address", "0x0"),
            "args": state["args"] if state["args"] else list(file_input.get("args", [])),
            "type_args": state["type_args"] if state["type_args"] else list(file_input.get("type_args", [])),
            "secondary_signer_addresses": state["secondary_signer_addresses"]
            if state["secondary_signer_addresses"]
            else list(file_input.get("secondary_signer_addresses", [])),
            "abi_enabled": state["abi_enabled"] and file_input.get("abi_enabled", True),
            "no_sign": state["no_sign"] or file_input.get("no_sign", False),
            "hash": state["hash"] or file_input.get("hash", ""),
            "fullnode": state["fullnode"] or file_input.get("fullnode", ""),
            "multisig_action": state["multisig_action"] or file_input.get("multisig_action", ""),
            "multisig_address": state["multisig_address"] or file_input.get("multisig_address", ""),
            "multisig_owner_addresses": state["multisig_owner_addresses"]
            if state["multisig_owner_addresses"]
            else list(file_input.get("multisig_owner_addresses", [])),
            "multisig_threshold": state["multisig_threshold"]
            if state["multisig_threshold"] is not None
            else file_input.get("multisig_threshold", 0),
            "multisig_sequence": state["multisig_sequence"]
            if state["multisig_sequence"] is not None
            else file_input.get("multisig_sequence", 0),
            "multisig_hash_only": state["multisig_hash_only"] or bool(file_input.get("multisig_hash_only", False)),
            "multi_key_public_keys": state["multi_key_public_keys"]
            if state["multi_key_public_keys"]
            else list(file_input.get("multi_key_public_keys", [])),
            "multi_key_signers": state["multi_key_signers"]
            if state["multi_key_signers"]
            else list(file_input.get("multi_key_signers", [])),
            "multi_key_threshold": state["multi_key_threshold"]
            if state["multi_key_threshold"] is not None
            else file_input.get("multi_key_threshold", 0),
        }
        if state["action"] != "inspect" and not spec["function"] and not spec["script_hex"] and state["txn_type"] != "multi-sig":
            return fail("missing function")
        if state["txn_type"] not in {"single", "multi-agent", "multi-key", "multi-sig"}:
            return fail(f"unsupported txn type: {state['txn_type']}")
        if state["txn_type"] == "multi-agent" and not spec["secondary_signer_addresses"]:
            return fail("multi-agent requires --secondary-signer-address")
        if state["txn_type"] == "multi-key":
            if int(spec["multi_key_threshold"]) < 1:
                return fail("multi-key requires --multi-key-threshold >= 1")
            if len(spec["multi_key_public_keys"]) < int(spec["multi_key_threshold"]):
                return fail("multi-key threshold cannot exceed public key count")
        if state["txn_type"] == "multi-sig":
            action = spec["multisig_action"]
            if action not in {"create-account", "propose", "approve", "execute"}:
                return fail("multi-sig requires --multisig-action")
            if action == "create-account":
                if int(spec["multisig_threshold"]) < 1:
                    return fail("multi-sig create-account requires --multisig-threshold >= 1")
                if len(spec["multisig_owner_addresses"]) < 1:
                    return fail("multi-sig create-account requires --multisig-owner-address")
            else:
                if not spec["multisig_address"]:
                    return fail(f"multi-sig {action} requires --multisig-address")
            if action == "approve" and int(spec["multisig_sequence"]) < 1:
                return fail("multi-sig approve requires --multisig-sequence")
        if not spec["abi_enabled"]:
            for item in spec["args"]:
                if str(item).startswith("raw:"):
                    return fail("raw:<hex> requires ABI mode")
        mode = sign_mode(state)
        if state["action"] in {"submit"} and mode == "none" and state["sdk_mode"] != "mock":
            return fail("submit requires signing material")
        parsed_args = [parse_arg(item) for item in spec["args"]]
        seed = "|".join(
            [
                state["action"],
                state["txn_type"],
                spec["network"],
                spec["function"],
                spec["sender_address"],
                ",".join(spec["args"]),
                ",".join(spec["type_args"]),
                str(spec["abi_enabled"]).lower(),
                mode,
            ]
        )
        digest = stable_digest(seed)
        payload = {
            "cli": "aptx",
            "implementation": "python",
            "sdk_backend": "aptos-python-sdk",
            "sdk_mode": state["sdk_mode"],
            "action": state["action"],
            "txn_type": state["txn_type"],
            "abi_enabled": spec["abi_enabled"],
            "input": {
                "network": spec["network"],
                "function": spec["function"],
                "script_hex": spec["script_hex"],
                "sender_address": spec["sender_address"],
                "args": spec["args"],
                "parsed_args": parsed_args,
                "type_args": spec["type_args"],
                "secondary_signer_addresses": spec["secondary_signer_addresses"],
                "hash": spec["hash"],
                "fullnode": spec["fullnode"],
                "multisig_action": spec["multisig_action"],
                "multisig_address": spec["multisig_address"],
                "multisig_owner_addresses": spec["multisig_owner_addresses"],
                "multisig_threshold": spec["multisig_threshold"],
                "multisig_sequence": spec["multisig_sequence"],
                "multisig_hash_only": spec["multisig_hash_only"],
                "multi_key_public_keys": spec["multi_key_public_keys"],
                "multi_key_signers": spec["multi_key_signers"],
                "multi_key_threshold": spec["multi_key_threshold"],
            },
            "signing": {
                "mode": mode,
                "provided": mode != "none",
                "redacted": True,
            },
            "result": {
                "mode": "simulate" if state["action"] == "run" and spec["no_sign"] else state["action"],
                "success": True,
                "vm_status": "Executed successfully",
                "tx_hash": f"0x{digest[:32]}",
                "gas_used": len(spec["function"]) + len(spec["args"]) * 111 + len(spec["type_args"]) * 37,
                "notes": ["mock backend active", "sdk integration point reserved"]
                if state["sdk_mode"] == "mock"
                else ["sdk backend requested"],
            },
        }
        artifacts_dir = state["artifacts_dir"]
        if artifacts_dir:
            Path(artifacts_dir).mkdir(parents=True, exist_ok=True)
            (Path(artifacts_dir) / "result.json").write_text(json.dumps(payload, indent=2))

        output_format = detect_format(state["output"], state["output_format"], "json" if state["output"] else "table")
        if output_format == "json":
            rendered = json.dumps(payload, indent=2)
        elif output_format == "yaml":
            rendered = render_yaml(payload)
        elif output_format == "ascii":
            rendered = render_ascii(payload)
        else:
            rendered = render_table(payload)

        if state["output"] and state["output"] != "-":
            Path(state["output"]).write_text(rendered + "\n")
        elif not state["quiet"]:
            print(rendered)
        return 0
    except Exception as exc:
        return fail(str(exc))
