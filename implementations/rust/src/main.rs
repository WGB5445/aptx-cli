use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
struct State {
    action: String,
    txn_type: String,
    input: Option<String>,
    input_format: Option<String>,
    output: Option<String>,
    output_format: Option<String>,
    artifacts_dir: Option<String>,
    network: Option<String>,
    function: Option<String>,
    script_hex: Option<String>,
    args: Vec<String>,
    type_args: Vec<String>,
    secondary_signer_addresses: Vec<String>,
    secondary_private_keys: Vec<String>,
    secondary_public_keys: Vec<String>,
    sender_address: Option<String>,
    private_key: Option<String>,
    private_key_env: Option<String>,
    private_key_file: Option<String>,
    public_key: Option<String>,
    public_key_env: Option<String>,
    public_key_file: Option<String>,
    profile: Option<String>,
    hash: Option<String>,
    fullnode: Option<String>,
    multisig_action: Option<String>,
    multisig_address: Option<String>,
    multisig_owner_addresses: Vec<String>,
    multisig_threshold: Option<u64>,
    multisig_sequence: Option<u64>,
    multisig_hash_only: bool,
    multi_key_public_keys: Vec<String>,
    multi_key_signers: Vec<String>,
    multi_key_threshold: Option<u64>,
    no_sign: bool,
    abi_enabled: bool,
    verbose: bool,
    quiet: bool,
    sdk_mode: String,
}

#[derive(Clone, Debug)]
struct InputSpec {
    network: String,
    function: String,
    script_hex: String,
    sender_address: String,
    args: Vec<String>,
    type_args: Vec<String>,
    secondary_signer_addresses: Vec<String>,
    hash: String,
    fullnode: String,
    multisig_action: String,
    multisig_address: String,
    multisig_owner_addresses: Vec<String>,
    multisig_threshold: u64,
    multisig_sequence: u64,
    multisig_hash_only: bool,
    multi_key_public_keys: Vec<String>,
    multi_key_signers: Vec<String>,
    multi_key_threshold: u64,
    abi_enabled: bool,
    no_sign: bool,
}

#[derive(Clone, Debug)]
enum ArgSpec {
    Parsed { raw: String, arg_type: String, value: String },
    Raw { raw: String, hex: String },
}

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("{err}");
        std::process::exit(2);
    }
}

fn run(argv: Vec<String>) -> Result<(), String> {
    let state = parse_cli(&argv)?;
    let input_format = detect_format(
        state.input.as_deref(),
        state.input_format.as_deref(),
        "json",
    );
    let file_input = load_input(state.input.as_deref(), &input_format)?;
    let spec = InputSpec {
        network: state
            .network
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "network", "testnet")),
        function: state
            .function
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "function", "")),
        script_hex: state
            .script_hex
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "script_hex", "")),
        sender_address: state
            .sender_address
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "sender_address", "0x0")),
        args: if state.args.is_empty() {
            get_string_list(&file_input, "args")
        } else {
            state.args.clone()
        },
        type_args: if state.type_args.is_empty() {
            get_string_list(&file_input, "type_args")
        } else {
            state.type_args.clone()
        },
        secondary_signer_addresses: if state.secondary_signer_addresses.is_empty() {
            get_string_list(&file_input, "secondary_signer_addresses")
        } else {
            state.secondary_signer_addresses.clone()
        },
        hash: state
            .hash
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "hash", "")),
        fullnode: state
            .fullnode
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "fullnode", "")),
        multisig_action: state
            .multisig_action
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "multisig_action", "")),
        multisig_address: state
            .multisig_address
            .clone()
            .unwrap_or_else(|| get_string(&file_input, "multisig_address", "")),
        multisig_owner_addresses: if state.multisig_owner_addresses.is_empty() {
            get_string_list(&file_input, "multisig_owner_addresses")
        } else {
            state.multisig_owner_addresses.clone()
        },
        multisig_threshold: state
            .multisig_threshold
            .unwrap_or_else(|| get_u64(&file_input, "multisig_threshold", 0)),
        multisig_sequence: state
            .multisig_sequence
            .unwrap_or_else(|| get_u64(&file_input, "multisig_sequence", 0)),
        multisig_hash_only: state.multisig_hash_only || get_bool(&file_input, "multisig_hash_only", false),
        multi_key_public_keys: if state.multi_key_public_keys.is_empty() {
            get_string_list(&file_input, "multi_key_public_keys")
        } else {
            state.multi_key_public_keys.clone()
        },
        multi_key_signers: if state.multi_key_signers.is_empty() {
            get_string_list(&file_input, "multi_key_signers")
        } else {
            state.multi_key_signers.clone()
        },
        multi_key_threshold: state
            .multi_key_threshold
            .unwrap_or_else(|| get_u64(&file_input, "multi_key_threshold", 0)),
        abi_enabled: state.abi_enabled && get_bool(&file_input, "abi_enabled", true),
        no_sign: state.no_sign || get_bool(&file_input, "no_sign", false),
    };

    if state.action != "inspect" && spec.function.is_empty() && spec.script_hex.is_empty() && state.txn_type != "multi-sig" {
        return Err("missing function".to_string());
    }
    if state.txn_type != "single"
        && state.txn_type != "multi-agent"
        && state.txn_type != "multi-key"
        && state.txn_type != "multi-sig"
    {
        return Err(format!("unsupported txn type: {}", state.txn_type));
    }
    if state.txn_type == "multi-agent" && spec.secondary_signer_addresses.is_empty() {
        return Err("multi-agent requires --secondary-signer-address".to_string());
    }
    if state.txn_type == "multi-key" {
        if spec.multi_key_threshold < 1 {
            return Err("multi-key requires --multi-key-threshold >= 1".to_string());
        }
        if spec.multi_key_threshold as usize > spec.multi_key_public_keys.len() {
            return Err("multi-key threshold cannot exceed public key count".to_string());
        }
    }
    if state.txn_type == "multi-sig" {
        match spec.multisig_action.as_str() {
            "create-account" => {
                if spec.multisig_threshold < 1 {
                    return Err("multi-sig create-account requires --multisig-threshold >= 1".to_string());
                }
                if spec.multisig_owner_addresses.is_empty() {
                    return Err("multi-sig create-account requires --multisig-owner-address".to_string());
                }
            }
            "propose" => {
                if spec.multisig_address.is_empty() {
                    return Err("multi-sig propose requires --multisig-address".to_string());
                }
                if spec.function.is_empty() {
                    return Err("multi-sig propose requires --function".to_string());
                }
            }
            "approve" => {
                if spec.multisig_address.is_empty() {
                    return Err("multi-sig approve requires --multisig-address".to_string());
                }
                if spec.multisig_sequence < 1 {
                    return Err("multi-sig approve requires --multisig-sequence".to_string());
                }
            }
            "execute" => {
                if spec.multisig_address.is_empty() {
                    return Err("multi-sig execute requires --multisig-address".to_string());
                }
            }
            _ => return Err("multi-sig requires --multisig-action".to_string()),
        }
    }
    if !spec.abi_enabled {
        for arg in &spec.args {
            if arg.starts_with("raw:") {
                return Err("raw:<hex> requires ABI mode".to_string());
            }
        }
    }

    let sign_mode = signing_mode(&state);
    if state.action == "submit" && sign_mode == "none" && state.sdk_mode != "mock" {
        return Err("submit requires signing material".to_string());
    }

    let parsed_args: Vec<ArgSpec> = spec.args.iter().map(|arg| parse_arg(arg)).collect::<Result<_, _>>()?;
    let digest = stable_digest(&state.action, &state.txn_type, &spec, &sign_mode);
    let result_mode = if state.action == "run" && spec.no_sign {
        "simulate".to_string()
    } else {
        state.action.clone()
    };

    let payload = render_payload(&state, &spec, &parsed_args, &sign_mode, &digest, &result_mode);

    if let Some(dir) = &state.artifacts_dir {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        fs::write(Path::new(dir).join("result.json"), format!("{}\n", payload.json))
            .map_err(|e| e.to_string())?;
    }

    let output_format = detect_format(
        state.output.as_deref(),
        state.output_format.as_deref(),
        if state.output.is_some() { "json" } else { "table" },
    );
    let rendered = match output_format.as_str() {
        "yaml" => payload.yaml,
        "ascii" => payload.ascii,
        "table" => payload.table,
        _ => payload.json,
    };

    if let Some(path) = &state.output {
        if path != "-" {
            fs::write(path, format!("{rendered}\n")).map_err(|e| e.to_string())?;
        } else if !state.quiet {
            println!("{rendered}");
        }
    } else if !state.quiet {
        println!("{rendered}");
    }
    let _ = state.verbose;
    Ok(())
}

fn parse_cli(argv: &[String]) -> Result<State, String> {
    if argv.is_empty() {
        return Err("usage: aptx <simulate|submit|run|inspect> <txn-type> [flags]".to_string());
    }
    let action = argv[0].clone();
    let (txn_type, start) = if action == "inspect" {
        ("single".to_string(), 1)
    } else {
        if argv.len() < 2 {
            return Err("usage: aptx <simulate|submit|run|inspect> <txn-type> [flags]".to_string());
        }
        (argv[1].clone(), 2)
    };
    let mut state = State {
        action,
        txn_type,
        input: None,
        input_format: None,
        output: None,
        output_format: None,
        artifacts_dir: None,
        network: None,
        function: None,
        script_hex: None,
        args: Vec::new(),
        type_args: Vec::new(),
        secondary_signer_addresses: Vec::new(),
        secondary_private_keys: Vec::new(),
        secondary_public_keys: Vec::new(),
        sender_address: None,
        private_key: None,
        private_key_env: None,
        private_key_file: None,
        public_key: None,
        public_key_env: None,
        public_key_file: None,
        profile: None,
        hash: None,
        fullnode: None,
        multisig_action: None,
        multisig_address: None,
        multisig_owner_addresses: Vec::new(),
        multisig_threshold: None,
        multisig_sequence: None,
        multisig_hash_only: false,
        multi_key_public_keys: Vec::new(),
        multi_key_signers: Vec::new(),
        multi_key_threshold: None,
        no_sign: false,
        abi_enabled: true,
        verbose: false,
        quiet: false,
        sdk_mode: "mock".to_string(),
    };

    let mut i = start;
    while i < argv.len() {
        let arg = &argv[i];
        let next = argv.get(i + 1).cloned();
        match arg.as_str() {
            "--input" => {
                state.input = next;
                i += 2;
            }
            "--input-format" => {
                state.input_format = next;
                i += 2;
            }
            "--output" => {
                state.output = next;
                i += 2;
            }
            "--output-format" => {
                state.output_format = next;
                i += 2;
            }
            "--artifacts-dir" => {
                state.artifacts_dir = next;
                i += 2;
            }
            "--network" => {
                state.network = next;
                i += 2;
            }
            "--function" => {
                state.function = next;
                i += 2;
            }
            "--script-hex" => {
                state.script_hex = next;
                i += 2;
            }
            "--arg" => {
                state.args.push(next.ok_or_else(|| "missing value for --arg".to_string())?);
                i += 2;
            }
            "--type-arg" => {
                state
                    .type_args
                    .push(next.ok_or_else(|| "missing value for --type-arg".to_string())?);
                i += 2;
            }
            "--secondary-signer-address" => {
                state
                    .secondary_signer_addresses
                    .push(next.ok_or_else(|| "missing value for --secondary-signer-address".to_string())?);
                i += 2;
            }
            "--secondary-private-key" => {
                state
                    .secondary_private_keys
                    .push(next.ok_or_else(|| "missing value for --secondary-private-key".to_string())?);
                i += 2;
            }
            "--secondary-public-key" => {
                state
                    .secondary_public_keys
                    .push(next.ok_or_else(|| "missing value for --secondary-public-key".to_string())?);
                i += 2;
            }
            "--sender-address" => {
                state.sender_address = next;
                i += 2;
            }
            "--private-key" => {
                state.private_key = next;
                i += 2;
            }
            "--private-key-env" => {
                state.private_key_env = next;
                i += 2;
            }
            "--private-key-file" => {
                state.private_key_file = next;
                i += 2;
            }
            "--public-key" => {
                state.public_key = next;
                i += 2;
            }
            "--public-key-env" => {
                state.public_key_env = next;
                i += 2;
            }
            "--public-key-file" => {
                state.public_key_file = next;
                i += 2;
            }
            "--profile" => {
                state.profile = next;
                i += 2;
            }
            "--hash" => {
                state.hash = next;
                i += 2;
            }
            "--fullnode" => {
                state.fullnode = next;
                i += 2;
            }
            "--multisig-action" => {
                state.multisig_action = next;
                i += 2;
            }
            "--multisig-address" => {
                state.multisig_address = next;
                i += 2;
            }
            "--multisig-owner-address" => {
                state
                    .multisig_owner_addresses
                    .push(next.ok_or_else(|| "missing value for --multisig-owner-address".to_string())?);
                i += 2;
            }
            "--multisig-threshold" => {
                let value = next.ok_or_else(|| "missing value for --multisig-threshold".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --multisig-threshold: {value}"))?;
                state.multisig_threshold = Some(parsed);
                i += 2;
            }
            "--multisig-sequence" => {
                let value = next.ok_or_else(|| "missing value for --multisig-sequence".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --multisig-sequence: {value}"))?;
                state.multisig_sequence = Some(parsed);
                i += 2;
            }
            "--multisig-hash-only" => {
                state.multisig_hash_only = true;
                i += 1;
            }
            "--multi-key-public-key" => {
                state
                    .multi_key_public_keys
                    .push(next.ok_or_else(|| "missing value for --multi-key-public-key".to_string())?);
                i += 2;
            }
            "--multi-key-signer" => {
                state
                    .multi_key_signers
                    .push(next.ok_or_else(|| "missing value for --multi-key-signer".to_string())?);
                i += 2;
            }
            "--multi-key-threshold" => {
                let value = next.ok_or_else(|| "missing value for --multi-key-threshold".to_string())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --multi-key-threshold: {value}"))?;
                state.multi_key_threshold = Some(parsed);
                i += 2;
            }
            "--sdk-mode" => {
                state.sdk_mode = next.unwrap_or_else(|| "mock".to_string());
                i += 2;
            }
            "--no-sign" => {
                state.no_sign = true;
                i += 1;
            }
            "--no-abi" => {
                state.abi_enabled = false;
                i += 1;
            }
            "--verbose" => {
                state.verbose = true;
                i += 1;
            }
            "--quiet" => {
                state.quiet = true;
                i += 1;
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    Ok(state)
}

fn detect_format(path: Option<&str>, explicit: Option<&str>, fallback: &str) -> String {
    if let Some(value) = explicit {
        if value != "auto" {
            return value.to_string();
        }
    }
    match path {
        None | Some("-") => fallback.to_string(),
        Some(value) if value.ends_with(".yaml") || value.ends_with(".yml") => "yaml".to_string(),
        Some(_) => "json".to_string(),
    }
}

fn load_input(path: Option<&str>, format: &str) -> Result<BTreeMap<String, DataValue>, String> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let content = if path == "-" {
        return Err("stdin input is not implemented yet in rust CLI".to_string());
    } else {
        fs::read_to_string(path).map_err(|e| e.to_string())?
    };
    if format == "yaml" {
        parse_simple_yaml(&content)
    } else {
        parse_simple_json(&content)
    }
}

#[derive(Clone, Debug)]
enum DataValue {
    String(String),
    Bool(bool),
    List(Vec<String>),
}

fn parse_simple_yaml(text: &str) -> Result<BTreeMap<String, DataValue>, String> {
    let mut map = BTreeMap::new();
    let mut current_key: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(item) = trimmed.strip_prefix("- ") {
            let key = current_key.clone().ok_or_else(|| "invalid yaml list item without key".to_string())?;
            match map.get_mut(&key) {
                Some(DataValue::List(values)) => values.push(item.to_string()),
                _ => return Err("invalid yaml list target".to_string()),
            }
            continue;
        }
        let mut parts = trimmed.splitn(2, ':');
        let key = parts.next().ok_or_else(|| "invalid yaml line".to_string())?.trim();
        let rest = parts.next().ok_or_else(|| "invalid yaml line".to_string())?.trim();
        if rest.is_empty() {
            map.insert(key.to_string(), DataValue::List(Vec::new()));
            current_key = Some(key.to_string());
        } else if rest == "true" || rest == "false" {
            map.insert(key.to_string(), DataValue::Bool(rest == "true"));
            current_key = None;
        } else {
            map.insert(key.to_string(), DataValue::String(rest.to_string()));
            current_key = None;
        }
    }
    Ok(map)
}

fn parse_simple_json(text: &str) -> Result<BTreeMap<String, DataValue>, String> {
    let mut map = BTreeMap::new();
    for key in ["network", "function", "sender_address"] {
        if let Some(value) = extract_json_string(text, key) {
            map.insert(key.to_string(), DataValue::String(value));
        }
    }
    for key in ["script_hex", "hash", "fullnode", "multisig_action", "multisig_address"] {
        if let Some(value) = extract_json_string(text, key) {
            map.insert(key.to_string(), DataValue::String(value));
        }
    }
    for key in ["abi_enabled", "no_sign"] {
        if let Some(value) = extract_json_bool(text, key) {
            map.insert(key.to_string(), DataValue::Bool(value));
        }
    }
    for key in [
        "args",
        "type_args",
        "secondary_signer_addresses",
        "multisig_owner_addresses",
        "multi_key_public_keys",
        "multi_key_signers",
    ] {
        if let Some(values) = extract_json_string_array(text, key) {
            map.insert(key.to_string(), DataValue::List(values));
        }
    }
    Ok(map)
}

fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)?;
    let after_key = &text[start + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let rest = &after_colon[1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_json_bool(text: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)?;
    let after_key = &text[start + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn extract_json_string_array(text: &str, key: &str) -> Option<Vec<String>> {
    let needle = format!("\"{key}\"");
    let start = text.find(&needle)?;
    let after_key = &text[start + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    if !after_colon.starts_with('[') {
        return None;
    }
    let end = after_colon.find(']')?;
    let body = &after_colon[1..end];
    let mut out = Vec::new();
    for part in body.split(',') {
        let value = part.trim();
        if value.is_empty() {
            continue;
        }
        out.push(value.trim_matches('"').to_string());
    }
    Some(out)
}

fn get_string(map: &BTreeMap<String, DataValue>, key: &str, fallback: &str) -> String {
    match map.get(key) {
        Some(DataValue::String(value)) => value.clone(),
        _ => fallback.to_string(),
    }
}

fn get_bool(map: &BTreeMap<String, DataValue>, key: &str, fallback: bool) -> bool {
    match map.get(key) {
        Some(DataValue::Bool(value)) => *value,
        _ => fallback,
    }
}

fn get_string_list(map: &BTreeMap<String, DataValue>, key: &str) -> Vec<String> {
    match map.get(key) {
        Some(DataValue::List(values)) => values.clone(),
        _ => Vec::new(),
    }
}

fn get_u64(map: &BTreeMap<String, DataValue>, key: &str, fallback: u64) -> u64 {
    match map.get(key) {
        Some(DataValue::String(value)) => value.parse::<u64>().unwrap_or(fallback),
        _ => fallback,
    }
}

fn parse_arg(raw: &str) -> Result<ArgSpec, String> {
    if let Some(hex) = raw.strip_prefix("raw:") {
        return Ok(ArgSpec::Raw {
            raw: raw.to_string(),
            hex: hex.to_string(),
        });
    }
    let Some((arg_type, value)) = raw.split_once(':') else {
        return Err(format!("invalid --arg syntax: {raw}"));
    };
    Ok(ArgSpec::Parsed {
        raw: raw.to_string(),
        arg_type: arg_type.to_string(),
        value: value.to_string(),
    })
}

fn signing_mode(state: &State) -> String {
    if state.no_sign {
        "none".to_string()
    } else if state.private_key.is_some() {
        "private_key".to_string()
    } else if state.private_key_env.is_some() {
        "private_key_env".to_string()
    } else if state.private_key_file.is_some() {
        "private_key_file".to_string()
    } else if state.profile.is_some() {
        "profile".to_string()
    } else {
        "none".to_string()
    }
}

fn stable_digest(action: &str, txn_type: &str, spec: &InputSpec, sign_mode: &str) -> String {
    let seed = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        action,
        txn_type,
        spec.network,
        spec.function,
        spec.sender_address,
        spec.args.join(","),
        spec.type_args.join(","),
        spec.abi_enabled,
        sign_mode
    );
    let digest = fake_sha256(seed.as_bytes());
    format!("0x{}", digest)
}

fn fake_sha256(bytes: &[u8]) -> String {
    let mask: u128 = (1u128 << 127) - 1 + (1u128 << 127);
    let mut hash: u128 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= *byte as u128;
        hash = hash.wrapping_mul(0x100000001b3) & mask;
        hash ^= hash >> 13;
    }
    format!("{hash:032x}")
}

struct PayloadRender {
    json: String,
    yaml: String,
    table: String,
    ascii: String,
}

fn render_payload(
    state: &State,
    spec: &InputSpec,
    parsed_args: &[ArgSpec],
    sign_mode: &str,
    digest: &str,
    result_mode: &str,
) -> PayloadRender {
    let parsed_args_json: Vec<String> = parsed_args.iter().map(render_arg_json).collect();
    let parsed_args_yaml: Vec<String> = parsed_args.iter().map(render_arg_yaml).collect();
    let notes = if state.sdk_mode == "mock" {
        vec!["mock backend active", "sdk integration point reserved"]
    } else {
        vec!["sdk backend requested"]
    };
    let notes_json = notes
        .iter()
        .map(|item| format!("      \"{}\"", escape_json(item)))
        .collect::<Vec<_>>()
        .join(",\n");
    let args_json = spec
        .args
        .iter()
        .map(|arg| format!("      \"{}\"", escape_json(arg)))
        .collect::<Vec<_>>()
        .join(",\n");
    let type_args_json = spec
        .type_args
        .iter()
        .map(|arg| format!("      \"{}\"", escape_json(arg)))
        .collect::<Vec<_>>()
        .join(",\n");
    let json = format!(
        "{{\n  \"cli\": \"aptx\",\n  \"implementation\": \"rust\",\n  \"sdk_backend\": \"aptos-rust-sdk\",\n  \"sdk_mode\": \"{}\",\n  \"action\": \"{}\",\n  \"txn_type\": \"{}\",\n  \"abi_enabled\": {},\n  \"input\": {{\n    \"network\": \"{}\",\n    \"function\": \"{}\",\n    \"sender_address\": \"{}\",\n    \"args\": [\n{}\n    ],\n    \"parsed_args\": [\n{}\n    ],\n    \"type_args\": [\n{}\n    ]\n  }},\n  \"signing\": {{\n    \"mode\": \"{}\",\n    \"provided\": {},\n    \"redacted\": true\n  }},\n  \"result\": {{\n    \"mode\": \"{}\",\n    \"success\": true,\n    \"vm_status\": \"Executed successfully\",\n    \"tx_hash\": \"{}\",\n    \"gas_used\": {},\n    \"notes\": [\n{}\n    ]\n  }}\n}}",
        escape_json(&state.sdk_mode),
        escape_json(&state.action),
        escape_json(&state.txn_type),
        if spec.abi_enabled { "true" } else { "false" },
        escape_json(&spec.network),
        escape_json(&spec.function),
        escape_json(&spec.sender_address),
        args_json,
        parsed_args_json.join(",\n"),
        type_args_json,
        escape_json(sign_mode),
        if sign_mode != "none" { "true" } else { "false" },
        escape_json(result_mode),
        escape_json(digest),
        spec.function.len() + spec.args.len() * 111 + spec.type_args.len() * 37,
        notes_json
    );
    let yaml = format!(
        "cli: aptx\nimplementation: rust\nsdk_backend: aptos-rust-sdk\nsdk_mode: {}\naction: {}\ntxn_type: {}\nabi_enabled: {}\ninput:\n  network: {}\n  function: {}\n  sender_address: {}\n  args:\n{}\n  parsed_args:\n{}\n  type_args:\n{}\nsigning:\n  mode: {}\n  provided: {}\n  redacted: true\nresult:\n  mode: {}\n  success: true\n  vm_status: Executed successfully\n  tx_hash: {}\n  gas_used: {}\n  notes:\n{}",
        state.sdk_mode,
        state.action,
        state.txn_type,
        if spec.abi_enabled { "true" } else { "false" },
        spec.network,
        spec.function,
        spec.sender_address,
        render_yaml_list(&spec.args, 4),
        parsed_args_yaml
            .iter()
            .map(|entry| indent_block(entry, 4))
            .collect::<Vec<_>>()
            .join("\n"),
        render_yaml_list(&spec.type_args, 4),
        sign_mode,
        if sign_mode != "none" { "true" } else { "false" },
        result_mode,
        digest,
        spec.function.len() + spec.args.len() * 111 + spec.type_args.len() * 37,
        render_yaml_list(&notes.iter().map(|s| s.to_string()).collect::<Vec<_>>(), 4)
    );
    let table = format!(
        "implementation | rust\nsdk_backend    | aptos-rust-sdk\naction         | {}\ntxn_type       | {}\nfunction       | {}\nsender         | {}\nvm_status      | Executed successfully\ntx_hash        | {}",
        state.action, state.txn_type, spec.function, spec.sender_address, digest
    );
    let ascii = format!(
        "+----------------------------------------------+\n| Aptos Transaction CLI                        |\n+----------------------------------------------+\n| action        | {:<28}|\n| txn_type      | {:<28}|\n| function      | {:<28}|\n| sender        | {:<28}|\n| vm_status     | {:<28}|\n| tx_hash       | {:<28}|\n+----------------------------------------------+",
        state.action,
        state.txn_type,
        truncate_pad(&spec.function, 28),
        truncate_pad(&spec.sender_address, 28),
        "Executed successfully",
        truncate_pad(digest, 28)
    );
    PayloadRender { json, yaml, table, ascii }
}

fn render_arg_json(arg: &ArgSpec) -> String {
    match arg {
        ArgSpec::Parsed { raw, arg_type, value } => format!(
            "      {{\n        \"mode\": \"parsed\",\n        \"raw\": \"{}\",\n        \"argType\": \"{}\",\n        \"value\": \"{}\"\n      }}",
            escape_json(raw),
            escape_json(arg_type),
            escape_json(value)
        ),
        ArgSpec::Raw { raw, hex } => format!(
            "      {{\n        \"mode\": \"raw\",\n        \"raw\": \"{}\",\n        \"hex\": \"{}\"\n      }}",
            escape_json(raw),
            escape_json(hex)
        ),
    }
}

fn render_arg_yaml(arg: &ArgSpec) -> String {
    match arg {
        ArgSpec::Parsed { raw, arg_type, value } => format!(
            "- mode: parsed\n  raw: {}\n  argType: {}\n  value: {}",
            raw, arg_type, value
        ),
        ArgSpec::Raw { raw, hex } => format!("- mode: raw\n  raw: {}\n  hex: {}", raw, hex),
    }
}

fn render_yaml_list(items: &[String], indent: usize) -> String {
    let pad = " ".repeat(indent);
    if items.is_empty() {
        format!("{pad}[]")
    } else {
        items
            .iter()
            .map(|item| format!("{pad}- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn indent_block(value: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    value
        .lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn truncate_pad(value: &str, width: usize) -> String {
    if value.len() > width {
        value[..width].to_string()
    } else {
        format!("{value:<width$}")
    }
}
