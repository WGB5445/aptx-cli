# Keyless 跨 SDK 实现研究

## 当前状态

| SDK | Keyless 支持 | 状态 |
|-----|-------------|------|
| TypeScript (`@aptos-labs/ts-sdk`) | ✅ 完整 | 生产就绪，唯一全功能实现 |
| Rust (`aptos-core/types`) | ✅ 类型 + 链上验证 | 完整的类型定义和 Groth16 验证器 |
| Rust (`aptos-rust-sdk`) | ⚠️ 部分 | `keyless` feature 声明了但没有 crypto 实现 |
| Python | ❌ | 无 |
| Go | ❌ | 无 |
| WASM 独立包 | ❌ | 无 |
| FFI 包 | ❌ | 无 |

## Keyless 工作原理

```
用户登录 OIDC → 得到 JWT
JWT.nonce = Poseidon(EPK, expiry, blinder)       # EPK = 临时 Ed25519 公钥

Pepper Service  →  pepper (31 bytes, VUF 派生)
Prover Service  →  Groth16 证明 (ZK-proof)
                   证明内容: "我持有一个来自已知 OIDC 提供商的合法 JWT，
                              且该 JWT 的 nonce 承诺了这个 EPK"

链上验证:
  1. 验证 training wheels 签名 (防 DoS)
  2. 验证 Groth16 证明 (BN254 曲线)
  3. 验证 EPK 未过期
  4. 验证临时 Ed25519 签名
```

**关键分离点**: Groth16 **证明生成** 必须走服务调用（prover service）；
Groth16 **验证** 可以在客户端完成。

## Rust 可行性

`aptos-core/types/src/keyless/` 已有完整实现：
- `groth16_sig.rs` — `Groth16Proof` (ark-bn254)
- `bn254_circom.rs` — BN254 G1/G2 操作
- `mod.rs` — `KeylessSignature`, `KeylessPublicKey`, `Pepper`, `IdCommitment`

关键依赖：`ark-bn254`, `ark-ff`, `ark-groth16`, `ark-ec`（均支持 `no_std`）

### 提取策略

不要依赖整个 `aptos-core`（过重）。新建 `aptos-keyless-core` crate，提取：

```toml
[dependencies]
ark-bn254 = { version = "0.4", default-features = false, features = ["curve"] }
ark-groth16 = { version = "0.4", default-features = false }
ark-ff = { version = "0.4", default-features = false }
ark-serialize = { version = "0.4", default-features = false }
poseidon-ark = "0.0.1"   # BN254-friendly Poseidon hash
sha3 = { version = "0.10", default-features = false }
```

暴露的能力：
- `derive_address(iss, uid_key, uid_val, aud, pepper) -> [u8; 32]`
- `compute_id_commitment(aud, uid_val, uid_key, pepper) -> [u8; 32]`
- `compute_nonce(epk_bytes, expiry, blinder) -> String`
- BCS 序列化/反序列化所有 keyless 类型

## WASM 方案

### 证明生成 — 不应该在 WASM 中做

RapidSNARK（C++/Assembly，12x 性能优于 arkworks）无法编译到 WASM。
纯 arkworks 证明生成在 WASM 中会需要几分钟。

**正确架构**: 所有 SDK 都调用 prover service HTTP API。

### 链上验证 — 可行

arkworks 系列 crate 支持 `no_std` + WASM：

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
ark-bn254 = { version = "0.4", default-features = false }
ark-groth16 = { version = "0.4", default-features = false }
```

**需要解决**:
- 将 `SystemTime` 替换为 `js-sys::Date`（在 WASM 中 std time 不可用）
- 预估二进制大小：~3–5 MB（ark-bn254 是主要成本）
- 约 1 周工程量

### 暴露的 WASM API

```rust
#[wasm_bindgen]
pub fn derive_keyless_address(iss: &str, uid_key: &str, uid_val: &str, aud: &str, pepper: &[u8]) -> Vec<u8>

#[wasm_bindgen]
pub fn compute_nonce(epk_bytes: &[u8], expiry_secs: u64, blinder: &[u8]) -> String

#[wasm_bindgen]
pub fn bcs_encode_keyless_public_key(iss: &str, id_commitment: &[u8]) -> Vec<u8>
```

## FFI 方案

### C ABI 导出

```rust
// Cargo.toml: crate-type = ["cdylib"]
#[no_mangle]
pub extern "C" fn aptos_keyless_derive_address(
    iss: *const c_char,
    uid_key: *const c_char,
    uid_val: *const c_char,
    aud: *const c_char,
    pepper: *const u8, pepper_len: usize,
    out: *mut u8,       // caller-allocated 32 bytes
) -> i32  // 0 = ok
```

用 `cbindgen` 自动生成 C 头文件。

### 各语言绑定

| 语言 | 方案 | 复杂度 |
|------|------|--------|
| Python | `PyO3` + `maturin`（最优雅）或 `cffi` | ⭐⭐ |
| Go | `cgo` 或 `purego`（dlopen，避免 CGO_ENABLED=0 限制）| ⭐⭐⭐ |
| Node.js | `napi-rs`（自动类型转换）| ⭐⭐ |
| 其他 | Mozilla `UniFFI`（一份 UDL → 多语言绑定）| ⭐⭐ |

### PyO3 示例（Python）

```rust
use pyo3::prelude::*;

#[pyfunction]
fn derive_keyless_address(iss: &str, uid_key: &str, uid_val: &str, aud: &str, pepper: Vec<u8>) -> PyResult<Vec<u8>> {
    let addr = aptos_keyless_core::derive_address(iss, uid_key, uid_val, aud, &pepper)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(addr.to_vec())
}

#[pymodule]
fn aptos_keyless(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(derive_keyless_address, m)?)?;
    Ok(())
}
```

```python
import aptos_keyless
addr = aptos_keyless.derive_keyless_address(
    iss="https://accounts.google.com",
    uid_key="sub",
    uid_val="1234567890",
    aud="my-app-client-id",
    pepper=bytes(31),
)
```

### `purego` Go（无 CGO）

```go
import "github.com/ebitengine/purego"

func loadKeylessLib() {
    lib, _ := purego.Dlopen("libaptos_keyless.so", purego.RTLD_NOW)
    purego.RegisterLibFunc(&deriveAddress, lib, "aptos_keyless_derive_address")
}
```

## 推荐实施路径

```
Phase 1 (2–3 周):
  ├── 创建 aptos-keyless-core Rust crate（从 aptos-core/types 提取）
  ├── 功能: derive_address, compute_id_commitment, compute_nonce
  ├── 功能: BCS encode/decode for KeylessPublicKey, KeylessSignature
  └── 纯 Rust 单元测试（与 TS SDK 输出对比）

Phase 2 (WASM, 1 周):
  ├── wasm-bindgen 目标: 地址派生 + nonce 计算
  └── 发布到 npm 作为 @aptos-labs/keyless-wasm

Phase 3 (FFI, 2 周):
  ├── PyO3: aptos-keyless Python 包
  ├── purego/cgo: Go bindings
  └── 测试: 与 TS SDK 输出做交叉验证
```

## 不需要 Rust/WASM/FFI 的部分

| 操作 | 为什么不需要 | 应该怎么做 |
|------|------------|----------|
| 生成 Groth16 证明 | RapidSNARK 无法跨平台 | 调用 prover service HTTP API |
| 获取 pepper | 需要带 JWT 的 HTTP 请求 | 调用 pepper service |
| OIDC 登录 | 浏览器/平台相关 | 各语言自己处理 OAuth 流 |

## 结论

**短期最优方案**: 在各 SDK 中直接 HTTP 调用 prover/pepper service（和 TS SDK 一样），
并用纯语言自生态实现 BCS 序列化（已经有了）。

**中期**: 用 Phase 1 的 Rust crate 做跨 SDK BCS 和地址派生的一致性保障，
作为共享的黄金标准。

**WASM/FFI 是值得投资的**，但不是 keyless MVP 的前提。
