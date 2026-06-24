# Rust FFI 集成指南：Python + Go

通用模板，适用于任何需要将 Rust 库暴露给 Python 和 Go 的项目。

---

## 目录结构

```
your-rust-lib/
  Cargo.toml
  cbindgen.toml
  src/
    lib.rs           ← 核心逻辑
    ffi.rs           ← C ABI 导出层
  include/
    your_lib.h       ← cbindgen 自动生成，commit 进仓库

bindings/
  python/
    your_lib/
      _native/       ← CI 构建后放 .so/.dylib/.dll，gitignore
        .gitkeep
      __init__.py    ← ctypes 加载器
    pyproject.toml
  go/
    tools/
      download/
        main.go      ← go generate 下载脚本
    native/          ← go generate 后出现，gitignore
      .gitkeep
    your_lib.go      ← cgo 调用层
    your_lib_linux_amd64.go   ← build tag + LDFLAGS
    your_lib_darwin_arm64.go
    gen.go           ← //go:generate 指令

.github/
  workflows/
    release.yml      ← 构建多平台产物并上传 Release
```

---

## 一、Rust 侧

### `Cargo.toml`

```toml
[package]
name = "your-lib"
version = "0.1.0"
edition = "2021"

[lib]
# 同时输出：
#   .so / .dylib / .dll  (Python 用)
#   .a / .lib            (Go 静态链接用)
crate-type = ["cdylib", "staticlib"]
```

### `src/lib.rs` — 核心逻辑（纯 Rust，无 FFI 污染）

```rust
pub fn derive_address(input: &str, key: &[u8]) -> Result<[u8; 32], String> {
    // 你的实际逻辑
    todo!()
}
```

### `src/ffi.rs` — C ABI 导出层

设计原则：
- **调用方分配输出 buffer**，Rust 不 malloc 给调用方
- **返回 i32 错误码**（0 成功，负数失败）
- **字符串用 `*const c_char`**，调用方负责生命周期
- **Bytes 用 `*const u8` + `usize` 长度对**

```rust
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// input: null-terminated C string
/// key / key_len: caller-owned byte slice
/// out: caller-allocated 32-byte buffer
/// returns: 0 on success, -1 on invalid UTF-8, -2 on logic error
#[no_mangle]
pub unsafe extern "C" fn your_lib_derive_address(
    input: *const c_char,
    key: *const u8,
    key_len: usize,
    out: *mut u8,       // caller allocates [u8; 32]
) -> c_int {
    // 安全地解包 C 字符串
    let input_str = match CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let key_slice = std::slice::from_raw_parts(key, key_len);

    match crate::derive_address(input_str, key_slice) {
        Ok(addr) => {
            std::ptr::copy_nonoverlapping(addr.as_ptr(), out, 32);
            0
        }
        Err(_) => -2,
    }
}

/// 返回 Rust 分配字符串的唯一例外：版本号（只读，静态生命周期）
#[no_mangle]
pub extern "C" fn your_lib_version() -> *const c_char {
    b"0.1.0\0".as_ptr() as *const c_char
}
```

### `cbindgen.toml` — 自动生成 C 头文件

```toml
language = "C"
include_guard = "YOUR_LIB_H"
documentation = true
no_includes = false

[export]
prefix = "your_lib_"        # 只导出这个前缀的函数
```

生成头文件：
```bash
cargo install cbindgen
cbindgen --config cbindgen.toml --crate your-lib --output include/your_lib.h
```

**把 `include/your_lib.h` commit 进仓库**，Go 和 Python 都依赖它。

生成结果示例：
```c
#ifndef YOUR_LIB_H
#define YOUR_LIB_H

#include <stdint.h>
#include <stddef.h>

int32_t your_lib_derive_address(
    const char *input,
    const uint8_t *key, size_t key_len,
    uint8_t *out
);

const char *your_lib_version(void);

#endif /* YOUR_LIB_H */
```

---

## 二、Python 侧

### 设计原则

- 用 `ctypes` 加载预编译 `.so`，打进包内，无需用户安装 Rust
- `_native/` 目录 gitignore，CI 构建后放进去再打包
- 对外暴露纯 Python API，调用方感知不到 ctypes

### `bindings/python/your_lib/__init__.py`

```python
import ctypes
import platform
import pathlib
import os

def _load_lib():
    here = pathlib.Path(__file__).parent / "_native"
    system = platform.system().lower()
    machine = platform.machine().lower()

    # 标准化 arch 名称
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(machine, machine)

    names = {
        "linux":  f"libaptos_keyless_linux_{arch}.so",
        "darwin": f"libaptos_keyless_darwin_{arch}.dylib",
        "windows": f"aptos_keyless_windows_{arch}.dll",
    }
    name = names.get(system)
    if name is None:
        raise OSError(f"unsupported platform: {system}/{arch}")

    lib_path = here / name
    if not lib_path.exists():
        raise FileNotFoundError(
            f"native library not found: {lib_path}\n"
            f"If installing from source, run: python -m your_lib.build"
        )
    return ctypes.CDLL(str(lib_path))

_lib = _load_lib()

# 声明函数签名（必须，否则 ctypes 默认返回 c_int 且不检查参数）
_lib.your_lib_derive_address.restype  = ctypes.c_int
_lib.your_lib_derive_address.argtypes = [
    ctypes.c_char_p,          # input
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # key, key_len
    ctypes.POINTER(ctypes.c_uint8),                    # out
]

_lib.your_lib_version.restype  = ctypes.c_char_p
_lib.your_lib_version.argtypes = []


# ── 对外 Python API ──────────────────────────────────────────────

def derive_address(input: str, key: bytes) -> bytes:
    """Derive a 32-byte address from input string and key."""
    out = (ctypes.c_uint8 * 32)()
    key_arr = (ctypes.c_uint8 * len(key))(*key)
    rc = _lib.your_lib_derive_address(
        input.encode("utf-8"),
        key_arr, ctypes.c_size_t(len(key)),
        out,
    )
    _check(rc)
    return bytes(out)

def version() -> str:
    return _lib.your_lib_version().decode()

def _check(rc: int) -> None:
    if rc == 0:
        return
    msgs = {-1: "invalid UTF-8 input", -2: "internal error"}
    raise ValueError(msgs.get(rc, f"unknown error code {rc}"))
```

### `bindings/python/pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "your-lib"
version = "0.1.0"
requires-python = ">=3.9"
# 无额外依赖 — ctypes 是标准库

[tool.setuptools.packages.find]
where = ["."]

[tool.setuptools.package-data]
"your_lib" = ["_native/*"]
```

### 打包流程（CI 里）

```bash
# 1. 编译当前平台的 .so
cargo build --release

# 2. 复制到 _native/（命名含平台信息）
cp target/release/libyour_lib.so \
   bindings/python/your_lib/_native/libyour_lib_linux_x86_64.so

# 3. 打 wheel
pip install build
python -m build bindings/python/ --wheel

# 产物: dist/your_lib-0.1.0-py3-none-linux_x86_64.whl
# pip install 直接用，.so 已打包在内
```

---

## 三、Go 侧

### `bindings/go/gen.go`

```go
package yourlib

//go:generate go run ./tools/download
```

### `bindings/go/tools/download/main.go`

```go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

// 每次发布后更新这两个常量
const (
	version = "v0.1.0"
	baseURL = "https://github.com/your-org/your-lib/releases/download"
)

// sha256 of each platform's .a, filled in after CI builds
var checksums = map[string]string{
	"linux_amd64":   "",
	"linux_arm64":   "",
	"darwin_amd64":  "",
	"darwin_arm64":  "",
	"windows_amd64": "",
}

func main() {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	platform := goos + "_" + goarch

	libFile := "libyour_lib.a"
	if goos == "windows" {
		libFile = "your_lib.lib"
	}

	outDir  := filepath.Join("native", platform)
	outPath := filepath.Join(outDir, libFile)

	if _, err := os.Stat(outPath); err == nil {
		fmt.Println("native lib already present, skipping download")
		return
	}

	url := fmt.Sprintf("%s/%s/libyour_lib_%s.a", baseURL, version, platform)
	fmt.Println("downloading", url)

	resp, err := http.Get(url)
	if err != nil {
		fatalf("http get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fatalf("unexpected status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fatalf("read body: %v", err)
	}

	if want, ok := checksums[platform]; ok && want != "" {
		got := sha256Hex(data)
		if got != want {
			fatalf("checksum mismatch for %s\n  got  %s\n  want %s", platform, got, want)
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		fatalf("write: %v", err)
	}
	fmt.Println("saved →", outPath)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
```

### `bindings/go/your_lib_linux_amd64.go`

```go
//go:build linux && amd64

package yourlib

// #cgo LDFLAGS: -L${SRCDIR}/native/linux_amd64 -lyour_lib -ldl -lm -lpthread
// #include "../../include/your_lib.h"
import "C"
```

类似地为每个平台建一个文件（darwin_arm64, darwin_amd64, windows_amd64...），只改 build tag 和 LDFLAGS 路径。

### `bindings/go/your_lib.go` — 实际 API

```go
package yourlib

// #include "../../include/your_lib.h"
import "C"
import (
	"fmt"
	"unsafe"
)

// DeriveAddress calls the Rust implementation.
func DeriveAddress(input string, key []byte) ([32]byte, error) {
	var out [32]byte
	if len(key) == 0 {
		return out, fmt.Errorf("key must not be empty")
	}
	rc := C.your_lib_derive_address(
		C.CString(input),                                // Go GC owns this until the call returns
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		C.size_t(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if rc != 0 {
		return out, fmt.Errorf("derive_address error code %d", rc)
	}
	return out, nil
}

func Version() string {
	return C.GoString(C.your_lib_version())
}
```

### `.gitignore`（Go binding 目录）

```
native/linux_amd64/
native/linux_arm64/
native/darwin_amd64/
native/darwin_arm64/
native/windows_amd64/
```

### 用户工作流

```bash
go get github.com/your-org/your-lib-go
go generate github.com/your-org/your-lib-go   # 下载 .a，只需一次
go build ./...
```

---

## 四、CI — 构建多平台产物

```yaml
# .github/workflows/release.yml
name: release

on:
  push:
    tags: ["v*"]

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            platform: linux_amd64
            ext_so: so
          - os: ubuntu-latest
            target: aarch64-unknown-linux-gnu
            platform: linux_arm64
            ext_so: so
            cross: true
          - os: macos-latest
            target: aarch64-apple-darwin
            platform: darwin_arm64
            ext_so: dylib
          - os: macos-latest
            target: x86_64-apple-darwin
            platform: darwin_amd64
            ext_so: dylib
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            platform: windows_amd64
            ext_so: dll

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      # Linux cross-compile
      - if: matrix.cross
        run: cargo install cross --git https://github.com/cross-rs/cross

      - name: Build
        run: |
          if [ "${{ matrix.cross }}" = "true" ]; then
            cross build --release --target ${{ matrix.target }}
          else
            cargo build --release --target ${{ matrix.target }}
          fi
        shell: bash

      - name: Rename artifacts
        shell: bash
        run: |
          TARGET=target/${{ matrix.target }}/release
          # .so / .dylib / .dll  → Python
          cp $TARGET/libyour_lib.${{ matrix.ext_so }} \
             libyour_lib_${{ matrix.platform }}.${{ matrix.ext_so }}
          # .a / .lib → Go
          cp $TARGET/libyour_lib.a \
             libyour_lib_${{ matrix.platform }}.a || \
          cp $TARGET/your_lib.lib \
             libyour_lib_${{ matrix.platform }}.a || true

      - uses: actions/upload-artifact@v4
        with:
          name: native-${{ matrix.platform }}
          path: libyour_lib_${{ matrix.platform }}.*

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          merge-multiple: true

      - name: Compute checksums
        run: sha256sum libyour_lib_*.a > checksums.txt && cat checksums.txt

      - uses: softprops/action-gh-release@v1
        with:
          files: |
            libyour_lib_*
            checksums.txt

  publish-python:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          merge-multiple: true
          path: bindings/python/your_lib/_native/

      - run: pip install build && python -m build bindings/python/ --wheel
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          packages-dir: bindings/python/dist/
```

---

## 五、版本同步 checklist

发新版本时：

```
1. 更新 Cargo.toml version
2. git tag v0.2.0 && git push --tags
3. CI 自动构建所有平台产物并上传 Release
4. 从 Release 页面拿 checksums.txt
5. 更新 bindings/go/tools/download/main.go 里的 version 和 checksums
6. commit，用户 go generate 后自动拿到新版本
7. PyPI wheel 由 CI 自动发布，pip install 直接拿到
```

---

## 六、常见坑

| 坑 | 解法 |
|----|------|
| Linux `.so` 依赖 glibc 版本过新 | 用 `manylinux_2_28` Docker 镜像构建 |
| macOS `.dylib` 有 rpath 问题 | `install_name_tool -id @rpath/lib.dylib` |
| Windows `.dll` 找不到 | 和 `.exe` 放同目录，或加进 `PATH` |
| Go cgo `C.CString` 内存泄漏 | `defer C.free(unsafe.Pointer(cstr))` |
| Python ctypes 参数类型错误 | 必须显式声明 `argtypes`，不能省 |
| Rust panic 穿越 FFI 边界 | 每个 `extern "C"` 函数套 `std::panic::catch_unwind` |
