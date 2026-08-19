# libreatrust

[![CI](https://github.com/jsjtsty/libreatrust/actions/workflows/ci.yml/badge.svg)](https://github.com/jsjtsty/libreatrust/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE.txt)

`libreatrust` is a Rust library and C-compatible ABI layer for secure access clients. It contains the protocol, authentication, resource, routing, and transport logic that can be shared by native desktop applications and other language runtimes.

## Scope

The library provides:

- Authentication state machines for password, SMS, captcha, and callback flows
- Session material import, export, resumption, and lifecycle management
- Client resource parsing and snapshot access
- Managed-domain and managed-IP route decisions
- TCP, UDP, and L3 tunnel primitives
- Proxy service primitives with event and traffic statistics
- DNS and node-group resource access
- C ABI bindings for Swift, Kotlin, C/C++, and other FFI consumers

The library does not provide a login UI, WebView hosting, or platform-specific user-interface orchestration. Those responsibilities belong to the integrating application.

## Transport lifecycle and keepalive

L3 tunnel transport maintenance is managed inside the transport implementation. An active L3 tunnel maintains its protocol heartbeat and can run the configured business-level ICMP keepalive when an appropriate managed target is available. The proxy service can create a dedicated L3 session for this purpose and closes it together with the proxy service.

This keeps transport maintenance close to the tunnel lifecycle and avoids requiring upper layers to coordinate a separate KeepAlive API.

## C ABI

The generated public header is available at [`include/libreatrust.h`](include/libreatrust.h). The ABI follows these conventions:

- Functions use the `atr_` prefix.
- Input strings and buffers are borrowed for the duration of the call.
- Returned strings, buffers, lists, and structures are released with their matching `*_free` function.
- Clients and tunnels are represented by opaque handles.
- Authentication and resource data are returned as plain C structures for platform-specific adaptation.

See [`examples/c_api_smoke.c`](examples/c_api_smoke.c) for a minimal C integration example.

## Build

Build the Rust workspace and all release library formats:

```bash
cargo build --workspace --release --locked
```

The release build produces:

- `cdylib`: `dylib` on macOS, `so` on Linux, and `dll` on Windows
- `staticlib`: static-linking library for supported targets
- `include/libreatrust.h`: public C header

Run the local checks with:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

## Release artifacts

GitHub Actions builds and uploads artifacts for:

- Linux x86_64 and arm64
- macOS arm64 and x86_64
- Windows x86_64 and arm64

Version tags create GitHub Releases containing platform-specific archives. Consumers that need the C ABI should use the archive matching their target platform and architecture.

## Related projects

- [NulConnect](https://github.com/jsjtsty/NulConnect) — macOS client
- [nulconnect-helper](https://github.com/jsjtsty/nulconnect-helper) — privileged platform helper

## License

`libreatrust` is licensed under the GNU Affero General Public License v3.0. See [LICENSE.txt](LICENSE.txt).
