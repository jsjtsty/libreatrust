# libreatrust

Rust SDK and ABI layer for the transport core.

## What it provides

- Resource parsing and route decisions
- Session material management
- A state-driven auth flow with no UI or WebView hosting
- TCP, UDP, and L3 tunnel primitives
- A C ABI for Kotlin, Swift, C++, and other runtimes
- Resource snapshot getters for raw bytes, DNS, node groups, route lists, and VIPs
- Login helpers for callback flows and post-login client resource fetch

## Output artifacts

- `cdylib` for `so` / `dylib` / `dll`
- `staticlib` for static linking
- `include/libreatrust.h` as the public C header

## ABI design

- Prefix: `atr_`
- Input strings are borrowed `const char *`
- Returned strings, blobs, and lists are owned by the caller after return
- Free returned values with the matching `*_free()` function
- Opaque handles are used for clients and tunnels
- Auth returns plain C structs, so upper layers can own UX and platform-specific adaptation
- UDP tunnel APIs mirror the TCP shape: open, read, write, close, free
- Resource snapshots can be exported without re-parsing internal formats on the upper layer
- Callback login can pre-set device identity before finishing the flow

## Auth model

This library does not host a login UI and does not implement WebView orchestration.

The auth session is a pure state machine:

- request available methods
- start password or SMS login
- receive captcha or SMS code challenges as C structs
- complete callback flows by providing the callback URL payload
- import/export session material

## Build

```bash
cargo build --release
```

## C example

See `examples/c_api_smoke.c`.
