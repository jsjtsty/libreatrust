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
- A cancellable session KeepAlive service using remote DNS or a configured HTTP URL

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
- KeepAlive is an independent service: start it after authentication and resource loading, and stop it before disconnecting

## KeepAlive

`KeepAliveService` sends a probe immediately and then at the configured interval (60 seconds by default).
With no URL it sends a DNS query through the configured remote DNS resource. Set `KeepAliveConfig::url` to
an `http://` or `https://` endpoint that is available through the managed resources to use an HTTP probe.
HTTPS is terminated with rustls inside the library while the underlying TCP connection remains managed.

The service is intentionally separate from `ProxyService`, so applications that use raw tunnels can use the
same session protection. It must be stopped by the caller when the authenticated client is disconnected.

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
