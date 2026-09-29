# libreatrust

[![CI](https://github.com/jsjtsty/libreatrust/actions/workflows/ci.yml/badge.svg)](https://github.com/jsjtsty/libreatrust/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE.txt)

[English](README.md) | 简体中文

`libreatrust` 是 **深信服 aTrust**（零信任 / SDP 接入服务）的第三方开源客户端库，使用 Rust 编写，并提供 C 兼容的 ABI。aTrust 的协议、认证、资源、路由和传输逻辑都在这里实现，可以被原生桌面应用和其他语言运行时共用。

> **声明：** 本项目为非官方项目，与深信服科技无隶属、认可或支持关系。“aTrust”“深信服”是其各自所有者的商标。请仅用于你有权访问的服务。

## 功能范围

本库提供：

- 密码、短信、验证码和回调（Web）登录的认证状态机
- 会话材料的导入、导出、恢复和生命周期管理
- 客户端资源解析和快照访问
- 受管域名和受管 IP 的路由决策
- TCP、UDP 和 L3 隧道
- 代理服务，带事件通知（轮询或回调）和流量统计
- DNS 与节点组资源访问
- 运行时可开关的诊断日志（默认关闭，`atr_set_verbose_logging`，5 MB 轮转）
- 面向 Swift、Kotlin、C/C++ 等 FFI 调用方的 C ABI

本库不提供登录界面、WebView 承载或平台相关的界面编排，这些由集成它的应用负责。

## 已知限制

- **仅支持 IPv4。** 隧道目前只承载 IPv4 流量。资源列表里的 IPv6 条目（地址、CIDR、范围）会被忽略，访问 IPv6 目标时一律直连，不走隧道。aTrust 的线上格式里有 IPv6 字段，所以这是实现上的缺口，不是协议限制；要支持 IPv6 隧道，需要用一个下发了 IPv6 资源的服务端来验证。

## 传输生命周期与保活

L3 隧道的传输维护由传输层内部负责。活动中的 L3 隧道会维持协议心跳，并在存在合适的受管目标时执行配置的业务级 ICMP 保活。代理服务可以为此创建专用的 L3 会话，并在代理服务关闭时一并关闭。

这样传输维护和隧道生命周期绑定在一起，上层不需要再协调单独的保活 API。

## C ABI

生成的公开头文件位于 [`include/libreatrust.h`](include/libreatrust.h)。ABI 遵循以下约定：

- 函数使用 `atr_` 前缀。
- 传入的字符串和缓冲区仅在调用期间借用。
- 返回的字符串、缓冲区、列表和结构体由对应的 `*_free` 函数释放。
- 客户端和隧道用不透明句柄表示。
- 认证和资源数据以普通 C 结构体返回，便于各平台自行适配。

最小集成示例见 [`examples/c_api_smoke.c`](examples/c_api_smoke.c)。

## 构建

构建 Rust 工作区和所有发布库格式：

```bash
cargo build --workspace --release --locked
```

发布构建会产出：

- `cdylib`：macOS 为 `dylib`，Linux 为 `so`，Windows 为 `dll`
- `staticlib`：支持平台上的静态链接库
- `include/libreatrust.h`：公开 C 头文件

本地检查：

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

## 发布产物

GitHub Actions 会为以下平台构建并上传产物：

- Linux x86_64 和 arm64
- macOS arm64 和 x86_64
- Windows x86_64 和 arm64

版本标签会创建 GitHub Release，包含各平台的压缩包。需要 C ABI 的使用者请选择与目标平台和架构匹配的压缩包。

## 相关项目

- [NulConnect](https://github.com/jsjtsty/NulConnect) — 基于本库的 macOS aTrust 客户端
- [nulconnect-helper](https://github.com/jsjtsty/nulconnect-helper) — 特权平台辅助程序

## 许可证

`libreatrust` 使用 GNU Affero General Public License v3.0 许可。见 [LICENSE.txt](LICENSE.txt)。
