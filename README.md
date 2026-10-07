# 🚀 edgetunnel 2.1

> 本仓库是保留模块架构与安全加固的 fork，业务代码已手动同步至 [cmliu/edgetunnel@af4f983](https://github.com/cmliu/edgetunnel/commit/af4f9837e1843e34159018713bc8749ccec3004d)（2026-09-22）。入口为 `src/index.js`；后续同步按模块移植。
> ![后台页面](./img.png)

[![Stars](https://img.shields.io/github/stars/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/stargazers)
[![Forks](https://img.shields.io/github/forks/cmliu/edgetunnel?style=flat-square&logo=github)](https://github.com/cmliu/edgetunnel/network/members)
[![License](https://img.shields.io/github/license/cmliu/edgetunnel?style=flat-square)](https://github.com/cmliu/edgetunnel/blob/main/LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Group-blue?style=flat-square&logo=telegram)](https://t.me/CMLiussss)
[![YouTube](https://img.shields.io/badge/YouTube-Channel-red?style=flat-square&logo=youtube)](https://www.youtube.com/watch?v=LeT4jQUh8ok)
[![zread](https://img.shields.io/badge/Ask_Zread-_.svg?style=flat-square&color=00b0aa&labelColor=000000&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTQuOTYxNTYgMS42MDAxSDIuMjQxNTZDMS44ODgxIDEuNjAwMSAxLjYwMTU2IDEuODg2NjQgMS42MDE1NiAyLjI0MDFWNC45NjAxQzEuNjAxNTYgNS4zMTM1NiAxLjg4ODEgNS42MDAxIDIuMjQxNTYgNS42MDAxSDQuOTYxNTZDNS4zMTUwMiA1LjYwMDEgNS42MDE1NiA1LjMxMzU2IDUuNjAxNTYgNC45NjAxVjIuMjQwMUM1LjYwMTU2IDEuODg2NjQgNS4zMTUwMiAxLjYwMDEgNC45NjE1NiAxLjYwMDFaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00Ljk2MTU2IDEwLjM5OTlIMi4yNDE1NkMxLjg4ODEgMTAuMzk5OSAxLjYwMTU2IDEwLjY4NjQgMS42MDE1NiAxMS4wMzk5VjEzLjc1OTlDMS42MDE1NiAxNC4xMTM0IDEuODg4MSAxNC4zOTk5IDIuMjQxNTYgMTQuMzk5OUg0Ljk2MTU2QzUuMzE1MDIgMTQuMzk5OSA1LjYwMTU2IDE0LjExMzQgNS42MDE1NiAxMy43NTk5VjExLjAzOTlDNS42MDE1NiAxMC42ODY0IDUuMzE1MDIgMTAuMzk5OSA0Ljk2MTU2IDEwLjM5OTlaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik0xMy43NTg0IDEuNjAwMUgxMS4wMzg0QzEwLjY4NSAxLjYwMDEgMTAuMzk4NCAxLjg4NjY0IDEwLjM5ODQgMi4yNDAxVjQuOTYwMUMxMC4zOTg0IDUuMzEzNTYgMTAuNjg1IDUuNjAwMSAxMS4wMzg0IDUuNjAwMUgxMy43NTg0QzE0LjExMTkgNS42MDAxIDE0LjM5ODQgNS4zMTM1NiAxNC4zOTg0IDQuOTYwMVYyLjI0MDFDMTQuMzk4NCAxLjg4NjY0IDE0LjExMTkgMS42MDAxIDEzLjc1ODQgMS42MDAxWiIgZmlsbD0iI2ZmZiIvPgo8cGF0aCBkPSJNNCAxMkwxMiA0TDQgMTJaIiBmaWxsPSIjZmZmIi8%2BCjxwYXRoIGQ9Ik00IDEyTDEyIDQiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxLjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPgo8L3N2Zz4K&logoColor=ffffff)](https://zread.ai/cmliu/edgetunnel)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/cmliu/edgetunnel)

---

## 📖 项目简介

**edgetunnel** 是一个基于 CF Workers/Pages 平台的边缘计算隧道解密方案。它能够高效地处理网络流量，并提供强大的管理面板和灵活的节点配置能力。

- 🖥️ **Demo 演示站点**：[https://EDT-Pages.github.io/admin](https://EDT-Pages.github.io/admin)

### ✨ 核心特性

- 🛡️ **协议支持**：支持 VLESS、Trojan、Shadowsocks 等主流协议，深度集成加密传输。
- 📊 **管理面板**：内置可视化后台，支持实时配置修改、日志查看及流量统计。
- 🛠️ **部署灵活**：完整适配 CF Workers 及 CF Pages (GitHub / 上传)。
- 🔄 **订阅系统**：内置自动订阅生成及混淆转换，适配主流客户端（Clash, Sing-box, Surge 等）。
- ⚡ **性能加速**：支持自定义 ProxyIP、SOCKS5/HTTP/HTTPS/TURN/SSTP 链式代理及优选 API，优化网络延迟。
- 🌐 **多台适配**：完美适配 Windows, Android, iOS, MacOS 及各种软路由固件。

---

## 💡 部署与本地验证

本 fork 使用 Cloudflare Workers 的 Git 构建集成。`main` 推送后由既有 Workers Builds 自动构建部署；GitHub 的 `Test` 检查负责单元测试、Worker 打包和本地运行验证。

- Worker 入口、KV 绑定、变量保留策略及区域设置统一维护在 `wrangler.jsonc`。
- 管理员通过 Cloudflare 后台配置 `ADMIN`，访问 Worker 自定义域名下的 `/admin` 登录。
- 不直接把上游 `_worker.js` 或 ZIP 覆盖到本 fork；上游单文件/Pages 部署教程仅供参考：[上游说明](https://github.com/cmliu/edgetunnel)。

本地验证（推荐 Node.js 24，使用项目声明的 pnpm 版本）：

```bash
pnpm install
pnpm test
pnpm build
pnpm test:worker
```

`pnpm build` 仅执行 Wrangler dry-run 打包，不发布 Worker。`test:worker` 使用打包产物、测试常量和本地 KV，禁止外部网络请求；TLS 回归测试会生成临时测试证书并启动本机测试服务器。以上检查不会访问生产 KV。

---

## 🔑 环境变量说明

| 变量名                    | 必填 | 示例                                          | 详细备注                                                                                       |
| :------------------------ | :--: | :-------------------------------------------- | :--------------------------------------------------------------------------------------------- |
| **ADMIN**                 |  ✅  | `123456`                                      | 后台管理面板登录密码                                                                           |
| **KEY**                   |  ❌  | `CMLiussss`                                   | 快速订阅路径密钥，访问 `/CMLiussss` 即可快速获取节点                                           |
| **UUID**                  |  ❌  | `90cd4a77-141a-43c9-991b-08263cfe9c10`        | 强制固定UUID，只支持**UUIDv4**标准格式                                                         |
| **PROXYIP**               |  ❌  | `proxyip.cmliussss.net:443`                   | 全局自定义反代 IP                                                                              |
| **URL**                   |  ❌  | `https://cloudflare-error-page-3th.pages.dev` | 默认主页伪装地址（可填写网页 URL 或 `1101`）                                                   |
| **GO2SOCKS5**             |  ❌  | `*.example.com`                               | 在内置代理名单上追加域名；逗号分隔，自动去重                                                   |
| **DEBUG**                 |  ❌  | `1`或`true`                                   | **开发者模式**，默认**关闭**调试日志功能（console.log），设置`1`或`true`则**开启**调试日志功能 |
| **OFF_LOG**               |  ❌  | `1`或`true`                                   | 默认**开启**KV日志记录功能，设置`1`或`true`则**关闭**日志记录功能                              |
| **BEST_SUB**              |  ❌  | `1`或`true`                                   | 默认**关闭**作为**优选订阅生成器**的功能，设置`1`或`true`则**开启**该功能                      |
| **PRELOAD_RACE_DIAL**     |  ❌  | `true`                                        | 预加载竞速拨号，默认关闭；设置 `1` 或 `true` 开启                                              |
| **TCP_CONCURRENT_DIAL**   |  ❌  | `2`                                           | 直连并发，默认 2；未配置时中国移动网络默认 1。有效的正整数配置覆盖默认值                       |
| **PROXY_CONCURRENT_DIAL** |  ❌  | `1`                                           | 反代并发，默认 1                                                                               |

---

## 🔧 高级实用技巧

如需修改 **订阅地址里的TOKEN** 和 **用于节点验证的UUID** ，可通过修改变量

1. 修改`ADMIN`或`KEY`变量的值，可以随机修改 **订阅地址里的TOKEN** 和 **用于节点验证的UUID**
2. 设置`UUID`变量可以强制固定 **订阅地址里的TOKEN** 和 **用于节点验证的UUID**，注意必须是**UUIDv4**标准格式，否则会导致节点无法使用。

本工具支持通过 **PATH路径** 动态切换底层代理方案：

- 指定 `PROXYIP` 案例

  ```url
  /proxyip=proxyip.cmliussss.net
  /?proxyip=proxyip.cmliussss.net
  ```

- 指定 `SOCKS5` 案例

  ```url
  /socks5=user:password@127.0.0.1:1080
  /?socks5=user:password@127.0.0.1:1080
  /socks://dXNlcjpwYXNzd29yZA==@127.0.0.1:1080 (默认激活全局SOCKS5)
  /socks5://user:password@127.0.0.1:1080 (默认激活全局SOCKS5)
  ```

- 指定 `HTTP代理` 案例

  ```url
  /http=user:password@127.0.0.1:1080
  /http://user:password@127.0.0.1:8080 (默认激活全局SOCKS5)
  ```

- 指定 `Trojan fallback` 案例（由于使用场景为自建对接, 仅 Trojan 入站，fallback 服务需为同密码、非 WebSocket、非 TLS. 此时 UDP 透传给 fallback, 性能优秀, 功能完整）
  ```url
  /trojan=1.1.1.1:1234
  ```

---

## 订阅兼容与新增配置

永久订阅地址和 UUID 生成规则保持不变。订阅转换服务使用按 UTC 日序号生成的临时 TOKEN，接受今天及昨天的 TOKEN；转换响应保持占位 UUID 和域名，真实节点凭证仅在用户客户端响应中替换。

旧 `config.json` 读取时会补齐缺失字段，保留已有设置，不需要迁移或重置 KV。新增 `ALPN` 默认为空；`订阅转换配置` 中 `SUBLIST`、`UDP`、`XUDP`、`TLS13`、`APPEND_TYPE`、`SORT` 默认关闭，`EXPAND` 默认开启。gRPC 节点使用 `authority` 与 `serviceName`，XHTTP 节点包含 padding 配置；Base64 节点不再输出 `allowInsecure`，Clash/Sing-box 保留各自的证书设置。

本 fork 保留严格 Cookie 比较、`Secure; SameSite=Strict`、完整 UUID 的版本接口校验和对外错误脱敏；不提供通过 URL 传入 Cloudflare API 凭证的用量查询。`UsageAPI` 的既有配置仍可用于读取用量，缺失用量时不输出虚构流量统计。

---

## 💻 客户端适配情况

| 平台        | 推荐客户端                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| :---------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Windows** | [v2rayN](https://github.com/2dust/v2rayN/releases)、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、[FlClash](https://github.com/chen08209/FlClash/releases)、[mihomo-party](https://github.com/mihomo-party-org/clash-party/releases)、[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)、[Clashmi](https://github.com/KaringX/clashmi/releases)、[FlyClash](https://github.com/GtxFury/FlyClash/releases)、[Karing](https://github.com/KaringX/karing/releases)、[Bettbox](https://github.com/appshubcc/Bettbox/releases)  |
| **Android** | [v2rayNG](https://github.com/2dust/v2rayNG/releases)、[ClashMetaForAndroid](https://github.com/MetaCubeX/ClashMetaForAndroid/releases/)、[FlClash](https://github.com/chen08209/FlClash/releases)、[Clashmi](https://github.com/KaringX/clashmi/releases)、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、[NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases)、[FlyClash](https://github.com/GtxFury/FlyClash/releases)、[Karing](https://github.com/KaringX/karing/releases)、[Bettbox](https://github.com/appshubcc/Bettbox/releases) |
| **iOS**     | Surge、Shadowrocket、Stash、[Hiddify](https://github.com/hiddify/hiddify-app/releases)、Loon、Egern、[Clashmi](https://clashmi.app/download)、[Karing](https://karing.app/)、Quantumult X                                                                                                                                                                                                                                                                                                                                                                             |
| **macOS**   | [FlClash](https://github.com/chen08209/FlClash/releases)、[mihomo-party](https://github.com/mihomo-party-org/clash-party/releases)、[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev/releases)、Surge、[Clashmi](https://clashmi.app/download)、[Karing](https://karing.app/)、[FlyClash](https://github.com/GtxFury/FlyClash/releases)                                                                                                                                                                                                           |
| **鸿蒙**    | [ClashBox](https://github.com/xiaobaigroup/ClashBox/releases)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

---

## ⭐ 项目热度

![Stargazers over time](https://github.com/cmliu/cmliu/blob/main/star/edgetunnel.svg)

---

## 🙏 特别鸣谢

### 💖 赞助支持 - 提供云服务器维持[订阅转换服务](https://sub.cmliussss.net/)

- [Yuusei Network](https://yuusei.io/)
- [VMRack](https://www.vmrack.net?ref_code=5Zk7eNhbgL7)

### 🛠 开源代码引用

- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)
- [3Kmfi6HP/EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
- [SHIJS1999/cloudflare-worker-vless-ip](https://github.com/SHIJS1999/cloudflare-worker-vless-ip)
- [Stanley-baby](https://github.com/Stanley-baby)
- [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/master/Clash/config)
- [股神](https://t.me/CF_NAT/38889)
- [Workers/Pages Metrics](https://t.me/zhetengsha/3382)
- [白嫖哥](https://t.me/bestcfipas)
- [Mingyu](https://github.com/ymyuuu/workers-vless)
- [ToiCF/CF-Workers-HTTPS](https://github.com/ToiCF/CF-Workers-HTTPS)
- [ToiCF/CF-Workers-TURN](https://github.com/ToiCF/CF-Workers-TURN)
- [ToiCF/CF-Workers-SoftEther](https://github.com/ToiCF/CF-Workers-SoftEther)
- [eooce](https://github.com/eooce/Cloudflare-proxy)
- [Sukka](https://ip.skk.moe/)
- [zhangtaile](https://github.com/cmliu/edgetunnel/pull/999)
- [1345695](https://github.com/1345695/edcloudwasm)
- [ToiCF/GrainTCP](https://github.com/ToiCF/GrainTCP)
- [xream](https://github.com/cmliu/edgetunnel/pull/1359)

---

## ⚠️ 免责声明

1. 本项目（"edgetunnel"）仅供**教育、科学研究及个人安全测试**之目的。
2. 使用者在下载或使用本项目代码时，必须严格遵守所在地区的法律法规。
3. 作者 **cmliu** 对任何滥用本项目代码导致的行为或后果均不承担任何责任。
4. 本项目不对因使用代码引起的任何直接或间接损害负责。
5. 建议在测试完成后 24 小时内删除本项目相关部署。

---

**如果您觉得项目对您有帮助，请给一个 Star 🌟，这是对我最大的鼓励！**
