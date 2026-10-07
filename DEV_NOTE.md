# 开发笔记

## 上游同步

本项目 fork 自 [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)，保留 ESM 模块架构，停用上游自动同步工作流。

- 原同步基准：`723883198b6ce48a4cb99faf3c8cd2f9ff89f63b`。
- 当前业务同步基准：`af4f9837e1843e34159018713bc8749ccec3004d`，2026-09-22。
- 本次同步前本地提交：`621e68b46fe8a6287c233ec57a0f1c567000f41c`；恢复引用：`codex/pre-upstream-621e68b`。
- 业务代码按模块移植，没有把上游提交加入 Git 父链；下次比较必须使用上述业务同步基准，不能仅以 `git merge-base` 判断已同步范围。

### 后续同步

```bash
git fetch upstream
git log af4f983..upstream/main --oneline
git diff af4f983..upstream/main -- _worker.js README.md CHANGELOG
```

先按行为和依赖映射移植，再验证本地差异。上游仍为单文件，不直接合并覆盖入口，也不恢复上游自动同步或自动关闭 PR 的工作流。

| 行为                              | 本地模块                                                                                               |
| --------------------------------- | ------------------------------------------------------------------------------------------------------ |
| 路由、认证、管理、配置            | `index.js`、`auth.js`、`admin.js`、`config.js`                                                         |
| 订阅、转换、客户端兼容            | `subscription/`、`best-ip.js`、`utils/secret.js`                                                       |
| WS、gRPC、XHTTP                   | `handler-*.js`、`ws-*.js`、`xhttp-*.js`                                                                |
| 协议解析、SS、Trojan UDP/fallback | `protocol.js`、`shadowsocks.js`、`trojan-*.js`、`udp.js`                                               |
| 连接、代理和解析                  | `tunnel.js`、`connection.js`、`tcp-connect.js`、`proxy*.js`、`dns.js`、`turn-protocol.js`、`sstp-*.js` |
| TLS、上传和下行合包               | `tls/`、`streams/`                                                                                     |

上表均相对 `src/`。TLS 握手按 1.2/1.3 分模块，Shadowsocks 会话独立于 WS 调度，SSTP 报文与读取器独立于握手流程。

## 必须保留的本地差异

- 认证 Cookie 严格比较，保留 `Secure; SameSite=Strict`；版本接口完整匹配 UUID，不采用上游部分 UUID 的校验。
- 不恢复 `admin/getCloudflareUsage` 和凭证用量查询函数；该旧路由明确返回 404，避免携带查询参数访问静态页面。保留原有 `UsageAPI` 读取及 Usage 空值兼容。
- 对外错误响应脱敏；不恢复无功能的超长声明或特征规避注释。
- 使用官方 `cloudflare:sockets`，不依赖上游的 `request.fetcher.connect` 内部属性。
- 部署入口、KV、`keep_vars`、区域配置由本地 `wrangler.jsonc` 管理；上游不覆盖。

## 并发、配置与资源管理

- 代理参数、并发数、白名单和调试开关按请求计算；共享缓存只保存解析结果与纯计算结果，不保存当前请求配置或代理账号。
- `读取config_JSON` 的配置对象为局部变量；缺失字段递归补默认值，不回写已有 `config.json`。
- 直连并发默认 2，中国移动未显式指定时为 1；反代并发默认 1，预加载默认关闭。白名单追加去重。
- DoH 缓存按服务、规范化域名与记录类型区分；最多 256 项，至少保留 5 分钟，空结果同样缓存。
- 本地补充 CONNECT 首包回灌背压修复、下行尾包与直发顺序修复、DNS socket 清理、建连/TLS 超时定时器清理、socket closed 与 fallback 下行异常消费。
- TLS 1.2/1.3 与 ChaCha20 兼容实现沿用上游；HTTPS 域名代理走平台 TLS，IP 地址代理的自定义 TLS 与上游一样不校验服务器证书链。这不改变管理登录或节点证书验证开关。

## 验证与交付

- `pnpm test`：单元测试、可控流/socket 回归，以及本机 TLS 服务器的真实握手。
- `pnpm build`：Wrangler dry-run，产物位于 `dist/`，不发布生产。
- `pnpm test:worker`：需先 build；用本地 workerd、测试 KV 和假凭证验证路由及三种传输，禁止外部网络。
- 格式/类型检查脚本当前未配置；JavaScript 通过词法引用检查、Vitest、打包与 workerd 验证。模拟测试不证明线上吞吐或 CPU 收益。
- 推送 main 后分别核对 GitHub `Test` 与 `Workers Builds: edgetunnel`；保留恢复引用，不用手动部署补偿自动交付失败。
