# 开发笔记

## 上游同步

本项目 fork 自 [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)，已脱离自动同步。

### 上游最后同步 commit

- **commit**: `7238831`（Merge pull request #1082 from cmliu/beta2.1-BYOB）
- **日期**: 2026-04-08 之前
- **原始文件**: `_worker.js`（单文件，~3500 行）

### 同步操作指南

定期检查上游更新时：

1. 查看上游变更：
   ```bash
   git remote add upstream https://github.com/cmliu/edgetunnel.git  # 仅首次
   git fetch upstream
   git log upstream/main --oneline -20
   git diff 7238831..upstream/main -- _worker.js
   ```

2. 上游仍是单文件 `_worker.js`，我们已拆分为 ESM 模块。对照下表找到对应模块手动合入：

### 模块映射表（原始行号 → 模块文件）

| 原始行号范围 | 模块文件 | 功能 |
|------------|---------|------|
| 1-9 | `src/state.js` | 全局变量、常量 |
| 11-401 | `src/index.js` | 入口 + 路由分发 |
| 58-78, 213 | `src/auth.js` | 登录验证、cookie |
| 74-213 | `src/admin.js` | /admin/* 路由 |
| 207-361 | `src/subscription/index.js` | /sub 订阅路由 |
| 397-695 | `src/handler-xhttp.js` | XHTTP 代理 |
| 697-913 | `src/handler-grpc.js` | gRPC 代理 |
| 916-1323 | `src/handler-ws.js` | WebSocket 代理 |
| 1325-1418 | `src/protocol.js` | VLESS + Trojan 解析 |
| 1420-1498 | `src/shadowsocks.js` | SS 加密/解密 |
| 1500-1770 | `src/tunnel.js` | TCP/UDP 转发 |
| 1772-1863 | `src/proxy.js` | SOCKS5/HTTP 代理 |
| 1866-1868 | `src/utils/log.js` | 日志函数 |
| 1870-2085 | `src/subscription/clash.js` | Clash 热补丁 |
| 2087-2272 | `src/subscription/singbox.js` | SingBox 热补丁 |
| 2274-2290 | `src/subscription/surge.js` | Surge 热补丁 |
| 2293-2346 | `src/logging.js` | 请求日志 + Telegram |
| 2348-2398 | `src/utils/format.js` | 格式化工具 |
| 2359-2371 | `src/utils/crypto.js` | MD5MD5 |
| 2373-2379 | `src/utils/path.js` | 随机路径 |
| 2400-2562 | `src/dns.js` | DoH + ECH + 地址解析 |
| 2565-2766 | `src/config.js` | 配置管理 |
| 2769-3065 | `src/best-ip.js` | 优选 IP |
| 3067-3172 | `src/proxy.js` | 代理参数解析 |
| 3174-3205 | `src/utils/crypto.js` | sha224 |
| 3207-3302 | `src/dns.js` | 解析地址端口 |
| 3305-3332 | `src/proxy.js` | SOCKS5 验证 |
| 3334-3453 | `src/templates.js` | HTML 模板 |

## 安全加固记录

基于上游 commit `7238831` 做了以下安全修改：

- 认证 cookie 比较 `==` → `===`
- Cookie 添加 `Secure; SameSite=Strict`
- 移除 Cloudflare 用量查询功能（API Key 通过 URL 传递有泄露风险）
- 对外错误响应脱敏
- 删除"无恶意声明"超长注释
