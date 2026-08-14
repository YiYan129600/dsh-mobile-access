# dsh-mobile-access

给 DeepSeek Harness 的「手机接入设置」插件：一页搞定 Tailscale / 局域网检测、扫码配对、**直连 / HTTP/2 连接方式自由切换**，以及旧版 harness 在纯 HTTP 手机源下的兼容补丁。

One-page mobile access setup for DeepSeek Harness: live Tailscale/LAN detection, scan-to-pair QR, a **direct / HTTP-2 connection mode toggle**, and an insecure-origin polyfill so the web UI also boots on plain-HTTP phone origins.

- 纯宿主插件，**无客户端 bundle、无构建步骤、零运行时依赖**（二维码由内建 MIT 库离线生成，不调外部服务）
- 安装后访问 `http://127.0.0.1:<port>/mobile-access` 查看设置页（机器可读状态在 `/mobile-access/status.json`）

## 功能 / Features

| 模块 | 说明 |
|---|---|
| 环境清单 | webserver 绑定、Tailscale 检测、局域网检测、防火墙命令，逐项点亮 |
| 扫码配对 | 一次性令牌（15 分钟）、设备注册、心跳、一键撤销；签发/停止端点仅回环可用 |
| **连接方式** | 直连 HTTP（tailnet IP）↔ **HTTP/2**（Tailscale Serve，HTTPS 域名，一键开启/关闭 + 可达性探测），选择持久化在浏览器 localStorage |
| 兼容补丁 | 可选向 index.html 注入 `crypto.randomUUID` polyfill（旧版 harness 非安全源修复） |

## 安装 / Install

```sh
dsh plugin --profile web add github:YiYan129600/dsh-mobile-access
# 然后重启 dsh web
```

## 使用 / Use

1. 打开设置页 `http://127.0.0.1:3080/mobile-access`，按清单逐项点亮：
   - **绑定全部网卡**：重启时加 `--host 0.0.0.0`，或把页面里给出的 patch 片段写进 profile 的 `cordis.patch.yml`（推荐，一劳永逸）
   - **Tailscale**：电脑与手机各装 [Tailscale](https://tailscale.com/download)，用同一账号登录；页面会自动显示 `100.x` tailnet 地址
   - **防火墙**：管理员 PowerShell 跑一次页面里给出的 netsh 命令（只放行 Tailscale 网段，公网不暴露）
2. **选连接方式**：
   - 直连：选地址 → 「生成配对二维码」→ 手机扫码
   - HTTP/2：填 HTTPS 域名（如 `yiyan.tail172eda.ts.net`，从 Tailscale 面板复制）→ 「开启 HTTP/2」（会弹 UAC，点「是」）→ 状态变绿色后回到上方生成二维码
3. 手机（同一 tailnet）扫码打开 DSH；桌面 UI 无需配对直接可用，`/m` 移动端需配对

> HTTP/2 说明：`tailscale serve` 监听 tailnet 内网 443，仅同账号设备可达，TLS 证书自动签发。手机上所有请求走一条多路复用连接，高延迟蜂窝网下加载显著更快。

## 安全说明 / Security

DSH 的 `/api` 信任围栏只是防 DNS 重绑定，**不是登录鉴权**。对手机开放前请至少做到其一：

- 走 Tailscale 私有网（防火墙只放行 `100.64.0.0/10`），或
- 依赖配对令牌与撤销（本插件提供；注意本插件不硬拦截主 `/api`——当前 harness 无 `api/gate` 挂载点）

## 配置 / Config

在 profile 的 `cordis.patch.yml` 里可覆盖插件行配置（均为可选项）：

```yaml
- id: mobile-access
  config:
    pagePath: /mobile-access        # 设置页路径
    polyfill: true                  # 注入 crypto.randomUUID 兼容补丁
    pairTtlMs: 900000               # 配对令牌有效期（毫秒）
    http2:
      tailscaleBin: 'C:\\Program Files\\Tailscale\\tailscale.exe'  # tailscale CLI 路径
```

## 常见问题 / FAQ

- **手机能打开页面但看不到会话？** 多半是 harness 版本过旧：非安全源下 `crypto.randomUUID` 不存在，RPC 层起不来。本插件默认注入的 polyfill 就是修这个的；升级 harness 后可以关掉。
- **扫码后打不开？** 确认手机与电脑在同一个 Tailscale 账号下、`tailscale status` 显示在线，且防火墙命令已执行。
- **HTTP/2 开启后探测失败？** 等 1 分钟让证书签发后重试；若一直失败，检查 Tailscale admin console 的 MagicDNS 与 HTTPS 证书开关。
- **想要专用手机端 UI？** 本插件负责"把网络打通"；配对令牌是自有的。若同时使用 `dsh-remote-web-ui`，其 `/m` 移动界面与本插件互不冲突。

## License

MIT。`lib/qrcode.js` 来自 [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator)（Kazuhiko Arase，MIT）。
