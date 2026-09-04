# dsh-mobile-access

给 DeepSeek Harness 的「手机接入设置」插件：一页搞定 Tailscale / 局域网检测、扫码配对、**直连 / HTTP/2 连接方式自由切换**，以及旧版 harness 在纯 HTTP 手机源下的兼容补丁。

One-page mobile access setup for DeepSeek Harness: live Tailscale/LAN detection, scan-to-pair QR, a **direct / HTTP-2 connection mode toggle**, and an insecure-origin polyfill so the web UI also boots on plain-HTTP phone origins.

- 纯宿主插件 + **极简客户端入口**，**无构建步骤、零运行时依赖**（二维码由内建 MIT 库离线生成，不调外部服务）
- 安装后默认界面**侧栏底部出现 📱 按钮**，点开直达设置页（也可以直接访问 `http://127.0.0.1:<port>/mobile-access`；机器可读状态在 `/mobile-access/status.json`）

## 功能 / Features

| 模块 | 说明 |
|---|---|
| 环境清单 | webserver 绑定、Tailscale 检测、局域网检测、**API 信任围栏**、防火墙命令，逐项点亮 |
| 扫码配对 | 一次性令牌（15 分钟）、**持久设备凭证（落盘、重启不丢、30 天滚动）**、多设备共存、逐个撤销 / 一键撤销；签发/撤销端点仅回环可用 |
| **连接方式** | 直连 HTTP（tailnet IP）↔ **HTTP/2**（Tailscale Serve，HTTPS 域名，一键开启/关闭 + 可达性探测），选择持久化在浏览器 localStorage |
| **信任围栏引导** | 探测手机来源对 `/api` 的放行状态；HTTP/2 模式未放行时给出 `web-app.trustedHosts` patch 片段；**拒绝生成扫码后是空壳的二维码**（页面能开但 `/api` 403） |
| **PWA 主屏** | 注入 manifest + theme-color + apple-touch-icon（内置 512px 图标）；扫码配对后落到**欢迎页**，引导「添加到主屏幕」，点开即全屏 standalone |
| 兼容补丁 | 可选向 index.html 注入 `crypto.randomUUID` polyfill（默认 `auto`：脚本自带守卫、新 harness 零影响；可设 `false` 彻底关闭） |

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
   - HTTP/2：填 HTTPS 域名（如 `yiyan.tail172eda.ts.net`，从 Tailscale 面板复制）→ 「开启 HTTP/2」（会弹 UAC，点「是」）→ **等清单里「API 信任围栏」变绿**（若红：复制页面给出的 `web-app.trustedHosts` 片段进 profile 的 `cordis.patch.yml` 并重启）→ 回到上方生成二维码
3. 手机（同一 tailnet）扫码 → 落到**配对欢迎页**（已配对 ✓ + 设备名 + 凭证有效期）→ 按引导「添加到主屏幕」→ 从主屏幕图标全屏进入 DSH；桌面 UI 无需配对直接可用，`/m` 移动端需配对

> HTTP/2 说明：`tailscale serve` 监听 tailnet 内网 443，仅同账号设备可达，TLS 证书自动签发。手机上所有请求走一条多路复用连接，高延迟蜂窝网下加载显著更快。**注意**：HTTP/2 模式手机以 `*.ts.net` 域名访问，必须把该域名加入 `web-app.trustedHosts`，否则 `/api` 被 DSH 的信任围栏挡成 403（页面能开、数据全空）——本插件已做探测与 patch 片段引导，杜绝"空壳二维码"。

## 安全说明 / Security

DSH 的 `/api` 信任围栏只是防 DNS 重绑定，**不是登录鉴权**。对手机开放前请至少做到其一：

- 走 Tailscale 私有网（防火墙只放行 `100.64.0.0/10`），或
- 依赖配对令牌与撤销（本插件提供；注意本插件不硬拦截主 `/api`——当前 harness 无 `api/gate` 挂载点）

配对设备凭证（id + secret 的 sha-256 哈希）落盘在 `~/.dsh/data/dsh-mobile-access/devices.json`（权限 0600 由 DSH 数据区惯例保证），浏览器以 30 天滚动 cookie 携带；撤销后凭证立即失效。HTTP/2 模式下 cookie 带 `Secure` 标记（仅 HTTPS 发送）。

## 配置 / Config

在 profile 的 `cordis.patch.yml` 里可覆盖插件行配置（均为可选项）：

```yaml
- id: mobile-access
  config:
    pagePath: /mobile-access        # 设置页路径
    polyfill: auto                  # auto(默认)=注入带守卫的 randomUUID 脚本(新 harness 零影响); false=彻底关闭; true=强制注入
    pairTtlMs: 900000               # 配对令牌有效期（毫秒）
    http2:
      tailscaleBin: 'C:\\Program Files\\Tailscale\\tailscale.exe'  # tailscale CLI 路径
```

> HTTP/2 模式还需把 ts.net 域名加入 **client-connection 的信任围栏**（否则 `/api` 403）。设置页「API 信任围栏」清单项会给出一键复制片段，形如：
> ```yaml
> - id: web-app
>   config:
>     trustedHosts:
>       - yiyan.tail172eda.ts.net
> ```

## 常见问题 / FAQ

- **手机能打开页面但看不到会话？** 两个可能：
  1. **HTTP/2 模式未放行信任围栏**：手机以 `*.ts.net` 域名访问时 `/api` 被 DSH 围栏 403。到设置页看「API 信任围栏」是否绿色；红则复制 patch 片段进 `cordis.patch.yml` 并重启。本插件在生成二维码前会做端到端探测，围栏没放行时直接拒绝生成。
  2. **harness 版本过旧**：非安全源下 `crypto.randomUUID` 不存在，RPC 层起不来。本插件默认注入的 polyfill 就是修这个的；升级 harness（≥ rc.6）后可将 `polyfill` 设为 `false` 关闭。
- **扫码后打不开？** 确认手机与电脑在同一个 Tailscale 账号下、`tailscale status` 显示在线，且防火墙命令已执行。
- **HTTP/2 开启后探测失败？** 等 1 分钟让证书签发后重试；若一直失败，检查 Tailscale admin console 的 MagicDNS 与 HTTPS 证书开关。
- **重启 dsh 后已配对的手机会掉线吗？** 不会——设备凭证已持久化（`~/.dsh/data/dsh-mobile-access/devices.json`），cookie 有效期 30 天滚动。可在设置页逐个撤销设备。
- **怎么把 DSH 变成手机上的"App"？** 配对后欢迎页有引导：iOS Safari 用「分享 → 添加到主屏幕」；Android Chrome 用菜单「添加到主屏幕」。之后点主屏幕图标即全屏打开（PWA standalone）。
- **想要专用手机端 UI？** 本插件负责"把网络打通"；配对令牌是自有的。若同时使用 `dsh-remote-web-ui`，其 `/m` 移动界面与本插件互不冲突。

## License

MIT。`lib/qrcode.js` 来自 [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator)（Kazuhiko Arase，MIT）。
