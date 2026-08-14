# dsh-mobile-access

给 DeepSeek Harness 的「手机接入设置」插件：一页搞定 Tailscale / 局域网检测、扫码直达二维码，以及旧版 harness 在纯 HTTP 手机源下的兼容补丁。

One-page mobile access setup for DeepSeek Harness: live Tailscale/LAN detection, a scan-to-open QR code, and an insecure-origin polyfill so the web UI also boots on plain-HTTP phone origins.

- 纯宿主插件，**无客户端 bundle、无构建步骤、零运行时依赖**（二维码由内建 MIT 库离线生成，不调外部服务）
- 安装后访问 `http://127.0.0.1:<port>/mobile-access` 查看设置页（机器可读状态在 `/mobile-access/status.json`）

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
2. 手机（同一 tailnet）扫码或手动输入地址即可打开 DSH

## 安全说明 / Security

本插件不改变任何访问控制：DSH 的 `/api` 信任围栏只是防 DNS 重绑定，**不是登录鉴权**。对手机开放前请至少做到其一：

- 走 Tailscale 私有网（默认就只放行 `100.64.0.0/10`），或
- 配合 [dsh-remote-web-ui](https://github.com/zhu1090093659/dsh-web-ui) 的扫码配对令牌（`requirePairingForLan` 门禁），把非回环请求全部挡在配对之后

## 配置 / Config

在 profile 的 `cordis.patch.yml` 里可覆盖插件行配置（均为可选项）：

```yaml
- id: mobile-access
  config:
    pagePath: /mobile-access   # 设置页路径
    polyfill: true             # 向 index.html 注入 crypto.randomUUID 兼容补丁
```

## 常见问题 / FAQ

- **手机能打开页面但看不到会话？** 多半是 harness 版本过旧：非安全源下 `crypto.randomUUID` 不存在，RPC 层起不来。本插件默认注入的 polyfill 就是修这个的；升级 harness 后可以关掉。
- **扫码后打不开？** 确认手机与电脑在同一个 Tailscale 账号下、`tailscale status` 显示在线，且防火墙命令已执行。
- **想要配对鉴权 / 专用手机端 UI？** 本插件只负责"把网络打通"。配上 `dsh-remote-web-ui` 后，手机端会落到带令牌鉴权的 `/m` 移动界面。

## License

MIT。`lib/qrcode.js` 来自 [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator)（Kazuhiko Arase，MIT）。
