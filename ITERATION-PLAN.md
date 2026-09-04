# dsh-mobile-access 迭代优化设计方案 v1：对标高星项目，补安全地基、修信任围栏缺口、上移动体验

> 状态：规划稿（基于 2026-09 GitHub 高星项目调研 + 本机 harness 0.1.0-rc.6 实测）
> 调研基线：dsh-mobile-access v0.2.0（git 6daac11）
> 本文档只做设计，不含实施。

---

## 1. 现状盘点（基于真实代码实测）

### 1.1 现有方案的能力面（v0.2.0）

```
【宿主】lib/index.js（零依赖、无构建）
   ├─ 环境检测：webserver 绑定 / Tailscale 100.x 检测 / LAN / 防火墙命令
   ├─ 配对协议 /mobile-access/api/pair/*：一次性令牌（15min）→ 内存态设备表 → 心跳 → 撤销
   ├─ 连接方式：直连 HTTP（tailnet IP）↔ HTTP/2（tailscale serve，UAC 提权）
   └─ tapIndex 注入 crypto.randomUUID polyfill（旧 harness 兼容）
【客户端】lib/client.js：侧栏底部 📱 按钮 → iframe 侧滑面板（主题桥接）
```

### 1.2 实测确认的四个结构性缺口

以下每一条都在本机 harness 0.1.0-rc.6 源码中验证过，不是猜测：

1. **HTTP/2 模式的信任围栏缺口（静默失败）**。
   `/api` 的围栏 `isTrustedApiRequest`（dsh-client-connection）只认 loopback 与 `trustedHosts`。`dsh-web-app` 的 `resolveLanTrust` 在绑定 `0.0.0.0` 时**自动派生的是 IPv4 字面量**（LAN IP + Tailscale 100.x IP）；而 HTTP/2 模式下手机的 Host 是 `yiyan.tailxxx.ts.net` 域名——**不在派生列表**，且当前 profile 的 patch yml 未配置 `web-app.trustedHosts`。结果：静态页能加载（fallback 无围栏），RPC 全 403，Web GUI 在手机上是"空壳"。这是"页面开了但没数据"级别的问题，而设置页的 HTTP/2 探测（probeHttps）只探测 HTTPS 可达，探测不到这层。
2. **配对是"软配对"**：`pair.accept` 发的 cookie TTL = 配对 TTL（15 分钟），过期后已配对设备没有任何持久凭证；设备表在内存里，`dsh web` 重启即清零（README footer 自己也承认）。且 harness 无 `api/gate` 挂载点，配对**不硬拦 `/api`**——同一 tailnet 里任何设备其实都能直连 `/api`，配对只是仪式感。
3. **移动端体验 = 桌面 Web GUI 缩小**：无 PWA manifest（tapIndex → applyIndexTaps 链路已验证可注入）、无添加到主屏幕、无任何移动端手势/布局优化；曾经互补的第三方 `@linxin666/dsh-remote-web-ui`（/m 移动界面）已被 profile 显式禁用，由本插件"全权负责"——但本插件只有"接入向导"，没有"移动端使用体验"。
4. **polyfill 已接近退役**：harness 0.1.0-rc.6 的前端已演进多版，`crypto.randomUUID` polyfill 注入应改为条件化（检测到新前端就不注入），避免永久性 html 注入噪音。

### 1.3 harness 侧可用的挂载点（0.1.0-rc.6 实测）

| 挂载点 | 状态 | 对迭代设计的意义 |
|---|---|---|
| `webServer.register(prefix/exact)` | 可用 | 设置页、manifest、图标、自有 API |
| `webServer.registerUpgrade(path)` | 可用（未被占用的路径） | 手机端 WebSocket 通知通道（§7.1） |
| `webServer.tapIndex` → `applyIndexTaps` | 可用 | PWA manifest / service worker 注册注入 |
| `webServer.registerFallback` | 单席位，已被 SPA dist 占用 | 不可用 |
| `api/gate`（拦截主 /api） | **不存在** | 配对硬校验只能走 §8 的网关方案（P3，默认不做） |
| `web-app.trustedHosts`（patch 配置） | 可用 | HTTP/2 缺口的正确修法（§5.1） |
| `sessions` / `sessionProjections` 服务 | 存在（订阅能力待验证） | P2 会话事件推送的数据源 |

### 1.4 PRIVILEGED_METHODS 约束（设计必须尊重）

`dsh-client-connection` 将 settings/credentials/agentPreset/llm.discoverModels 等方法**刻意钉死 loopback**（"until a real authentication layer exists"）。含义：

- 手机端做"只读会话 + 发消息 + 审批"是自然能力边界；
- 手机端**不该**做设置修改/凭据管理类 UI，做了也是 403；
- 这是官方安全设计，迭代方案不得尝试绕过（绕过 = 制造安全事件）。

---

## 2. 对标调研：GitHub 高星项目横评

（本章数据来自 gh CLI + README 调研，star 数为 2026-09-04 实测值；claudecodeui / omnara / ccpocket 的完整 README 已存档至 `D:\work\research\` 供实施时引用）

> 许可证合规提示：claudecodeui 为 **AGPL-3.0**，omnara 为 Apache-2.0，ccpocket 为 MIT；本插件为 MIT。实施时对 claudecodeui **只借鉴设计与交互模式，不复制代码**（AGPL 传染）；ccpocket/Apache 系借鉴时注明来源即可。

### 2.1 头部项目速览

| 项目 | Star | 形态 | 一句话 |
|---|---|---|---|
| slopus/happy | 23.6k | 云中继 + 原生 App | Codex/Claude Code 的移动+Web 客户端：实时语音、E2E 加密 |
| siteboon/claudecodeui | 13.6k | 本机 Web UI | Claude Code 浏览器 GUI（本地跑 Node 服务） |
| omnara-ai/omnara | 2.8k | 云中继 + 原生 App | AI agent 中心：远程审批、推送、多 agent 面板 |
| happier-dev/happier | 1.6k | **自托管** happy 分叉 | 去 Happy 云的自托管移动客户端 |
| K9i-0/ccpocket | 1.1k | 轻客户端 | 手机端 Claude Code 监控 |
| （参照）rustdesk / frp / tailscale | 122k / 109k / 36k | 基础设施 | 远程桌面 / 内网穿透 / 组网的成熟度上限 |

### 2.2 深度对标：架构 / 配对 / 移动功能矩阵

**happy（23.6k★，云中继 + 原生 App）与 happier（1.6k★，自托管分叉，作者原为 happy 贡献者）**

- 拓扑：手机/Web 客户端 ↔ 中继(relay) ↔ 本机 daemon（常驻）↔ agent CLI；协议 HTTP（Fastify /v1、/v2）+ **Socket.IO WebSocket**；点对点控制（手机→daemon spawn/发消息/bash）走 WS 上的 RPC 而非 REST；daemon **出站长连**中继，无需入站端口。
- 协议细节（happier 更进一步）：**WebSocket 是主数据通路**（双向全量消息，带单调 `seq`），HTTP 只做断线后批量补齐与文件传输；写操作带**乐观并发 `expectedVersion`**，冲突返回当前版本——移动端弱网重连的确定性重放靠这两件事保证。
- 配对与身份：**无密码、设备密钥对模型**（NaCl/TweetNaCl 签 challenge → 按 publicKey upsert 账户 → JWT）；扫码 QR 只编码 server URL + 临时挑战，**扫码后仍需已在登录的设备上批准，并配双端确认码**防钓鱼；happier 演化为四类 QR 流（加手机/恢复账户/连终端/Secret Key）并把"设备登录"与"终端/daemon 授权"分开。
- E2EE：legacy NaCl secretbox（XSalsa20-Poly1305）+ 新 dataKey 模式（AES-256-GCM，per-session/per-machine 密钥用 tweetnacl.box 封装）；服务器零知识只存 ciphertext。
- 移动功能：实时语音（ElevenLabs，可代答权限请求）、diff 渲染、会话 fork/rewind、git/worktree；happier 的 **Inbox 全局审批收件箱**（汇总权限请求/AskUserQuestion/ExitPlanMode）+ pending queue + steering + 跨机 handoff + smart notification routing（通知直达对应 session+server、不误投）。
- 活跃度：happy 近期以 App UX 打磨为主（cli-1.2.2 08-27）；happier 以 auth/协议/sync 底层工程为主（`ui-mobile-stable` 09-03 发版，dev 分支每日多提交）。

**claudecodeui（13.6k★，本机 Web UI）**

- 拓扑：响应式 React UI ↔ 自托管 Node/Express（`0.0.0.0:3001`，反代做 HTTPS/wss）↔ spawn 管理 CLI 进程（共享 `~/.claude` 会话与配置）；**单一 WebSocket 服务器按路径路由**（/ws、/shell、/desktop-notifications、/plugin-ws）。
- 鉴权：OSS 单用户密码 → JWT（SQLite）；WS upgrade 阶段验 JWT。
- 移动功能：**PWA（manifest + sw.js）+ Web Push(VAPID)**，通知事件枚举 `permission.required / run.failed / run.stopped / background_completed`；工具审批走 WS `permission_request` 帧。
- 活跃度：近 30 天 11 commits，v1.37.x 持续迭代。

**omnara（2.8k★，控制面 + 执行面分离）**：Go 控制面（Postgres/Redis/MinIO）+ 每机 `omnarad` daemon 外向拨号；RBAC + OAuth device grant；agent 本体是控制面事件日志、机器只是执行环境。**它是"另一条路"（自建 agent runtime），对插件形态参考价值低，仅架构思想可借**。

**ccpocket（1.1k★，Flutter 原生 App + 本机 bridge）——与本插件路线最同源**

- 拓扑：原生 App ↔ Node bridge（`0.0.0.0:8765` WebSocket）↔ Claude Agent SDK/Codex CLI（stdio 包装，非 fork）。
- **远程暴露方式与我们完全一致：局域网 QR/mDNS + 异地推荐 Tailscale**；可选 `BRIDGE_API_KEY` + `BRIDGE_ALLOWED_DIRS` 目录白名单做纵深；密钥存 iOS Keychain/Android Keystore。
- 移动功能（验证了移动端价值排序）：会话启停/恢复、**审批工具调用（命令/文件编辑/MCP/agent 提问）**、文件浏览器、git diff/暂存/提交、富输入（Markdown/语音/图片）、**弱网离线队列 + 重连补流**、推送（FCM 中继）、多机管理。
- 活跃度：近 30 天 30+ commits，几乎每日。

### 2.3 对标收敛出的七条通用结论

1. **传输层**：Tailscale/局域网 + 直连被 ccpocket 独立验证为成熟模式——我们不需要云中继（happy/happier 的中继主要服务于"无 Tailscale 用户"与跨机 handoff）。
2. **配对安全**：纯一次性令牌是底线；高星项目的进化方向是 challenge-response + 双端确认 + 设备密钥对；我们的"一次性令牌 + 持久设备凭证"（§5.2）落在合理区间（单用户 DSH 场景不需要"设备登录 vs 终端授权"的分离，happy 系是为多终端生态付出的复杂度）。
3. **移动端功能优先级**（多项目交叉验证）：会话查看/发消息是 GUI 天然能力（手机直连即得，无需插件增量）；插件的增量价值排序为 **审批/提问响应 > 完成通知（锁屏可达）> 多设备管理 > 附件/文件 > 语音**。
4. **弱网是移动端硬需求**：happier "WS 主通路 + 单调 seq + 乐观并发"、claudecodeui `chat.subscribe(lastSeq)` 重放、ccpocket 离线队列 + 重连补流——通知通道必须带 seq 与补流语义（§7.1 吸收）。
5. **通知闭环**：claudecodeui 的 Web Push + `permission_request` 帧证明正确形态是"**审批待办 → 锁屏推送 → 点开直达**"；happier 的 Inbox 进一步证明"**把审批从聊天流中解耦成全局收件箱 + smart routing（通知直达对应 session、不误投）是移动端最大体验杠杆**"（§7.2 吸收）。
6. **侵入性**：成功项目全部选择 wrapper/复用宿主（CLI/harness）而非替换；DSH 插件复用 harness 既有会话与审批面的路线与之同构。
7. **E2EE 的边界取舍**：happy/happier 对中继场景做零知识加密是因为**中继不可信**；我们的通道全程在 tailnet 私网内（等价于 happy 的自托管信任边界），且通知只传轻量事件不含正文、Web Push 协议自带 payload 加密——**插件级 E2EE 暂不做**，列为 §8 观察项（若未来通道承载会话正文再上）。

---

## 3. 定位决策：我们走哪条路线

**结论：走「tailnet 私网 + 浏览器/PWA 直连」路线，不做云中继、不做原生 App。**

论证（对标数据见 §2，此处是逻辑主干）：

1. **DSH 与 happy 的前提不同**。happy 解决的是"CLI 工具没有 UI"——所以它必须造客户端、造中继；DSH 已有完整 Web GUI，缺口只在网络正确性（§1.2-1）、安全地基（§1.2-2）与移动体验（§1.2-3）。为补三个缺口重造一整个移动客户端，性价比不成立。
2. **零依赖是本插件的立身之本**（3 个文件、零运行时依赖、无构建步骤）。云中继路线 = 服务器 + 账号体系 + 推送基础设施，超出个人插件的维护边界；happier 证明自托管 happy 形态可行，但那是"为 Claude Code 生态造客户端"的工作量级。
3. **Tailscale 已在链路里，且被独立验证**。ccpocket（1.1k★，Flutter 原生 App）在"可以做任何传输层"的前提下，仍然选择了局域网 QR + Tailscale 作为主通道——tailnet 私网（同账号设备可达 + 防火墙只放行 100.64/10）就是 happy 用 E2E 加密 + 云账号想逼近的安全边界。我们不需要再造信任层，需要的是**把现有信任层用对、用满**。
4. **高星项目的启示在功能优先级，不在架构**。happy/omnara 反复验证的移动端价值排序是：远程审批/提问响应 > 完成通知（锁屏可达）> 会话查看/续聊 > 语音。这个排序可以在 PWA + WS 通知 + Web Push 上逐层实现（§7 P2），不必换架构。

---

## 4. 迭代总览：四层，先修正确性，再谈体验

| 层 | 主题 | 一句话目标 | 版本 |
|---|---|---|---|
| P0 | 安全与正确性地基 | 二维码指向的地址**端到端可用**；配对凭证**重启不丢** | 0.3.0 |
| P1 | 移动体验 | 扫码 → 欢迎页 → **添加到主屏幕全屏使用** | 0.3.0 |
| P2 | agent 特化通知 | agent 完成/提问时**手机锁屏也能收到** | 0.4.0 |
| P3 | 可选与上游 | 硬校验网关 / api/gate 提案 / 语音 | 不排期 |

---

## 5. P0：安全与正确性地基

### 5.1 修 HTTP/2 信任围栏缺口（本迭代第一优先级）

问题回顾（§1.2-1）：HTTP/2 模式下手机 Host 是 ts.net 域名，不在 `resolveLanTrust` 自动派生的 IP 字面量里，`/api` 全 403——页面开得了、数据全没有，而设置页探测不到。

设计：

1. **探测升级**：`probeHttps` 成功后追加"围栏探测"——以目标域名为 Host 发一个无 Origin/Sec-Fetch 的请求到 `/api`（非浏览器请求，通过与否只取决于 Host 围栏），403 即判定围栏未放行。
2. **设置页新增清单项「API 信任围栏」**：未放行时红条显示 + 一键复制 patch 片段（注意 `id` 定向 patch 是整段 config 替换语义，片段必须完整自包含）：
   ```yaml
   - id: web-app
     config:
       trustedHosts:
         - yiyan.tailxxx.ts.net
   ```
3. **mint 前端到端校验**：生成配对二维码前自动跑「页面可达 + 围栏放行」双重探测，失败则拒绝生成并说明原因。原则：**绝不生成一个扫码后是空壳的二维码**。
4. 直连模式天然免疫（IP 字面量自动受信），清单项显示绿。

验收：HTTP/2 模式未配 trustedHosts → 设置页红条 + 可复制片段；配置后端到端探测绿，手机扫码后 Web GUI 数据正常加载。

### 5.2 设备凭证持久化

1. 设备表落盘 `~/.dsh/data/dsh-mobile-access/devices.json`（`DSH_HOME` 数据区；`mkdirSync recursive` + 临时文件 + rename 原子写；UTF-8 无 BOM）。
   结构：`{ deviceId, name?, secretHash, ua, ip, pairedAt, lastSeen, revoked? }`。
2. cookie 升级为**滚动 30 天**的设备凭证（`HttpOnly; SameSite=Lax`；HTTPS 模式追加 `Secure`），配对令牌仍一次性 15 分钟不变（安全语义不变）。
3. **多设备共存**：mint 新令牌不再清空设备表（现状 `devices.clear()` 是隐形单设备假设），设备列表逐个可撤销。
4. 重启后设备表仍在；「停止并撤销全部」= 清文件 + 失效所有 cookie。

验收：重启 `dsh web` 后设备列表保留；撤销设备 A 不影响设备 B。

### 5.3 polyfill 条件退役

tapIndex 注入前检测 `window.crypto.randomUUID` 已可用性（探测脚本内联于 polyfill 自身：只在缺失时定义——现状已如此）。迭代点：README/设置页标注"harness ≥ rc.6 可关闭"，`polyfill: true` 默认值改为 `auto`（探测到新前端行为时跳过注入，保持配置兼容）。

---

## 6. P1：移动体验（PWA + 配对落地页）

### 6.1 PWA manifest 注入（tapIndex → applyIndexTaps 链路已验证可用）

1. 插件 prefix 路由 serve `/mobile-access/manifest.webmanifest`（动态生成：name=DSH、start_url=/、display=standalone、theme_color 跟随 DSH 主题）+ 图标（内置 SVG/PNG，不引外链）。
2. tapIndex 注入 `<link rel="manifest">`、`theme-color`、`apple-touch-icon`——对桌面浏览器无副作用（不添加就没有行为），注入内容保持最小。
3. **不做 service worker**：在线会话型 GUI 的离线缓存没有正向价值，反而引入更新陷阱。manifest 单独即可达成"添加到主屏幕 → 全屏无地址栏"。

### 6.2 配对落地页（手机侧第一屏）

现状：accept 后 302 直奔 `/`（桌面布局）。改为 302 `/mobile-access/welcome`：

- 「已配对 ✓」+ 设备名（UA 解析）+ 凭证有效期；
- **添加到主屏幕引导**（iOS Safari 与 Android Chrome 分开文案）；
- 「进入主界面」按钮；
- P2 后在此页挂 Web Push 订阅入口（§7.2）。

验收：扫码后手机先看到欢迎页；从主屏幕图标点开为全屏 standalone。

---

## 7. P2：agent 特化通知（0.4.0）

### 7.1 SSE 通知通道（实现决策：SSE 替代 WS；挂载点与 seq/补流语义不变）

> **实现注记（v0.4.0 落地）**：设计原案是 `webServer.registerUpgrade` WebSocket 通道；零依赖约束下手写 WS 帧编解码（~150 行、mask/分片/关闭帧）风险高于收益，而本通道是**纯单向推送**，故改用 **SSE（Server-Sent Events）**——普通 prefix 路由即可（无需 registerUpgrade），EventSource 原生提供自动重连 + `Last-Event-ID`，恰好就是 §7.1 要求的"seq + 重连补流"，零依赖。若未来出现真正双向需求再上 WS。

- 路由 `GET ${pagePath}/events`：设备凭证 cookie 鉴权（无效 401），`text/event-stream` + 25s keepalive；断开时发布 `device.offline`、建立时发布 `device.online`。
- **seq + 重连补流**（对标结论 §2.3-4）：每事件单调 `seq`，服务端环形缓冲 200 条；客户端重连自动带 `Last-Event-ID`，服务端补发缺口；缺口超出缓冲则跳过（客户端下条即最新）。
- 事件分类（数据源 = harness `session/event` 全局事件总线，`ctx.on('session/event', (session, event) => …)` 已实测可订阅）：
  - 插件自有（零外部依赖）：`pair.changed`（mint/accept/revoke/stop）、`device.online/offline`；
  - agent 事件（classifySessionEvent 映射）：`ask.arrived`（tool/call = ask_user_question）、`run.completed`（turn/end）、`run.failed`（tool/result 带 error）、`todo.changed`（tool/call = todo_write）——**轻量事件**（kind + sessionId + ts，不含正文；assistant/chunk 等流式事件直接丢弃，防爆）。
- 前端：tapIndex 注入迷你 EventSource 客户端（~1KB），配对手机会话打开时 toast 呈现；桌面无 cookie 只发一次 401 即停。

### 7.2 Web Push（HTTP/2 模式专属增值）

- VAPID 密钥对本地生成存储；`sw.js` 由插件 serve；订阅入口在 welcome 页与设置页。
- **审批直达闭环**（对标结论 §2.3-5，happier Inbox / claudecodeui `permission_request` 的共同形态）：`ask.arrived` 触发锁屏推送 → 点击通知 deep-link 到对应会话的审批/提问 UI，而非首页；通知携带 session 标识做 **smart routing**（直达对应会话、不误投——单机 DSH 场景即 session id + server 无歧义）。
- 约束：Push API 需 HTTPS + 用户授权 → **只在 HTTP/2（tailscale serve HTTPS）模式可用**，与 §5.1 修复后的模式绑定，形成"HTTP/2 完整增值包"：更快（多路复用）+ 围栏正确 + 锁屏通知。
- 直连 HTTP 模式在设置页明示「通知不可用（需 HTTPS）」，绝不静默降级。

验收：手机锁屏时 agent 完成或提问 → 系统通知；点击唤起 GUI 并落到对应会话。

---

## 8. P3：可选与上游（本期不做，记录边界）

| 项 | 判断 |
|---|---|
| 移动网关代理（独立端口反代 + cookie 硬校验 + 方法白名单） | 真正解决"配对不硬拦 /api"的自力方案；零依赖手写反代可行，但维护面大、且 PRIVILEGED_METHODS 依然不可用。**默认不做**，待上游信号。 |
| 配对纵深增强（可选 PIN / API Key + 桌面端"已登录设备批准 + 双端确认码"） | happier 与 ccpocket（`BRIDGE_API_KEY` + 目录白名单）验证过的低成本纵深；§5.2 的设备凭证已是主体，此项作为**观察项**——当 tailnet 内存在不受控设备（共享账号）时再上。 |
| 通道 E2EE（NaCl secretbox / AES-GCM dataKey，happy 系模式） | happy/happier 做零知识加密的前提是**中继不可信**；我们全程 tailnet 私网 + 轻量事件不含正文 + Web Push 协议自带加密，收益边际。**观察项**——若未来通知通道承载会话正文/审批决策再上。 |
| 上游提案：api/gate 或设备凭证校验钩子 | 与 harness "until a real authentication layer exists" 的既定方向一致，值得提案；提案后本插件 §5.2 的设备凭证可直接成为 gate 的输入。 |
| 语音输入（Web Speech API） | 需 HTTPS；属 GUI 输入框增强，与本插件职责边界模糊，观察项。 |
| happy 式原生 App / 云中继 | **明确不做**（§3 定位决策）。 |

---

## 9. 风险与开放问题

1. **web-app patch 整段替换语义**：给用户的 trustedHosts 片段必须完整自包含（web-app 的 printUrl/surfaceContext 用默认值即可，但文档要写明"已有自定义 web-app config 的需手动合并"）。
2. **harness 升级移动语义**：trustedHosts/围栏逻辑属 harness 内部实现，升级可能变化——围栏探测进周期自检（§5.1），坏了对用户可见，而不是静默。
3. **sessionProjections 订阅能力未验证**：P2 第二期的前置，实施前先写 30 行验证脚本确认服务面。
4. **cookie 属性在两种模式下的差异**（Secure 仅 HTTPS 可加）：welcome 页与设置页要如实展示当前凭证形态。
5. **多设备并发的配对竞态**：mint/accept 目前单令牌单槽，多设备先后扫码各 mint 各 accept，需确认无互踩（现状 mint 清 current 不清 devices，改造后语义更清晰）。
6. **tapIndex 注入与桌面端共存**：manifest/theme-color 无桌面副作用，但注入要保持最小、幂等。
7. **WS 握手的 cookie 携带**：`/mobile-access/ws` upgrade 请求会自动带同源 cookie，但 `SameSite=Lax` 对 upgrade 握手的语义需实测（Lax 只放行顶级导航 GET，WS 握手是 GET——按规范应携带，但 Safari/Chrome 行为需在真机验证；不行则握手改用一次性 `?ticket=` 换 cookie）。
8. **PWA 图标资产**：manifest 图标需 PNG（iOS 不认 SVG 图标）；零依赖前提下内嵌一张 192/512 PNG（或生成时用 canvas 光栅化——不引构建步骤）。

---

## 10. 实施路径（遵循 D4：先本机验证，再上游仓库）

- **Phase 1 = P0（0.3.0 前半）**：围栏探测 + patch 片段 + 设备持久化；本机两模式（直连/HTTP2）回归；手机实测扫码 → GUI 数据加载。
- **Phase 2 = P1（0.3.0 后半）**：manifest + welcome 页；手机添加主屏幕实测。
- **Phase 3 = P2（0.4.0）**：WS 通道先行，Web Push 随后（仅 HTTP/2 模式）。
- 每阶段完成即推 GitHub（D5/D6：自有仓库、公开），README 同步更新功能表与 FAQ（尤其把 §1.2-1 的坑写进 FAQ）。
- 版本策略：0.3.0 = P0+P1；0.4.0 = P2；P3 不排期。
