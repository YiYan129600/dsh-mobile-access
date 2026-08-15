// dsh-mobile-access — mobile access setup + pairing for DeepSeek Harness.
//
// Host-only plugin (no client bundle, no build step, zero runtime deps):
//  1. Serves a setup page at /mobile-access: reachability checklist, an
//     address picker (Tailscale 公网 / 局域网), and a scan-to-pair QR flow.
//  2. Owns the pairing protocol on /mobile-access/api/pair/*: one-time
//     tokens, device registry, heartbeat, and revocation. The paired phone
//     lands on the regular web UI.
//  3. Optionally injects a crypto.randomUUID polyfill into index.html so the
//     web UI also runs on plain-HTTP phone origins on older harness builds.
//
// Security notes: mint/stop endpoints are loopback-only. This harness has no
// api/gate seam, so pairing does not hard-gate the main /api — keep the
// recommended firewall posture (Tailscale 100.64/10 only) as the boundary.
import { networkInterfaces } from 'node:os';
import { randomUUID } from 'node:crypto';
import https from 'node:https';
import { spawn } from 'node:child_process';
import qrcode from './qrcode.js';

export const name = 'mobile-access';

/** Hard dependency: cordis only injects services the plugin declares. */
export const inject = ['webServer'];

const DEFAULT_PAGE_PATH = '/mobile-access';
const PAIR_COOKIE = 'dsh_mob_pair';
const DEFAULT_PAIR_TTL_MS = 15 * 60 * 1000;

/** True for Tailscale's CGNAT range 100.64.0.0/10. */
function isTailscaleIp(ip) {
  const m = /^(\d+)\.(\d+)\./.exec(ip);
  if (!m) return false;
  const o1 = Number(m[1]);
  const o2 = Number(m[2]);
  return o1 === 100 && o2 >= 64 && o2 <= 127;
}

/** IPv4 addresses on this host, tagged by reachability class. */
function detectAddresses() {
  const tailscale = [];
  const lan = [];
  for (const addrs of Object.values(networkInterfaces())) {
    for (const addr of addrs ?? []) {
      if (addr.family !== 'IPv4' || addr.internal) continue;
      if (isTailscaleIp(addr.address)) tailscale.push(addr.address);
      else lan.push(addr.address);
    }
  }
  return { tailscale, lan };
}

/** Server-side QR as an inline SVG string, or null on failure. */
function qrSvg(text) {
  try {
    const qr = qrcode(0, 'M');
    qr.addData(text, 'Byte');
    qr.make();
    return qr.createSvgTag({ cellSize: 6, margin: 2, scalable: true });
  } catch {
    return null;
  }
}

function htmlEscape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

/**
 * Run a Tailscale CLI command elevated via UAC (Windows). The user confirms
 * the elevation dialog; `tailscale serve` config persists in tailscaled.
 * @param bin - absolute path to tailscale.exe.
 * @param args - CLI arguments.
 * @returns exit code (0 = success), or -1 on spawn failure.
 */
function runTailscaleElevated(bin, args) {
  return new Promise((resolve) => {
    const quoted = args.map((a) => `'${a.replaceAll("'", "''")}'`).join(',');
    const script = `try { Start-Process -FilePath '${bin.replaceAll("'", "''")}' -ArgumentList ${quoted} -Verb RunAs -Wait -PassThru | Out-Null; exit 0 } catch { exit 1 }`;
    const child = spawn('powershell.exe', ['-NoProfile', '-WindowStyle', 'Hidden', '-Command', script], { stdio: 'ignore', windowsHide: true });
    child.on('error', () => resolve(-1));
    child.on('exit', (code) => resolve(code ?? -1));
  });
}

/** Probe an HTTPS origin from the host (serve reachability check). */
function probeHttps(hostname) {
  return new Promise((resolve) => {
    const req = https.get(`https://${hostname}/`, { timeout: 6000 }, (res) => {
      res.resume();
      resolve({ ok: res.statusCode >= 200 && res.statusCode < 500, status: res.statusCode });
    });
    req.on('error', (err) => resolve({ ok: false, error: err.code ?? err.message }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: 'timeout' });
    });
  });
}

/** True when the request Host authority is a loopback literal. */
function isLoopbackAuthority(hostHeader) {
  if (!hostHeader) return false;
  try {
    const hostname = new URL(`http://${hostHeader}`).hostname;
    if (hostname === 'localhost' || hostname === '[::1]') return true;
    const parts = hostname.split('.');
    return parts.length === 4 && parts[0] === '127' && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
  } catch {
    return false;
  }
}

function parseCookies(header) {
  const out = {};
  for (const pair of String(header ?? '').split(';')) {
    const idx = pair.indexOf('=');
    if (idx <= 0) continue;
    out[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
  }
  return out;
}

/** In-memory pairing state: one active token, a device registry. */
function createPairService(ttlMs) {
  let current = null;
  const devices = new Map();
  return {
    mint() {
      const token = randomUUID().replaceAll('-', '').slice(0, 20);
      current = { token, createdAt: Date.now(), expiresAt: Date.now() + ttlMs };
      devices.clear();
      return current;
    },
    accept(token, meta) {
      if (!current || current.token !== token) return null;
      if (Date.now() > current.expiresAt) return { expired: true };
      const id = randomUUID();
      devices.set(id, { id, ...meta, pairedAt: Date.now(), lastSeen: Date.now() });
      current = null; // one-time: the token dies with its first successful accept
      return { id };
    },
    heartbeat(id) {
      const device = devices.get(id);
      if (!device) return false;
      device.lastSeen = Date.now();
      return true;
    },
    list() {
      return [...devices.values()].map((d) => ({
        id: d.id,
        ip: d.ip,
        ua: d.ua,
        pairedAt: d.pairedAt,
        lastSeen: d.lastSeen,
      }));
    },
    snapshot(token) {
      const deviceList = this.list();
      const phase = deviceList.length > 0 ? 'connected' : current !== null && Date.now() <= current.expiresAt ? 'waiting' : 'stopped';
      return {
        phase,
        token: token ?? current?.token ?? null,
        devices: deviceList,
      };
    },
    stop() {
      current = null;
      devices.clear();
    },
  };
}

function readJsonBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        resolve(null);
      }
    });
    req.on('error', () => resolve(null));
  });
}

function sendJson(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

const UUID_POLYFILL =
  '<script>if(typeof crypto.randomUUID!=="function"){crypto.randomUUID=function(){var b=crypto.getRandomValues(new Uint8Array(16));b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;var h=Array.prototype.map.call(b,function(x){return x.toString(16).padStart(2,"0")});return h.slice(0,4).join("")+"-"+h.slice(4,6).join("")+"-"+h.slice(6,8).join("")+"-"+h.slice(8,10).join("")+"-"+h.slice(10).join("");};}</script>';

function injectPolyfill(html) {
  const lower = html.toLowerCase();
  const idx = lower.indexOf('<head');
  if (idx === -1) return UUID_POLYFILL + html;
  const insertAt = html.indexOf('>', idx) + 1;
  return html.slice(0, insertAt) + UUID_POLYFILL + html.slice(insertAt);
}

function firewallCommand(port) {
  return `netsh advfirewall firewall add rule name="DSH Web (Tailscale)" dir=in action=allow protocol=TCP localport=${port} remoteip=100.64.0.0/10 profile=any`;
}

function bindPatchSnippet() {
  return [
    '# in the profile cordis.patch.yml:',
    '- id: webserver',
    '  config:',
    '    host: 0.0.0.0',
    '    port: !!js ctx.webStartup.port ?? 3080',
  ].join('\n');
}

function pageHtml(state, pairState) {
  const { host, port, tailscale, lan } = state;
  const bound = host === '0.0.0.0';
  const fw = firewallCommand(port);
  const patch = bindPatchSnippet();
  const addresses = [
    ...tailscale.map((a) => ({ address: a, label: 'Tailscale 公网' })),
    ...lan.map((a) => ({ address: a, label: '局域网' })),
  ];
  const hasAny = addresses.length > 0;
  const statusDot = (ok) => `<span class="dot ${ok ? 'ok' : 'warn'}"></span>`;
  const mono = (v) => `<span class="mono">${htmlEscape(v)}</span>`;

  const picker = hasAny
    ? `<ul class="addrlist">${addresses
        .map(
          (a, i) => `<li><label><input type="radio" name="addr" value="${htmlEscape(a.address)}" ${i === 0 ? 'checked' : ''}><span class="alabel">${htmlEscape(a.label)}</span><code class="mono">${htmlEscape(a.address)}</code></label></li>`,
        )
        .join('')}</ul>`
    : `<p class="hint">没有可用地址——先完成下方清单里的 Tailscale 步骤。</p>`;

  const bindRow = bound
    ? `<li class="pass">${statusDot(true)}<div><b>服务已绑定全部网卡</b><p>webserver host = ${mono('0.0.0.0:'.concat(String(port)))}，外部设备可以到达。</p></div></li>`
    : `<li class="fail">${statusDot(false)}<div><b>服务只绑定了本机回环</b><p>当前 host = ${mono(`${host}:${port}`)}，手机无法到达。重启 dsh web 时加 <span class="mono">--host 0.0.0.0</span>，或在 profile 的 cordis.patch.yml 里固化：</p><pre>${htmlEscape(patch)}</pre></div></li>`;

  const tailscaleRow = tailscale.length
    ? `<li class="pass">${statusDot(true)}<div><b>Tailscale 已连接</b><p>tailnet 地址：${mono(tailscale.join('、'))}（任何网络可用，手机登录同一账号即可）</p></div></li>`
    : `<li class="fail">${statusDot(false)}<div><b>未检测到 Tailscale</b><p>先装 <a href="https://tailscale.com/download">Tailscale</a> 并登录，这里会实时出现 tailnet 地址。</p></div></li>`;

  const lanRow = lan.length
    ? `<li class="pass">${statusDot(true)}<div><b>局域网可用</b><p>${mono(lan.join('、'))}（仅同一网络下手机可访问）</p></div></li>`
    : `<li class="fail">${statusDot(false)}<div><b>无局域网地址</b><p>仅 Tailscale 组网时忽略此项。</p></div></li>`;

  const fwRow = `<li class="warn">${statusDot('maybe')}<div><b>防火墙需放行一次</b><p>管理员 PowerShell 执行（只放行 Tailscale 网段，公网不暴露）：</p><pre>${htmlEscape(fw)}</pre><button class="copy" data-copy="${htmlEscape(fw)}">复制命令</button></div></li>`;

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mobile Access — DSH</title>
<style>
  :root{
    --bg:#101820;--panel:#18222d;--line:#26323f;--text:#e8ecf0;--muted:#8a97a5;
    --amber:#ffb02e;--cyan:#4fc3f7;--green:#3fbf7f;--red:#e5604e;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font:15px/1.6 system-ui,"Segoe UI","Microsoft YaHei",sans-serif;
       display:flex;justify-content:center;padding:40px 16px;min-height:100vh}
  main{width:100%;max-width:640px}
  header .eyebrow{font:600 11px/1 ui-monospace,Consolas,monospace;letter-spacing:.22em;color:var(--amber);text-transform:uppercase}
  h1{font-size:26px;font-weight:700;letter-spacing:.01em;margin:6px 0 2px}
  header p{color:var(--muted);font-size:13px}
  .statusline{display:flex;align-items:center;gap:8px;margin-top:14px;font:600 12px/1 ui-monospace,Consolas,monospace;color:var(--muted);letter-spacing:.08em}
  .pulse{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 rgba(63,191,127,.55);animation:pulse 2.4s infinite}
  .pulse.off{background:var(--red);box-shadow:none;animation:none}
  @keyframes pulse{70%{box-shadow:0 0 0 10px rgba(63,191,127,0)}100%{box-shadow:0 0 0 0 rgba(63,191,127,0)}}
  @media (prefers-reduced-motion:reduce){.pulse{animation:none}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-top:20px}
  .beacon{display:flex;flex-direction:column;align-items:center;text-align:center;gap:14px}
  .rings{position:relative;padding:34px}
  .rings::before,.rings::after{content:"";position:absolute;inset:0;border-radius:50%;border:1px solid var(--line)}
  .rings::before{inset:8px;border-color:rgba(79,195,247,.35)}
  .rings::after{inset:18px;border-style:dashed;border-color:rgba(79,195,247,.25)}
  .rings svg{position:relative;display:block;background:#fff;border-radius:6px;width:190px;height:190px}
  .qr-empty{position:relative;width:190px;height:190px;display:flex;align-items:center;justify-content:center;background:#fff;border-radius:6px;color:#8a97a5;font:12px ui-monospace,Consolas,monospace}
  .url{font:600 15px/1.4 ui-monospace,Consolas,monospace;color:var(--cyan);word-break:break-all}
  .hint{color:var(--muted);font-size:12.5px}
  button{font:600 12px/1 ui-monospace,Consolas,monospace;color:#fff;background:var(--amber);border:none;border-radius:7px;padding:8px 14px;cursor:pointer;letter-spacing:.05em}
  button:hover{filter:brightness(1.08)}
  button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
  button.ghost{background:transparent;color:var(--muted);border:1px solid var(--line)}
  button.copied{background:var(--green)}
  .addrlist{list-style:none;display:flex;flex-direction:column;gap:8px;margin-top:4px;text-align:left}
  .addrlist label{display:flex;align-items:center;gap:10px;background:#0c141b;border:1px solid var(--line);border-radius:9px;padding:10px 12px;cursor:pointer}
  .addrlist input{accent-color:var(--cyan)}
  .alabel{font-size:13px;color:var(--text)}
  .modeline{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:8px}
  .modeline label{display:flex;align-items:center;gap:8px;font-size:13.5px;cursor:pointer}
  .modeline input{accent-color:var(--cyan)}
  .devices{margin-top:10px;font-size:12.5px;color:var(--muted);text-align:left}
  ul.check{list-style:none;display:flex;flex-direction:column;gap:12px;margin-top:20px}
  ul.check li{display:flex;gap:12px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
  ul.check b{font-size:14.5px}
  ul.check p{color:var(--muted);font-size:13px;margin-top:3px}
  ul.check .mono,pre,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
  .mono{color:var(--cyan)}
  pre{background:#0c141b;border:1px solid var(--line);border-radius:9px;padding:12px;margin-top:8px;overflow-x:auto;color:#cfe3ee}
  ul.check .copy{margin-top:10px}
  .dot{flex:none;width:9px;height:9px;border-radius:50%;margin-top:6px}
  .dot.ok{background:var(--green)}.dot.warn{background:var(--amber)}.dot.err{background:var(--red)}
  a{color:var(--cyan)}
  footer{margin-top:26px;color:var(--muted);font-size:12px;text-align:center}
</style>
</head>
<body>
<main>
  <header>
    <div class="eyebrow">DSH · Mobile Access</div>
    <h1>把手机接进来</h1>
    <p>选择网络 → 生成配对二维码 → 手机扫码即用。同一台机器、同一份会话。</p>
    <div class="statusline"><span class="pulse ${hasAny ? '' : 'off'}"></span>${hasAny ? 'BEACON ACTIVE' : 'BEACON OFFLINE'}</div>
  </header>
  <section class="card beacon">
    <div class="rings"><div class="qr-empty" id="pairqr">未生成</div></div>
    <div class="url" id="pairurl">选择地址后点「生成配对二维码」</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:center">
      <button id="mint">生成配对二维码</button>
      <button id="stop" class="ghost">停止并撤销全部手机</button>
    </div>
    <div class="devices" id="devices"></div>
    <div style="width:100%;text-align:left;margin-top:6px">
      <div class="modeline">
        <label><input type="radio" name="mode" value="direct" checked><span>直连 HTTP</span></label>
        <label><input type="radio" name="mode" value="http2"><span>HTTP/2（Tailscale Serve，更快）</span></label>
      </div>
    </div>
    <div style="width:100%;text-align:left;margin-top:6px" id="directPanel">${picker}</div>
    <div style="width:100%;text-align:left;margin-top:6px;display:none" id="http2Panel">
      <label style="font-size:12.5px;color:var(--muted)">HTTPS 域名（Tailscale MagicDNS，形如 主机名.tailxxx.ts.net）</label>
      <input id="http2host" type="text" placeholder="yiyan.tail172eda.ts.net" style="width:100%;margin-top:6px;padding:9px 12px;background:#0c141b;border:1px solid var(--line);border-radius:9px;color:var(--text);font:13px ui-monospace,Consolas,monospace">
      <div style="display:flex;gap:10px;margin-top:10px">
        <button id="http2on">开启 HTTP/2</button>
        <button id="http2off" class="ghost">关闭 HTTP/2</button>
      </div>
      <p class="hint" id="http2status" style="margin-top:8px">开启会弹出 UAC 授权框（请点「是」）；开启后二维码指向 https 地址，手机端多路复用加载更快。</p>
    </div>
    <p class="hint">二维码有效期 15 分钟，仅限一次配对；手机扫码后自动打开 DSH 主界面。</p>
  </section>
  <ul class="check">
    ${bindRow}
    ${tailscaleRow}
    ${lanRow}
    ${fwRow}
  </ul>
  <footer>dsh-mobile-access · 二维码由内建生成器离线绘制 · 配对状态保存在本机内存，重启 dsh 后需重新生成</footer>
</main>
<script>
  var addrInputs = document.querySelectorAll('input[name=addr]');

  // Theme bridge: the parent shell forwards resolved DSH design tokens via
  // postMessage (the iframe document cannot read them directly). Map them
  // onto this page's palette and follow color-scheme changes live.
  function applyDshTheme(m) {
    if (!m || !m.colors) return;
    var map = {
      '--bg': m.colors.bg,
      '--panel': m.colors.panel,
      '--line': m.colors.line,
      '--text': m.colors.text,
      '--muted': m.colors.muted,
      '--amber': m.colors.brand,
      '--cyan': m.colors.brand,
      '--green': m.colors.ok,
      '--red': m.colors.err,
    };
    var root = document.documentElement;
    for (var k in map) if (map[k]) root.style.setProperty(k, map[k]);
    root.style.colorScheme = m.dark ? 'dark' : 'light';
  }
  window.addEventListener('message', function (e) {
    if (e.data && e.data.type === 'dsh-theme') applyDshTheme(e.data);
  });
  function selectedAddr() {
    for (var i = 0; i < addrInputs.length; i++) if (addrInputs[i].checked) return addrInputs[i].value;
    return null;
  }
  function setQr(html) { document.getElementById('pairqr').outerHTML = html; }
  function flash(btn) {
    btn.classList.add('copied');
    var old = btn.textContent;
    btn.textContent = '已复制';
    setTimeout(function () { btn.textContent = old; btn.classList.remove('copied'); }, 1500);
  }
  function copyText(text, btn) {
    function done() { flash(btn); }
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch (e) {}
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  }
  var modeInputs = document.querySelectorAll('input[name=mode]');
  function currentMode() {
    for (var i = 0; i < modeInputs.length; i++) if (modeInputs[i].checked) return modeInputs[i].value;
    return 'direct';
  }
  function syncModePanels() {
    var mode = currentMode();
    document.getElementById('directPanel').style.display = mode === 'direct' ? '' : 'none';
    document.getElementById('http2Panel').style.display = mode === 'http2' ? '' : 'none';
    try { localStorage.setItem('dsh-ma-mode', mode); } catch (e) {}
  }
  for (var i = 0; i < modeInputs.length; i++) modeInputs[i].addEventListener('change', syncModePanels);
  var savedMode = null;
  try { savedMode = localStorage.getItem('dsh-ma-mode'); } catch (e) {}
  if (savedMode) {
    for (var i = 0; i < modeInputs.length; i++) if (modeInputs[i].value === savedMode) modeInputs[i].checked = true;
    syncModePanels();
  }
  var hostInput = document.getElementById('http2host');
  try { var savedHost = localStorage.getItem('dsh-ma-http2-host'); if (savedHost) hostInput.value = savedHost; } catch (e) {}
  hostInput.addEventListener('change', function () {
    try { localStorage.setItem('dsh-ma-http2-host', hostInput.value.trim()); } catch (e) {}
  });
  function http2Status(text) { document.getElementById('http2status').textContent = text; }

  document.getElementById('mint').addEventListener('click', function () {
    var payload;
    if (currentMode() === 'http2') {
      var hostname = hostInput.value.trim();
      if (!hostname) { alert('请先填写 HTTPS 域名'); return; }
      payload = { mode: 'http2', hostname: hostname };
    } else {
      var addr = selectedAddr();
      if (!addr) { alert('没有可用地址'); return; }
      payload = { address: addr };
    }
    fetch('/mobile-access/api/pair/mint', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (!data.ok) { alert(data.error || '生成失败'); return; }
      setQr(data.qrSvg);
      var urlEl = document.getElementById('pairurl');
      urlEl.textContent = data.url;
      urlEl.onclick = function () { copyText(data.url, urlEl); };
      urlEl.style.cursor = 'pointer';
      refreshStatus();
    });
  });

  document.getElementById('http2on').addEventListener('click', function () {
    var hostname = hostInput.value.trim();
    if (!hostname) { alert('请先填写 HTTPS 域名'); return; }
    http2Status('正在启动，请留意屏幕上的 UAC 授权框并点「是」…');
    fetch('/mobile-access/api/http2/enable', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hostname: hostname })
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (!d.ok) { http2Status('开启失败：' + (d.error || d.code)); return; }
      var p = d.probe || {};
      http2Status(p.ok
        ? '已开启：https://' + hostname + ' 可访问（HTTP/2 生效中，可回到上方生成二维码）'
        : 'serve 已启动但探测未通过（' + (p.error || p.status) + '），等证书签发后再试一次');
    });
  });
  document.getElementById('http2off').addEventListener('click', function () {
    fetch('/mobile-access/api/http2/disable', { method: 'POST' }).then(function (r) { return r.json(); }).then(function (d) {
      http2Status(d.ok ? '已关闭，恢复直连模式' : '关闭失败');
    });
  });
  document.getElementById('stop').addEventListener('click', function () {
    fetch('/mobile-access/api/pair/stop', { method: 'POST' }).then(function () {
      document.getElementById('pairqr').innerHTML = '未生成';
      document.getElementById('pairurl').textContent = '已停止';
      refreshStatus();
    });
  });
  function refreshStatus() {
    fetch('/mobile-access/api/pair/status').then(function (r) { return r.json(); }).then(function (s) {
      var el = document.getElementById('devices');
      if (!s) return;
      if (s.phase === 'waiting') el.textContent = '等待手机扫码…';
      else if (s.phase === 'stopped') el.textContent = '未开启配对';
      else if (s.phase === 'expired') el.textContent = '二维码已过期，请重新生成';
      else if (s.devices && s.devices.length) {
        el.textContent = '已配对设备：' + s.devices.map(function (d) { return d.ip || 'unknown'; }).join('、');
      }
    });
  }
  setInterval(refreshStatus, 4000);
  refreshStatus();
</script>
</body>
</html>`;
}

function statusJson(state, pairState) {
  const primary = state.tailscale[0] ?? state.lan[0] ?? null;
  return JSON.stringify(
    {
      host: state.host,
      port: state.port,
      boundToAllInterfaces: state.host === '0.0.0.0',
      tailscale: state.tailscale,
      lan: state.lan,
      phoneUrl: primary ? `http://${primary}:${state.port}` : null,
      firewallCommand: firewallCommand(state.port),
      pair: pairState.snapshot(),
    },
    null,
    2,
  );
}

export function apply(ctx, config = {}) {
  const ws = ctx.get('webServer');
  if (ws === undefined) return;
  const options = {
    pagePath: DEFAULT_PAGE_PATH,
    polyfill: true,
    pairTtlMs: DEFAULT_PAIR_TTL_MS,
    ...config,
  };
  const pair = createPairService(options.pairTtlMs);
  const disposers = [];

  const route = {
    kind: 'prefix',
    path: options.pagePath,
    handler: async (req, res) => {
      const { tailscale, lan } = detectAddresses();
      const state = { host: ws.host, port: ws.port, tailscale, lan };
      const url = req.url ?? '';
      const api = `${options.pagePath}/api`;

      if (url.startsWith(`${api}/pair/mint`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'mint is loopback-only' });
        const body = await readJsonBody(req);
        const mode = body?.mode === 'http2' ? 'http2' : 'direct';
        let pairBase;
        if (mode === 'http2') {
          const hostname = typeof body?.hostname === 'string' && body.hostname !== '' ? body.hostname : null;
          if (!hostname) return sendJson(res, 400, { ok: false, error: 'hostname required for http2 mode' });
          pairBase = `https://${hostname}`;
        } else {
          const address = typeof body?.address === 'string' ? body.address : tailscale[0] ?? lan[0];
          if (!address) return sendJson(res, 400, { ok: false, error: 'no address available' });
          if (!tailscale.includes(address) && !lan.includes(address)) return sendJson(res, 400, { ok: false, error: 'unknown address' });
          pairBase = `http://${address}:${state.port}`;
        }
        const active = pair.mint();
        const pairUrl = `${pairBase}/?pair=${active.token}`;
        return sendJson(res, 200, { ok: true, url: pairUrl, token: active.token, expiresAt: active.expiresAt, qrSvg: qrSvg(pairUrl) ?? null });
      }

      if (url.startsWith(`${api}/http2/enable`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'enable is loopback-only' });
        const body = await readJsonBody(req);
        const hostname = typeof body?.hostname === 'string' && body.hostname !== '' ? body.hostname : null;
        if (!hostname) return sendJson(res, 400, { ok: false, error: 'hostname required' });
        const targetPort = Number.isInteger(body?.targetPort) ? body.targetPort : state.port;
        const bin = options.http2?.tailscaleBin ?? 'C:\\Program Files\\Tailscale\\tailscale.exe';
        const code = await runTailscaleElevated(bin, ['serve', '--bg', String(targetPort)]);
        if (code !== 0) return sendJson(res, 500, { ok: false, error: 'serve 启动失败（UAC 未授权或 Tailscale 未安装）', code });
        const probe = await probeHttps(hostname);
        return sendJson(res, 200, { ok: true, probe });
      }

      if (url.startsWith(`${api}/http2/disable`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'disable is loopback-only' });
        const bin = options.http2?.tailscaleBin ?? 'C:\\Program Files\\Tailscale\\tailscale.exe';
        const code = await runTailscaleElevated(bin, ['serve', 'unset']);
        return sendJson(res, code === 0 ? 200 : 500, { ok: code === 0, code });
      }

      if (url.startsWith(`${api}/http2/probe`)) {
        const hostname = new URL(url, 'http://x').searchParams.get('hostname');
        if (!hostname) return sendJson(res, 400, { ok: false, error: 'hostname required' });
        return sendJson(res, 200, await probeHttps(hostname));
      }

      if (url.startsWith(`${api}/pair/accept`)) {
        const token = new URL(url, 'http://x').searchParams.get('pair');
        const result = pair.accept(token, { ip: req.socket.remoteAddress ?? null, ua: String(req.headers['user-agent'] ?? '').slice(0, 120) });
        if (result === null || result.expired) {
          return sendJson(res, 403, { ok: false, error: result?.expired ? 'pair token expired' : 'invalid pair token' });
        }
        const cookie = `${PAIR_COOKIE}=${result.id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(options.pairTtlMs / 1000)}`;
        res.writeHead(302, { location: '/', 'set-cookie': cookie, 'content-length': '0' });
        return res.end();
      }

      if (url.startsWith(`${api}/pair/heartbeat`)) {
        const cookies = parseCookies(req.headers.cookie);
        const ok = pair.heartbeat(cookies[PAIR_COOKIE]);
        return sendJson(res, ok ? 200 : 401, { ok });
      }

      if (url.startsWith(`${api}/pair/stop`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'stop is loopback-only' });
        pair.stop();
        return sendJson(res, 200, { ok: true });
      }

      if (url.startsWith(`${api}/pair/status`)) {
        return sendJson(res, 200, pair.snapshot());
      }

      if (url.startsWith(`${options.pagePath}/status.json`)) {
        const body = statusJson(state, pair);
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
        return res.end(body);
      }

      const body = pageHtml(state, pair.snapshot());
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body) });
      res.end(body);
    },
  };
  disposers.push(ws.register(route));

  if (options.polyfill && typeof ws.tapIndex === 'function') {
    const dispose = ws.tapIndex((html) => injectPolyfill(html));
    if (typeof dispose === 'function') disposers.push(dispose);
  }

  ctx.on('dispose', () => {
    for (const dispose of disposers) {
      try {
        dispose();
      } catch {}
    }
  });
}
