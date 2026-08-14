// dsh-mobile-access — one-page mobile access setup for DeepSeek Harness.
//
// Pure host-side plugin (no client bundle, no build step, no runtime
// dependencies beyond Node builtins):
//  1. Serves a self-contained setup page at /mobile-access with a live
//     reachability checklist (bind host / Tailscale / firewall) and a
//     scan-to-open QR code rendered server-side (vendored MIT qrcode
//     generator — fully offline).
//  2. Optionally injects a crypto.randomUUID polyfill into index.html so the
//     desktop UI also runs on plain-HTTP LAN/Tailscale origins on harness
//     builds that predate the insecure-context fix.
//
// It never rebinds the webserver, never touches the firewall, and never
// logs anyone in — those are host-policy actions the page explains instead.
import { networkInterfaces } from 'node:os';
import qrcode from './qrcode.js';

export const name = 'mobile-access';

const DEFAULT_PAGE_PATH = '/mobile-access';

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

function pageHtml(state) {
  const { host, port, tailscale, lan, qr } = state;
  const bound = host === '0.0.0.0';
  const primary = tailscale[0] ?? lan[0] ?? null;
  const phoneUrl = primary ? `http://${primary}:${port}` : null;
  const fw = firewallCommand(port);
  const patch = bindPatchSnippet();
  const qrMarkup = qr ? qr : `<div class="qr-fallback">QR 生成失败</div>`;

  const statusDot = (ok) => `<span class="dot ${ok ? 'ok' : 'warn'}"></span>`;
  const mono = (v) => `<span class="mono">${htmlEscape(v)}</span>`;

  const tailscaleRow = tailscale.length
    ? `<li class="pass">${statusDot(true)}<div><b>Tailscale 已连接</b><p>tailnet 地址：${mono(tailscale.join('、'))}</p></div></li>`
    : `<li class="fail">${statusDot(false)}<div><b>未检测到 Tailscale</b><p>先装 <a href="https://tailscale.com/download">Tailscale</a> 并用任意账号登录，这里会实时出现 tailnet 地址。</p></div></li>`;

  const lanRow = lan.length
    ? `<li class="pass">${statusDot(true)}<div><b>局域网可用</b><p>${mono(lan.join('、'))}（同 WiFi 下手机可直接访问）</p></div></li>`
    : `<li class="fail">${statusDot(false)}<div><b>无局域网地址</b><p>仅 Tailscale 组网时忽略此项。</p></div></li>`;

  const bindRow = bound
    ? `<li class="pass">${statusDot(true)}<div><b>服务已绑定全部网卡</b><p>webserver host = ${mono('0.0.0.0:'.concat(String(port)))}，外部设备可以到达。</p></div></li>`
    : `<li class="fail">${statusDot(false)}<div><b>服务只绑定了本机回环</b><p>当前 host = ${mono(`${host}:${port}`)}，手机无法到达。重启 dsh web 时加 <span class="mono">--host 0.0.0.0</span>，或在 profile 的 cordis.patch.yml 里固化：</p><pre>${htmlEscape(patch)}</pre></div></li>`;

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
  .url{font:600 15px/1.4 ui-monospace,Consolas,monospace;color:var(--cyan);word-break:break-all}
  .hint{color:var(--muted);font-size:12.5px}
  button.copy{font:600 12px/1 ui-monospace,Consolas,monospace;color:var(--bg);background:var(--amber);border:none;border-radius:7px;padding:8px 14px;cursor:pointer;letter-spacing:.05em}
  button.copy:hover{filter:brightness(1.08)}
  button.copy:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
  button.copy.copied{background:var(--green)}
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
    <p>同一台机器、同一份会话。手机扫码后即可远程规划、执行、追溯。</p>
    <div class="statusline"><span class="pulse ${primary ? '' : 'off'}"></span>${primary ? 'BEACON ACTIVE' : 'BEACON OFFLINE'}</div>
  </header>
  ${phoneUrl ? `<section class="card beacon">
    <div class="rings">${qrMarkup}</div>
    <div class="url">${htmlEscape(phoneUrl)}</div>
    <button class="copy" data-copy="${htmlEscape(phoneUrl)}">复制地址</button>
    <p class="hint">手机安装 Tailscale 并用同一账号登录后，扫码（或手动输入地址）即可打开 DSH。</p>
  </section>` : `<section class="card beacon"><p class="hint">没有可用的网络地址——先完成下面清单里的 Tailscale 或局域网步骤，再刷新本页。</p></section>`}
  <ul class="check">
    ${bindRow}
    ${tailscaleRow}
    ${lanRow}
    ${fwRow}
  </ul>
  <footer>dsh-mobile-access · QR 由内建生成器离线绘制 · 搭配 dsh-remote-web-ui 可获得配对令牌鉴权与专用移动端界面</footer>
</main>
<script>
  document.querySelectorAll('.copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy');
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () { flash(); }, function () { fallback(); });
      } else { fallback(); }
      function fallback() {
        var ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); flash(); } catch (e) {}
        document.body.removeChild(ta);
      }
      function flash() {
        btn.textContent = '已复制';
        btn.classList.add('copied');
        setTimeout(function () { btn.textContent = '复制'; btn.classList.remove('copied'); }, 1500);
      }
    });
  });
</script>
</body>
</html>`;
}

function statusJson(state) {
  return JSON.stringify(
    {
      host: state.host,
      port: state.port,
      boundToAllInterfaces: state.host === '0.0.0.0',
      tailscale: state.tailscale,
      lan: state.lan,
      phoneUrl: state.tailscale[0] ?? state.lan[0] ? `http://${(state.tailscale[0] ?? state.lan[0])}:${state.port}` : null,
      firewallCommand: firewallCommand(state.port),
    },
    null,
    2,
  );
}

export function apply(ctx, config = {}) {
  const ws = ctx.get('webServer');
  if (ws === undefined) return;
  const options = { pagePath: DEFAULT_PAGE_PATH, polyfill: true, ...config };
  const disposers = [];

  const route = {
    kind: 'prefix',
    path: options.pagePath,
    handler: (req, res) => {
      const { tailscale, lan } = detectAddresses();
      const state = { host: ws.host, port: ws.port, tailscale, lan };
      if (req.url.startsWith(`${options.pagePath}/status.json`)) {
        const body = statusJson(state);
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
        res.end(body);
        return;
      }
      state.qr = (() => {
        const primary = tailscale[0] ?? lan[0];
        return primary ? qrSvg(`http://${primary}:${state.port}`) : null;
      })();
      const body = pageHtml(state);
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
