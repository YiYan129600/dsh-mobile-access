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
import { networkInterfaces, hostname, tmpdir, homedir } from 'node:os';
import {
  randomUUID,
  randomBytes,
  createHash,
  createHmac,
  createCipheriv,
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  hkdfSync,
  sign as cryptoSign,
  ECDH,
} from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { spawn, execFile } from 'node:child_process';
import { readFileSync, unlinkSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import qrcode from './qrcode.js';

export const name = 'mobile-access';

/** Hard dependency: cordis only injects services the plugin declares. */
export const inject = ['webServer'];

const DEFAULT_PAGE_PATH = '/mobile-access';
const PAIR_COOKIE = 'dsh_mob_pair';
const DEFAULT_PAIR_TTL_MS = 15 * 60 * 1000;
const DEVICE_COOKIE_MAX_AGE_S = 30 * 24 * 3600; // rolling 30-day device credential

/**
 * Parse the Tailscale adapter's connection-specific DNS suffix out of
 * `ipconfig /all` output (the only non-admin Windows source). Pure function
 * so the parser is unit-testable.
 * @param stdout - raw ipconfig /all text.
 * @returns the suffix (e.g. `tail172eda.ts.net`) or null.
 */
export function parseTailscaleSuffix(stdout) {
  if (typeof stdout !== 'string' || stdout === '') return null;
  const lines = stdout.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (!/tailscale/i.test(lines[i])) continue;
    for (let j = i + 1; j < Math.min(i + 14, lines.length); j++) {
      if (/adapter/i.test(lines[j]) && j > i + 1) break;
      const m = /connection-specific DNS Suffix\s*\.\s*:\s*([a-z0-9.-]+)/i.exec(lines[j]);
      if (m) return m[1].toLowerCase();
    }
  }
  return null;
}

/**
 * Detect the tailnet MagicDNS suffix (cached; best effort, never throws).
 * Runs `ipconfig /all` with the output redirected to a temp FILE instead of
 * capturing stdout through a pipe: restricted host environments forbid
 * pipe-based stdio capture, while cmd's own file redirect works everywhere.
 */
/**
 * Detect the tailnet MagicDNS suffix (cached; best effort, never throws).
 * Strategy 1: pipe capture with the absolute ipconfig path (normal hosts).
 * Strategy 2: cmd file redirect into the DSH home (hosts where pipe-based
 * stdio capture is restricted). Failure degrades to null — the page input
 * persists the user's manual value in localStorage instead.
 */
let tailnetSuffixCache;
function detectTailnetSuffix() {
  if (tailnetSuffixCache !== undefined) return tailnetSuffixCache;
  tailnetSuffixCache = null;
  if (process.platform !== 'win32') return tailnetSuffixCache;

  const tryPipe = () =>
    new Promise((resolve) => {
      let settled = false;
      try {
        execFile('C:\\Windows\\System32\\ipconfig.exe', ['/all'], { timeout: 8000, windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout) => {
          if (settled) return;
          settled = true;
          resolve(!err && stdout ? parseTailscaleSuffix(String(stdout)) : null);
        });
      } catch {
        return resolve(null);
      }
    });

  const tryFileRedirect = () =>
    new Promise((resolve) => {
      const dir = join(process.env.DSH_HOME ?? tmpdir(), 'data', 'dsh-mobile-access');
      const file = join(dir, `ipconfig-${process.pid}.txt`);
      let child;
      try {
        mkdirSync(dir, { recursive: true });
        child = spawn('cmd.exe', ['/d', '/c', `ipconfig /all > "${file}"`], { stdio: 'ignore', windowsHide: true });
      } catch {
        return resolve(null);
      }
      const timer = setTimeout(() => {
        try { child.kill(); } catch {}
      }, 8000);
      child.on('error', () => {
        clearTimeout(timer);
        resolve(null);
      });
      child.on('exit', () => {
        clearTimeout(timer);
        try {
          const suffix = parseTailscaleSuffix(readFileSync(file, 'utf8'));
          unlinkSync(file);
          resolve(suffix);
        } catch {
          resolve(null);
        }
      });
    });

  return (async () => {
    const viaPipe = await tryPipe();
    if (viaPipe) {
      tailnetSuffixCache = viaPipe;
      return tailnetSuffixCache;
    }
    const viaFile = await tryFileRedirect();
    tailnetSuffixCache = viaFile;
    return tailnetSuffixCache;
  })();
}

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

/**
 * Probe the /api trust fence for a given origin from the host side.
 * A non-browser request (no Origin / Sec-Fetch) passes or fails purely on
 * Host-header trust (dsh-client-connection isTrustedApiRequest): loopback or a
 * trustedHosts authority passes; everything else 403s. 403 => fence blocked.
 * @param origin - 'http://ip:port' (direct) or 'https://tailname.ts.net' (http2).
 * @returns { ok, status, error? } where ok = fence allows /api.
 * Exported for tests.
 */
export function probeApiFence(origin) {
  return new Promise((resolve) => {
    let req;
    try {
      const mod = origin.startsWith('https:') ? https : http;
      req = mod.get(`${origin}/api/`, { timeout: 6000 }, (res) => {
        res.resume();
        // 403 is the fence's rejection; 4xx/5xx beyond that means "reachable and allowed"
        resolve({ ok: res.statusCode !== 403, status: res.statusCode });
      });
    } catch {
      return resolve({ ok: false, error: 'invalid origin' });
    }
    req.on('error', (err) => resolve({ ok: false, error: err.code ?? err.message }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: 'timeout' });
    });
  });
}

/** Build a copyable web-app trustedHosts patch snippet for a tailnet domain. */
function trustedHostsPatchSnippet(hostname) {
  return [
    '# API 信任围栏：把 HTTP/2 域名加入 /api 白名单（id 定向 patch 是整段替换，已有自定义 web-app config 请手动合并）',
    '- id: web-app',
    '  config:',
    '    trustedHosts:',
    `      - ${hostname}`,
  ].join('\n');
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

/** Persistent device registry (disk-backed) plus a single one-time pairing
 * token slot (memory). Device records survive `dsh web` restarts; each paired
 * device owns an id + secret (secret stored as sha-256 hash) that the browser
 * carries in a 30-day rolling cookie. Exported for unit tests. */
export function createPairService(ttlMs, storeFile) {
  let current = null; // one active mint token
  const devices = loadDevices(storeFile); // { id: record }
  let dirty = false;
  const persist = () => {
    if (!dirty) return;
    saveDevices(storeFile, devices);
    dirty = false;
  };
  return {
    mint() {
      const token = randomUUID().replaceAll('-', '').slice(0, 20);
      current = { token, createdAt: Date.now(), expiresAt: Date.now() + ttlMs };
      return current;
    },
    accept(token, meta) {
      if (!current || current.token !== token) return null;
      if (Date.now() > current.expiresAt) return { expired: true };
      const id = randomUUID();
      const secret = randomBytes(24).toString('hex');
      devices[id] = {
        id,
        secretHash: hashSecret(secret),
        name: meta?.name ?? null,
        ua: meta?.ua,
        ip: meta?.ip,
        pairedAt: Date.now(),
        lastSeen: Date.now(),
        revoked: false,
      };
      dirty = true;
      persist();
      current = null; // one-time: the token dies with its first successful accept
      return { id, secret };
    },
    /** Resolve a `id.secret` cookie value to the live device record, or null. */
    resolve(cookieValue) {
      if (typeof cookieValue !== 'string') return null;
      const dot = cookieValue.indexOf('.');
      if (dot <= 0) return null;
      const id = cookieValue.slice(0, dot);
      const secret = cookieValue.slice(dot + 1);
      const device = devices[id];
      if (!device || device.revoked) return null;
      if (hashSecret(secret) !== device.secretHash) return null;
      if (device.lastSeen < Date.now() - 60_000) {
        device.lastSeen = Date.now(); // throttle disk writes to ~1/min/device
        dirty = true;
      }
      return device;
    },
    heartbeat(cookieValue) {
      const device = this.resolve(cookieValue);
      if (!device) return false;
      persist();
      return true;
    },
    list() {
      return Object.values(devices).map((d) => ({
        id: d.id,
        ip: d.ip,
        ua: d.ua,
        name: d.name,
        pairedAt: d.pairedAt,
        lastSeen: d.lastSeen,
        hasPush: Boolean(d.push),
      }));
    },
    /** Attach/clear a Web Push subscription to a device (persisted). */
    setPush(id, subscription) {
      const device = devices[id];
      if (!device) return false;
      if (subscription) device.push = { endpoint: subscription.endpoint, keys: subscription.keys };
      else delete device.push;
      dirty = true;
      persist();
      return true;
    },
    /** Devices that have a Web Push subscription. */
    pushTargets() {
      const out = [];
      for (const device of Object.values(devices)) {
        if (device.push && !device.revoked) out.push({ id: device.id, push: device.push });
      }
      return out;
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
    revoke(id) {
      if (!devices[id]) return false;
      delete devices[id];
      dirty = true;
      persist();
      return true;
    },
    stop() {
      current = null;
      for (const key of Object.keys(devices)) delete devices[key];
      dirty = true;
      persist();
    },
  };
}

/** sha-256 hex of a device secret (never store plaintext secrets). Exported for tests. */
export function hashSecret(secret) {
  return createHash('sha256').update(secret).digest('hex');
}

/** Load the device map { id: record } from disk; {} on any failure. Exported for tests. */
export function loadDevices(file) {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/** Atomically persist the device map (tmp file + rename). Never throws. Exported for tests. */
export function saveDevices(file, map) {
  try {
    mkdirSync(join(file, '..'), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(map), 'utf8');
    renameSync(tmp, file);
  } catch {
    /* best effort — pairing still works in memory this run */
  }
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

// --- PWA: app manifest + icon + home-screen injection -----------------------
const ICON_PATH = fileURLToPath(new URL('./icon.png', import.meta.url));
const THEME_DARK = '#101820';
const THEME_LIGHT = '#f4f6f9';

/** Dynamic manifest so start_url/theme follow the actual harness context. Exported for tests. */
export function manifestJson(pagePath) {
  return JSON.stringify({
    name: 'DSH',
    short_name: 'DSH',
    description: 'DeepSeek Harness — AI agent 工作台',
    start_url: '/',
    display: 'standalone',
    background_color: THEME_DARK,
    theme_color: THEME_DARK,
    icons: [
      { src: `${pagePath}/icon.png`, sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: `${pagePath}/icon.png`, sizes: '192x192', type: 'image/png', purpose: 'any' },
    ],
  });
}

function pwaTags(pagePath) {
  return (
    `<link rel="manifest" href="${pagePath}/manifest.webmanifest">` +
    `<meta name="theme-color" content="${THEME_DARK}">` +
    `<link rel="apple-touch-icon" href="${pagePath}/icon.png">`
  );
}

/** Inject PWA link/meta tags into index.html head (harmless on desktop). Exported for tests. */
export function injectPwa(html, pagePath) {
  const tags = pwaTags(pagePath);
  const lower = html.toLowerCase();
  const idx = lower.indexOf('<head');
  if (idx === -1) return tags + html;
  const insertAt = html.indexOf('>', idx) + 1;
  return html.slice(0, insertAt) + tags + html.slice(insertAt);
}

/** Cheap UA -> human device name for the welcome page. Exported for tests. */
export function deviceNameFromUa(ua) {  if (!ua) return '未知设备';
  const u = String(ua);
  if (/iPhone/i.test(u)) return 'iPhone';
  if (/iPad/i.test(u)) return 'iPad';
  if (/Android/i.test(u)) return 'Android 设备';
  if (/Macintosh|Mac OS X/i.test(u) && !/iPhone/i.test(u)) return 'Mac';
  if (/Windows/i.test(u)) return 'Windows 设备';
  if (/Linux/i.test(u)) return 'Linux 设备';
  return '未知设备';
}

function isIosUa(ua) {
  return /iPhone|iPad|iPod/i.test(String(ua ?? ''));
}

/** Post-pair landing page: first screen a phone sees after scanning. Exported for tests. */
export function welcomePageHtml(pairState, device, pagePath, push) {
  const manifestUrl = `${pagePath}/manifest.webmanifest`;
  const iconUrl = `${pagePath}/icon.png`;
  const pushBlock = push && push.enabled
    ? `<section class="card push" id="pushCard">
        <h2>锁屏通知</h2>
        <p class="sub">agent 完成一轮、提问待处理时，锁屏也能收到（需 HTTPS + 浏览器授权）。</p>
        <div class="actions">
          <button id="pushEnable" class="btn primary">开启锁屏通知</button>
          <span id="pushStatus" class="hint"></span>
        </div>
        <p class="hint" id="pushNeedHttps" style="display:none;color:#ffb02e">当前是直连 HTTP 模式，锁屏通知不可用——请改用 HTTP/2（HTTPS）连接方式。</p>
      </section>
      <script>
        (function () {
          var btn = document.getElementById('pushEnable');
          var status = document.getElementById('pushStatus');
          var needHttps = document.getElementById('pushNeedHttps');
          if (!btn) return;
          if (!window.isSecureContext) {
            needHttps.style.display = 'block';
            btn.style.display = 'none';
            return;
          }
          if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
            status.textContent = '此浏览器不支持 Web Push';
            btn.style.display = 'none';
            return;
          }
          btn.addEventListener('click', function () {
            btn.disabled = true;
            status.textContent = '请求授权…';
            navigator.serviceWorker.register(${JSON.stringify(`${pagePath}/sw.js`)}).then(function (reg) {
              return Notification.requestPermission().then(function (perm) {
                if (perm !== 'granted') throw new Error('permission denied');
                return reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: ${JSON.stringify(push.publicKey)} });
              });
            }).then(function (sub) {
              return fetch(${JSON.stringify(`${pagePath}/api/push/subscribe`)}, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ subscription: sub.toJSON() })
              });
            }).then(function (r) { return r.json(); }).then(function (d) {
              status.textContent = d.ok ? '已开启 ✓（锁屏可收到通知）' : '开启失败';
              btn.style.display = 'none';
            }).catch(function (e) {
              status.textContent = '开启失败：' + e.message;
              btn.disabled = false;
            });
          });
        })();
      </script>`
    : '';
  const addHomeIos =
    '打开 Safari 浏览器菜单（底部「分享」按钮）→ 选择「添加到主屏幕」→ 确认。以后点主屏幕图标即可全屏进入 DSH。';
  const addHomeAndroid =
    '在 Chrome 浏览器菜单中点击「添加到主屏幕」（或出现「安装应用」横幅时点安装）。以后点主屏幕图标即可全屏进入 DSH。';
  const pairedCard = device
    ? `<section class="card ok">
        <div class="bigcheck">✓</div>
        <h2>已配对</h2>
        <p class="sub">设备：<b>${htmlEscape(device.name)}</b>（${htmlEscape(device.ip || 'unknown')}）</p>
        <p class="sub">凭证有效 <b>30 天</b>，滚动续期；在电脑端可随时撤销。</p>
        <div class="guide">${isIosUa(device.ua) ? addHomeIos : addHomeAndroid}</div>
        <div class="actions"><a class="btn primary" href="/">进入主界面</a></div>
      </section>
      ${pushBlock}`
    : `<section class="card warn">
        <h2>未找到配对凭证</h2>
        <p class="sub">请回到电脑端的「手机接入」设置页，重新生成配对二维码。</p>
      </section>`;
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>已配对 — DSH Mobile</title>
<link rel="manifest" href="${manifestUrl}">
<meta name="theme-color" content="${THEME_DARK}">
<link rel="apple-touch-icon" href="${iconUrl}">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg,#101820);color:#e8ecf0;font:15px/1.6 system-ui,"Segoe UI","Microsoft YaHei",sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
  main{width:100%;max-width:420px}
  .card{background:#18222d;border:1px solid #26323f;border-radius:18px;padding:28px;text-align:center}
  .bigcheck{width:64px;height:64px;border-radius:50%;background:#3fbf7f;color:#fff;font-size:34px;font-weight:700;
            display:flex;align-items:center;justify-content:center;margin:0 auto 14px}
  h2{font-size:20px;margin-bottom:6px}
  .sub{color:#8a97a5;font-size:13px;margin:4px 0}
  .sub b{color:#cfe3ee}
  .guide{margin:16px 0 6px;padding:12px 14px;background:#0c141b;border:1px solid #26323f;border-radius:10px;
         color:#cfe3ee;font-size:12.5px;text-align:left}
  .actions{margin-top:16px}
  .btn{display:inline-block;padding:11px 26px;border-radius:9px;font-weight:600;text-decoration:none;
       font-size:14px;letter-spacing:.03em}
  .btn.primary{background:#4d6bfe;color:#fff}
  .btn:disabled{opacity:.5}
  .card.push{margin-top:14px}
  .hint{font-size:12px;color:#8a97a5;margin-top:8px;display:block}
  .eyebrow{font:600 11px/1 ui-monospace,Consolas,monospace;letter-spacing:.22em;color:#4fc3f7;text-transform:uppercase;
           text-align:center;margin-bottom:12px}
</style>
</head>
<body>
<main>
  <div class="eyebrow">DSH · MOBILE</div>
  ${pairedCard}
</main>
</body>
</html>`;
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

function pageHtml(state, pairState, suggestedHost) {
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

  const fenceRow = `<li class="warn" id="fenceRow">${statusDot('maybe')}<div><b>API 信任围栏</b><p>手机访问主界面时 /api 必须放行（dsh-client-connection 的 trustedHosts 围栏，读取 connection 行）。直连模式（IP 字面量）自动受信；HTTP/2 模式需把 ts.net 域名 concat 进 connection 行的 trustedHosts（harness 没有 web-app 行，patch 该 id 会静默无效），否则页面能开、数据全空。</p><div id="fenceDetail" class="hint">探测中…</div></div></li>`;

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mobile Access — DSH</title>
<style>
  :root{
    --bg:#101820;--panel:#18222d;--line:#26323f;--text:#e8ecf0;--muted:#8a97a5;
    --inset:#0c141b;--mono:#cfe3ee;
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
  .qr-empty{position:relative;width:190px;height:190px;display:flex;align-items:center;justify-content:center;background:#fff;border-radius:6px;color:var(--muted,#8a97a5);font:12px ui-monospace,Consolas,monospace}
  .url{font:600 15px/1.4 ui-monospace,Consolas,monospace;color:var(--cyan);word-break:break-all}
  .hint{color:var(--muted);font-size:12.5px}
  button{font:600 12px/1 ui-monospace,Consolas,monospace;color:#fff;background:var(--amber);border:none;border-radius:7px;padding:8px 14px;cursor:pointer;letter-spacing:.05em}
  button:hover{filter:brightness(1.08)}
  button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
  button.ghost{background:transparent;color:var(--muted);border:1px solid var(--line)}
  button.copied{background:var(--green)}
  .addrlist{list-style:none;display:flex;flex-direction:column;gap:8px;margin-top:4px;text-align:left}
  .addrlist label{display:flex;align-items:center;gap:10px;background:var(--inset,#0c141b);border:1px solid var(--line);border-radius:9px;padding:10px 12px;cursor:pointer}
  .addrlist input{accent-color:var(--cyan)}
  .alabel{font-size:13px;color:var(--text)}
  .modeline{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:8px}
  .modeline label{display:flex;align-items:center;gap:8px;font-size:13.5px;cursor:pointer}
  .modeline input{accent-color:var(--cyan)}
  .devices{margin-top:10px;font-size:12.5px;color:var(--muted);text-align:left}
  .devices .devrow{display:inline-flex;align-items:center;gap:6px;margin:3px 10px 3px 0}
  .devices .devrow code{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--cyan)}
  .devices .revoke{font:600 11px/1 ui-monospace,Consolas,monospace;color:var(--red);background:transparent;border:1px solid var(--line);border-radius:6px;padding:3px 8px;cursor:pointer}
  .devices .revoke:hover{border-color:var(--red)}
  ul.check{list-style:none;display:flex;flex-direction:column;gap:12px;margin-top:20px}
  ul.check li{display:flex;gap:12px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
  ul.check b{font-size:14.5px}
  ul.check p{color:var(--muted);font-size:13px;margin-top:3px}
  ul.check .mono,pre,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
  .mono{color:var(--cyan)}
  pre{background:var(--inset,#0c141b);border:1px solid var(--line);border-radius:9px;padding:12px;margin-top:8px;overflow-x:auto;color:var(--mono,#cfe3ee)}
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
      <input id="http2host" type="text" placeholder="yiyan.tail172eda.ts.net" ${suggestedHost ? `value="${htmlEscape(suggestedHost)}"` : ''} style="width:100%;margin-top:6px;padding:9px 12px;background:var(--inset,#0c141b);border:1px solid var(--line);border-radius:9px;color:var(--text);font:13px ui-monospace,Consolas,monospace">
      <p class="hint" style="margin-top:6px">域名由 Tailscale 自动分配（格式：机器名.tailnet后缀.ts.net，可在 Tailscale 控制台 Machines 页确认）。已自动检测预填，通常无需修改。</p>
      <div style="display:flex;gap:10px;margin-top:10px">
        <button id="http2on">开启 HTTP/2</button>
        <button id="http2off" class="ghost">关闭 HTTP/2</button>
      </div>
      <p class="hint" id="http2status" style="margin-top:8px">开启会弹出 UAC 授权框（请点「是」）；开启后二维码指向 https 地址，手机端多路复用加载更快。</p>
    </div>
    <p class="hint">二维码有效期 15 分钟，仅限一次配对；手机扫码后自动打开 DSH 主界面。</p>
  </section>
  <section class="card">
    <b>锁屏通知（Web Push）</b>
    <div id="pushBody" class="hint">加载中…</div>
  </section>
  <ul class="check">
    ${bindRow}
    ${tailscaleRow}
    ${lanRow}
    ${fenceRow}
    ${fwRow}
  </ul>
  <footer>dsh-mobile-access · 二维码由内建生成器离线绘制 · 配对设备持久保存在本机（重启不丢），可逐个撤销</footer>
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
      '--inset': m.colors.code,
      '--mono': m.colors.text,
    };
    var root = document.documentElement;
    for (var k in map) if (map[k]) root.style.setProperty(k, map[k]);
    root.style.colorScheme = m.dark ? 'dark' : 'light';
  }
  window.addEventListener('message', function (e) {
    if (e.data && e.data.type === 'dsh-theme') applyDshTheme(e.data);
  });
  // Announce readiness to the parent panel (it replies with the theme).
  try {
    if (window.parent && window.parent !== window) {
      window.parent.postMessage({ type: 'ma-ready' }, '*');
    }
  } catch (e) {}
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
    fenceProbe();
  }
  for (var i = 0; i < modeInputs.length; i++) modeInputs[i].addEventListener('change', syncModePanels);
  for (var i = 0; i < addrInputs.length; i++) addrInputs[i].addEventListener('change', fenceProbe);
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
    fenceProbe();
  });
  function http2Status(text) { document.getElementById('http2status').textContent = text; }

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function trustedHostsSnippet(hostname) {
    var safe = String(hostname).replace(/['\\]/g, '');
    return '# API 信任围栏：把 HTTP/2 域名加入 /api 白名单（connection 行只拥有 trustedHosts 一个键；.concat 保留运行时 LAN 字面量，直连模式不受影响）\n- id: connection\n  config:\n    trustedHosts: !!js ctx.webRuntime.trustedHosts.concat(\'' + safe + '\')';
  }
  // Probe the /api trust fence for the currently selected mode and render the
  // checklist row outcome (green = allowed, red + copyable patch for http2).
  function fenceProbe() {
    var mode = currentMode();
    var payload;
    if (mode === 'http2') {
      var h = hostInput.value.trim();
      if (!h) { return; }
      payload = { mode: 'http2', hostname: h };
    } else {
      var addr = selectedAddr();
      if (!addr) { return; }
      payload = { mode: 'direct', address: addr };
    }
    var row = document.getElementById('fenceRow');
    var el = document.getElementById('fenceDetail');
    if (!row || !el) return;
    row.className = 'warn';
    el.innerHTML = '探测中…';
    fetch('/mobile-access/api/fence/probe', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (!d) { el.textContent = '探测失败（服务未响应）'; return; }
      if (d.fenceOk) {
        row.className = 'pass';
        el.innerHTML = '<span style="color:var(--green)">已放行（/api 非 403）——手机扫码后主界面数据可正常加载。</span>';
      } else if (d.mode === 'http2') {
        row.className = 'fail';
        var patch = trustedHostsSnippet(hostInput.value.trim());
        el.innerHTML = '<span style="color:var(--red)">围栏未放行（/api 返回 ' + (d.fenceStatus || '403') + (d.reachable ? '' : '，且 ' + (d.reachError || '不可达')) + '）。把下面的片段加进 profile 的 cordis.patch.yml，重启 dsh 后回来再生成二维码：</span><pre>' + escapeHtml(patch) + '</pre><button class="copy" data-copy="' + escapeHtml(patch) + '">复制片段</button>';
      } else {
        row.className = 'fail';
        el.innerHTML = '<span style="color:var(--red)">围栏未放行（/api 返回 ' + (d.fenceStatus || '403') + '）——直连模式（IP 字面量）通常自动受信，请确认 webserver 已绑定 0.0.0.0。</span>';
      }
    }).catch(function () { el.textContent = '探测失败'; });
  }

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
        var html = '已配对设备（持久保存，重启不丢）：';
        for (var i = 0; i < s.devices.length; i++) {
          var d = s.devices[i];
          html += '<span class="devrow"><code>' + escapeHtml(d.ip || 'unknown') + '</code><button class="revoke" data-id="' + d.id + '" title="撤销此设备">撤销</button></span>';
        }
        el.innerHTML = html;
        var revokes = el.querySelectorAll('.revoke');
        for (var j = 0; j < revokes.length; j++) {
          revokes[j].addEventListener('click', function () {
            var id = this.getAttribute('data-id');
            fetch('/mobile-access/api/pair/revoke', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ id: id })
            }).then(function () { refreshStatus(); });
          });
        }
      } else {
        el.textContent = '无已配对设备';
      }
    });
  }
  function refreshPush() {
    fetch('/mobile-access/status.json').then(function (r) { return r.json(); }).then(function (s) {
      var el = document.getElementById('pushBody');
      if (!el) return;
      var n = s && s.notifications;
      if (!n || !n.pushEnabled) { el.textContent = '未启用（配置 push: false 时关闭）'; return; }
      var html = '已订阅设备：' + (n.pushSubscribers || 0) + ' 个；VAPID 公钥：<span class="mono">' + escapeHtml((n.vapidPublicKey || '').slice(0, 14)) + '…</span> ';
      html += '<button class="copy" id="pushTest">测试推送</button>';
      el.innerHTML = html;
      var btn = document.getElementById('pushTest');
      if (btn) btn.addEventListener('click', function () {
        fetch('/mobile-access/api/push/test', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}'
        }).then(function (r) { return r.json(); }).then(function (d) {
          alert(d.ok ? '已发送，请查看手机通知' : '发送失败：' + (d.error || d.status || '没有已订阅的设备'));
        });
      });
      var note = document.createElement('p');
      note.className = 'hint';
      note.textContent = '仅 HTTP/2（HTTPS）模式可用；手机配对后会在欢迎页引导开启。';
      el.appendChild(note);
    });
  }
  setInterval(refreshPush, 8000);
  refreshPush();
  setInterval(refreshStatus, 4000);
  refreshStatus();
</script>
</body>
</html>`;
}

// --- P2: SSE notification channel (zero-dependency, EventSource native
// auto-reconnect + Last-Event-ID replay instead of a hand-rolled WS) ---------
const SSE_KEEPALIVE_MS = 25000;
const SSE_BUFFER_SIZE = 200;

/** Ring-buffer of recent notices for replay on reconnect (per design §7.1).
 * Exported for tests. */
export class SseHub {
  constructor() {
    this.seq = 0;
    this.buffer = [];
    this.clients = new Set();
  }
  publish(payload) {
    this.seq += 1;
    const entry = { seq: this.seq, payload };
    this.buffer.push(entry);
    if (this.buffer.length > SSE_BUFFER_SIZE) this.buffer.shift();
    for (const c of [...this.clients]) this.send(c, entry);
    return entry;
  }
  send(c, entry) {
    try {
      c.res.write(`id: ${entry.seq}\nevent: notice\ndata: ${JSON.stringify(entry.payload)}\n\n`);
    } catch {
      this.remove(c);
    }
  }
  /** Register a connection; replay any gap between lastSeq+1 and newest. */
  add(res, deviceId, lastSeq) {
    const c = { res, deviceId, lastSeq };
    this.clients.add(c);
    const newest = this.seq;
    if (lastSeq && lastSeq < newest && this.buffer.length) {
      const oldest = this.buffer[0].seq;
      if (lastSeq >= oldest - 1) {
        for (const e of this.buffer) if (e.seq > lastSeq) this.send(c, e);
      }
    }
    return c;
  }
  remove(c) {
    this.clients.delete(c);
  }
  count() {
    return this.clients.size;
  }
}

/**
 * Map a harness session/event to a lightweight notification kind, or null to
 * skip. Only low-frequency, high-value events are surfaced; NO message body is
 * forwarded (the SSE channel only clears the DNS fence, not an auth layer).
 * Exported for tests.
 */
export function classifySessionEvent(event) {
  const type = event?.type;
  if (type === 'turn/end') return { kind: 'run.completed' };
  if (type === 'tool/call') {
    const data = event?.data ?? {};
    const tool = data.tool?.name ?? data.name ?? data.toolName ?? '';
    if (tool === 'ask_user_question') return { kind: 'ask.arrived' };
    if (tool === 'todo_write') return { kind: 'todo.changed' };
    return null;
  }
  if (type === 'tool/result') {
    const data = event?.data ?? {};
    if (data.error || data.isError || (data.result && typeof data.result === 'object' && data.result.error)) return { kind: 'run.failed' };
    return null;
  }
  return null;
}

/** Lightweight in-page toast + EventSource client injected into the shell. */
function sseClientScript(pagePath) {
  const ev = `${pagePath}/events`;
  const labels = {
    'ask.arrived': '📩 新提问待处理',
    'run.completed': '✓ Agent 完成一轮',
    'run.failed': '⚠ Agent 出错',
    'todo.changed': '📋 待办有更新',
    'pair.changed': '🔗 配对状态变化',
    'device.online': '📱 设备上线',
    'device.offline': '📱 设备离线',
  };
  return `<script>
(function(){
  try {
    if (!window.EventSource) return;
    var src = new EventSource(${JSON.stringify(ev)});
    var toast = null;
    var hideTimer = null;
    src.addEventListener('notice', function (e) {
      var d;
      try { d = JSON.parse(e.data); } catch (err) { return; }
      var msg = labels[d.kind] || ('通知：' + (d.kind || ''));
      if (!toast) {
        toast = document.createElement('div');
        toast.style.cssText = 'position:fixed;left:12px;right:12px;bottom:12px;z-index:2147483647;background:rgba(16,24,32,.96);color:#e8ecf0;border:1px solid #26323f;border-radius:10px;padding:10px 14px;font:13px/1.5 system-ui,sans-serif;box-shadow:0 8px 28px rgba(0,0,0,.45);max-width:420px;margin:0 auto';
        document.body.appendChild(toast);
      }
      toast.textContent = msg;
      toast.style.display = 'block';
      clearTimeout(hideTimer);
      hideTimer = setTimeout(function(){ if (toast) toast.style.display = 'none'; }, 4000);
    });
    src.onerror = function () {
      // 401 (no device cookie) or network down: browsers stop reconnecting on
      // HTTP error status, so this fires once on desktop — harmless.
    };
  } catch (e) {}
})();
</script>`;
}

/** Inject the SSE toast client into index.html head (phone devices only do
 * any real work — desktop requests 401 once and EventSource stops). */
export function injectSseClient(html, pagePath) {
  const script = sseClientScript(pagePath);
  const lower = html.toLowerCase();
  const idx = lower.indexOf('</body>');
  if (idx === -1) return html + script;
  return html.slice(0, idx) + script + html.slice(idx);
}

/** Human-readable label for a notification kind (settings page preview). */
function kindLabel(kind) {
  return {
    'ask.arrived': '新提问待处理',
    'run.completed': 'Agent 完成一轮',
    'run.failed': 'Agent 出错',
    'todo.changed': '待办更新',
    'pair.changed': '配对状态变化',
    'device.online': '设备上线',
    'device.offline': '设备离线',
  }[kind] ?? kind;
}

/** One-line push body for a notification kind (never forwards message content). */
function notifyBody(payload) {
  const session = payload.sessionId ? `（会话 ${String(payload.sessionId).slice(0, 8)}…）` : '';
  switch (payload.kind) {
    case 'ask.arrived': return `有新的提问等待处理${session}`;
    case 'run.completed': return `Agent 完成了一轮执行${session}`;
    case 'run.failed': return `Agent 出错了${session}`;
    case 'todo.changed': return `待办列表有更新${session}`;
    case 'pair.changed': return '配对状态已变化';
    case 'device.online': return '设备已上线';
    case 'device.offline': return '设备已离线';
    default: return 'DSH 有新的通知';
  }
}

// --- P2: Web Push (VAPID + RFC 8291 aes128gcm, zero-dependency) -------------
function base64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function base64urlDecode(s) {
  return Buffer.from(s, 'base64url');
}
function hkdfExtract(salt, ikm) {
  return createHmac('sha256', salt).update(ikm).digest();
}
function hkdfExpand(prk, info, length) {
  const out = Buffer.alloc(length);
  let t = Buffer.alloc(0);
  let offset = 0;
  let i = 1;
  while (offset < length) {
    t = createHmac('sha256', prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    t.copy(out, offset);
    offset += t.length;
    i += 1;
  }
  return out;
}
/** P-256 uncompressed public point (0x04 || x || y) from a public key. */
function publicKeyUncompressed(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}
/** Parse a DER ECDSA signature into raw r||s (both fixed 32 bytes). */
function derToRaw(der) {
  if (der[0] !== 0x30) throw new Error('bad DER');
  let off = 2; // skip SEQUENCE tag + length byte (ECDSA signatures are <128 bytes)
  const readInt = () => {
    if (der[off] !== 0x02) throw new Error('bad DER int');
    const len = der[off + 1];
    const start = off + 2;
    off = start + len;
    let bytes = der.subarray(start, off);
    if (bytes.length > 32) bytes = bytes.subarray(bytes.length - 32); // DER may pad a leading 0
    const raw = Buffer.alloc(32);
    bytes.copy(raw, 32 - bytes.length);
    return raw;
  };
  const r = readInt();
  const s = readInt();
  return Buffer.concat([r, s]);
}
/** VAPID ES256 JWT for a push-service audience. */
export function makeVapidJwt(privateKey, aud, contact) {
  const enc = (o) => base64url(Buffer.from(JSON.stringify(o), 'utf8'));
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { aud, exp: now + 12 * 3600, sub: contact };
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const der = cryptoSign('sha256', Buffer.from(signingInput), privateKey);
  return `${signingInput}.${base64url(derToRaw(der))}`;
}
/** Load or generate a persistent VAPID key pair (EC P-256, PEM private + base64url public). */
export function loadOrCreateVapidKeys(file) {
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8'));
    if (raw.privateKey && raw.publicKey) return raw;
  } catch {}
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const data = {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: base64url(publicKeyUncompressed(publicKey)),
  };
  try {
    mkdirSync(join(file, '..'), { recursive: true });
    writeFileSync(file, JSON.stringify(data), 'utf8');
  } catch {}
  return data;
}
/**
 * Encrypt a UTF-8 payload for a Web Push subscription (RFC 8291 aes128gcm).
 * @param subscription - { endpoint, keys: { p256dh, auth } } (browser format).
 * @param plaintext - string or Buffer.
 * @returns the aes128gcm body buffer.
 */
export function encryptPayload(subscription, plaintext) {
  const uaPublic = base64urlDecode(subscription.keys.p256dh);
  const authSecret = base64urlDecode(subscription.keys.auth);
  const ecdh = new ECDH('prime256v1');
  ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const shared = ecdh.computeSecret(uaPublic); // 32 bytes
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0', 'utf8'), uaPublic, asPublic]);
  const prk = hkdfExtract(authSecret, shared);
  const ikm = hkdfExpand(prk, keyInfo, 32);
  const uaLen = Buffer.from([0, uaPublic.length]);
  const asLen = Buffer.from([0, asPublic.length]);
  const context = Buffer.concat([Buffer.from('P-256\0', 'utf8'), uaLen, uaPublic, asLen, asPublic]);
  const cek = hkdfExpand(ikm, Buffer.concat([context, Buffer.from('Content-Encoding: aes128gcm\0', 'utf8')]), 16);
  const nonce = hkdfExpand(ikm, Buffer.concat([context, Buffer.from('Content-Encoding: nonce\0', 'utf8')]), 12);
  const salt = randomBytes(16);
  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  const encrypted = Buffer.concat([cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  const rs = Buffer.alloc(4);
  rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPublic.length]), asPublic, encrypted, tag]);
}
/** POST a Web Push message to the subscription's push service. */
export function sendWebPush(subscription, body, headers) {
  return new Promise((resolve) => {
    let url;
    try {
      url = new URL(subscription.endpoint);
    } catch {
      return resolve({ ok: false, error: 'bad endpoint' });
    }
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(
      { hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80), path: url.pathname + url.search, method: 'POST', headers },
      (res) => {
        res.resume();
        res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode }));
      },
    );
    req.on('error', (e) => resolve({ ok: false, error: e.code ?? e.message }));
    req.setTimeout(8000, () => {
      req.destroy();
      resolve({ ok: false, error: 'timeout' });
    });
    req.end(body);
  });
}
/** Build a VAPID-authorized push call and send it. */
export async function pushToDevice(vapid, subscription, message, contact) {
  try {
    const url = new URL(subscription.endpoint);
    const aud = `${url.protocol}//${url.host}`;
    const jwt = makeVapidJwt(vapid.privateKey, aud, contact);
    const body = await encryptPayload(subscription, JSON.stringify(message));
    const headers = {
      'content-encoding': 'aes128gcm',
      'content-type': 'application/octet-stream',
      ttl: '86400',
      authorization: `vapid t=${jwt}, k=${vapid.publicKey}`,
    };
    return await sendWebPush(subscription, body, headers);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Service worker template (pagePath-aware icon). */
function serviceWorkerScript(pagePath) {
  const icon = `${pagePath}/icon.png`;
  return `self.addEventListener('push', function (e) {
  var data = {};
  try { data = e.data ? e.data.json() : {}; } catch (err) {}
  e.waitUntil(self.registration.showNotification(data.title || 'DSH', {
    body: data.body || '',
    icon: ${JSON.stringify(icon)},
    badge: ${JSON.stringify(icon)},
    tag: 'dsh-' + (data.kind || 'notice'),
    data: data
  }));
});
self.addEventListener('notificationclick', function (e) {
  e.notification.close();
  var url = '/';
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {
    for (var i = 0; i < list.length; i++) { if ('focus' in list[i]) { list[i].focus(); return; } }
    if (clients.openWindow) return clients.openWindow(url);
  }));
});
`;
}

function statusJson(state, pairState, hubCount, pushInfo) {
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
      notifications: {
        enabled: true,
        ssePath: '/mobile-access/events',
        connectedDevices: hubCount,
        pushEnabled: pushInfo.pushEnabled,
        pushSubscribers: pushInfo.pushSubscribers,
        vapidPublicKey: pushInfo.vapidPublicKey,
      },
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
    polyfill: 'auto',
    pairTtlMs: DEFAULT_PAIR_TTL_MS,
    ...config,
  };
  const dataRoot = process.env.DSH_HOME ?? join(homedir(), '.dsh');
  const devicesFile = join(dataRoot, 'data', 'dsh-mobile-access', 'devices.json');
  const vapidFile = join(dataRoot, 'data', 'dsh-mobile-access', 'vapid.json');
  const pair = createPairService(options.pairTtlMs, devicesFile);
  const hub = new SseHub();
  const disposers = [];
  const vapid = loadOrCreateVapidKeys(vapidFile);
  const pushContact = options.push?.contact ?? 'mailto:mobile-access@localhost';
  const pushEnabled = options.push !== false;

  /** Broadcast to live SSE clients AND fire Web Push to subscribed devices. */
  const notify = (payload) => {
    hub.publish(payload);
    if (!pushEnabled) return;
    for (const target of pair.pushTargets()) {
      pushToDevice(
        vapid,
        target.push,
        { title: kindLabel(payload.kind) ?? 'DSH', body: notifyBody(payload), kind: payload.kind, sessionId: payload.sessionId ?? null },
        pushContact,
      ).catch(() => {});
    }
  };

  // Map harness session events to lightweight notifications (no message bodies).
  const offSessionEvents = ctx.on('session/event', (session, event) => {
    const classified = classifySessionEvent(event);
    if (!classified) return;
    notify({ kind: classified.kind, sessionId: session?.id ?? null, ts: Date.now() });
  });
  disposers.push(() => { try { offSessionEvents(); } catch {} });

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
          // End-to-end gate: never mint a QR that opens a shell GUI (page loads
          // via the unguarded fallback but /api fence 403s). Host-side probes only.
          const [reach, fence] = await Promise.all([probeHttps(hostname), probeApiFence(pairBase)]);
          if (!reach.ok) {
            return sendJson(res, 400, { ok: false, error: `HTTPS 不可达（${reach.error ?? reach.status}）——serve 未生效或证书未签发，稍后再试`, stage: 'reachability' });
          }
          if (!fence.ok) {
            return sendJson(res, 400, { ok: false, error: 'API 信任围栏未放行（/api 返回 403）——按上方「API 信任围栏」给出的 connection 片段写进 profile 的 cordis.patch.yml 并重启 dsh', stage: 'fence' });
          }
        } else {
          const address = typeof body?.address === 'string' ? body.address : tailscale[0] ?? lan[0];
          if (!address) return sendJson(res, 400, { ok: false, error: 'no address available' });
          if (!tailscale.includes(address) && !lan.includes(address)) return sendJson(res, 400, { ok: false, error: 'unknown address' });
          pairBase = `http://${address}:${state.port}`;
        }
        const active = pair.mint();
        // secure=1 tells the phone's accept endpoint to mark the device cookie
        // Secure (only meaningful/sent over the HTTPS http2 origin).
        const pairUrl = `${pairBase}/?pair=${active.token}${mode === 'http2' ? '&secure=1' : ''}`;
        notify({ kind: 'pair.changed', phase: 'waiting', ts: Date.now() });
        return sendJson(res, 200, { ok: true, url: pairUrl, token: active.token, expiresAt: active.expiresAt, qrSvg: qrSvg(pairUrl) ?? null });
      }

      if (url.startsWith(`${api}/fence/probe`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'fence probe is loopback-only' });
        const body = await readJsonBody(req);
        const mode = body?.mode === 'http2' ? 'http2' : 'direct';
        if (mode === 'http2') {
          const hostname = typeof body?.hostname === 'string' && body.hostname !== '' ? body.hostname : null;
          if (!hostname) return sendJson(res, 400, { ok: false, error: 'hostname required' });
          const origin = `https://${hostname}`;
          const [reach, fence] = await Promise.all([probeHttps(hostname), probeApiFence(origin)]);
          return sendJson(res, 200, {
            ok: reach.ok !== false && fence.ok,
            mode,
            origin,
            reachable: reach.ok !== false,
            reachStatus: reach.status ?? null,
            reachError: reach.error ?? null,
            fenceOk: fence.ok,
            fenceStatus: fence.status ?? null,
          });
        }
        const address = typeof body?.address === 'string' ? body.address : tailscale[0] ?? lan[0];
        if (!address) return sendJson(res, 400, { ok: false, error: 'no address available' });
        const origin = `http://${address}:${state.port}`;
        const fence = await probeApiFence(origin);
        return sendJson(res, 200, {
          ok: fence.ok,
          mode,
          origin,
          reachable: !fence.error,
          reachError: fence.error ?? null,
          fenceOk: fence.ok,
          fenceStatus: fence.status ?? null,
        });
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
        const params = new URL(url, 'http://x').searchParams;
        const token = params.get('pair');
        // secure=1 rides the minted URL for http2 mode so the device cookie is
        // marked Secure (only sent over HTTPS); direct mode omits it so the
        // cookie still works over plain-HTTP tailnet addresses.
        const secure = params.get('secure') === '1';
        const result = pair.accept(token, { ip: req.socket.remoteAddress ?? null, ua: String(req.headers['user-agent'] ?? '').slice(0, 120) });
        if (result === null || result.expired) {
          return sendJson(res, 403, { ok: false, error: result?.expired ? 'pair token expired' : 'invalid pair token' });
        }
        const secureAttr = secure ? '; Secure' : '';
        const cookie = `${PAIR_COOKIE}=${result.id}.${result.secret}; Path=/; HttpOnly; SameSite=Lax${secureAttr}; Max-Age=${DEVICE_COOKIE_MAX_AGE_S}`;
        notify({ kind: 'pair.changed', phase: 'connected', deviceId: result.id, ts: Date.now() });
        res.writeHead(302, { location: `${options.pagePath}/welcome`, 'set-cookie': cookie, 'content-length': '0' });
        return res.end();
      }

      if (url.startsWith(`${api}/pair/heartbeat`)) {
        const cookies = parseCookies(req.headers.cookie);
        const ok = pair.heartbeat(cookies[PAIR_COOKIE]);
        return sendJson(res, ok ? 200 : 401, { ok });
      }

      if (url.startsWith(`${api}/pair/revoke`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'revoke is loopback-only' });
        const body = await readJsonBody(req);
        const id = typeof body?.id === 'string' ? body.id : null;
        if (!id) return sendJson(res, 400, { ok: false, error: 'id required' });
        const revoked = pair.revoke(id);
        if (revoked) notify({ kind: 'pair.changed', phase: 'revoked', deviceId: id, ts: Date.now() });
        return sendJson(res, revoked ? 200 : 404, { ok: revoked });
      }

      if (url.startsWith(`${api}/pair/stop`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'stop is loopback-only' });
        pair.stop();
        notify({ kind: 'pair.changed', phase: 'stopped', ts: Date.now() });
        return sendJson(res, 200, { ok: true });
      }

      if (url.startsWith(`${api}/pair/status`)) {
        return sendJson(res, 200, pair.snapshot());
      }

      if (url.startsWith(`${options.pagePath}/status.json`)) {
        const body = statusJson(state, pair, hub.count(), {
          pushEnabled,
          pushSubscribers: pair.pushTargets().length,
          vapidPublicKey: vapid.publicKey,
        });
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
        return res.end(body);
      }

      // PWA: app manifest + icon (cacheable static).
      if (url.startsWith(`${options.pagePath}/manifest.webmanifest`)) {
        const body = manifestJson(options.pagePath);
        res.writeHead(200, {
          'content-type': 'application/manifest+json; charset=utf-8',
          'content-length': Buffer.byteLength(body),
          'cache-control': 'no-cache',
        });
        return res.end(body);
      }
      if (url.startsWith(`${options.pagePath}/icon.png`)) {
        try {
          const icon = readFileSync(ICON_PATH);
          res.writeHead(200, { 'content-type': 'image/png', 'content-length': icon.length, 'cache-control': 'public, max-age=86400' });
          return res.end(icon);
        } catch {
          return sendJson(res, 404, { ok: false, error: 'icon missing' });
        }
      }

      // Post-pair landing page: renders "paired" from the device cookie.
      if (url.startsWith(`${options.pagePath}/welcome`)) {
        const cookies = parseCookies(req.headers.cookie);
        const device = pair.resolve(cookies[PAIR_COOKIE]);
        const deviceMeta = device
          ? { name: deviceNameFromUa(device.ua), ua: device.ua, ip: device.ip }
          : null;
        const body = welcomePageHtml(pair.snapshot(), deviceMeta, options.pagePath, {
          enabled: pushEnabled,
          publicKey: vapid.publicKey,
        });
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body) });
        return res.end(body);
      }

      // SSE notification channel: paired devices only (device cookie required).
      if (url.startsWith(`${api}/events`)) {
        const cookies = parseCookies(req.headers.cookie);
        const device = pair.resolve(cookies[PAIR_COOKIE]);
        if (!device) {
          res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('unauthorized');
          return;
        }
        const rawLast = req.headers['last-event-id'];
        const lastSeq = rawLast ? Number(rawLast) : 0;
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
          'x-accel-buffering': 'no',
        });
        res.write('retry: 3000\n\n');
        const client = hub.add(res, device.id, Number.isFinite(lastSeq) && lastSeq > 0 ? lastSeq : 0);
        const heartbeat = setInterval(() => {
          try {
            res.write(': ping\n\n');
          } catch {
            clearInterval(heartbeat);
            hub.remove(client);
          }
        }, SSE_KEEPALIVE_MS);
        req.on('close', () => {
          clearInterval(heartbeat);
          hub.remove(client);
          notify({ kind: 'device.offline', deviceId: device.id, ts: Date.now() });
        });
        notify({ kind: 'device.online', deviceId: device.id, ts: Date.now() });
        return; // stream stays open; caller must not end the response
      }

      // Web Push: subscribe/unsubscribe (device-cookie auth, works from phone
      // over the DNS fence), test (loopback), and the service worker script.
      if (url.startsWith(`${api}/push/subscribe`)) {
        const cookies = parseCookies(req.headers.cookie);
        const device = pair.resolve(cookies[PAIR_COOKIE]);
        if (!device) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
        const body = await readJsonBody(req);
        const sub = body?.subscription;
        if (!sub || typeof sub.endpoint !== 'string' || sub.endpoint.length > 500 || !sub.keys || typeof sub.keys.p256dh !== 'string' || typeof sub.keys.auth !== 'string') {
          return sendJson(res, 400, { ok: false, error: 'invalid subscription' });
        }
        pair.setPush(device.id, sub);
        return sendJson(res, 200, { ok: true });
      }
      if (url.startsWith(`${api}/push/unsubscribe`)) {
        const cookies = parseCookies(req.headers.cookie);
        const device = pair.resolve(cookies[PAIR_COOKIE]);
        if (!device) return sendJson(res, 401, { ok: false, error: 'unauthorized' });
        pair.setPush(device.id, null);
        return sendJson(res, 200, { ok: true });
      }
      if (url.startsWith(`${api}/push/test`)) {
        if (!isLoopbackAuthority(req.headers.host)) return sendJson(res, 403, { ok: false, error: 'test is loopback-only' });
        const body = await readJsonBody(req);
        const id = typeof body?.id === 'string' ? body.id : null;
        const targets = pair.pushTargets();
        const target = (id ? targets.find((t) => t.id === id) : undefined) ?? targets[0];
        if (!target) return sendJson(res, 404, { ok: false, error: 'no push-enabled device' });
        const result = await pushToDevice(vapid, target.push, { title: 'DSH 测试通知', body: '推送链路正常 ✓', kind: 'test' }, pushContact);
        return sendJson(res, result.ok ? 200 : 502, { ok: result.ok, ...result });
      }
      if (url.startsWith(`${options.pagePath}/sw.js`)) {
        const body = serviceWorkerScript(options.pagePath);
        res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-cache' });
        return res.end(body);
      }

      let suggestedHost = null;
      const suffix = await detectTailnetSuffix();
      if (suffix) {
        try {
          suggestedHost = `${hostname().toLowerCase()}.${suffix}`;
        } catch {}
      }
      const body = pageHtml(state, pair.snapshot(), suggestedHost);
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body) });
      res.end(body);
    },
  };
  disposers.push(ws.register(route));

  // polyfill: 'auto' (default) injects the guarded script — the polyfill only
  // defines crypto.randomUUID when it is missing, so on current harnesses it is
  // a no-op; set false to remove the injection entirely (harness >= rc.6).
  if (options.polyfill !== false && typeof ws.tapIndex === 'function') {
    const dispose = ws.tapIndex((html) => injectPolyfill(html));
    if (typeof dispose === 'function') disposers.push(dispose);
  }

  // PWA home-screen support: manifest + theme-color + apple-touch-icon in the
  // shell head. Desktop browsers are unaffected (no-op until "add to home").
  if (typeof ws.tapIndex === 'function') {
    const dispose = ws.tapIndex((html) => injectPwa(html, options.pagePath));
    if (typeof dispose === 'function') disposers.push(dispose);
  }

  // SSE toast client: phones with a device cookie get live notifications;
  // desktops without one get a single 401 and EventSource stops itself.
  if (typeof ws.tapIndex === 'function') {
    const dispose = ws.tapIndex((html) => injectSseClient(html, options.pagePath));
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
