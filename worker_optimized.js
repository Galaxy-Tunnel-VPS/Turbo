import { connect } from "cloudflare:sockets";

// ============================================
// CONFIG & ENV
// ============================================
const CFG = {
    UUID: "",
    TROJAN_PASS: "",
    PROXYIP: "cdn-b100.xn--b6gac.eu.org",
    PROXY_LIST_URL: "https://raw.githubusercontent.com/gprox-galaxy/Gproxy-domaip/refs/heads/main/PROXYIP.txt",
    DOH_URLS: [
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://2mms0p4zud.cloudflare-gateway.com/dns-query"
    ],
    CACHE_TTL_PROXY: 300,
    CACHE_TTL_DNS: 300,
    DOH_TIMEOUT: 3000,
    RATE_LIMIT: 30,
    CB_THRESHOLD: 3,
    CB_COOLDOWN: 60000,
    RETRY_BASE: 1000,
    RETRY_MAX: 8000,
};

// ============================================
// IN-MEMORY CACHE (isolate-level)
// ============================================
class MemCache {
    constructor() { this.store = new Map(); }
    get(k) {
        const item = this.store.get(k);
        if (!item) return null;
        if (Date.now() > item.exp) { this.store.delete(k); return null; }
        return item.val;
    }
    set(k, v, sec) { this.store.set(k, { val: v, exp: Date.now() + sec * 1000 }); }
}
const gCache = new MemCache();

// ============================================
// CIRCUIT BREAKER
// ============================================
class CircuitBreaker {
    constructor(t = 3, cd = 60000) { this.fails = new Map(); this.t = t; this.cd = cd; }
    fail(k) {
        const r = this.fails.get(k) || { c: 0, t: 0 };
        r.c++; r.t = Date.now();
        this.fails.set(k, r);
    }
    ok(k) { this.fails.delete(k); }
    isOpen(k) {
        const r = this.fails.get(k);
        if (!r) return false;
        if (r.c >= this.t && Date.now() - r.t < this.cd) return true;
        if (Date.now() - r.t >= this.cd) this.fails.delete(k);
        return false;
    }
    filterHealthy(arr) { return arr.filter(x => !this.isOpen(x)); }
}
const cb = new CircuitBreaker(CFG.CB_THRESHOLD, CFG.CB_COOLDOWN);

// ============================================
// RATE LIMITER
// ============================================
class RateLimiter {
    constructor(max = 30, win = 60000) { this.m = new Map(); this.max = max; this.win = win; }
    allow(ip) {
        const now = Date.now(), cutoff = now - this.win;
        const arr = (this.m.get(ip) || []).filter(t => t > cutoff);
        if (arr.length >= this.max) return false;
        arr.push(now); this.m.set(ip, arr); return true;
    }
}
const rl = new RateLimiter(CFG.RATE_LIMIT, 60000);

// ============================================
// UUID
// ============================================
function isValidUUID(u) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u);
}

// ============================================
// SHA224 (Pure JS) — cached result
// ============================================
function sha224(str) {
    function rr(v, a) { return (v >>> a) | (v << (32 - a)); }
    const mp = Math.pow, mw = mp(2, 32), rb = str.length * 8;
    let res = '', w = [], h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    let s = str + '\x80';
    while (s.length % 64 - 56) s += '\x00';
    for (let i = 0; i < s.length; i++) { const j = s.charCodeAt(i); if (j >> 8) return null; w[i >> 2] |= j << ((3 - i) % 4) * 8; }
    w[w.length] = (rb / mw) | 0; w[w.length] = rb;
    for (let j = 0; j < w.length;) {
        const ww = w.slice(j, j += 16), oh = h.slice(0);
        for (let i = 0; i < 64; i++) {
            if (i >= 16) { const w15 = ww[i - 15], w2 = ww[i - 2]; ww[i] = (ww[i - 16] + (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) + ww[i - 7] + (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))) | 0; }
            const a = h[0], e = h[4], t1 = (h[7] + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & h[5]) ^ (~e & h[6])) + k[i] + ww[i]), t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & h[1]) ^ (a & h[2]) ^ (h[1] & h[2])));
            h = [(t1 + t2) | 0].concat(h); h[4] = (h[4] + t1) | 0; h.pop();
        }
        for (let i = 0; i < 8; i++) h[i] = (h[i] + oh[i]) | 0;
    }
    for (let i = 0; i < 7; i++) { const x = h[i]; res += ((x >> 28) & 0xf).toString(16) + ((x >> 24) & 0xf).toString(16) + ((x >> 20) & 0xf).toString(16) + ((x >> 16) & 0xf).toString(16) + ((x >> 12) & 0xf).toString(16) + ((x >> 8) & 0xf).toString(16) + ((x >> 4) & 0xf).toString(16) + (x & 0xf).toString(16); }
    return res;
}

let _tpHash = null, _tpVal = null;
function getTrojanHash(pw) {
    if (pw === _tpVal && _tpHash) return _tpHash;
    _tpVal = pw; _tpHash = sha224(pw);
    return _tpHash;
}

// ============================================
// TIMING-SAFE COMPARE
// ============================================
function safeEq(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return r === 0;
}

// ============================================
// PROXYIP FETCH (cached + circuit breaker)
// ============================================
async function getProxyIP(def, url) {
    if (!url || url.includes("YOUR_USERNAME")) return def;
    const ck = `pl_${url}`;
    const cached = gCache.get(ck);
    if (cached) {
        const h = cb.filterHealthy(cached);
        if (h.length) return h[Math.floor(Math.random() * h.length)];
    }
    try {
        const r = await fetch(url, { cf: { cacheTtl: CFG.CACHE_TTL_PROXY, cacheEverything: true } });
        if (r.ok) {
            const list = (await r.text()).split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
            if (list.length) {
                gCache.set(ck, list, CFG.CACHE_TTL_PROXY);
                const h = cb.filterHealthy(list);
                return h.length ? h[Math.floor(Math.random() * h.length)] : list[Math.floor(Math.random() * list.length)];
            }
        }
    } catch (e) {}
    return def;
}

// ============================================
// DoH WITH TIMEOUT & CACHE
// ============================================
async function dohResolve(msg, urls) {
    const key = `dns_${Array.from(new Uint8Array(msg)).join('_')}`;
    const c = gCache.get(key);
    if (c) return c;
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), CFG.DOH_TIMEOUT);
    for (const u of urls) {
        try {
            const r = await fetch(u, { method: "POST", headers: { "content-type": "application/dns-message" }, body: msg, signal: ctrl.signal });
            clearTimeout(tid);
            const buf = await r.arrayBuffer();
            gCache.set(key, buf, CFG.CACHE_TTL_DNS);
            return buf;
        } catch (e) { continue; }
    }
    clearTimeout(tid);
    throw new Error("DoH failed");
}

// ============================================
// EXPONENTIAL BACKOFF
// ============================================
function backoff(n) { return Math.min(CFG.RETRY_BASE * Math.pow(2, n), CFG.RETRY_MAX); }

// ============================================
// ARRAYBUFFER CONCAT (no Blob)
// ============================================
function abConcat(arr) {
    const total = arr.reduce((s, b) => s + (b.byteLength || b.length), 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const b of arr) {
        out.set(b instanceof ArrayBuffer ? new Uint8Array(b) : b, off);
        off += b.byteLength || b.length;
    }
    return out.buffer;
}

// ============================================
// MAIN EXPORT
// ============================================
export default {
    async fetch(req, env, ctx) {
        const ip = req.headers.get("CF-Connecting-IP") || "unknown";
        if (!rl.allow(ip)) return new Response("Too many requests", { status: 429 });

        const uuid = env.UUID || env.uuid || CFG.UUID;
        const tp = env.TROJAN_PASS || env.trojan_pass || CFG.TROJAN_PASS;
        const pip = env.PROXYIP || env.proxyip || env.PROXY_IP || CFG.PROXYIP;
        const plu = env.PROXY_LIST_URL || CFG.PROXY_LIST_URL;
        let doh = CFG.DOH_URLS;
        if (env.DNS_RESOLVER_URL) { const u = env.DNS_RESOLVER_URL; doh = Array.isArray(u) ? u : [u]; }

        const hasV = isValidUUID(uuid);
        const hasT = !!tp;

        if (!hasV && !hasT) {
            return new Response(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Error</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;}
.box{background:#1e293b;padding:40px;border-radius:16px;box-shadow:0 10px 40px rgba(0,0,0,0.3);}
h1{color:#f87171;}code{background:#334155;padding:2px 8px;border-radius:4px;}</style></head>
<body><div class="box"><h1>⚠️ Not Configured</h1><p>Set <code>UUID</code> or <code>TROJAN_PASS</code> in environment variables.</p></div></body></html>`,
                { status: 500, headers: { "Content-Type": "text/html; charset=utf-8" } });
        }

        if (req.headers.get("Upgrade") === "websocket") {
            return proxyOverWS(req, { uuid, tp, pip, plu, doh });
        }
        return new Response(getPage(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
};

// ============================================
// WEBSOCKET HANDLER
// ============================================
async function proxyOverWS(req, cfg) {
    const pair = new WebSocketPair();
    const [client, ws] = Object.values(pair);
    ws.accept();

    let addr = "", portLog = "";
    const log = (i, e) => { console.log(`[${addr}:${portLog}] ${i}`, e || ""); };
    const early = req.headers.get("sec-websocket-protocol") || "";
    const stream = makeReadableWS(ws, early, log);

    let remote = { value: null };
    let udpWrite = null;
    let isDns = false;

    stream.pipeTo(new WritableStream({
        async write(chunk, ctrl) {
            if (isDns && udpWrite) return udpWrite(chunk);
            if (remote.value) {
                const w = remote.value.writable.getWriter();
                await w.write(chunk); w.releaseLock(); return;
            }

            const fb = new Uint8Array(chunk.slice(0, 1))[0];
            let res = null, proto = "unknown";

            if (fb === 0x00 && isValidUUID(cfg.uuid)) {
                try { res = parseVless(chunk, cfg.uuid); if (!res.hasError) proto = "vless"; } catch (e) { res = { hasError: true, message: e.message }; }
            }
            if ((!res || res.hasError) && cfg.tp) {
                res = parseTrojan(chunk, cfg.tp);
                if (res && !res.hasError) proto = "trojan";
            }
            if (!res || res.hasError) { throw new Error("Invalid protocol"); }

            const { addressRemote = "", portRemote = 443, rawDataIndex, responseHeader, isUDP } = res;
            addr = addressRemote; portLog = `${portRemote} ${isUDP ? "udp" : "tcp"} [${proto}]`;

            if (isUDP && portRemote !== 53) throw new Error("UDP only for DNS");
            if (isUDP && portRemote === 53) isDns = true;

            const raw = chunk.slice(rawDataIndex);
            if (isDns) {
                const { write } = await handleUDP(ws, responseHeader, cfg.doh, log);
                udpWrite = write; udpWrite(raw); return;
            }
            handleTCP(remote, addressRemote, portRemote, raw, ws, responseHeader, cfg, log);
        },
        close() { log("WS closed"); },
        abort(r) { log("WS abort", JSON.stringify(r)); }
    })).catch(e => { log("pipeTo error", e.message); });

    return new Response(null, { status: 101, webSocket: client });
}

// ============================================
// TCP OUTBOUND
// ============================================
async function handleTCP(remote, addrRemote, portRemote, rawData, ws, respHeader, cfg, log) {
    async function connectAndWrite(a, p) {
        const s = connect({ hostname: a, port: p });
        remote.value = s;
        log(`Connected ${a}:${p}`);
        const w = s.writable.getWriter();
        await w.write(rawData); w.releaseLock();
        return s;
    }

    async function retry(attempt = 0) {
        const proxy = await getProxyIP(cfg.pip, cfg.plu);
        const target = proxy || addrRemote;
        log(`Retry #${attempt} via ${target}`);
        try {
            const s = await connectAndWrite(target, portRemote);
            s.closed.catch(() => {}).finally(() => { safeClose(ws); });
            relayToWS(s, ws, null, null, log);
        } catch (e) {
            cb.fail(target);
            log(`Retry failed: ${e.message}`);
            if (attempt < 2) {
                await new Promise(r => setTimeout(r, backoff(attempt)));
                await retry(attempt + 1);
            } else {
                safeClose(ws);
            }
        }
    }

    try {
        const s = await connectAndWrite(addrRemote, portRemote);
        relayToWS(s, ws, respHeader, () => retry(0), log);
    } catch (e) {
        log(`Direct failed: ${e.message}`);
        await retry(0);
    }
}

// ============================================
// WEBSOCKET STREAM
// ============================================
function makeReadableWS(ws, early, log) {
    let cancelled = false;
    return new ReadableStream({
        start(ctrl) {
            ws.addEventListener("message", e => ctrl.enqueue(e.data));
            ws.addEventListener("close", () => { safeClose(ws); ctrl.close(); });
            ws.addEventListener("error", e => { log("WS error"); ctrl.error(e); });
            const { earlyData, error } = base64ToAB(early);
            if (error) ctrl.error(error);
            else if (earlyData) ctrl.enqueue(earlyData);
        },
        cancel(r) {
            log(`Readable cancel: ${r}`);
            cancelled = true; safeClose(ws);
        }
    });
}

// ============================================
// VLESS PARSER
// ============================================
function parseVless(buf, uid) {
    if (buf.byteLength < 24) return { hasError: true, message: "VLESS too short" };
    const ver = new Uint8Array(buf.slice(0, 1));
    const sliced = new Uint8Array(buf.slice(1, 17));
    const str = stringify(sliced);
    const uuids = uid.includes(",") ? uid.split(",") : [uid];
    if (!uuids.some(u => str === u.trim())) return { hasError: true, message: "Invalid user" };

    const optLen = new Uint8Array(buf.slice(17, 18))[0];
    const cmd = new Uint8Array(buf.slice(18 + optLen, 18 + optLen + 1))[0];
    let isUDP = false;
    if (cmd === 1) isUDP = false;
    else if (cmd === 2) isUDP = true;
    else return { hasError: true, message: `Cmd ${cmd} not supported` };

    const portIdx = 18 + optLen + 1;
    const portRemote = new DataView(buf.slice(portIdx, portIdx + 2)).getUint16(0);
    let addrIdx = portIdx + 2;
    const addrType = new Uint8Array(buf.slice(addrIdx, addrIdx + 1))[0];
    let addrLen = 0, addrValIdx = addrIdx + 1, addrVal = "";

    switch (addrType) {
        case 1: addrLen = 4; addrVal = new Uint8Array(buf.slice(addrValIdx, addrValIdx + 4)).join("."); break;
        case 2: addrLen = new Uint8Array(buf.slice(addrValIdx, addrValIdx + 1))[0]; addrValIdx += 1; addrVal = new TextDecoder().decode(buf.slice(addrValIdx, addrValIdx + addrLen)); break;
        case 3: addrLen = 16; const dv = new DataView(buf.slice(addrValIdx, addrValIdx + 16)); const v6 = []; for (let i = 0; i < 8; i++) v6.push(dv.getUint16(i * 2).toString(16)); addrVal = v6.join(":"); break;
        default: return { hasError: true, message: `Bad addr type ${addrType}` };
    }
    if (!addrVal) return { hasError: true, message: "Empty address" };
    return { hasError: false, addressRemote: addrVal, addressType: addrType, portRemote, rawDataIndex: addrValIdx + addrLen, responseHeader: new Uint8Array([ver[0], 0]), isUDP };
}

// ============================================
// TROJAN PARSER
// ============================================
function parseTrojan(buf, pw) {
    if (buf.byteLength < 58) return { hasError: true, message: "Trojan too short" };
    const bytes = new Uint8Array(buf);
    if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) return { hasError: true, message: "Missing CRLF" };
    const got = new TextDecoder().decode(bytes.slice(0, 56));
    if (!safeEq(got, getTrojanHash(pw))) return { hasError: true, message: "Bad password" };

    const cmd = bytes[58];
    if (cmd !== 0x01 && cmd !== 0x03) return { hasError: true, message: `Bad cmd ${cmd}` };
    const at = bytes[59];
    let av, al, ai;

    switch (at) {
        case 0x01: al = 4; ai = 60; if (buf.byteLength < ai + al + 2) return { hasError: true, message: "IPv4 truncated" }; av = Array.from(bytes.slice(ai, ai + al)).join("."); break;
        case 0x03: al = bytes[60]; ai = 61; if (buf.byteLength < ai + al + 2) return { hasError: true, message: "Domain truncated" }; av = new TextDecoder().decode(bytes.slice(ai, ai + al)); break;
        case 0x04: al = 16; ai = 60; if (buf.byteLength < ai + al + 2) return { hasError: true, message: "IPv6 truncated" }; av = Array.from({ length: 8 }, (_, i) => new DataView(buf).getUint16(ai + i * 2).toString(16)).join(":"); break;
        default: return { hasError: true, message: `Bad addr type ${at}` };
    }
    const port = new DataView(buf).getUint16(ai + al);
    const crlf = ai + al + 2;
    if (bytes[crlf] !== 0x0d || bytes[crlf + 1] !== 0x0a) return { hasError: true, message: "Missing final CRLF" };
    return { hasError: false, addressRemote: av, addressType: at === 0x03 ? 2 : at, portRemote: port, rawDataIndex: crlf + 2, responseHeader: new Uint8Array(0), isUDP: cmd === 0x03 };
}

// ============================================
// RELAY
// ============================================
async function relayToWS(remoteSocket, ws, respHeader, retry, log) {
    let header = respHeader;
    let hasData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, ctrl) {
            hasData = true;
            if (ws.readyState !== 1) { ctrl.error("WS closed"); return; }
            if (header && header.byteLength > 0) {
                ws.send(abConcat([header, chunk]));
                header = null;
            } else {
                ws.send(chunk);
            }
        },
        close() { log(`Remote closed (data: ${hasData})`); },
        abort(r) { console.error("Remote abort", r); }
    })).catch(e => {
        console.error("relay error", e);
        safeClose(ws);
    });
    if (!hasData && retry) { log("Retrying..."); retry(); }
    else if (!hasData) { safeClose(ws); }
}

// ============================================
// UDP / DoH
// ============================================
async function handleUDP(ws, respHeader, dohUrls, log) {
    let sent = false;
    const ts = new TransformStream({
        transform(chunk, ctrl) {
            for (let i = 0; i < chunk.byteLength;) {
                const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                const data = new Uint8Array(chunk.slice(i + 2, i + 2 + len));
                i += 2 + len; ctrl.enqueue(data);
            }
        }
    });
    ts.readable.pipeTo(new WritableStream({
        async write(chunk) {
            try {
                const res = await dohResolve(chunk, dohUrls);
                const sz = res.byteLength;
                const szBuf = new Uint8Array([sz >> 8 & 255, sz & 255]);
                if (ws.readyState === 1) {
                    if (sent) { ws.send(abConcat([szBuf, res])); }
                    else { ws.send(abConcat([respHeader, szBuf, res])); sent = true; }
                }
            } catch (e) { log("DoH failed", e.message); }
        }
    })).catch(e => log("UDP pipe error", e.message));
    const w = ts.writable.getWriter();
    return { write: x => w.write(x) };
}

// ============================================
// UTILS
// ============================================
function base64ToAB(b64) {
    if (!b64) return { earlyData: null, error: null };
    try {
        b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
        const dec = atob(b64);
        return { earlyData: Uint8Array.from(dec, c => c.charCodeAt(0)).buffer, error: null };
    } catch (e) { return { earlyData: null, error: e }; }
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));
function unsafeStringify(arr, off = 0) {
    return (byteToHex[arr[off + 0]] + byteToHex[arr[off + 1]] + byteToHex[arr[off + 2]] + byteToHex[arr[off + 3]] + "-" + byteToHex[arr[off + 4]] + byteToHex[arr[off + 5]] + "-" + byteToHex[arr[off + 6]] + byteToHex[arr[off + 7]] + "-" + byteToHex[arr[off + 8]] + byteToHex[arr[off + 9]] + "-" + byteToHex[arr[off + 10]] + byteToHex[arr[off + 11]] + byteToHex[arr[off + 12]] + byteToHex[arr[off + 13]] + byteToHex[arr[off + 14]] + byteToHex[arr[off + 15]]).toLowerCase();
}
function stringify(arr, off = 0) {
    const u = unsafeStringify(arr, off);
    if (!isValidUUID(u)) throw new TypeError("Bad UUID");
    return u;
}
function safeClose(s) { try { if (s.readyState === 1 || s.readyState === 2) s.close(); } catch (e) {} }

// ============================================
// UI
// ============================================
function getPage() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Galaxy-Tunnel VLESS / TROJAN</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body, html { width: 100%; height: 100%; background: #02060d; overflow: hidden; font-family: 'Segoe UI', Arial, sans-serif; display: flex; justify-content: center; align-items: center; }
    .space-bg { position: absolute; width: 100%; height: 100%; background: radial-gradient(circle at 50% 35%, rgba(10, 45, 80, 0.7) 0%, transparent 65%), radial-gradient(circle at 80% 80%, rgba(0, 150, 200, 0.15) 0%, transparent 50%), #02060d; z-index: 1; }
    .starfield { position: absolute; width: 100%; height: 100%; background-image: radial-gradient(2px 2px at 20px 30px, #ffffff, rgba(0,0,0,0)), radial-gradient(2px 2px at 40px 70px, rgba(0,212,255,0.8), rgba(0,0,0,0)), radial-gradient(1px 1px at 90px 40px, #ffffff, rgba(0,0,0,0)), radial-gradient(2px 2px at 160px 120px, rgba(0,212,255,0.9), rgba(0,0,0,0)); background-repeat: repeat; background-size: 220px 220px; animation: starTwinkle 4s ease-in-out infinite alternate; opacity: 0.6; }
    @keyframes starTwinkle { 0% { opacity: 0.4; transform: scale(1); } 100% { opacity: 0.8; transform: scale(1.02); } }
    .card-frame { position: relative; z-index: 10; width: 90vw; max-width: 480px; aspect-ratio: 1 / 1; background: rgba(4, 12, 24, 0.75); border: 1.5px solid rgba(0, 212, 255, 0.6); box-shadow: 0 0 25px rgba(0, 212, 255, 0.25), inset 0 0 25px rgba(0, 212, 255, 0.1); backdrop-filter: blur(12px); display: flex; flex-direction: column; justify-content: space-between; align-items: center; padding: 35px 25px 25px; border-radius: 4px; }
    .graphic-container { position: relative; width: 230px; height: 230px; display: flex; justify-content: center; align-items: center; }
    .ring { position: absolute; width: 240px; height: 75px; border: 2px solid rgba(0, 230, 255, 0.85); border-radius: 50%; transform: rotate(-28deg); box-shadow: 0 0 15px rgba(0, 212, 255, 0.8), inset 0 0 15px rgba(0, 212, 255, 0.5); pointer-events: none; animation: ringGlow 3s ease-in-out infinite alternate; }
    @keyframes ringGlow { 0% { opacity: 0.7; box-shadow: 0 0 12px rgba(0,212,255,0.6); } 100% { opacity: 1; box-shadow: 0 0 25px rgba(0,212,255,1); } }
    canvas { position: absolute; top: 0; left: 0; }
    .content-bottom { width: 100%; display: flex; flex-direction: column; align-items: center; text-align: center; position: relative; }
    .title { font-size: 34px; font-weight: 900; font-style: italic; color: #ffffff; letter-spacing: 2px; text-transform: uppercase; text-shadow: 0 0 12px rgba(255, 255, 255, 0.7); line-height: 1.1; }
    .subtitle { font-size: 16px; font-weight: 600; color: #7b93a7; letter-spacing: 5px; margin-top: 6px; text-transform: uppercase; }
    .access-badge { align-self: flex-end; margin-top: 15px; font-size: 20px; font-weight: 900; font-style: italic; color: #00e5ff; text-transform: uppercase; text-align: right; letter-spacing: 1px; line-height: 1.1; text-shadow: 0 0 15px rgba(0, 229, 255, 0.85); animation: statusPulse 2s infinite alternate; }
    @keyframes statusPulse { 0% { opacity: 0.8; text-shadow: 0 0 8px rgba(0,229,255,0.5); } 100% { opacity: 1; text-shadow: 0 0 20px rgba(0,229,255,1); } }
  </style>
</head>
<body>
  <div class="space-bg"></div>
  <div class="starfield"></div>
  <div class="card-frame">
    <div class="graphic-container">
      <div class="ring"></div>
      <canvas id="nodeCanvas" width="230" height="230"></canvas>
    </div>
    <div class="content-bottom">
      <h1 class="title">GALAXY-TUNNEL</h1>
      <div class="subtitle">VLESS / TROJAN</div>
      <div class="access-badge">GALAXY VPROXY<br>IS ACCESS</div>
    </div>
  </div>
  <script>
    const canvas = document.getElementById('nodeCanvas');
    const ctx = canvas.getContext('2d');
    const numNodes = 32; const nodes = []; const radius = 75;
    let angleX = 0.004; let angleY = 0.007;
    for (let i = 0; i < numNodes; i++) {
      let theta = Math.acos(Math.random() * 2 - 1);
      let phi = Math.random() * Math.PI * 2;
      nodes.push({ x: radius * Math.sin(theta) * Math.cos(phi), y: radius * Math.sin(theta) * Math.sin(phi), z: radius * Math.cos(theta) });
    }
    function rotateX(node, angle) { let cos = Math.cos(angle); let sin = Math.sin(angle); let y1 = node.y * cos - node.z * sin; let z1 = node.z * cos + node.y * sin; node.y = y1; node.z = z1; }
    function rotateY(node, angle) { let cos = Math.cos(angle); let sin = Math.sin(angle); let x1 = node.x * cos - node.z * sin; let z1 = node.z * cos + node.x * sin; node.x = x1; node.z = z1; }
    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      let cx = canvas.width / 2; let cy = canvas.height / 2;
      nodes.forEach(node => { rotateX(node, angleX); rotateY(node, angleY); });
      ctx.strokeStyle = 'rgba(0, 220, 255, 0.35)'; ctx.lineWidth = 1;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          let dist = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y, nodes[i].z - nodes[j].z);
          if (dist < 60) { ctx.beginPath(); ctx.moveTo(nodes[i].x + cx, nodes[i].y + cy); ctx.lineTo(nodes[j].x + cx, nodes[j].y + cy); ctx.stroke(); }
        }
      }
      nodes.forEach(node => {
        let size = (node.z + radius) / (2 * radius) * 3 + 2;
        ctx.beginPath(); ctx.arc(node.x + cx, node.y + cy, size, 0, Math.PI * 2);
        ctx.fillStyle = '#00f0ff'; ctx.shadowBlur = 8; ctx.shadowColor = '#00f0ff'; ctx.fill(); ctx.shadowBlur = 0;
      });
      requestAnimationFrame(draw);
    }
    draw();
  </script>
</body>
</html>`;
}
