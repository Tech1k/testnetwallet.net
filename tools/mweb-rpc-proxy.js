#!/usr/bin/env node
/*
 * MWEB BROADCAST bridge. The wallet builds + signs an MWEB transaction entirely in the browser;
 * the only thing it can't do is hand the finished raw tx to litecoind, because the node's REST
 * interface is read-only. This is the one small write path: a method-ALLOWLISTED JSON-RPC
 * forwarder that accepts ONLY `sendrawtransaction` and `testmempoolaccept`, injects the
 * rpcuser:rpcpassword the browser must never hold, and adds CORS. Everything else is rejected.
 *
 *   RPC_URL=http://127.0.0.1:19332 RPC_USER=litecoinrpc RPC_PASS=secret PORT=19090 \
 *     node tools/mweb-rpc-proxy.js
 *
 * Then in the wallet: Settings -> "MWEB broadcast endpoint" = http://localhost:19090
 * In production, front it with TLS on the SAME origin as your /rest/ node (so the page CSP,
 * which already allows that origin, covers it) and keep it bound to localhost behind the proxy.
 * NEVER expose generic litecoind RPC to the internet - only these two read/broadcast methods.
 */
const http = require('http');
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:19332';
const RPC_USER = process.env.RPC_USER || 'litecoinrpc';
const RPC_PASS = process.env.RPC_PASS || '';
const PORT = Number(process.env.PORT || 19090);
const ALLOW = new Set(['sendrawtransaction', 'testmempoolaccept']);

const cors = (res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
};
const reply = (res, code, obj) => {
  cors(res); res.setHeader('Content-Type', 'application/json');
  res.writeHead(code); res.end(JSON.stringify(obj));
};

http.createServer((req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (req.method !== 'POST') return reply(res, 405, { error: { message: 'POST only' } });
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 1e6) { req.destroy(); return; } });
  req.on('end', () => {
    let method, params;
    try {
      const j = JSON.parse(body);
      method = j.method; params = j.params;
      if (!method && typeof j.hex === 'string') { method = 'sendrawtransaction'; params = [j.hex]; }   // convenience: {hex}
    } catch (_) { return reply(res, 400, { error: { message: 'bad json' } }); }
    if (!ALLOW.has(method)) return reply(res, 403, { error: { message: 'method not allowed: ' + method } });

    const payload = JSON.stringify({ jsonrpc: '1.0', id: 'mweb', method, params: params || [] });
    const u = new URL(RPC_URL);
    const preq = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname || '/', method: 'POST',
      headers: {
        'content-type': 'text/plain',
        'content-length': Buffer.byteLength(payload),
        authorization: 'Basic ' + Buffer.from(RPC_USER + ':' + RPC_PASS).toString('base64'),
      },
    }, (pres) => {
      let out = ''; pres.on('data', (d) => { out += d; });
      pres.on('end', () => { cors(res); res.setHeader('Content-Type', 'application/json'); res.writeHead(pres.statusCode || 502); res.end(out); });
    });
    preq.on('error', (e) => reply(res, 502, { error: { message: 'rpc error: ' + e.message } }));
    preq.end(payload);
  });
}).listen(PORT, () => console.log('MWEB RPC proxy: http://localhost:' + PORT + '  ->  ' + RPC_URL + '  (allow: ' + [...ALLOW].join(', ') + ')'));
