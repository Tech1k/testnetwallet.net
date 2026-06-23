#!/usr/bin/env node
/*
 * Local CORS bridge for browser-testing Monero against a public node that has no CORS headers
 * (and/or HSTS-upgrades http->https, like node2.monerodevs.org). Everything stays local http,
 * which sidesteps CORS, HSTS and mixed-content all at once.
 *
 *   node tools/cors-proxy.js                 # -> http://localhost:28089  ->  node2.monerodevs.org:28089
 *   XMR_UPSTREAM=http://host:port PORT=28089 node tools/cors-proxy.js
 *
 * Then in the wallet: Settings -> "Monero node RPC (testnet)" = http://localhost:28089, and Connect & sync.
 * THIS IS A LOCAL TEST TOOL ONLY. In production your own node serves CORS + HTTPS directly (no proxy).
 */
const http = require("http");
const UPSTREAM = process.env.XMR_UPSTREAM || "http://node2.monerodevs.org:28089";
const PORT = Number(process.env.PORT || 28089);

const cors = (res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");
};

http.createServer((req, res) => {
  cors(res);
  if(req.method === "OPTIONS"){ res.writeHead(204); return res.end(); }
  const target = new URL(req.url, UPSTREAM);
  const preq = http.request(target, { method: req.method, headers: { ...req.headers, host: target.host } }, (pres) => {
    cors(res);
    res.writeHead(pres.statusCode || 502, pres.headers);
    pres.pipe(res);                                  // streams binary (.bin sync endpoints) through untouched
  });
  preq.on("error", (e) => { try { res.writeHead(502); res.end("proxy error: " + e.message); } catch(_){} });
  req.pipe(preq);
}).listen(PORT, () => console.log(`CORS proxy: http://localhost:${PORT}  ->  ${UPSTREAM}`));
