// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Browser relay transport: a WebSocket to the dumb {sid,msg} relay, wrapped to the
 * { send, recv(type), hello, close } shape the takers expect. Takers connect with
 * the default role; the relay assigns a session id and forwards raw messages both
 * ways. Error/abort messages fast-fail any pending recv.
 *
 * Uses the global WebSocket (browser). Node callers/tests inject their own in-memory
 * transport instead of calling this.
 */
const ERROR_TYPES = new Set(['error', 'xmr_error', 'abort']);

export function connectRelay(url, { timeoutMs = 12000 } = {}) {
  return new Promise((resolve, reject) => {
    let ws;
    try { ws = new WebSocket(url); } catch (e) { reject(new Error('could not connect to the relay: ' + e.message)); return; }
    const inbox = [];
    const waiters = [];
    let hello = null, closed = false, settled = false, pinger = null, fatalErr = null;

    const openTimer = setTimeout(() => { if (!settled) { try { ws.close(); } catch {} reject(new Error('timed out connecting to the relay')); } }, timeoutMs);
    const rejectWaiters = (err) => { while (waiters.length) { const w = waiters.shift(); clearTimeout(w.to); w.reject(err); } };

    const transport = {
      get hello() { return hello; },
      get closed() { return closed; },
      send(msg) { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg)); else throw new Error('relay not open'); },
      recv(type, ms = 600000) {
        const i = inbox.findIndex((m) => m.type === type);
        if (i >= 0) return Promise.resolve(inbox.splice(i, 1)[0]);
        if (fatalErr) return Promise.reject(fatalErr); // L-2: a prior error/abort fast-fails every recv
        if (closed) return Promise.reject(new Error('relay closed'));
        return new Promise((res, rej) => {
          const to = setTimeout(() => { const j = waiters.indexOf(w); if (j >= 0) waiters.splice(j, 1); rej(new Error('timeout waiting for ' + type)); }, ms);
          const w = { type, resolve: res, reject: rej, to };
          waiters.push(w);
        });
      },
      close() { closed = true; clearInterval(pinger); try { ws.close(); } catch {} },
    };

    ws.onopen = () => { pinger = setInterval(() => { try { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: '_ping' })); } catch {} }, 25000); };
    ws.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (!m || typeof m.type !== 'string') return;
      // Defense-in-depth: drop prototype-pollution keys at ANY depth (nested objects such as the XMR
      // `bundle` were previously unscanned) before any consumer reads the message. The relay + maker are
      // untrusted; no legitimate message carries these keys, so rejecting the whole frame is safe. Depth-bounded.
      const hasDangerKey = (v, d) => {
        if (!v || typeof v !== 'object' || d > 6) return false;
        for (const k of Object.keys(v)) if (k === '__proto__' || k === 'constructor' || k === 'prototype') return true;
        for (const k of Object.keys(v)) if (hasDangerKey(v[k], d + 1)) return true;
        return false;
      };
      if (hasDangerKey(m, 0)) return;
      if (m.type === '_pong') return;
      if (m.type === '_relay_hello') { hello = m; if (!settled) { settled = true; clearTimeout(openTimer); resolve(transport); } return; }
      if (ERROR_TYPES.has(m.type)) { const err = new Error('maker: ' + (m.reason || m.type)); err.relayError = m; fatalErr = err; rejectWaiters(err); return; } // L-2: sticky; fast-fails current + future recv
      const i = waiters.findIndex((w) => w.type === m.type);
      if (i >= 0) { const w = waiters.splice(i, 1)[0]; clearTimeout(w.to); w.resolve(m); }
      else inbox.push(m);
    };
    ws.onerror = () => { if (!settled) { settled = true; clearTimeout(openTimer); reject(new Error('relay connection error')); } };
    ws.onclose = () => { closed = true; clearInterval(pinger); clearTimeout(openTimer); rejectWaiters(new Error('relay closed')); };
  });
}
