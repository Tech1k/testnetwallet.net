/* ============================================================================
 * mweb-node.mjs - data layer for the single-file MWEB helper (tools/mweb.php).
 *
 * The wallet talks ONLY to the helper, on one origin:
 *   GET  <helper>?tip            -> tip height + mweb-active
 *   GET  <helper>?from=H&to=H2   -> the MWEB outputs/inputs in that height range
 *   POST <helper>  {method,...}  -> broadcast (sendrawtransaction / testmempoolaccept)
 *
 * The helper fronts litecoind over localhost; keys never leave the browser, and it
 * serves outputs BY HEIGHT RANGE - the browser scans them locally (mweb.mjs), so the
 * helper never learns which outputs are yours. This replaces the old read-only /rest
 * CORS proxy AND the separate broadcast proxy with one drop-in file.
 * ========================================================================== */
import * as mweb from './mweb.mjs';

const REQ_TIMEOUT = 30000;   // per-request abort (ms); a range scan loops blocks server-side
const SCAN_CHUNK = 500;      // heights per scan request (the helper also caps server-side)

function url(node) { return String(node || '').trim().replace(/\/+$/, ''); }

async function jget(u, signal) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), REQ_TIMEOUT);
  const onAbort = () => ctl.abort();
  if (signal) { if (signal.aborted) ctl.abort(); else signal.addEventListener('abort', onAbort); }
  try {
    const res = await fetch(u, { signal: ctl.signal, headers: { accept: 'application/json' } });
    const txt = await res.text();
    let j; try { j = JSON.parse(txt); } catch (_) { throw new Error('MWEB helper returned HTTP ' + res.status + ' (is this the mweb.php URL?)'); }
    if (j && j.error) throw new Error(j.error.message || JSON.stringify(j.error));
    return j;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

export async function getTip(node, signal) {
  const j = await jget(url(node) + '?tip', signal);
  return { height: j.height, hash: j.hash, chain: j.chain, mwebActive: !!j.mwebActive };
}

// Scan heights [fromH, toH] inclusive, in chunks. Seeds from (and mutates) opts.owned / opts.spent
// so callers can resume from a cache. onProgress(height, ownedCount) fires per chunk.
// Throws AbortError if opts.signal aborts. Returns { owned, spent, lastHeight }.
export async function scanRange(node, keys, fromH, toH, opts = {}) {
  const { gap = 50, onProgress, signal, owned = new Map(), spent = new Set() } = opts;
  for (let start = fromH; start <= toH; start += SCAN_CHUNK) {
    if (signal && signal.aborted) throw new DOMException('aborted', 'AbortError');
    const end = Math.min(start + SCAN_CHUNK - 1, toH);
    const data = await jget(url(node) + '?from=' + start + '&to=' + end, signal);
    for (const blk of (data.blocks || [])) {
      const found = mweb.scanBlockOutputs(keys, blk.outputs, gap);
      for (const u of found) { u.height = blk.height; owned.set(u.output_id, u); }
      // spend detection: an MWEB input references the spent output by output_id (owned is keyed by it).
      if (blk.inputs) for (const inp of blk.inputs) {
        const ref = (typeof inp === 'string') ? inp : (inp && inp.output_id);
        if (ref && owned.has(ref)) spent.add(ref);
      }
    }
    if (onProgress) onProgress(end, owned.size);
  }
  return { owned, spent, lastHeight: toH };
}

// Unspent balance (litoshi, BigInt) from an owned map + spent set.
export function balanceOf(owned, spent) {
  let bal = 0n;
  for (const [id, u] of owned) if (!spent.has(id)) bal += BigInt(u.value);
  return bal;
}

/* ---------------- broadcast (POST to the same helper) ---------------- */
async function rpcPost(node, method, params, signal) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), REQ_TIMEOUT);
  const onAbort = () => ctl.abort();
  if (signal) { if (signal.aborted) ctl.abort(); else signal.addEventListener('abort', onAbort); }
  try {
    const res = await fetch(url(node), {
      method: 'POST', signal: ctl.signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method, params }),
    });
    const txt = await res.text();
    let j; try { j = JSON.parse(txt); } catch (_) { throw new Error('MWEB helper returned HTTP ' + res.status + ' (POST not handled - is mweb.php deployed?)'); }
    if (j.error) throw new Error(j.error.message || JSON.stringify(j.error));
    return j.result;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

// Dry-run: ask the node whether it WOULD accept the tx (no broadcast). Returns { txid, allowed, ... }.
export async function testAccept(node, rawHex, signal) {
  const r = await rpcPost(node, 'testmempoolaccept', [[rawHex]], signal);
  return Array.isArray(r) ? r[0] : r;
}

// Broadcast the extended MWEB raw-tx hex. Returns the txid on success, throws the node's reason on failure.
export async function broadcast(node, rawHex, signal) {
  return rpcPost(node, 'sendrawtransaction', [rawHex], signal);
}
