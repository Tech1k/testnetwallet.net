/* ============================================================================
 * mweb-node.mjs - Litecoin Core REST data layer for MWEB receive-side scanning.
 *
 * Talks to a litecoind exposing the read-only REST interface (-rest=1), fronted
 * by a CORS+TLS reverse proxy. No third-party indexer and no light-wallet
 * server: blocks come straight from the node, every output is scanned locally
 * in mweb.mjs, and keys never leave the browser. This is the HTTP/browser
 * counterpart to mwebd (which is P2P and not reachable from a web page).
 *
 * Endpoints used (all read-only GETs):
 *   /rest/chaininfo.json                 -> tip height, best hash, mweb active
 *   /rest/blockhashbyheight/<height>.json-> { blockhash }
 *   /rest/block/<hash>.json              -> full block incl. .mweb {outputs,inputs,...}
 * ========================================================================== */
import * as mweb from './mweb.mjs';

const REQ_TIMEOUT = 20000;     // per-request abort (ms)
const SCAN_CONCURRENCY = 16;   // blocks fetched in parallel per batch (multiplexes over HTTP/2 to the node)

// Normalize a node URL to its origin (tolerate a trailing slash or /rest).
function base(url) { return String(url || '').trim().replace(/\/+$/, '').replace(/\/rest$/, ''); }

async function jget(url, signal) {
  const ctl = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; ctl.abort(); }, REQ_TIMEOUT);
  const onAbort = () => ctl.abort();
  if (signal) { if (signal.aborted) ctl.abort(); else signal.addEventListener('abort', onAbort); }
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('json')) throw new Error('unexpected content-type: ' + ct);
    return await res.json();
  } catch (e) {
    // A timeout fires ctl.abort() too, which would otherwise be an indistinguishable AbortError that
    // the sync driver treats as a deliberate user-cancel (silent). Re-throw it as a normal error so it
    // surfaces; only a genuine external signal abort stays an AbortError.
    if (timedOut) throw new Error('request timed out (' + REQ_TIMEOUT + 'ms): ' + url);
    throw e;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

export async function getTip(node, signal) {
  const j = await jget(base(node) + '/rest/chaininfo.json', signal);
  return {
    height: j.blocks,
    hash: j.bestblockhash,
    chain: j.chain,
    ibd: !!j.initialblockdownload,
    mwebActive: !!(j.softforks && j.softforks.mweb && j.softforks.mweb.active),
  };
}
export async function getBlockHash(node, height, signal) {
  const j = await jget(base(node) + '/rest/blockhashbyheight/' + height + '.json', signal);
  return j.blockhash;
}
export async function getBlock(node, hash, signal) {
  return jget(base(node) + '/rest/block/' + hash + '.json', signal);
}
async function getBlockAt(node, height, signal) {
  return getBlock(node, await getBlockHash(node, height, signal), signal);
}

// Cheap health probe (chaininfo only, no scanning).
export async function probe(node, signal) {
  try { return { ok: true, ...(await getTip(node, signal)) }; }
  catch (e) { return { ok: false, error: e.message || String(e) }; }
}

// Scan heights [fromH, toH] inclusive. Seeds from (and mutates) opts.owned / opts.spent
// so callers can resume from a cache. onProgress(height, ownedCount) fires per batch.
// Throws AbortError if opts.signal aborts. Returns { owned, spent, lastHeight }.
export async function scanRange(node, keys, fromH, toH, opts = {}) {
  const { gap = 50, onProgress, signal, owned = new Map(), spent = new Set() } = opts;
  for (let start = fromH; start <= toH; start += SCAN_CONCURRENCY) {
    if (signal && signal.aborted) throw new DOMException('aborted', 'AbortError');
    const end = Math.min(start + SCAN_CONCURRENCY - 1, toH);
    const heights = [];
    for (let h = start; h <= end; h++) heights.push(h);
    const blocks = await Promise.all(heights.map((h) => getBlockAt(node, h, signal)));
    for (let i = 0; i < blocks.length; i++) {
      const h = heights[i];
      const mw = blocks[i] && blocks[i].mweb;
      if (!mw) continue;
      const found = mweb.scanBlockOutputs(keys, mw.outputs, gap);
      for (const u of found) { u.height = h; owned.set(u.output_id, u); }
      // Spend detection: an MWEB input references the spent output by its output_id, and `owned` is
      // keyed by output_id. Confirmed vs litecoin src/rpc/blockchain.cpp (objInput.pushKV("output_id",..))
      // and libmw Input.h (m_outputID). REST gives inputs as objects here; tolerate the compact
      // bare-hash-string form too.
      if (mw.inputs) for (const inp of mw.inputs) {
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

/* ---------------- broadcast (the one write path) ----------------
 * POSTs a JSON-RPC call to the method-allowlisted proxy (tools/mweb-rpc-proxy.js), which forwards
 * only sendrawtransaction / testmempoolaccept to litecoind. Returns litecoind's JSON-RPC result. */
async function rpcPost(endpoint, method, params, signal) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), REQ_TIMEOUT);
  const onAbort = () => ctl.abort();
  if (signal) { if (signal.aborted) ctl.abort(); else signal.addEventListener('abort', onAbort); }
  try {
    const res = await fetch(endpoint, {
      method: 'POST', signal: ctl.signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method, params }),
    });
    const txt = await res.text();
    let j; try { j = JSON.parse(txt); } catch (_) { throw new Error('non-JSON from broadcast endpoint (HTTP ' + res.status + ')'); }
    if (j.error) throw new Error((j.error.message || JSON.stringify(j.error)));
    return j.result;
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

// Dry-run: ask the node whether it WOULD accept the tx (no broadcast). Returns { txid, allowed, ... }.
export async function testAccept(endpoint, rawHex, signal) {
  const r = await rpcPost(endpoint, 'testmempoolaccept', [[rawHex]], signal);
  return Array.isArray(r) ? r[0] : r;
}

// Broadcast the extended MWEB raw-tx hex. Returns the txid on success, throws the node's reason on failure.
export async function broadcast(endpoint, rawHex, signal) {
  return rpcPost(endpoint, 'sendrawtransaction', [rawHex], signal);
}
