// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Esplora-backed BTC/LTC chain adapter (mempool.space / litecoinspace shape), used
 * by BOTH takers. Read + broadcast + spend-watch over fetch. One `getOutput` shape
 * serves both consumers (HTLC reads .scriptpubkey/.confirmations; the XMR driver
 * reads .scriptPubKeyHex/.value). `confirmations` is computed from the chain tip and
 * is NEVER NaN (a bad tip yields 0 so a swap waits rather than proceeding blind).
 */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function esploraChain({ api, pollMs = 15000, pollTries = 240 }) {
  const base = String(api).replace(/\/+$/, '');
  // Bounded fetch: abort after a timeout so a slow/unreachable explorer fails fast instead of
  // hanging a balance refresh, broadcast, or confirmation poll forever.
  const fetchT = (u, opt, ms = 12000) => { const ac = new AbortController(); const t = setTimeout(() => ac.abort(), ms); return fetch(u, Object.assign({ signal: ac.signal }, opt || {})).finally(() => clearTimeout(t)); };
  const get = async (p) => { const r = await fetchT(base + p); const t = await r.text(); if (!r.ok) throw new Error('GET ' + p + ': ' + r.status); try { return JSON.parse(t); } catch { return t; } };
  const post = async (p, body) => { const r = await fetchT(base + p, { method: 'POST', body }); const t = (await r.text()).trim(); if (!r.ok) throw new Error(t || ('POST ' + p + ' ' + r.status)); return t; };
  const tipHeight = async () => { const t = await get('/blocks/tip/height'); const h = parseInt(String(t).trim(), 10); if (!Number.isInteger(h) || h < 0) throw new Error('bad tip height'); return h; };
  const outspendOnce = async (txid, vout) => {
    const os = await get('/tx/' + txid + '/outspend/' + vout);
    if (os && os.spent && os.txid) { const st = await get('/tx/' + os.txid); const vin = st.vin.find((v) => v.txid === txid && v.vout === vout); if (vin && vin.witness) return { spent: true, txid: os.txid, vin: os.vin, witness: vin.witness }; }
    return { spent: false };
  };
  const self = {
    async getUtxos(address) { const u = await get('/address/' + encodeURIComponent(address) + '/utxo'); return Array.isArray(u) ? u : []; },
    async freeBalance(address) { const u = await self.getUtxos(address); return u.filter((o) => o.status && o.status.confirmed).reduce((s, o) => s + o.value, 0); },
    async getOutput(txid, vout) {
      let tx; try { tx = await get('/tx/' + txid); } catch { return null; }
      if (!tx || !Array.isArray(tx.vout) || !tx.vout[vout]) return null;
      const o = tx.vout[vout];
      let confirmations = 0;
      if (tx.status && tx.status.confirmed) {
        try { const tip = await tipHeight(); const bh = Number(tx.status.block_height); if (Number.isInteger(tip) && Number.isInteger(bh)) confirmations = Math.max(0, tip - bh + 1); } catch {}
      }
      return { value: o.value, scriptpubkey: o.scriptpubkey, scriptPubKeyHex: o.scriptpubkey, confirmed: !!(tx.status && tx.status.confirmed), confirmations };
    },
    async broadcast(hex) { return post('/tx', hex); },
    async waitConfirmed(txid, conf) {
      const need = (conf || 0) <= 0 ? 0 : conf; // honor the requested depth (H1), not just "any confirmation"
      for (let i = 0; i < pollTries; i++) {
        try {
          const s = await get('/tx/' + txid + '/status');
          if (s && s.confirmed) {
            if (need <= 1) return;
            try { const tip = await tipHeight(); const bh = Number(s.block_height); if (Number.isInteger(tip) && Number.isInteger(bh) && (tip - bh + 1) >= need) return; } catch {}
          }
        } catch {}
        if (need <= 0) return;
        await sleep(pollMs);
      }
      throw new Error('confirm timeout ' + txid);
    },
    /** Block until txid:vout is spent; resolve the spending tx's witness. */
    async watchSpend(txid, vout) { return (await self.findSpend(txid, vout)).witness; },
    /** Block until txid:vout is spent; resolve { txid, vout, witness } of the spender. */
    async findSpend(txid, vout) {
      for (let i = 0; i < pollTries; i++) { try { const s = await outspendOnce(txid, vout); if (s.spent) return { txid: s.txid, vout: s.vin, witness: s.witness }; } catch {} await sleep(pollMs); }
      throw new Error('findSpend timeout ' + txid + ':' + vout);
    },
    /** One-shot: is txid:vout already spent? {spent, txid?, witness?}. */
    async getSpend(txid, vout) { try { return await outspendOnce(txid, vout); } catch { return { spent: false }; } },
    /**
     * Poll an address until its CONFIRMED UTXOs sum to >= minSats (the deposit step).
     * Requires confirmation (an unconfirmed/RBF-able deposit is not "detected") and
     * sums across multiple UTXOs (a dust-split deposit still completes). Resolves
     * { total, utxos }.
     */
    async waitForFunding(address, minSats, { onPoll } = {}) {
      for (let i = 0; i < pollTries; i++) {
        let total = 0, pending = 0, err = null;
        try {
          const all = await self.getUtxos(address);
          const confirmed = all.filter((o) => o.status && o.status.confirmed);
          total = confirmed.reduce((s, o) => s + o.value, 0);
          if (total >= minSats) { if (onPoll) { try { onPoll(i, total, 0, null); } catch {} } return { total, utxos: confirmed }; }
          // Also surface UNCONFIRMED (mempool) value so the UI can acknowledge a just-sent deposit
          // instead of dead air. It is NOT treated as funding; only confirmed >= minSats completes.
          pending = all.filter((o) => !(o.status && o.status.confirmed)).reduce((s, o) => s + o.value, 0);
        } catch (e) { err = e; } // explorer slow/unreachable this round -> report it, don't go silent
        // ALWAYS tick, every round (incl. errors), so the UI has a live heartbeat instead of a frozen
        // "waiting" when a flaky/operator-run explorer is dropping requests or lagging its UTXO index.
        if (onPoll) { try { onPoll(i, total, pending, err); } catch {} }
        await sleep(pollMs);
      }
      throw new Error('no confirmed funding of >= ' + minSats + ' sats appeared at ' + address);
    },
  };
  return self;
}
