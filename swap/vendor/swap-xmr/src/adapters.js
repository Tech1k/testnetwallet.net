// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr/adapters: the REAL chain adapters the driver (src/driver.js) needs,
 * so the same drivers run live (esplora for BTC/LTC, monero-ts for XMR) exactly
 * as they do against the mock adapters in tests. Used by the live harness
 * (tools/xmr-swap-live.mjs) and by the maker daemon's XMR handler.
 *
 * Deps are injected (btc = @scure/btc-signer, sc = swap-core, x = WASM crypto,
 * moneroTs) so this module stays environment-agnostic and import-light.
 */

const enc = (u) => Buffer.from(u).toString('hex');
const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function retry(label, fn, tries = 10, waitMs = 15000) {
  for (let i = 0; i < tries; i++) { try { return await fn(); } catch (e) { if (i === tries - 1) throw new Error(`${label}: ${e.message}`); await sleep(waitMs); } }
}

/**
 * Esplora-backed BTC/LTC chain adapter. `fundKeyHex` is the maker/taker's funding
 * key (its p2wpkh holds the coins that fund tx_lock). All methods match the
 * driver's `chains.btc` interface.
 */
export function esploraBtcChain({ btc, sc, x, api, network, fundKeyHex, feeRate = 2, pollMs = 15000, pollTries = 240, onConf = null, fetchTimeoutMs = 20000 }) {
  const fundPub = fromHex(x.secp_pubkey(fundKeyHex));
  const fundAddr = btc.p2wpkh(fundPub, network).address;
  // Bound every request with an AbortController timeout (mirrors swap-taker/esplora.js). A hung TCP
  // connection to the esplora during a confirmation poll, watchSpend, or broadcast must NOT block the swap
  // step forever: near T2 an indefinite stall on Bob's unwind refund means punished AND stranded XMR.
  const fetchT = async (url, opts) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), fetchTimeoutMs);
    try { return await fetch(url, { ...(opts || {}), signal: ac.signal }); } finally { clearTimeout(timer); }
  };
  const get = async (p) => { const r = await fetchT(api + p); const t = await r.text(); if (!r.ok) throw new Error(`GET ${p}: ${r.status} ${t}`); try { return JSON.parse(t); } catch { return t; } };
  const post = async (p, body) => { const r = await fetchT(api + p, { method: 'POST', body }); const t = (await r.text()).trim(); if (!r.ok) throw new Error(`POST ${p}: ${t}`); return t; };
  // One-shot: who (if anyone) spent txid:vout, with the spender's witness for that input.
  const outspendOnce = async (txid, vout) => {
    const os = await get(`/tx/${txid}/outspend/${vout}`);
    if (os && os.spent && os.txid) {
      const st = await get(`/tx/${os.txid}`);
      const vin = st.vin.find((v) => v.txid === txid && v.vout === vout);
      if (vin && vin.witness) return { spent: true, txid: os.txid, vin: os.vin, witness: vin.witness };
    }
    return { spent: false };
  };
  return {
    fundAddr,
    /** Sum of CONFIRMED UTXOs at the funding address (for the maker's liquidity gate). */
    async freeBalance() {
      const u = await get(`/address/${fundAddr}/utxo`);
      return (u || []).filter((o) => o.status && o.status.confirmed).reduce((s, o) => s + o.value, 0);
    },
    async buildLockFunding({ address, amount }) {
      // Coin-select an amount-sufficient UTXO set (not just the single largest), so a
      // pool split across several outputs can still fund a lock. ~68 vB per p2wpkh
      // input + ~85 vB overhead (2 outputs); covers amount + fee.
      const all = (await get(`/address/${fundAddr}/utxo`)).filter((u) => u.status && u.status.confirmed).sort((a, b) => b.value - a.value);
      if (!all.length) throw new Error('no confirmed funding utxo at ' + fundAddr);
      const wu = btc.p2wpkh(fundPub, network).script;
      const picked = [];
      let sum = 0;
      for (const u of all) {
        picked.push(u); sum += u.value;
        const fee = Math.ceil((picked.length * 68 + 85) * feeRate);
        if (sum >= amount + fee) break;
      }
      const finalFee = Math.ceil((picked.length * 68 + 85) * feeRate);
      if (sum < amount + finalFee) throw new Error(`insufficient funding at ${fundAddr}: have ${sum}, need ${amount}+${finalFee} fee`);
      const utxos = picked.map((u) => ({ inp: { txid: u.txid, index: u.vout, sequence: 0xfffffffd, witnessUtxo: { script: wu, amount: BigInt(u.value) } }, key: fromHex(fundKeyHex) }));
      const f = sc.buildFundingTx({ utxos, contractAddress: address, amount, changeAddress: fundAddr, feeRate, network });
      return { txid: f.txid, vout: f.vout, amount, hex: f.hex }; // UNBROADCAST
    },
    async broadcast(hex) {
      // Idempotent bounded retry. The REDEEM broadcast runs against an operator-run esplora (tLTC ->
      // testnetscan); a single transient hiccup there must NOT throw the whole swap into a multi-hour
      // reclaim. And if a prior attempt actually landed the tx but only its RESPONSE was lost, the retry
      // errors with "already known / in mempool / in block chain"; treat THAT as success and return the
      // real txid (derived locally from the same bytes), never a false interrupt. A genuine rejection
      // (bad fee, already-spent input) never says "already", so it still surfaces after the retries.
      let txid = null;
      try { txid = btc.Transaction.fromRaw(fromHex(hex), { allowUnknownOutputs: true, allowUnknownInputs: true, disableScriptCheck: true }).id; } catch {}
      let last;
      for (let i = 0; i < 6; i++) {
        try { return await post('/tx', hex); }
        catch (e) {
          if (txid && /already|txn-already|in the mempool|in block chain/i.test(String((e && e.message) || e))) return txid;
          last = e; await sleep(3000);
        }
      }
      throw last;
    },
    async waitConfirmed(txid, conf) {
      const need = (conf || 0) <= 0 ? 0 : conf; // honor the requested depth (H1), not just "any confirmation"
      // Optional per-poll progress: report the current confirmation depth so a caller can render
      // "1/2" during the (on testnet, 20+ min) wait instead of a frozen "waiting". Never affects
      // the return conditions below; a throwing hook is swallowed.
      const tick = (d) => { if (onConf) { try { onConf(d, need); } catch {} } };
      for (let i = 0; i < pollTries; i++) {
        try {
          const s = await get(`/tx/${txid}/status`);
          if (s && s.confirmed) {
            if (need <= 1) { tick(1); return; }
            let depth = 1;
            try { const tip = parseInt(String(await get('/blocks/tip/height')).trim(), 10); const bh = Number(s.block_height); if (Number.isInteger(tip) && Number.isInteger(bh)) depth = Math.max(1, tip - bh + 1); } catch {}
            tick(depth);
            if (depth >= need) return;
          } else { tick(0); }
        } catch {}
        if (need <= 0) return;
        await sleep(pollMs);
      }
      throw new Error('confirm timeout ' + txid);
    },
    async getOutput(txid, vout) {
      const t = await retry('getOutput', () => get(`/tx/${txid}`), 12, 5000);
      if (!t || !Array.isArray(t.vout) || !t.vout[vout]) throw new Error(`getOutput: no vout ${txid}:${vout}`);
      const o = t.vout[vout];
      return { value: o.value, scriptPubKeyHex: o.scriptpubkey };
    },
    /** Current confirmation depth of txid (0 if unconfirmed / unreadable). For the forward-resume
     *  timelock-margin check (how many blocks remain before the lock's BIP68 cancel window). Retries
     *  transient API errors so a flaky operator esplora doesn't collapse to a false 0; a persistent
     *  failure returns 0, which the caller treats as "unknown -> fail closed to reclaim" (never a false
     *  green light to broadcast). A legitimately-unconfirmed tx returns 0 without retrying. */
    async txConfs(txid) {
      try {
        return await retry('txConfs', async () => {
          const s = await get(`/tx/${txid}/status`);
          if (!s || !s.confirmed) return 0;
          const tip = parseInt(String(await get('/blocks/tip/height')).trim(), 10);
          const bh = Number(s.block_height);
          if (!Number.isInteger(tip) || !Number.isInteger(bh)) throw new Error('bad height response');
          return Math.max(1, tip - bh + 1);
        }, 3, 2000);
      } catch { return 0; }
    },
    /** One-shot check whether txid:vout is already spent (non-blocking); {spent, txid?, witness?}. */
    async getSpend(txid, vout) { try { return await outspendOnce(txid, vout); } catch { return { spent: false }; } },
    async watchSpend(txid, vout) { return (await this.findSpend(txid, vout)).witness; },
    /** Poll until txid:vout is spent; resolve { txid, vout, witness } of the spender. */
    async findSpend(txid, vout) {
      for (let i = 0; i < pollTries; i++) {
        try { const s = await outspendOnce(txid, vout); if (s.spent) return { txid: s.txid, vout: s.vin, witness: s.witness }; } catch {}
        await sleep(pollMs);
      }
      throw new Error('findSpend timeout ' + txid + ':' + vout);
    },
  };
}

/**
 * monero-ts-backed XMR engine adapter. `fundWallet` is an opened monero-ts wallet
 * holding spendable XMR (used by Alice's `lock`); Bob's side only uses waitLocked
 * + sweep (which open their own wallets from the shared view / combined keys).
 */
export function moneroXmrEngine({ moneroTs, node, networkType, fundWallet, pollMs = 20000, pollTries = 300 }) {
  const NT = networkType;
  return {
    async lock({ address, amount }) {
      const w = await fundWallet;
      const txs = await retry('xmr lock', () => w.createTxs({ accountIndex: 0, address, amount: BigInt(amount), relay: true }));
      return txs[0].getHash();
    },
    async waitLocked({ address, privateViewKey, restoreHeight, amount }) {
      // Gate on UNLOCKED balance (matured, ~10 confs), not just seen; Bob must not
      // release the redeem adaptor against XMR that is still 0-conf / unmatured.
      const w = await moneroTs.createWalletFull({ networkType: NT, server: { uri: node }, primaryAddress: address, privateViewKey, restoreHeight, password: '' });
      try { for (let i = 0; i < pollTries; i++) { try { await w.sync(); if ((await w.getUnlockedBalance()) >= BigInt(amount)) return; } catch {} await sleep(pollMs); } throw new Error('waitLocked timeout (xmr not confirmed/matured)'); }
      finally { await w.close(); }
    },
    async sweep({ privateSpendKey, privateViewKey, primaryAddress, restoreHeight, dest }) {
      const w = await moneroTs.createWalletFull({ networkType: NT, server: { uri: node }, privateSpendKey, privateViewKey, primaryAddress, restoreHeight, password: '' });
      try {
        let sawUnlocked = false;
        for (let i = 0; i < pollTries; i++) { try { await w.sync(); if ((await w.getUnlockedBalance()) > 0n) { sawUnlocked = true; break; } } catch {} await sleep(pollMs); }
        if (!sawUnlocked) throw new Error('xmr sweep: no unlocked balance observed before timeout (funds NOT swept)');
        const txs = await retry('xmr sweep', () => w.sweepUnlocked({ address: dest, relay: true }));
        const ids = txs.map((t) => t.getHash());
        if (!ids.length) throw new Error('xmr sweep produced no transactions');
        return ids;
      } finally { await w.close(); }
    },
    // Current daemon height. Used as a wallet restoreHeight so waitLocked/sweep scan from ~now
    // instead of genesis (a genesis rescan can exceed the sweep timeout). Mirrors the browser
    // engine's getDaemonHeight.
    async daemonHeight() {
      const d = await moneroTs.connectToDaemonRpc(node);
      return Number(await d.getHeight());
    },
  };
}
