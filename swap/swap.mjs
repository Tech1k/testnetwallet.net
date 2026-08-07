// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * TestnetWallet <-> TestnetSwap integration glue.
 *
 * The wallet is the swap TAKER (= Alice). Everything the shared taker engine needs is INJECTED here, so
 * swap/vendor/* stays byte-identical to the testnetswap repo (see swap/vendor/VENDOR.lock). The wallet's
 * advantage over the website taker: it holds the user's keys and funds, so there is no manual deposit.
 *   - XMR -> tBTC/tLTC: the Monero lock is SENT from the user's open monero-ts wallet (createTx+relayTx),
 *     and the settle coin is redeemed straight to the user's own receive address.
 *   - tLTC <-> tBTC (HTLC): the settle contract is funded from the user's balance (see runHtlcSwap).
 *
 * This module is pure: app.js passes the wallet context (open XMR wallet, node, addresses, a store
 * adapter, a BTC funder). No app.js state is reached into directly.
 */
import './vendor/swap-taker/buffer-shim.js';
import * as sc from './vendor/swap-core/src/index.js';
import * as btc from './vendor/swap-core/vendor/btc-signer.mjs';
import * as as from './vendor/swap-xmr/src/adaptorswap.js';
import * as driver from './vendor/swap-xmr/src/driver.js';
import { esploraBtcChain } from './vendor/swap-xmr/src/adapters.js';
import { loadXmrCrypto } from './vendor/swap-xmr/src/crypto.js';
import { esploraChain } from './vendor/swap-taker/esplora.js';
import { connectRelay } from './vendor/swap-taker/relay.js';
import { runXmrTaker, runXmrResume, requestXmrQuote, reclaimXmr,
         runHtlcTaker, refundHtlc, genHtlcKeys, htlcFundingAddress } from './vendor/swap-taker/taker.js';
import * as moneroEngine from '../monero-engine.mjs';

/* ---- config (override via window globals for local dev) ---- */
export const RELAY = (typeof window !== 'undefined' && window.TESTNETSWAP_RELAY) || 'wss://relay.testnetswap.com/';
const relayUrlFor = (makerId) => (makerId ? RELAY + (RELAY.includes('?') ? '&' : '?') + 'maker=' + encodeURIComponent(makerId) : RELAY);
// Settle coins the XMR path can receive; the HTLC pair is tLTC<->tBTC.
export const ESPLORA = { tBTC: 'https://mempool.space/testnet4/api', tLTC: 'https://testnetscan.com/ltc-testnet/api' };
const SETTLE_NET = { tBTC: sc.BTC_TESTNET4, tLTC: sc.LTC_TESTNET };
export const settleApi = (c) => ESPLORA[c] || ESPLORA.tBTC;
export const settleNet = (c) => SETTLE_NET[c] || sc.BTC_TESTNET4;
export const explorerTx = (coin, txid) => settleApi(coin).replace('/api', '') + '/tx/' + txid;
// Reorg-safe confirmation depth on the settle chain before we reveal a secret / lock XMR. testnet4-class
// chains can reorg several blocks deep, so this is materially deeper than a mainnet 1-3, and per-coin.
const REORG_CONF = { tBTC: 6, tLTC: 6 };
const settleConf = (coin) => REORG_CONF[coin] || 6;
const REDEEM_FEE_SATS = 1000;          // matches the driver's redeemTemplate default; net received = lock - fee
const PICO = 1e12, SATS = 1e8;
export const fmtXmr = (p) => (Number(p) / PICO).toFixed(6).replace(/0+$/, '').replace(/\.$/, '');
export const fmtBtc = (s) => (Number(s) / SATS).toFixed(8).replace(/0+$/, '').replace(/\.$/, '');
export const netSats = (grossSats) => Math.max(0, Number(grossSats) - REDEEM_FEE_SATS);

/* ---- WASM adaptor crypto (small; loaded on first swap) ---- */
let _x = null;
export async function loadCrypto() { if (!_x) _x = await loadXmrCrypto(); return _x; }

/* ---- recovery persistence: a single-slot blob, stored via a host adapter (app.js -> the wallet vault) ---- */
let _store = { get: () => null, set: () => {}, clear: () => {} };
export function configureStore(adapter) { _store = adapter; }
export function getRecovery() { try { return _store.get() || null; } catch { return null; } }
// The single recovery slot can hold EITHER an XMR blob or an HTLC blob; classify by shape.
// XMR blobs are the default (legacy ones on disk have no `kind` field), so test HTLC first.
export function recoveryKind() {
  const r = getRecovery();
  if (!r) return null;
  if (r.kind === 'htlc' || r.kind === 'htlc-predeposit') return 'htlc';
  if (r.lockOutpoint && r.km) return 'xmr';
  return null;
}
export function hasRecovery() { return recoveryKind() != null; }
export function clearRecovery() { try { _store.clear(); } catch {} }
// Await the ACTUAL disk write (the adapter's set returns the persistence promise), so a swap that is
// about to lock/fund fails CLOSED if persistence fails - never lock without a durably saved reclaim path.
const saveRecovery = async (r) => { await _store.set(r); };

/* ---- XMR chain backed by the wallet's OWN Monero engine ----
 * lock(): SEND the 2-of-2 lock from the user's open, already-synced wallet (no manual deposit).
 * sweep(): reclaim path - open a fresh wallet from the recovered combined keys and sweep home. */
function makeWalletXmrChain({ xmrWallet, net, nodeUrl, onNode = () => {} }) {
  return {
    async lock({ address, amount }) {
      const tx = await xmrWallet.createTx({ accountIndex: 0, destinations: [{ address, amount: BigInt(amount) }], relay: false });
      await xmrWallet.relayTx(tx);
      try { return tx.getHash(); } catch { return 'xmr-lock'; }
    },
    async sweep({ privateSpendKey, privateViewKey, primaryAddress, restoreHeight, dest }) {
      const w = await moneroEngine.openFromKeys({ network: net, nodeUrl, primaryAddress, privateViewKey, privateSpendKey, restoreHeight: restoreHeight || 0 });
      try {
        let ok = false;
        for (let i = 0; i < 1200; i++) {
          try { await w.sync(); if ((await w.getUnlockedBalance()) > 0n) { ok = true; break; } }
          catch { onNode('reconnecting to the Monero node…'); }
          await new Promise((r) => setTimeout(r, 12000));
        }
        if (!ok) throw new Error('no unlocked Monero to reclaim yet (still maturing). Retry shortly.');
        const txs = await w.sweepUnlocked({ address: dest, relay: true });
        const ids = (Array.isArray(txs) ? txs : [txs]).filter(Boolean).map((t) => t.getHash());
        if (!ids.length) throw new Error('sweep produced no transaction');
        return ids;
      } finally { try { await w.close(); } catch {} }
    },
  };
}

/* ---- quote preview (cheap; quote_only, its own throwaway connection) ---- */
export async function getXmrQuote({ fromCoin = 'tXMR', toCoin = 'tBTC', sendPico, makerId = null }) {
  const relay = await connectRelay(relayUrlFor(makerId));
  try { return await requestXmrQuote({ transport: relay, fromCoin, toCoin, sendPico: Math.round(sendPico), quoteOnly: true }); }
  finally { try { relay.close && relay.close(); } catch {} }
}

/* ---- run an XMR -> settle swap to completion; the wallet locks the XMR from the user's balance ---- */
/* True only if txid:vout is spent AND the spending tx has CONFIRMED. getSpend alone reports a mempool spend
 * as spent, which is NOT enough to give up the ONLY (random, non-seed-derived) refund key - a mempool-only
 * spend can still be evicted. Never throws (a read failure -> false -> keep the key). */
async function confirmedSpend(chain, txid, vout) {
  try {
    const sp = await chain.getSpend(txid, vout);
    if (!(sp && sp.spent && sp.txid)) return false;
    const o = await chain.getOutput(sp.txid, 0);                 // read the spender tx's own confirmation depth
    return !!(o && o.confirmed);
  } catch { return false; }
}

/* Wait for a just-broadcast settle-coin redeem to CONFIRM to `conf` depth before the caller drops the
 * recovery blob. Returns false on timeout / missing txid so the caller KEEPS the blob (the redeem stays
 * re-drivable via finishXmrSwap) instead of losing both legs if the redeem is later evicted. Never throws. */
async function confirmRedeem(btcChain, redeemTxid, conf, onStatus, toCoin) {
  if (!redeemTxid) return false;                                 // nothing to track -> cannot safely confirm; keep the blob
  onStatus('redeeming', 'your ' + toCoin + ' redeem is broadcast; waiting for it to confirm', { coin: toCoin, txid: redeemTxid });
  try { await btcChain.waitConfirmed(redeemTxid, conf); return true; }
  catch { onStatus('redeeming', 'your ' + toCoin + ' redeem is broadcast but not yet confirmed; keep this open, or use Finish later to complete it', { coin: toCoin, txid: redeemTxid }); return false; }
}

export async function runXmrSwap({
  fromCoin = 'tXMR', toCoin = 'tBTC', sendPico, makerId = null,
  xmrWallet, xmrNet, nodeUrl, btcReceiveAddr, xmrRefundAddr, restoreHeight = 0, minLockSats = null,
  onStatus = () => {},
}) {
  if (!xmrWallet) throw new Error('the Monero wallet is not open/synced yet');
  if (!btcReceiveAddr) throw new Error('missing a ' + toCoin + ' receive address');
  // Defense in depth for the single recovery slot: never start a fresh swap over a recoverable blob.
  if (hasRecovery()) throw new Error('a swap is already pending; finish or clear it before starting another');
  const x = await loadCrypto();
  const relay = await connectRelay(relayUrlFor(makerId));
  try {
    const q = await requestXmrQuote({ transport: relay, fromCoin, toCoin, sendPico: Math.round(sendPico), quoteOnly: false });
    // Require the maker to POSITIVELY confirm the Monero network: an omitted `network` must be a hard failure,
    // not a silent fallback to our own net, before we derive any lock address from it.
    if (!q.network || q.network !== xmrNet) throw new Error('the maker did not confirm the Monero network (' + xmrNet + '); aborting before any lock');
    const net = q.network;
    // rate-honesty floor: refuse (before locking) if the execution quote dropped below what was shown
    if (minLockSats != null && Number(q.lock_sats) < Math.floor(Number(minLockSats) * 0.98)) {
      throw new Error('the maker now offers ' + fmtBtc(q.lock_sats) + ' ' + toCoin + ', below your quoted ' + fmtBtc(minLockSats) + '. Re-quote and try again.');
    }
    // SEND-side ceiling: the maker dictates xmr_pico, but it must NEVER exceed what the user asked to
    // send. Allow the maker to ask for LESS (better for the user), never more (bait-and-switch overcharge).
    const wantPico = Math.round(sendPico);
    // Reject anything that is not a finite, positive amount within (0, wantPico]: allow the maker to ask for
    // LESS, never more (overcharge) and never a NaN/garbage value (which would otherwise flow to BigInt(NaN)).
    if (q.xmr_pico != null && !(Number.isFinite(Number(q.xmr_pico)) && Number.isInteger(Number(q.xmr_pico)) && Number(q.xmr_pico) > 0 && Number(q.xmr_pico) <= wantPico)) {
      throw new Error('the maker asked to lock ' + fmtXmr(q.xmr_pico) + ' XMR, not within (0, your ' + fmtXmr(wantPico) + ']. Aborting before any lock.');
    }
    const km = as.genKeyMaterial(x);
    const btcChain = esploraBtcChain({ btc, sc, x, api: settleApi(toCoin), network: settleNet(toCoin), fundKeyHex: km.btcKey });
    const xmrChain = makeWalletXmrChain({ xmrWallet, net, nodeUrl });
    const params = {
      fromCoin, toCoin,                                   // coin tickers -> the driver emits coin-correct status notes (no hardcoded tBTC/tXMR)
      sendCoinNetwork: settleNet(toCoin), moneroNetwork: net,
      t1Blocks: q.t1_blocks, t2Blocks: q.t2_blocks, lockAmount: q.lock_sats, minConf: settleConf(toCoin),
      xmrAmount: q.xmr_pico != null ? Number(q.xmr_pico) : wantPico,
      xmrRestoreHeight: restoreHeight, xmrSweepDest: xmrRefundAddr, aliceBtcDest: btcReceiveAddr,
      setupTimeoutMs: 60000, lockTimeoutMs: 3_600_000, redeemTimeoutMs: 3_600_000, onStatus,
    };
    // Persist the reclaim blob (awaited) BEFORE any XMR is locked - a stall is then always recoverable.
    const onBeforeLock = async (recovery) => {
      await saveRecovery({ kind: 'xmr', ...recovery, toCoin, sendPico, btcDest: btcReceiveAddr, xmrRefund: xmrRefundAddr, makerId, xmrRestoreHeight: restoreHeight, at: Math.floor(Date.now() / 1000) });
    };
    const res = await runXmrTaker({
      x, btc, as, driver, transport: relay, chains: { btc: btcChain, xmr: xmrChain }, km, params,
      onBeforeLock, sc, relayFactory: () => connectRelay(relayUrlFor(makerId)),
    });
    // FUND-SAFETY (mirror the HTLC redeem guard in runHtlcSwap): the driver returns 'redeemed' the instant the
    // settle-coin redeem is BROADCAST, not confirmed. Clearing now would be catastrophic if that redeem were
    // then evicted/reorged after the maker scraped m_a from the mempool witness and swept the XMR - the cleared
    // blob held the ONLY km/lockOutpoint/bCancelSig, so BOTH legs would be unrecoverable. Keep the blob until the
    // redeem CONFIRMS to the reorg-safe depth; a stall leaves it resumable via finishXmrSwap.
    const confirmed = await confirmRedeem(btcChain, res && res.redeemTxid, settleConf(toCoin), onStatus, toCoin);
    if (confirmed) clearRecovery();
    return { ...res, confirmed, quotedSats: Number(q.lock_sats), netSats: netSats(q.lock_sats), toCoin, sentPico: params.xmrAmount };
  } finally { try { relay.close && relay.close(); } catch {} }
}

/* ---- finish a persisted (interrupted) XMR swap forward: receive the settle coin without reclaiming ---- */
export async function finishXmrSwap({ recovery, onStatus = () => {} }) {
  if (!recovery || !recovery.lockOutpoint) return { state: 'must_reclaim', reason: 'incomplete_recovery' };
  const x = await loadCrypto();
  const settle = recovery.toCoin || 'tBTC';
  const btcChain = esploraBtcChain({ btc, sc, x, api: settleApi(settle), network: settleNet(settle), fundKeyHex: recovery.km.btcKey });
  const res = await runXmrResume({
    x, btc, as, driver, chains: { btc: btcChain }, km: recovery.km, persisted: recovery,
    sendCoinNetwork: settleNet(settle), aliceDest: recovery.btcDest, sc,
    minRevealConf: settleConf(settle),   // reorg-safe reveal floor on the resume path (matches the live-path minConf)
    relayFactory: () => connectRelay(relayUrlFor(recovery.makerId || null)), onStatus,
  });
  // Same confirmation guard as the live path: only drop the blob once the resumed redeem CONFIRMS (or is
  // already confirmed on-chain), so an evicted re-broadcast stays resumable rather than lost.
  let confirmed = false;
  if (res && res.state === 'redeemed') confirmed = await confirmRedeem(btcChain, res.redeemTxid, settleConf(settle), onStatus, settle);
  if (confirmed) clearRecovery();
  return { ...res, confirmed, toCoin: settle };
}

/* ---- reclaim a stalled XMR swap: chase the maker's on-chain refund, recover the key, sweep XMR home ---- */
export async function reclaimXmrSwap({ recovery, xmrNet, nodeUrl, xmrDest, onProgress = () => {} }) {
  if (!recovery || !recovery.lockOutpoint) throw new Error('no recoverable Monero swap');
  const x = await loadCrypto();
  const settle = recovery.toCoin || 'tBTC';
  const btcChain = esploraBtcChain({ btc, sc, x, api: settleApi(settle), network: settleNet(settle), fundKeyHex: recovery.km.btcKey });
  const xmrChain = makeWalletXmrChain({ xmrWallet: null, net: recovery.moneroNetwork || xmrNet, nodeUrl, onNode: (m) => onProgress(m) });
  const res = await reclaimXmr({
    x, btc, as, driver, chains: { btc: btcChain, xmr: xmrChain }, recovery,
    sendCoinNetwork: settleNet(settle), xmrDest, aliceBtcDest: recovery.btcDest, onProgress,
  });
  clearRecovery();
  return res;
}

/* ===================== HTLC (tLTC <-> tBTC) =====================
 * Same-curve HTLC swap where the wallet is the taker. Unlike the XMR path (whose lock is sent
 * internally by makeWalletXmrChain), the HTLC taker can only fund its contract from CONFIRMED
 * UTXOs sitting at an ephemeral p2wpkh fund key. So the flow is deposit-then-fund:
 *   1. derive the fund address from fresh key material,
 *   2. the HOST (app.js) deposits `depositSats` there from the user's balance (injected `deposit` cb),
 *   3. once it confirms, runHtlcTaker coin-selects it, funds the contract, and drives the swap.
 * Recovery is REFUND-ONLY (the taker's secret/recvPriv are never persisted); a stall is reclaimed
 * by refunding the contract at T1 and/or sweeping any residual at the fund key (fundPrivHex is kept). */
const hx = (b) => sc.bytesToHex(b);
const nowSec = () => Math.floor(Date.now() / 1000);
const htlcCounterCoin = (c) => (c === 'tBTC' ? 'tLTC' : 'tBTC');
function htlcChains(from, to) {
  return { [from]: esploraChain({ api: settleApi(from) }), [to]: esploraChain({ api: settleApi(to) }) };
}
// The single-input funding-fee headroom the taker's coin-select needs on top of the contract amount
// (matches taker.js estFee for one input), plus a small pad so a fee-estimate wobble can't strand the run.
const htlcFundFee = (feeRate) => Math.ceil((68 + 110) * feeRate);
export function htlcDepositSats(sendSats, feeRate = 2) { return Math.round(Number(sendSats)) + htlcFundFee(feeRate) + 200; }

/* Preview an HTLC quote on a throwaway connection (the maker only starts a swap on `initiate`). */
export async function getHtlcQuote({ fromCoin, toCoin, sendSats, makerId = null }) {
  const relay = await connectRelay(relayUrlFor(makerId));
  try {
    relay.send(sc.buildMessage.requestQuote({ from: fromCoin, to: toCoin, sendSats: Math.round(sendSats) }));
    return await relay.recv('quote', 20000);
  } finally { try { relay.close && relay.close(); } catch {} }
}

/* Sweep whatever confirmed value sits at an HTLC fund key back to the user (deposit change, an
 * unfunded deposit, or a notFunded leftover). Returns null when there is nothing worth a tx. */
async function sweepHtlcFundKey({ fundPrivHex, from, dest, feeRate = 2, chains }) {
  if (!fundPrivHex || !dest) return null;
  const priv = sc.hexToBytes(fundPrivHex);
  const pub = sc.getPublicKey(priv);
  const net = settleNet(from);
  const fundAddr = btc.p2wpkh(pub, net).address;
  const utxos = (await chains[from].getUtxos(fundAddr)).filter((u) => u.status && u.status.confirmed);
  if (!utxos.length) return null;
  let total = 0n;
  const script = btc.p2wpkh(pub, net).script;
  const inputs = utxos.map((u) => { total += BigInt(u.value); return { txid: u.txid, index: u.vout, sequence: 0xfffffffd, witnessUtxo: { script, amount: BigInt(u.value) } }; });
  const rate = Math.max(1, Math.round(feeRate) || 1);
  const build = (fee) => { const tx = new btc.Transaction({}); for (const inp of inputs) tx.addInput(inp); tx.addOutputAddress(dest, total - fee, net); tx.sign(priv); tx.finalize(); return tx; };
  let tx = build(0n);                                          // pass 1: measure vsize
  const fee = BigInt(Math.max(1, Math.ceil((tx.vsize + inputs.length) * rate)));
  if (total - fee <= 546n) return null;                        // residual below dust; leave it (not worth a tx)
  tx = build(fee);
  const txid = await chains[from].broadcast(tx.hex);
  return { txid, sats: Number(total - fee) };
}

/* Run a full tLTC<->tBTC HTLC swap. `deposit(fundAddr, sats) => {txid}` moves coins from the user's
 * balance to the fund address (host-implemented, since only app.js holds the wallet keys). */
export async function runHtlcSwap({
  fromCoin, toCoin = null, sendSats, makerId = null, recvAddr, refundAddr = null,
  feeRate = 2, minConf = null, minRecvSats = null, deposit, onStatus = () => {},
}) {
  if (typeof deposit !== 'function') throw new Error('runHtlcSwap requires a deposit(fundAddr, sats) funder');
  if (!recvAddr) throw new Error('missing a ' + (toCoin || 'settle') + ' receive address');
  // Defense in depth for the single recovery slot: never overwrite a still-recoverable blob.
  if (hasRecovery()) throw new Error('a swap is already pending; finish or clear it before starting another');
  toCoin = toCoin || htlcCounterCoin(fromCoin);
  const mc = minConf != null ? minConf : settleConf(toCoin);   // reorg-safe depth on the reveal (to) chain
  sendSats = Math.round(Number(sendSats));
  const km = genHtlcKeys(sc);
  const fundAddr = htlcFundingAddress(sc, km, fromCoin);
  const chains = htlcChains(fromCoin, toCoin);
  const depositSats = htlcDepositSats(sendSats, feeRate);
  const fundKeyBlob = { fundPrivHex: hx(km.fundPriv), refundPrivHex: hx(km.refundPriv) };

  // Freshness gate (mirror the XMR path's pre-lock re-quote): the deposit is the user's FIRST irreversible
  // move, so confirm the maker is still reachable and still honoring the rate BEFORE depositing. Otherwise a
  // maker that went offline / dropped liquidity / moved the rate below the floor only rejects AFTER the coins
  // are parked at the fund key and must be swept back (two extra fees). Aborting here leaves nothing persisted.
  if (minRecvSats != null) {
    let fresh;
    try { fresh = await getHtlcQuote({ fromCoin, toCoin, sendSats, makerId }); }
    catch (_) { throw new Error('the maker is not reachable for a fresh quote right now; not depositing. Try again shortly.'); }
    if (!(Number(fresh.recv_sats) >= Number(minRecvSats))) throw new Error('the maker now offers ' + fmtBtc(fresh.recv_sats) + ' ' + toCoin + ', below your minimum ' + fmtBtc(minRecvSats) + '. Re-quote and try again.');
  }

  // Persist a pre-deposit reclaim note BEFORE moving any coins (AWAITED, so a storage failure aborts
  // before the deposit): a crash right after the deposit broadcast then still leaves the fund key
  // sweepable (recoverHtlcSwap), never a stranded deposit.
  await saveRecovery({ kind: 'htlc-predeposit', from: fromCoin, to: toCoin, sendSats, fundAddr, ...fundKeyBlob, makerId, at: nowSec() });

  onStatus('depositing', 'sending ' + fmtBtc(depositSats) + ' ' + fromCoin + ' to the swap deposit address');
  const dep = await deposit(fundAddr, depositSats);
  const depTxid = dep && dep.txid;
  onStatus('deposit_confirming', 'waiting for your deposit to confirm', { coin: fromCoin, txid: depTxid });
  // waitForFunding invokes onPoll positionally as (i, confirmedSats, pendingSats, err).
  await chains[fromCoin].waitForFunding(fundAddr, sendSats + htlcFundFee(feeRate), {
    onPoll: (i, total, pending) => onStatus('deposit_confirming', 'waiting for your deposit to confirm', { coin: fromCoin, txid: depTxid, have: total, pending }),
  });

  const relay = await connectRelay(relayUrlFor(makerId));
  try {
    const res = await runHtlcTaker({
      sc, transport: relay, chains, km,
      params: {
        from: fromCoin, to: toCoin, sendSats, minConf: mc, feeRate, recvAddr, minRecvSats,
        // Upgrade the reclaim blob to the full HTLC recovery the instant the contract funds (awaited,
        // pre-broadcast). Keep fundPrivHex so residual/notFunded value stays sweepable via recoverHtlcSwap.
        onAfterFund: async (recovery) => { await saveRecovery({ ...recovery, ...fundKeyBlob, makerId, at: nowSec() }); },
        onStatus,
      },
    });
    // Reclaim any funding change parked at the ephemeral fund key.
    await sweepHtlcFundKey({ fundPrivHex: hx(km.fundPriv), from: fromCoin, dest: refundAddr || recvAddr, feeRate, chains }).catch(() => {});
    // #1: only clear the recovery once the redeem actually CONFIRMED. If it is still unconfirmed (a stalled
    // receive chain), the secret is already public but the coin hasn't landed; keep the recovery blob so the
    // user can keep monitoring / recover, instead of wiping the state needed if the redeem is later evicted.
    if (res.confirmed !== false) clearRecovery();
    return { ...res, fromCoin, toCoin, sendSats, depositTxid: depTxid };
  } catch (e) {
    // notFunded == the contract never landed, but the DEPOSIT is at the fund key: keep recovery so the
    // user can sweep it (do NOT clear). A post-fund stall also keeps recovery for the T1 refund.
    throw e;
  } finally { try { relay.close && relay.close(); } catch {} }
}

/* Reclaim a stalled/interrupted HTLC swap: sweep anything at the fund key AND, if a contract was
 * funded, refund it once its locktime T1 has passed. Safe to retry; only clears when nothing is left. */
export async function recoverHtlcSwap({ recovery, destAddress, feeRate = 2, onStatus = () => {} }) {
  if (!recovery || !(recovery.kind === 'htlc' || recovery.kind === 'htlc-predeposit')) throw new Error('no recoverable HTLC swap');
  const from = recovery.from, to = recovery.to || htlcCounterCoin(from);
  if (!destAddress) throw new Error('missing a ' + from + ' destination address');
  const chains = htlcChains(from, to);
  const out = { swept: null, refunded: null, refundPending: false, depositPending: false };

  // 1) Sweep anything sitting at the ephemeral fund address (an unfunded deposit, a notFunded
  //    leftover, or funding change). Always safe, available immediately.
  try { out.swept = await sweepHtlcFundKey({ fundPrivHex: recovery.fundPrivHex, from, dest: destAddress, feeRate, chains }); }
  catch (e) { /* nothing to sweep, or already swept - fall through to the contract refund */ }

  // 2) If a contract was actually funded, refund it after T1 (the bulk of the value lives here).
  if (recovery.fundTxid != null && recovery.fundVout != null) {
    if (nowSec() < (recovery.t1 || 0)) { out.refundPending = true; }
    else {
      try {
        out.refunded = await refundHtlc({ sc, chains, recovery, destAddress, feeRate, onStatus });
        // FUND-SAFETY: refundHtlc only BROADCASTS the T1 refund. Do NOT drop the (only, random) refund key on a
        // mere broadcast - if that low-fee refund is evicted before confirming, the contract is still spendable
        // ONLY by this key. Keep the blob; a later reclaim run clears it once the contract is CONFIRMED spent.
        out.refundPending = true;
        onStatus('refunding', 'your ' + from + ' refund is broadcast; it clears once it confirms - reclaim again shortly to finish', { coin: from, txid: out.refunded && out.refunded.refundTxid });
      }
      catch (e) {
        const m = String((e && e.message) || e);
        if (/non[- ]?final|not[- ]?final|not yet|Locktime|BIP68|mempool/i.test(m)) out.refundPending = true; // CLTV vs median-time-past lag; retry later
        else if (/not found|missingorspent|already[ -]?spent/i.test(m)) {
          // NEVER infer "spent" from a null/absent output fetch (getSpend returns spent:false on ANY transport
          // failure), and require the spend to be CONFIRMED, not merely in the mempool, before giving up the
          // ONLY T1 refund key. A positively-confirmed spend also auto-clears a genuinely-refunded contract so
          // its reclaim card doesn't stick forever; anything less keeps the blob, retryable.
          if (!(await confirmedSpend(chains[from], recovery.fundTxid, recovery.fundVout))) out.refundPending = true;
        }
        else throw e;
      }
    }
  }

  // 3) Fail CLOSED before discarding the (random, non-seed-derived) fund key: sweepHtlcFundKey only
  //    moves CONFIRMED utxos, so an unconfirmed/mempool deposit - or a lookup that errored - must NOT
  //    clear the blob. If we didn't sweep and value could still sit at the fund address, keep it.
  if (!out.swept && !out.refundPending && recovery.fundPrivHex) {
    if (recovery.kind === 'htlc-predeposit' && recovery.fundTxid == null) {
      // A pre-deposit blob holds the ONLY (random, non-seed-derived) key to a deposit that may still be
      // inbound/propagating - a broadcast origin that differs from THIS settle esplora (e.g. a Settings API
      // override) can make a just-sent deposit invisible to getUtxos for a while, so an empty read is NOT
      // proof the deposit never happened. Never auto-clear it; the user clears it via the warned Clear
      // button if the deposit truly failed. (If the deposit confirmed, step 1 already swept + cleared it.)
      out.depositPending = true;
    } else try {
      const fundAddr = btc.p2wpkh(sc.getPublicKey(sc.hexToBytes(recovery.fundPrivHex)), settleNet(from)).address;
      const u = await chains[from].getUtxos(fundAddr);              // UNFILTERED: confirmed OR mempool
      const total = (Array.isArray(u) ? u : []).reduce((s, o) => s + Number(o.value || 0), 0);
      // Keep the key only for value the sweeper could actually recover. A post-funding change residual is a
      // few hundred sats and the sweeper itself skips anything netting <= dust after fee - so 800 keeps a
      // live deposit worth keeping the key for while not pinning the single recovery slot on dust forever.
      if (total > 800) out.depositPending = true;
    } catch (_) { out.depositPending = true; }                      // couldn't verify emptiness -> keep the key
  }

  if (!out.refundPending && !out.depositPending) clearRecovery();
  return out;
}

export { genHtlcKeys, htlcFundingAddress, runHtlcTaker, refundHtlc, esploraChain };
