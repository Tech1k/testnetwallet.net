// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr/driver: the reusable async role drivers that sequence the adaptorswap
 * toolkit into a live BTC/LTC <-> XMR swap, enforcing ORCHESTRATION_INVARIANTS.
 * The maker and the CLI/wallet taker each run one role; transport (the relay) and
 * chain I/O are injected, so the same drivers run in-process against mocks (tests)
 * and against real esplora + monero-ts + the WSS relay (production).
 *
 * Direction handled here: taker sends XMR, receives BTC/LTC  => taker = ALICE
 * (XMR provider), maker = BOB (BTC provider, liveness-critical; the maker should
 * always hold the BOB role). The reverse direction swaps the assignment.
 *
 * THEFT-SAFE ORDERING (load-bearing): Bob releases the tx_redeem adaptor ONLY
 * AFTER confirming Alice's XMR lock. Earlier, Alice could redeem the BTC (revealing
 * m_a) without locking XMR and Bob would lose his coin for nothing.
 *
 * transport: { send(msg), recv(type, timeoutMs) -> Promise<msg> }
 * btc: { buildLockFunding({address,amount}) -> {txid,vout,amount,hex},      // Bob
 *        broadcast(hex)->txid, waitConfirmed(txid,conf), getOutput(txid,vout)->{value,scriptPubKeyHex},
 *        watchSpend(txid,vout) -> Promise<witnessHex[]> }
 * xmr: { lock({address,amount})->txid,                                       // Alice
 *        waitLocked({address,privateViewKey,restoreHeight,amount}),           // Bob
 *        sweep({privateSpendKey,privateViewKey,primaryAddress,restoreHeight,dest})->txids }
 */
import * as as from './adaptorswap.js';
import * as btcswap from './btcswap.js';

export const MessageTypes = {
  BUNDLE: 'bundle', LOCK_OUTPOINT: 'lock_outpoint', CANCEL_PRESIG: 'cancel_presig',
  REFUND_ADAPTOR: 'refund_adaptor', BTC_LOCKED: 'btc_locked', XMR_LOCKED: 'xmr_locked',
  REDEEM_ADAPTOR: 'redeem_adaptor', ABORT: 'abort',
};
const M = MessageTypes;
const FEE = as.FEE_SATS;   // single source of truth (see adaptorswap.js): the driver's cancelAmount math and the templates' fee MUST be the same constant, or the adaptor sighash desyncs from the broadcast tx.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// The cancel output is spent by EITHER the maker's refund (IF branch: [sigB, sigA, OP_1, script],
// 4 items, a real sig at index 1) or Alice's own punish (ELSE branch: [sigA, <empty>, script], 3
// items, empty at index 1). Only a refund carries the adaptor sig that recovers m_b; a punish spend
// means the BTC is ALREADY Alice's, so it is terminal; never something to "reclaim from".
const isRefundSpend = (w) => Array.isArray(w) && w.length >= 4 && !!w[1] && String(w[1]).length > 0;
const dest = (btc, bundle, network) => btc.p2wpkh(Buffer.from(bundle.btcPub, 'hex'), network).address;
function fail(transport, reason) { try { transport.send({ type: M.ABORT, reason }); } catch {} return new Error('abort: ' + reason); }

/**
 * FUND-SAFETY gate for revealing Alice's XMR redeem (which leaks m_a). Returns null when it is safe to
 * broadcast NOW, or a reason string to abort-to-reclaim. The redeem must never go out unless the lock is
 * STILL unspent AND still has >= safetyBlocks of margin before its BIP68 cancel window (t1Blocks): a
 * maker that withholds the adaptor until the lock nears T1 could otherwise race the cancel and take both
 * legs. Needs a confirmation-depth source (chains.btc.txConfs); a chain adapter without one (mock) cannot
 * be gated and returns null; every production adapter provides txConfs. Shared by the live redeem
 * (aliceSwap) and the forward-resume redeem so the guarantee holds on both paths.
 */
export async function redeemMarginReason(chains, lockTxid, lockVout, t1Blocks, safetyBlocks, minRevealConf = 0) {
  try { if (chains.btc.getSpend) { const s = await chains.btc.getSpend(lockTxid, lockVout); if (s && s.spent) return 'the maker already spent the lock (cancel)'; } } catch {}
  if (!chains.btc.txConfs) return null; // no confirmation-depth source (mock) -> cannot gate
  let confs = 0; try { confs = await chains.btc.txConfs(lockTxid); } catch {}
  if (!(confs > 0)) return 'could not read the lock confirmations';
  // Absolute reorg-safe floor: never reveal m_a while the lock is SHALLOWER than minRevealConf, even if the
  // margin-to-T1 is huge. On a low-hashrate settle chain a reorg deeper than the lock could evict it and let
  // a maker who double-spends its funding UTXO scrape m_a from the mempool redeem AND keep its coin. No-op on
  // the happy path: Alice locks XMR only after the lock reached minConf, so confs >= minRevealConf here; and
  // a false trip is fail-safe (aborts to the maker-refund reclaim, never a loss).
  if (minRevealConf && confs < minRevealConf) return 'the maker lock is only ' + confs + ' confs deep (need ' + minRevealConf + ' to be reorg-safe before revealing the secret)';
  const margin = t1Blocks - confs;
  if (margin < safetyBlocks) return 'only ' + margin + ' blocks before the maker cancel window (need ' + safetyBlocks + ')';
  return null;
}

/**
 * BOB (BTC/LTC provider, maker). Returns { state:'completed', sweepTxids, ... }.
 * On a stall the caller catches and runs bobUnwind(); the cancel/refund material
 * needed for that is returned via the thrown error's .unwind, when available.
 */
export async function bobSwap({ x, btc, transport, chains, km, params }) {
  const { sendCoinNetwork, moneroNetwork, t1Blocks, t2Blocks, lockAmount, xmrAmount, xmrRestoreHeight, xmrSweepDest, onUnwindReady, onRedeemReleased, t } = withTimeouts(params);
  const bob = as.publicBundle(x, km);
  transport.send({ type: M.BUNDLE, bundle: bob });
  const bundleMsg = await transport.recv(M.BUNDLE, t.setup);
  const alice = bundleMsg.bundle;
  const vb = as.verifyBundle(x, alice); if (!vb.ok) throw fail(transport, 'bad alice bundle: ' + vb.reason);
  // Alice's REDEEM OUTPUT. The redeem adaptor (released later) is Bob's signature over the redeem
  // sighash, which commits to this output, so Bob MUST build the adaptor over the SAME address Alice
  // redeems to, or adaptor_verify fails on her side and the swap can never complete. Validate it on THIS
  // network BEFORE any BTC is locked (an undecodable/wrong-network address aborts cleanly, nothing
  // committed); absent (older takers / tests) falls back to Alice's derived p2wpkh, which she also uses.
  if (bundleMsg.redeemAddr != null) { try { btc.Address(sendCoinNetwork).decode(String(bundleMsg.redeemAddr)); } catch { throw fail(transport, 'alice redeem address invalid for this network'); } }
  const aliceRedeemDest = bundleMsg.redeemAddr || dest(btc, alice, sendCoinNetwork);

  // Both of these can throw (timelock validation / no fundable UTXOs). They run BEFORE any lock, so
  // nothing is committed, but route the failure through fail() so the taker receives an ABORT and fast-fails
  // instead of hanging until its setup timeout (mirrors the other pre-lock failure paths above).
  let ctx;
  try { ctx = as.sharedContext(x, btc, { alice, bob, sendCoinNetwork, moneroNetwork, t1Blocks, t2Blocks }); }
  catch (e) { throw fail(transport, 'shared-context/timelock validation failed: ' + ((e && e.message) || e)); }

  // Build (NOT broadcast) the funded 2-of-2 lock; share its outpoint.
  let lock;
  try { lock = await chains.btc.buildLockFunding({ address: ctx.btcLock.address, amount: lockAmount }); }
  catch (e) { throw fail(transport, 'maker could not build the lock funding: ' + ((e && e.message) || e)); }
  transport.send({ type: M.LOCK_OUTPOINT, txid: lock.txid, vout: lock.vout, amount: lock.amount });

  // Unwind handshake: both pre-sign cancel; Alice sends her refund adaptor. Bob
  // verifies BOTH before funding (else his BTC could be frozen with no unwind).
  const cancel = as.cancelTemplate(btc, { ctx, lockTxid: lock.txid, lockVout: lock.vout, lockAmount: lock.amount, network: sendCoinNetwork });
  const bCancelSig = as.makeCancelPreSig(x, { btcKey: km.btcKey, cancelSighash: cancel.sighashHex });
  transport.send({ type: M.CANCEL_PRESIG, sig: bCancelSig });
  const aCancelSig = (await transport.recv(M.CANCEL_PRESIG, t.setup)).sig;
  if (!as.verifyCancelPreSig(x, { counterpartyBtcPub: alice.btcPub, cancelSighash: cancel.sighashHex, sig: aCancelSig })) throw fail(transport, 'alice cancel pre-sig invalid');
  const cancelFinal = btcswap.finalize2of2(btc, cancel.tx, ctx.btcLock.witnessScript, aCancelSig, bCancelSig); // [A,B]; both hold both
  const cancelAmount = lock.amount - FEE;
  const refund = as.refundTemplate(btc, { ctx, cancelTxid: cancelFinal.txid, cancelVout: 0, cancelAmount, cancelScriptPubKeyHex: cancel.cancelScriptPubKeyHex, bobDest: dest(btc, bob, sendCoinNetwork), network: sendCoinNetwork });
  const refundAdaptor = (await transport.recv(M.REFUND_ADAPTOR, t.setup)).adaptor;
  if (!as.verifyRefundAdaptor(x, { aliceBtcPub: alice.btcPub, bobPb: bob.P, refundSighash: refund.sighashHex, adaptor: refundAdaptor })) throw fail(transport, 'alice refund adaptor invalid');

  // material for unwind if we stall later
  const unwind = { ctx, cancelFinalHex: cancelFinal.hex, cancelTxid: cancelFinal.txid, cancelScriptPubKeyHex: cancel.cancelScriptPubKeyHex, cancelAmount, refundTx: refund.tx, refundSighash: refund.sighashHex, refundAdaptor, alice, lockTxid: lock.txid, lockVout: lock.vout, redeemAdaptor: null, alicePa: alice.P };
  // Crash-resume: hand the host the MINIMAL, JSON-serializable material a restart needs to
  // reconstruct this unwind (bobReconstructUnwind) and run bobUnwind. Fired BEFORE the lock is
  // broadcast, so a crash any time after the lock hits the chain is auto-recoverable.
  if (onUnwindReady) { try { onUnwindReady({ alice, lockTxid: lock.txid, lockVout: lock.vout, lockAmount: lock.amount, aCancelSig, refundAdaptor }); } catch {} }

  // All unwind material verified -> broadcast tx_lock LAST.
  const lockTxid = await chains.btc.broadcast(lock.hex);
  transport.send({ type: M.BTC_LOCKED, txid: lockTxid });

  try {
    // Wait for Alice's XMR lock to confirm+unlock BEFORE releasing the redeem adaptor.
    await transport.recv(M.XMR_LOCKED, t.lock);
    await chains.xmr.waitLocked({ address: ctx.moneroLockAddress, privateViewKey: ctx.combinedViewPriv, restoreHeight: xmrRestoreHeight, amount: xmrAmount });

    const redeem = as.redeemTemplate(btc, { ctx, lockTxid, lockVout: lock.vout, lockAmount: lock.amount, aliceDest: aliceRedeemDest, network: sendCoinNetwork });
    const redeemAdaptor = as.makeRedeemAdaptor(x, { bobBtcKey: km.btcKey, alicePa: alice.P, redeemSighash: redeem.sighashHex });
    unwind.redeemAdaptor = redeemAdaptor; // lets unwind recover from a late redeem instead of refunding
    if (onRedeemReleased) { try { onRedeemReleased(redeemAdaptor); } catch {} } // persist it so a post-release crash can still recover from a late redeem
    transport.send({ type: M.REDEEM_ADAPTOR, adaptor: redeemAdaptor });

    const witness = await chains.btc.watchSpend(lockTxid, lock.vout); // Alice's tx_redeem
    const rec = as.bobRecoverFromRedeem(x, { redeemWitnessHex: witness, alicePa: alice.P, bobRedeemAdaptor: redeemAdaptor, bobMSpend: km.mSpend });
    if (!rec) throw new Error('failed to recover m_a from redeem witness');
    const sweepTxids = await chains.xmr.sweep({ privateSpendKey: rec.combinedSpendPriv, privateViewKey: ctx.combinedViewPriv, primaryAddress: ctx.moneroLockAddress, restoreHeight: xmrRestoreHeight, dest: xmrSweepDest });
    return { state: 'completed', sweepTxids, combinedSpendPriv: rec.combinedSpendPriv, moneroSpendPub: ctx.moneroSpendPub };
  } catch (e) {
    e.unwind = unwind; // caller can bobUnwind(...) to cancel + refund
    throw e;
  }
}

/**
 * Bob's unwind: cancel then refund (reveals m_b -> Alice reclaims XMR). Crucially,
 * it NEVER treats "I decided to cancel" as terminal for the XMR claim: at every
 * step it re-checks whether Alice's tx_redeem already spent the lock, and if so it
 * recovers s_a and sweeps the XMR (the winning outcome) instead of refunding.
 * Requires `unwind.redeemAdaptor` (set once Bob released it) to recover from redeem.
 */
export async function bobUnwind({ x, btc, chains, km, unwind, xmrRestoreHeight = 0, xmrSweepDest, refundConfTries = 40, refundConfPollMs = 15000 }) {
  // Try to claim from a redeem that may already be (or become) on-chain.
  const tryRedeem = async () => {
    if (!unwind.redeemAdaptor || !chains.btc.getSpend) return null;
    let s; try { s = await chains.btc.getSpend(unwind.lockTxid, unwind.lockVout); } catch { return null; }
    if (!s || !s.spent || !s.witness) return null;
    const rec = as.bobRecoverFromRedeem(x, { redeemWitnessHex: s.witness, alicePa: unwind.alicePa, bobRedeemAdaptor: unwind.redeemAdaptor, bobMSpend: km.mSpend });
    if (!rec) return null; // the spend wasn't a redeem (e.g. a cancel); fall through to refund
    const sweepTxids = await chains.xmr.sweep({ privateSpendKey: rec.combinedSpendPriv, privateViewKey: unwind.ctx.combinedViewPriv, primaryAddress: unwind.ctx.moneroLockAddress, restoreHeight: xmrRestoreHeight, dest: xmrSweepDest });
    return { state: 'completed', sweepTxids, combinedSpendPriv: rec.combinedSpendPriv, moneroSpendPub: unwind.ctx.moneroSpendPub };
  };

  // 1. Alice may have already redeemed before we gave up waiting.
  const pre = await tryRedeem(); if (pre) return pre;

  // 2. Broadcast tx_cancel. If it fails, the lock was likely already spent by a
  //    redeem that won the race; try to claim it.
  try { await chains.btc.broadcast(unwind.cancelFinalHex); }
  catch (e) { const r = await tryRedeem(); if (r) return r; throw e; }
  // If the cancel can't confirm, Alice's tx_redeem may have double-spent the lock and
  // won; re-check for the redeem before giving up (else a recoverable s_a is abandoned).
  try { await chains.btc.waitConfirmed(unwind.cancelTxid, 1); }
  catch (e) { const r = await tryRedeem(); if (r) return r; throw e; }

  // 3. Final re-check that Alice didn't redeem between cancel-confirm and refund; the
  //    XMR claim is never terminal until the refund is the proven spender (invariant
  //    in swap.js). Only then reveal m_b via refund so Alice can reclaim.
  const late = await tryRedeem(); if (late) return late;
  const fin = as.bobFinalizeRefund(x, btc, { tx: unwind.refundTx, ctx: unwind.ctx, bobBtcKey: km.btcKey, bobMSpend: km.mSpend, refundSighash: unwind.refundSighash, aliceRefundAdaptor: unwind.refundAdaptor, aliceBtcPub: unwind.alice.btcPub, bobPb: as.publicBundle(x, km).P });
  const refundTxid = await chains.btc.broadcast(fin.hex);   // reveals m_b, returns Bob's BTC; the sighash is fixed, so this CANNOT be RBF'd
  // KEEP-ALIVE (P1b): monitor the refund to confirmation instead of declaring success on broadcast. A caller
  // that forgets the durable record on a mere broadcast would strand Bob if the refund is evicted or never
  // confirms (no RBF to rescue it). While waiting, keep re-checking for a late redeem (still strictly better
  // for Bob). No confirmation-depth source (mock/tests) -> treat as settled. If it hasn't confirmed within the
  // budget, return 'refund_pending' so the caller KEEPS the record and resume() re-attempts (future: CPFP).
  let confirmed = !chains.btc.txConfs;
  for (let i = 0; !confirmed && i < refundConfTries; i++) {
    const r = await tryRedeem(); if (r) return r;
    let c = 0; try { c = await chains.btc.txConfs(refundTxid); } catch {}
    if (c >= 1) { confirmed = true; break; }
    await sleep(refundConfPollMs);
  }
  return { state: confirmed ? 'refunded' : 'refund_pending', refundTxid, confirmed };
}

/**
 * Rebuild the full bobUnwind material from the MINIMAL persisted set that onUnwindReady handed the
 * host (alice bundle, lock outpoint, Alice's cancel pre-sig, the refund adaptor, and, once released,
 * the redeem adaptor). Everything else (ctx, cancel, cancelFinal, refund tx/sighash) is derived
 * deterministically from Bob's seed-derived km + the swap params, so a crashed maker can resume and
 * run bobUnwind after a restart. Mirrors exactly what bobSwap builds inline.
 */
export function bobReconstructUnwind({ x, btc, km, persisted, sendCoinNetwork, moneroNetwork, t1Blocks, t2Blocks }) {
  const { alice, lockTxid, lockVout, lockAmount, aCancelSig, refundAdaptor, redeemAdaptor = null } = persisted;
  const bob = as.publicBundle(x, km);
  const ctx = as.sharedContext(x, btc, { alice, bob, sendCoinNetwork, moneroNetwork, t1Blocks, t2Blocks });
  const cancel = as.cancelTemplate(btc, { ctx, lockTxid, lockVout, lockAmount, network: sendCoinNetwork });
  const bCancelSig = as.makeCancelPreSig(x, { btcKey: km.btcKey, cancelSighash: cancel.sighashHex });
  const cancelFinal = btcswap.finalize2of2(btc, cancel.tx, ctx.btcLock.witnessScript, aCancelSig, bCancelSig); // [A,B]
  const cancelAmount = lockAmount - FEE;
  const refund = as.refundTemplate(btc, { ctx, cancelTxid: cancelFinal.txid, cancelVout: 0, cancelAmount, cancelScriptPubKeyHex: cancel.cancelScriptPubKeyHex, bobDest: dest(btc, bob, sendCoinNetwork), network: sendCoinNetwork });
  return { ctx, cancelFinalHex: cancelFinal.hex, cancelTxid: cancelFinal.txid, cancelScriptPubKeyHex: cancel.cancelScriptPubKeyHex, cancelAmount, refundTx: refund.tx, refundSighash: refund.sighashHex, refundAdaptor, alice, lockTxid, lockVout, redeemAdaptor, alicePa: alice.P };
}

/** ALICE (XMR provider, taker). Returns { state:'redeemed', redeemTxid }. */
export async function aliceSwap({ x, btc, transport, chains, km, params }) {
  const { sendCoinNetwork, moneroNetwork, t1Blocks, t2Blocks, lockAmount, minConf, minRevealConf, xmrAmount, aliceBtcDest, redeemSafetyBlocks = 12, t } = withTimeouts(params);
  const onStatus = (params && params.onStatus) || (() => {}); // optional, additive progress hook
  // Coin-correct status: use the real from/to tickers in the note AND meta, so integrators don't have to
  // rewrite hardcoded coin names (an sXMR->tLTC swap must never say tXMR/tBTC). Fall back to generic words
  // when a caller omits them. `coinMeta` is spread into every coin-bearing phase's meta.
  const fromTk = (params && params.fromCoin) || 'Monero', toTk = (params && params.toCoin) || 'settle coin';
  const coinMeta = { from: (params && params.fromCoin) || undefined, to: (params && params.toCoin) || undefined };
  const alice = as.publicBundle(x, km);
  const bob = (await transport.recv(M.BUNDLE, t.setup)).bundle;
  const vb = as.verifyBundle(x, bob); if (!vb.ok) throw fail(transport, 'bad bob bundle: ' + vb.reason);
  // Tell the maker the exact address we will redeem to, so it builds the redeem adaptor over the SAME
  // output (the adaptor commits to it). Must equal the aliceDest used in our own redeem below.
  transport.send({ type: M.BUNDLE, bundle: alice, redeemAddr: aliceBtcDest });
  onStatus('setup', 'negotiating the swap with the maker');

  const ctx = as.sharedContext(x, btc, { alice, bob, sendCoinNetwork, moneroNetwork, t1Blocks, t2Blocks });
  const lp = await transport.recv(M.LOCK_OUTPOINT, t.setup);

  const cancel = as.cancelTemplate(btc, { ctx, lockTxid: lp.txid, lockVout: lp.vout, lockAmount: lp.amount, network: sendCoinNetwork });
  const bCancelSig = (await transport.recv(M.CANCEL_PRESIG, t.setup)).sig;
  if (!as.verifyCancelPreSig(x, { counterpartyBtcPub: bob.btcPub, cancelSighash: cancel.sighashHex, sig: bCancelSig })) throw fail(transport, 'bob cancel pre-sig invalid');
  const aCancelSig = as.makeCancelPreSig(x, { btcKey: km.btcKey, cancelSighash: cancel.sighashHex });
  transport.send({ type: M.CANCEL_PRESIG, sig: aCancelSig });
  const cancelFinal = btcswap.finalize2of2(btc, cancel.tx, ctx.btcLock.witnessScript, aCancelSig, bCancelSig);
  const cancelAmount = lp.amount - FEE;
  const refund = as.refundTemplate(btc, { ctx, cancelTxid: cancelFinal.txid, cancelVout: 0, cancelAmount, cancelScriptPubKeyHex: cancel.cancelScriptPubKeyHex, bobDest: dest(btc, bob, sendCoinNetwork), network: sendCoinNetwork });
  const refundAdaptor = as.makeRefundAdaptor(x, { aliceBtcKey: km.btcKey, bobPb: bob.P, refundSighash: refund.sighashHex });
  transport.send({ type: M.REFUND_ADAPTOR, adaptor: refundAdaptor });

  // Wait for the BTC lock; bind to the real funded output; then lock XMR.
  const bl = await transport.recv(M.BTC_LOCKED, t.lock);
  // H5: the funded lock MUST be the same outpoint Alice pre-signed cancel/refund
  // against (lp.txid); else her whole reclaim path watches a txid where no
  // cancel/refund will appear and the XMR is stranded. Reject a mismatched BTC_LOCKED.
  if (bl.txid !== lp.txid) throw fail(transport, 'BTC_LOCKED txid does not match the pre-signed LOCK_OUTPOINT');
  onStatus('maker_locked', 'maker locked its ' + toTk, { txid: lp.txid, ...coinMeta });
  onStatus('confirming', 'waiting for the ' + toTk + ' lock to confirm', { txid: lp.txid, ...coinMeta });
  await chains.btc.waitConfirmed(lp.txid, minConf);
  const o = await chains.btc.getOutput(lp.txid, lp.vout);
  // H4: bind the amount to the AUTHORITATIVE on-chain value. All of Alice's spend
  // templates use lp.amount; if the maker over-declares it, every BTC spend is
  // structurally underfunded (rejected) and Alice can neither redeem nor reclaim.
  if (!o || o.scriptPubKeyHex !== ctx.btcLock.scriptPubKey || BigInt(o.value) !== BigInt(lp.amount) || BigInt(o.value) < BigInt(lockAmount)) {
    throw fail(transport, 'funded output does not match the agreed lock (script/amount)');
  }

  onStatus('locking_xmr', 'locking your ' + fromTk, coinMeta);   // give the actual XMR send its own visible phase (the taker/app maps it to the "your XMR locks" tracker step so the send is not dead-air)
  const xmrTxid = await chains.xmr.lock({ address: ctx.moneroLockAddress, amount: xmrAmount });
  transport.send({ type: M.XMR_LOCKED, txid: xmrTxid });
  onStatus('xmr_locked', 'your ' + fromTk + ' is locked; completing the swap', coinMeta);

  // Redeem only after receiving + verifying Bob's redeem adaptor.
  const redeemAdaptor = (await transport.recv(M.REDEEM_ADAPTOR, t.redeem)).adaptor;
  // FUND-SAFETY: broadcasting the redeem reveals m_a. Re-read fresh chain state and refuse if the lock is
  // already spent, or too close to its BIP68 cancel window; a malicious maker can withhold the adaptor
  // until the lock nears T1, then race the cancel to take BOTH legs. On abort nothing is revealed and
  // recovery is already persisted, so the host reclaims the XMR via the maker's refund. (aliceResumeRedeem
  // applies the same guard; this closes the equivalent gap on the live path.)
  // minRevealConf is the reorg-safe floor for revealing m_a; it defaults to minConf but should be set DEEPER
  // than lock-acceptance depth on a low-hashrate settle chain, so a shallow reorg can't evict the lock after
  // the redeem is public (see swap-xmr/SECURITY.md). Fail-safe: a trip aborts to the maker-refund reclaim.
  const marginReason = await redeemMarginReason(chains, lp.txid, lp.vout, t1Blocks, redeemSafetyBlocks, minRevealConf);
  if (marginReason) throw new Error('aborting before revealing the secret: ' + marginReason + '; reclaiming the XMR at the refund instead');
  const redeem = as.redeemTemplate(btc, { ctx, lockTxid: lp.txid, lockVout: lp.vout, lockAmount: lp.amount, aliceDest: aliceBtcDest || dest(btc, alice, sendCoinNetwork), network: sendCoinNetwork });
  const fin = as.aliceFinalizeRedeem(x, btc, { tx: redeem.tx, ctx, aliceBtcKey: km.btcKey, aliceMSpend: km.mSpend, redeemSighash: redeem.sighashHex, bobRedeemAdaptor: redeemAdaptor, bobBtcPub: bob.btcPub, alicePa: alice.P });
  onStatus('redeeming', 'redeeming your ' + toTk, coinMeta);
  return { state: 'redeemed', redeemTxid: await chains.btc.broadcast(fin.hex), ctx, refundSighash: refund.sighashHex, refundAdaptor, bob, km };
}

/**
 * ALICE forward-resume: finish a persisted swap by re-driving ONLY the redeem tail from the saved
 * reclaim blob, instead of reclaiming the XMR backward. Rebuilds ctx, decides ON-CHAIN whether forward
 * is still safe/possible, then (via the injected `recvRedeemAdaptor`, which reconnects + xmr_resume to
 * the maker) claims the already-released adaptor and broadcasts the settle-coin redeem.
 *
 * Returns one of:
 *   { state:'redeemed',     redeemTxid }: the settle coin is (or is already) yours
 *   { state:'must_reclaim', reason }: forward is unsafe/impossible; the caller falls back to reclaim
 *
 * SAFETY (why this can't lose the XMR): it broadcasts the redeem ONLY when the lock is UNSPENT and still
 * has `safetyBlocks` of margin before its BIP68 cancel timelock (t1Blocks). Alice's redeem has no
 * sequence lock, so it can confirm immediately, while the maker's cancel is invalid until the lock has
 * t1Blocks confirmations. With margin, the redeem confirms first, the maker recovers m_a from the
 * CONFIRMED redeem and sweeps the XMR (the normal outcome), and no refund ever happens. Too little
 * margin -> refuse and reclaim, so Alice's redeem secret is never leaked into a race she could lose
 * (which is the only path where the maker could both scrape m_a AND refund m_b). The lock outpoint is
 * public, so re-requesting the adaptor discloses nothing; a wrong/absent maker simply yields no adaptor.
 */
export async function aliceResumeRedeem({ x, btc, chains, km, persisted, sendCoinNetwork, aliceDest, safetyBlocks = 12, minRevealConf = 0, recvRedeemAdaptor, onStatus = () => {} }) {
  const p = persisted;
  // bCancelSig is REQUIRED for the forward path: without it a spent lock can't be positively classified
  // (cancel vs our own redeem), so we route to reclaim, which, unlike forward, tolerates a missing
  // bCancelSig (it just watches for the maker's cancel). Never enter forward on a blob we can't classify.
  if (!p || !p.bob || !p.bob.btcPub || !p.lockOutpoint || !p.bCancelSig || p.t1Blocks == null || p.t2Blocks == null) return { state: 'must_reclaim', reason: 'incomplete_recovery' };
  if (!aliceDest) return { state: 'must_reclaim', reason: 'no_dest' };
  const alice = as.publicBundle(x, km);
  const ctx = as.sharedContext(x, btc, { alice, bob: p.bob, sendCoinNetwork, moneroNetwork: p.moneroNetwork, t1Blocks: p.t1Blocks, t2Blocks: p.t2Blocks });
  // Cross-check the reconstructed lock address against the one persisted before locking (as reclaim does):
  // a corrupted blob or wrong key can't be driven to broadcast against a lock that isn't this swap's.
  if (p.ctx && p.ctx.moneroLockAddress && ctx.moneroLockAddress !== p.ctx.moneroLockAddress) throw new Error('resume: reconstructed Monero lock address does not match the saved one; refusing to act');
  const lockTxid = p.lockOutpoint.txid, lockVout = p.lockOutpoint.vout, lockAmount = p.lockOutpoint.amount;

  // Deterministic cancel txid, to tell an already-spent lock apart: a cancel (-> reclaim) vs Alice's own
  // earlier redeem (-> already done). The segwit txid excludes the witness, so signatures don't change
  // it; we still finalize with the saved pre-sigs to match exactly how the cancel is broadcast elsewhere.
  let cancelTxid = null;
  {
    const cancel = as.cancelTemplate(btc, { ctx, lockTxid, lockVout, lockAmount, network: sendCoinNetwork });
    const aCancelSig = as.makeCancelPreSig(x, { btcKey: km.btcKey, cancelSighash: cancel.sighashHex });
    try { cancelTxid = btcswap.finalize2of2(btc, cancel.tx, ctx.btcLock.witnessScript, aCancelSig, p.bCancelSig).txid; } catch { cancelTxid = null; }
  }

  // The single pre-flight decision, read from FRESH chain state. Returns a terminal result (redeemed /
  // must_reclaim) if forward is impossible/unsafe, or null if it is currently safe to proceed. It is run
  // TWICE: once before requesting the adaptor, and AGAIN immediately before broadcasting, because the
  // adaptor wait is long and maker-paced (a still-maturing swap can hold Alice for many settle-chain
  // blocks), so a margin/spentness snapshot taken at entry is stale by broadcast time. The redeem leaks
  // Alice's m_a, so it must never go out unless the lock is STILL unspent AND STILL has safetyBlocks of
  // margin before its BIP68 cancel window at the moment of broadcast.
  const preflight = async () => {
    let spend = { spent: false };
    try { if (chains.btc.getSpend) spend = await chains.btc.getSpend(lockTxid, lockVout); } catch {}
    if (spend && spend.spent) {
      if (cancelTxid && spend.txid === cancelTxid) return { state: 'must_reclaim', reason: 'cancelled' };
      if (cancelTxid) return { state: 'redeemed', redeemTxid: spend.txid, alreadyOnChain: true }; // not the cancel -> Alice's redeem
      return { state: 'must_reclaim', reason: 'spent_unclassified' }; // can't classify (cancel txid unknown) -> keep reclaim, never claim 'done'
    }
    // FAIL CLOSED if the lock's confirmation depth can't be read: a valid lock is always confirmed here
    // (Alice deposits only after the maker lock confirmed), so confs<=0 means the settle API is unreadable,
    // NOT a fresh lock; an unknown depth must never be treated as "plenty of margin".
    let confs = 0;
    try { if (chains.btc.txConfs) confs = await chains.btc.txConfs(lockTxid); } catch {}
    if (!(confs > 0)) return { state: 'must_reclaim', reason: 'confs_unknown' };
    // Absolute reorg-safe floor (see redeemMarginReason): refuse to reveal on a lock shallower than
    // minRevealConf even with ample T1 margin. A reorg during a long resume could otherwise drop the lock's
    // depth and leak m_a into a race. Fail-safe: routing to reclaim keeps the maker-refund path intact.
    if (minRevealConf && confs < minRevealConf) return { state: 'must_reclaim', reason: 'reorg_shallow', confs };
    const margin = p.t1Blocks - confs;
    if (margin < safetyBlocks) return { state: 'must_reclaim', reason: 'timelock_margin', margin };
    return null; // currently safe to proceed
  };

  const pre = await preflight();
  if (pre) return pre;

  // Get the maker's already-released redeem adaptor over a fresh, authenticated session.
  onStatus('resuming', 'Reconnecting to the maker to finish the swap; nothing new is committed.');
  const adaptor = recvRedeemAdaptor ? await recvRedeemAdaptor() : null;
  if (!adaptor) return { state: 'must_reclaim', reason: 'no_adaptor' };

  // RE-CHECK against fresh chain state right before revealing the redeem: the wait above may have eroded
  // the margin or the maker may have cancelled meanwhile. Only broadcast if it is still safe NOW.
  const post = await preflight();
  if (post) return post;

  const redeem = as.redeemTemplate(btc, { ctx, lockTxid, lockVout, lockAmount, aliceDest, network: sendCoinNetwork });
  const fin = as.aliceFinalizeRedeem(x, btc, { tx: redeem.tx, ctx, aliceBtcKey: km.btcKey, aliceMSpend: km.mSpend, redeemSighash: redeem.sighashHex, bobRedeemAdaptor: adaptor, bobBtcPub: p.bob.btcPub, alicePa: alice.P });
  onStatus('redeeming', 'Broadcasting your redeem to receive the settle coin.');
  return { state: 'redeemed', redeemTxid: await chains.btc.broadcast(fin.hex) };
}

/**
 * Alice's reclaim of XMR after Bob cancels+refunds: chase the BTC chain
 * lock -> cancel -> refund, recover m_b from Bob's refund witness, reconstruct the
 * combined Monero spend key, and sweep the locked XMR to `xmrDest`. Pass the lock
 * outpoint (lockTxid/lockVout); the cancel and refund txids are discovered on-chain
 * via `findSpend`, so the caller does not need to know them in advance.
 * `onProgress(msg)` is optional. (Single canonical reclaim implementation; the
 * wallet's swap.mjs delegates here.)
 */
export async function aliceReclaimXmr({ x, btc, chains, km, ctx, lockTxid, lockVout, bobPb, refundAdaptor, xmrRestoreHeight = 0, xmrDest, onProgress = () => {} }) {
  if (!chains.btc.findSpend) throw new Error('btc chain adapter needs findSpend() for reclaim');
  onProgress('watching the lock for the maker cancel');
  const cancel = await chains.btc.findSpend(lockTxid, lockVout);  // lock -> cancel
  onProgress('cancel seen (' + String(cancel.txid).slice(0, 12) + '…); watching for the refund');
  const refund = await chains.btc.findSpend(cancel.txid, 0);       // cancel -> refund (reveals m_b)
  onProgress('refund seen; recovering the Monero key');
  const rec = as.aliceRecoverFromRefund(x, { refundWitnessHex: refund.witness, bobPb, aliceRefundAdaptor: refundAdaptor, aliceMSpend: km.mSpend });
  if (!rec) throw new Error('failed to recover m_b from refund witness');
  onProgress('sweeping the Monero home');
  const sweepTxids = await chains.xmr.sweep({ privateSpendKey: rec.combinedSpendPriv, privateViewKey: ctx.combinedViewPriv, primaryAddress: ctx.moneroLockAddress, restoreHeight: xmrRestoreHeight, dest: xmrDest });
  return { state: 'xmr_reclaimed', sweepTxids, combinedSpendPriv: rec.combinedSpendPriv };
}

/**
 * Alice's PUNISH: the terminal state when Bob broadcasts tx_cancel but never tx_refund. After the
 * cancel output matures past its relative T2 timelock, Alice spends the cancel ELSE branch alone
 * (her btcPunishKey) to claim Bob's BTC. Her XMR stays locked (Bob never revealed m_b), but she is
 * made whole in BTC. Needs the FULL ctx (cancelScriptHex + t2Blocks) + her BTC destination.
 */
export async function alicePunish({ x, btc, chains, km, ctx, lockTxid, lockVout, lockAmount, aliceDest, network, onProgress = () => {} }) {
  if (!chains.btc.findSpend) throw new Error('btc chain adapter needs findSpend() for punish');
  onProgress('watching the lock for the maker cancel');
  const cancel = await chains.btc.findSpend(lockTxid, lockVout);   // lock -> cancel
  onProgress('cancel seen; waiting out the T2 timelock (' + ctx.t2Blocks + ' blocks) to punish');
  await chains.btc.waitConfirmed(cancel.txid, ctx.t2Blocks);       // CSV: punish is valid only after T2
  const r = await finalizePunishSpend({ x, btc, chains, km, ctx, lockTxid, lockVout, lockAmount, cancelTxid: cancel.txid, aliceDest, network, onProgress });
  if (r.state === 'refund_replaced') throw new Error('the maker RBF-refunded instead of being punished; use aliceReclaimOrPunish to recover m_b and reclaim the XMR');
  return r;
}

// Build + sign + broadcast Alice's punish spend of an already-matured cancel output, then CONFIRM it.
// Returns { state:'punished' } only once the punish confirms; { state:'refund_replaced', refund } if
// the maker RBF-evicted it with tx_refund; throws (retryable) if neither has settled yet.
async function finalizePunishSpend({ x, btc, chains, km, ctx, lockTxid, lockVout, lockAmount, cancelTxid, aliceDest, network, onProgress = () => {} }) {
  const ct = as.cancelTemplate(btc, { ctx, lockTxid, lockVout, lockAmount, network }); // for cancelScriptPubKeyHex
  const punish = as.punishTemplate(btc, { ctx, cancelTxid, cancelVout: 0, cancelAmount: lockAmount - FEE, cancelScriptPubKeyHex: ct.cancelScriptPubKeyHex, aliceDest, network });
  const sigA = x.ecdsa_sign(km.btcPunishKey, punish.sighashHex);
  const fin = btcswap.finalizePunish(btc, punish.tx, ctx.cancelScriptHex, sigA);
  onProgress('broadcasting the punish to claim the maker BTC');
  const punishTxid = await chains.btc.broadcast(fin.hex);
  // CRITICAL (fund-safety): the punish spends the cancel via a relative-timelock (CSV) input, so it
  // is BIP125-replaceable while unconfirmed. An always-online maker who withheld tx_refund can still
  // RBF-evict the punish with a higher-fee refund. So NEVER treat the punish as terminal until it
  // CONFIRMS; and if it is replaced, recover m_b from the maker's refund and reclaim the XMR instead.
  onProgress('punish broadcast; waiting for confirmation (guarding against a maker RBF-refund)');
  try {
    await chains.btc.waitConfirmed(punishTxid, 1);
    return { state: 'punished', punishTxid, cancelTxid };
  } catch {
    let sp = null; try { sp = await chains.btc.getSpend(cancelTxid, 0); } catch {}
    // Our punish IS the spender (it confirmed just after the wait window, or is already deep on a
    // retry): terminal success, not a retryable failure.
    if (sp && sp.spent && sp.txid === punishTxid) return { state: 'punished', punishTxid, cancelTxid };
    // A DIFFERENT tx (the maker's RBF refund) spent the cancel; recover m_b and reclaim instead.
    if (sp && sp.spent && sp.txid && isRefundSpend(sp.witness)) return { state: 'refund_replaced', refund: { txid: sp.txid, witness: sp.witness } };
    throw new Error('punish did not confirm and no replacement seen yet; safe to retry once the chain settles');
  }
}

// Ensure tx_cancel is on-chain, self-broadcasting Alice's own copy if the maker hasn't. Alice holds
// BOTH cancel pre-sigs during the swap, so she can finalize + broadcast the cancel independently;
// her only missing piece was persisting the maker's pre-sig. BIP68 gates the cancel to T1 relative
// to the lock, so an early broadcast is rejected; we retry until it (or the maker's cancel) lands.
// The cancel is rebuilt deterministically from km + the persisted maker pre-sig, so its txid matches
// whatever both sides pre-signed.
async function ensureCancelOnChain({ x, btc, chains, km, ctx, lockTxid, lockVout, lockAmount, bCancelSig, network, onProgress }) {
  const c0 = as.cancelTemplate(btc, { ctx, lockTxid, lockVout, lockAmount, network });
  const aCancelSig = as.makeCancelPreSig(x, { btcKey: km.btcKey, cancelSighash: c0.sighashHex });
  const cancelFinalHex = btcswap.finalize2of2(btc, c0.tx, ctx.btcLock.witnessScript, aCancelSig, bCancelSig).hex; // [A,B]
  onProgress('claiming back your tXMR: getting tx_cancel on-chain (broadcasting it yourself if the maker has not)');
  const watch = chains.btc.findSpend(lockTxid, lockVout); // resolves when ANY cancel (maker's or ours) lands
  let stop = false;
  (async () => {
    for (let i = 0; i < 480 && !stop; i++) {
      try { await chains.btc.broadcast(cancelFinalHex); onProgress('tx_cancel broadcast'); return; }
      catch { /* BIP68 too-early / already-spent; retry until T1 elapses or the maker cancels */ }
      await sleep(15000);
    }
  })().catch(() => {});
  try { return await watch; } finally { stop = true; }
}

/**
 * Alice's stall recovery that chooses the correct outcome. After tx_cancel is on-chain (the maker's,
 * or, if it withheld it, one Alice broadcast herself via ensureCancelOnChain),
 * race the maker's tx_refund (-> recover m_b and sweep the XMR home, the cooperative outcome)
 * against the cancel output maturing past T2 with NO refund (-> punish and claim the maker's BTC).
 * If a punish loses to a refund that lands first (cancel output already spent), fall back to the
 * XMR reclaim, the strictly better outcome for Alice. This is the single entry the taker should
 * use for reclaim; `aliceReclaimXmr` remains as the refund-only building block.
 */
export async function aliceReclaimOrPunish({ x, btc, chains, km, ctx, lockTxid, lockVout, lockAmount, bobPb, refundAdaptor, bCancelSig, xmrRestoreHeight = 0, xmrDest, aliceDest, network, onProgress = () => {} }) {
  if (!chains.btc.findSpend) throw new Error('btc chain adapter needs findSpend() for reclaim');
  if (!aliceDest) throw new Error('aliceReclaimOrPunish needs aliceDest (where a punish sends the reclaimed BTC)');
  // Get a cancel on-chain. If we hold the maker's cancel pre-sig, Alice broadcasts tx_cancel HERSELF
  // (BIP68-gated to T1) so her recovery is fully independent of the maker. Otherwise just watch for
  // the maker's cancel (backward compatible with older recovery blobs).
  let cancel;
  if (bCancelSig) {
    cancel = await ensureCancelOnChain({ x, btc, chains, km, ctx, lockTxid, lockVout, lockAmount, bCancelSig, network, onProgress });
  } else {
    onProgress('watching the lock for the maker cancel');
    cancel = await chains.btc.findSpend(lockTxid, lockVout);
  }
  onProgress('cancel seen (' + String(cancel.txid).slice(0, 12) + '…); watching for the maker refund');

  const findRefund = () => chains.btc.findSpend(cancel.txid, 0);   // cancel -> refund (reveals m_b)
  const reclaimFromRefund = async (refund) => {
    const rec = as.aliceRecoverFromRefund(x, { refundWitnessHex: refund.witness, bobPb, aliceRefundAdaptor: refundAdaptor, aliceMSpend: km.mSpend });
    if (!rec) throw new Error('failed to recover m_b from refund witness');
    onProgress('refund seen; sweeping the Monero home');
    const sweepTxids = await chains.xmr.sweep({ privateSpendKey: rec.combinedSpendPriv, privateViewKey: ctx.combinedViewPriv, primaryAddress: ctx.moneroLockAddress, restoreHeight: xmrRestoreHeight, dest: xmrDest });
    return { state: 'xmr_reclaimed', sweepTxids, combinedSpendPriv: rec.combinedSpendPriv };
  };

  // A cancel-output spend is EITHER the maker's refund (recover m_b + sweep the XMR) or Alice's OWN
  // punish from this or a prior attempt (the BTC is already hers -> terminal). Never feed a punish
  // witness to reclaimFromRefund; its empty adaptor slot would throw and loop the reclaim forever.
  const settleFromCancelSpend = (spend) => isRefundSpend(spend.witness)
    ? reclaimFromRefund(spend)
    : Promise.resolve({ state: 'punished', punishTxid: spend.txid, cancelTxid: cancel.txid });

  // Race: a cancel-output spend appears (settle it) vs. the cancel matures past T2 (punish for BTC).
  const spendP = findRefund().then((r) => ({ t: 'spend', r }), (e) => ({ t: 'spend_err', e }));
  const t2P = chains.btc.waitConfirmed(cancel.txid, ctx.t2Blocks).then(() => ({ t: 't2' }), (e) => ({ t: 't2_err', e }));
  const first = await Promise.race([spendP, t2P]);
  if (first.t === 'spend') return settleFromCancelSpend(first.r);
  // refund watch errored, or T2 reached first: wait out T2 (if not already), then punish.
  await t2P.catch(() => {});
  onProgress('no refund by T2; attempting to punish (claim the maker BTC)');
  let pr;
  try {
    pr = await finalizePunishSpend({ x, btc, chains, km, ctx, lockTxid, lockVout, lockAmount, cancelTxid: cancel.txid, aliceDest, network, onProgress });
  } catch (e) {
    // Punish couldn't be broadcast/confirmed and no replacement was detected; the cancel may now be
    // spent (by a maker refund, or by our own already-confirmed punish). Settle whichever it is;
    // otherwise surface for retry (the recovery blob is kept).
    let spend; try { spend = await findRefund(); } catch { throw e; }
    return settleFromCancelSpend(spend);
  }
  // The maker RBF-replaced the (unconfirmed) punish with tx_refund: recover m_b and reclaim the XMR.
  if (pr.state === 'refund_replaced') return reclaimFromRefund(pr.refund);
  return pr; // confirmed 'punished'
}

function withTimeouts(params) {
  // minConf defaults to 1: Alice must NOT lock XMR against an unconfirmed, RBF-able
  // tx_lock (M-1). Callers can raise it for reorg-prone chains.
  return { ...params, minConf: params.minConf ?? 1, minRevealConf: params.minRevealConf ?? (params.minConf ?? 1), t: { setup: params.setupTimeoutMs ?? 30000, lock: params.lockTimeoutMs ?? 600000, redeem: params.redeemTimeoutMs ?? 600000 } };
}
