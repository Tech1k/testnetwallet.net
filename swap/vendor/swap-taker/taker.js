// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * The shared TestnetSwap TAKER engine: non-custodial, client-side. ALL heavy deps
 * (swap-core `sc`, the swap-xmr `x`/`btc`/`as`/`driver`, chain + transport adapters)
 * are INJECTED, so this exact file vendors verbatim into the no-build sites
 * (testnetswap.com, TestnetWallet) and runs in Node tests; no import-path rewriting.
 *
 *  - runHtlcTaker : tBTC <-> tLTC via swap-core HTLC. Taker funds first (T1), maker
 *    funds (T2), taker redeems revealing the secret. Recovery: refundHtlc after T1.
 *  - runXmrTaker  : tXMR -> tBTC via the swap-xmr adaptor swap. Taker = Alice. The
 *    recovery blob is built + persisted (awaited) BEFORE the XMR lock so funds can
 *    never be stranded; reclaimXmr recovers from the maker's on-chain refund.
 *
 * Every flow takes an `onStatus(stage, detail)` callback for UI progress.
 */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * The xmr-resume challenge Alice signs with her swap btcKey to re-request the redeem adaptor after a
 * relay drop or a full reload. It MUST stay byte-identical across all three sites: this taker (in-session
 * resume + forward-resume), the maker's `resumeChallenge` (xmr-handler.js), and the tests. Binding the
 * public lock outpoint to the requesting sid is what authorizes the re-send to the right party.
 */
export function xmrResumeChallenge(sc, lockTxid, lockVout, sid) {
  return sc.bytesToHex(sc.sha256(new TextEncoder().encode('testnetswap/xmr-resume/v1|' + lockTxid + '|' + lockVout + '|' + (sid || ''))));
}

/* ---------------------------------------------------------------- HTLC (tBTC<->tLTC) */

/** Fresh ephemeral taker key material for one HTLC swap. */
export function genHtlcKeys(sc) {
  const secret = sc.randomSecret();
  const fundPriv = sc.randomSecret();
  const recvPriv = sc.randomSecret();
  const refundPriv = sc.randomSecret();
  return {
    secret, secretHash: sc.secretHashOf(secret),
    fundPriv, fundPub: sc.getPublicKey(fundPriv),
    recvPriv, recvPub: sc.getPublicKey(recvPriv),
    refundPriv, refundPub: sc.getPublicKey(refundPriv),
  };
}

/** The FROM-chain p2wpkh address the taker funds the swap from (its deposit address). */
export function htlcFundingAddress(sc, km, fromCoin) {
  return sc.btc.p2wpkh(km.fundPub, sc.getCoin(fromCoin).network).address;
}

/**
 * Drive the taker side of an HTLC swap. Requires a confirmed-enough funding UTXO at
 * htlcFundingAddress() (the host does the deposit step). Returns
 * { state:'redeemed', redeemTxid, recvAddr, recvSats, recovery } on success.
 * On a maker stall AFTER the taker funds, throws with `.recovery` set so the host can
 * persist it and later call refundHtlc() at T1.
 */
export async function runHtlcTaker({ sc, transport, chains, km, params }) {
  const { from, to, sendSats, minConf = 2, feeRate = 2, recvAddr, minRecvSats = null, onAfterFund, onStatus = () => {}, setupTimeoutMs = 60000, lockTimeoutMs = 3_600_000,
    revealMinMarginSecs = 2 * 3600, redeemFeeBumpStep = 6, redeemMaxFeeRate = 40, redeemBumps = 7, redeemPollMs = 60000, redeemPollTries = 10 } = params;
  // Safety coupling (assert, don't assume): the redeem RBF ladder must finish INSIDE the reveal margin, or a
  // slow redeem could still be unconfirmed when the maker can refund its lock at T2 and claim our T1 contract
  // with the by-then-public secret. Fail fast on inconsistent caller overrides instead of running silently unsafe.
  if (redeemBumps * (redeemPollTries - 1) * redeemPollMs >= revealMinMarginSecs * 1000) throw new Error('unsafe params: the redeem fee ladder does not fit inside revealMinMarginSecs');
  const now = () => Math.floor(Date.now() / 1000);
  const hx = sc.bytesToHex;
  const sendNet = sc.getCoin(from).network, recvNet = sc.getCoin(to).network;
  const fundAddr = htlcFundingAddress(sc, km, from);
  const fundScript = sc.btc.p2wpkh(km.fundPub, sendNet).script;
  const dest = recvAddr || sc.btc.p2wpkh(km.recvPub, recvNet).address;

  onStatus('quoting', 'requesting a quote');
  transport.send(sc.buildMessage.requestQuote({ from, to, sendSats }));
  const quote = await transport.recv('quote', setupTimeoutMs);

  transport.send(sc.buildMessage.initiate({ quoteId: quote.quote_id, from, to, sendSats, secretHash: hx(km.secretHash), takerRecvPubkey: hx(km.recvPub), takerRefundPubkey: hx(km.refundPub) }));
  const accept = await transport.recv('accept', setupTimeoutMs);
  const chk = sc.checkAcceptAgainstQuote(quote, accept, now());
  if (!chk.ok) throw new Error('accept check failed: ' + chk.reason);
  // M-1: enforce the rate the user agreed to; abort BEFORE locking if the maker's
  // execution-time offer is below the floor the caller (the previewed quote) set.
  if (minRecvSats != null && accept.recv_sats < minRecvSats) throw new Error('rate moved: maker now offers ' + accept.recv_sats + ' < your minimum ' + minRecvSats + ' ' + to + '; aborted before locking any coins');

  // taker funds first (contract pays the maker, locktime T1)
  const takerC = sc.takerContractParams({ secretHash: km.secretHash, makerRecvPubkey: sc.hexToBytes(accept.maker_recv_pubkey), takerRefundPubkey: km.refundPub, t1: accept.t1, sendCoin: from });
  // Coin-select enough CONFIRMED inputs (aggregate; don't hang on a dust-split
  // deposit, and never spend an unconfirmed/replaceable input into the contract).
  const conf = (params.fundingUtxos || (await chains[from].getUtxos(fundAddr))).filter((u) => u.status && u.status.confirmed).sort((a, b) => b.value - a.value);
  const picked = []; let sum = 0; const estFee = (n) => Math.ceil((n * 68 + 110) * feeRate);
  for (const u of conf) { picked.push(u); sum += u.value; if (sum >= sendSats + estFee(picked.length)) break; }
  if (!picked.length || sum < sendSats + estFee(picked.length)) throw new Error('not enough confirmed ' + from + ' at the deposit address (have ' + sum + ', need ~' + (sendSats + estFee(Math.max(1, picked.length))) + ')');
  const utxos = picked.map((u) => ({ inp: { txid: u.txid, index: u.vout, sequence: 0xfffffffd, witnessUtxo: { script: fundScript, amount: BigInt(u.value) } }, key: km.fundPriv }));
  const funding = sc.buildFundingTx({ utxos, contractAddress: takerC.address, amount: sendSats, changeAddress: fundAddr, feeRate, network: sendNet });

  // C-1 / H-1 / M-2: a COMPLETE, JSON-safe recovery blob (params only; the contract
  // is re-derived deterministically in refundHtlc), persisted via the AWAITED
  // onAfterFund hook BEFORE broadcast. funding.txid == the broadcast txid in
  // production, so persisting pre-broadcast is exact and a crash can't strand coins.
  const recovery = { kind: 'htlc', from, to, sendSats, recvSats: accept.recv_sats, t1: accept.t1, secretHash: hx(km.secretHash), makerRecvPubkey: accept.maker_recv_pubkey, fundTxid: funding.txid, fundVout: funding.vout, refundPrivHex: hx(km.refundPriv), fundAddr };
  if (onAfterFund) await onAfterFund(recovery); // a throw here aborts BEFORE any coins move
  onStatus('locking', 'funding your ' + from + ' contract');
  // M2: if broadcast throws, the contract may or may not have actually landed (flaky esplora).
  // Verify on-chain before deciding: if it did NOT land, signal `notFunded` so the host can
  // treat the persisted recovery as void (deposit untouched → retry), not a stranded "funded" swap.
  let fundTxid;
  try { fundTxid = await chains[from].broadcast(funding.hex); }
  catch (be) {
    let landed = false; try { const o = await chains[from].getOutput(funding.txid, funding.vout); landed = !!(o && o.value > 0); } catch {}
    if (!landed) { const err = new Error('funding broadcast failed (no coins moved): ' + (be.message || be)); err.notFunded = true; throw err; }
    fundTxid = funding.txid; // it actually landed despite the error
  }
  transport.send(sc.buildMessage.takerLocked({ quoteId: quote.quote_id, contractAddr: takerC.address, fundTxid, vout: funding.vout, t1: accept.t1 }));
  onStatus('locked', 'your ' + from + ' contract is funded', { txid: fundTxid, coin: from });

  try {
    onStatus('waiting', 'waiting for the maker to lock ' + to);
    // Scale the client waits to the ON-CHAIN budget, not a fixed 1h. With minConf=2 on both legs, the
    // taker must be able to outlast the maker's confirmations on the deposit (before MAKER_LOCKED) AND
    // its own minConf on the maker lock, on a chain where a confirmation can take an hour or more. The
    // safe outer bound is the reveal deadline (T2 minus the reveal margin); past it the swap can't
    // safely complete anyway, so waiting longer is pointless. An explicitly SHORT lockTimeoutMs
    // (<= 5 min, e.g. a test forcing a timeout) is honored as-is; otherwise use the on-chain budget.
    const revealDeadline = accept.t2 - revealMinMarginSecs;
    const budgetMs = Math.max(60_000, (revealDeadline - now()) * 1000);
    const makerLocked = await transport.recv('maker_locked', lockTimeoutMs <= 300_000 ? lockTimeoutMs : budgetMs);
    onStatus('maker_locked', 'the maker locked ' + to, { txid: makerLocked.fund_txid, coin: to, contract_addr: makerLocked.contract_addr });
    const makerC = sc.makerContractParams({ secretHash: km.secretHash, takerRecvPubkey: km.recvPub, makerRefundPubkey: sc.hexToBytes(accept.maker_refund_pubkey), t2: accept.t2, recvCoin: to });
    const vm = sc.verifyMakerContract({ witnessScript: makerC.witnessScript, fundedAddress: makerLocked.contract_addr, secretHash: km.secretHash, takerRecvPubkey: km.recvPub, makerRefundPubkey: sc.hexToBytes(accept.maker_refund_pubkey), t1: accept.t1, t2: accept.t2, nowSec: now(), recvCoin: to });
    if (!vm.ok) throw new Error('maker contract verify failed: ' + vm.reason);
    onStatus('confirming', 'verifying the maker’s ' + to + ' lock on-chain', { coin: to, txid: makerLocked.fund_txid, confirmations: 0, needed: minConf });
    let mout = null;
    // Poll until minConf deep, but no later than the reveal deadline (past it the L1 guard aborts
    // anyway). Polls at least once, so a fast/mocked confirmation returns immediately.
    for (;;) {
      mout = await chains[to].getOutput(makerLocked.fund_txid, makerLocked.vout);
      const c = mout && Number.isFinite(mout.confirmations) ? mout.confirmations : 0;
      onStatus('confirming', 'verifying the maker’s ' + to + ' lock on-chain', { coin: to, txid: makerLocked.fund_txid, confirmations: c, needed: minConf });
      if (mout && Number.isFinite(mout.confirmations) && mout.confirmations >= minConf) break;
      mout = null;
      if (now() >= revealDeadline) break;
      await new Promise((r) => setTimeout(r, 15000));
    }
    if (!mout) throw new Error('maker funded output not confirmed within the safe window (refunding at T1)');
    const vf = sc.verifyFundedOutput({ witnessScript: makerC.witnessScript, fundedScriptPubKey: mout.scriptpubkey, fundedValueSats: mout.value, expectedSats: accept.recv_sats, network: recvNet });
    if (!vf.ok) throw new Error('maker funded output check failed: ' + vf.reason);

    // L1: re-check the T2 margin RIGHT BEFORE revealing. verifyMakerContract asserted it once, but the
    // confirmation wait above (now up to minConf deep) can consume that margin. Revealing too close to
    // T2 risks the redeem not confirming before the maker can refund the same output and then claim our
    // T1 contract with the now-public secret. If the margin is gone, abort WITHOUT revealing; recovery
    // is already persisted, so the host refunds our own contract at T1 (safe, no secret exposed).
    if (accept.t2 - now() < revealMinMarginSecs) throw new Error('aborting before revealing the secret: only ' + Math.max(0, accept.t2 - now()) + 's until the maker T2, too tight to confirm the redeem safely; refunding at T1 instead');

    onStatus('redeeming', 'claiming your ' + to + ' (revealing the secret)');
    const redeemUtxo = { txid: makerLocked.fund_txid, vout: makerLocked.vout, amount: mout.value };
    const mkRedeem = (r) => sc.buildRedeemTx({ contract: makerC, utxo: redeemUtxo, secret: km.secret, privkey: km.recvPriv, destAddress: dest, feeRate: r, network: recvNet });
    let rate = feeRate, redeem = mkRedeem(rate);
    let redeemTxid = await chains[to].broadcast(redeem.hex);
    // RBF the redeem toward redeemMaxFeeRate if it is slow to confirm, so a low-fee tx does not sit for
    // hours behind higher-fee ones on a congested testnet4. Bumps are deliberately spaced by a full inner
    // poll window ((redeemPollTries-1)*redeemPollMs, ~9 min) TUNED to testnet4's ~10-min block target: a
    // normal block lands BEFORE the first bump, so most redeems confirm at the base fee with ZERO
    // replacements (no "your tx became invalid" churn on the explorer); it escalates only when a redeem is
    // GENUINELY stuck across several block intervals, NOT every 30s. On a slow-block testnet a tight cadence
    // sprints the whole fee ladder before the first block lands, overpaying and flooding the wallet with a
    // pile of conflicting replacements. The full ladder (redeemBumps cycles, ~72 min worst case) still
    // finishes well inside revealMinMarginSecs (~2h), so the redeem confirms before the maker's T2. Each
    // cycle rebuilds at the current rate + redeemFeeBumpStep and
    // replaces the prior tx (same input, RBF-signalled), climbing until it confirms, reaches
    // redeemMaxFeeRate, or has bumped redeemBumps times; redeemBumps is sized so the ladder can actually
    // reach redeemMaxFeeRate (else the count would cap the fee below the ceiling). It is also bounded by dust:
    // buildRedeemTx throws on a sub-dust output, which just stops the bumping (a tiny redeem self-limits to a
    // low fee). The first broadcast already reveals the secret, so this only helps the taker receive (and the
    // maker settle) sooner; it never changes the safety.
    let confirmed = false;
    for (let bump = 0; ; bump++) {
      for (let i = 0; i < redeemPollTries; i++) {
        if (i > 0) await new Promise((r) => setTimeout(r, redeemPollMs));
        onStatus('redeeming', 'your ' + to + ' redeem is broadcast (' + rate + ' sat/vB), waiting for it to confirm', { coin: to, txid: redeemTxid });
        try { const o = await chains[to].getOutput(redeemTxid, 0); if (o && o.confirmed) { confirmed = true; break; } } catch {}
      }
      if (confirmed || bump >= redeemBumps || rate >= redeemMaxFeeRate) break;
      const next = Math.min(rate + redeemFeeBumpStep, redeemMaxFeeRate);
      if (next <= rate) break;
      try { const b = mkRedeem(next); redeemTxid = await chains[to].broadcast(b.hex); rate = next; redeem = b; }
      catch { break; } // dust-bounded or the replacement was rejected -> keep the current redeem, wait it out
    }
    // The secret is public the instant the FIRST redeem was broadcast, so funds-safety now hinges on the
    // redeem actually CONFIRMING before the maker can refund its lock at T2 and (with the public secret) claim
    // our T1 contract. If the fee ladder ran out with the redeem still unconfirmed (a stalled chain), do NOT
    // report success and discard recovery after only the ladder span: keep the max-fee redeem in the mempool
    // and keep polling until it confirms or T2 is near, using the whole remaining safe window. Only a CONFIRMED
    // redeem is 'done' with recovery cleared; an unconfirmed return keeps the recovery blob and flags
    // confirmed:false so the host keeps state (re-broadcast/monitor) instead of wiping keys and losing the coin
    // if the redeem is later evicted (e.g. the maker refunds the lock at T2).
    const tailBufferSecs = Math.max(120, Math.ceil(2 * redeemPollMs / 1000));
    while (!confirmed && accept.t2 - now() > tailBufferSecs) {
      await new Promise((r) => setTimeout(r, redeemPollMs));
      onStatus('redeeming', 'your ' + to + ' redeem is in the mempool at ' + rate + ' sat/vB, waiting for a block', { coin: to, txid: redeemTxid });
      try { const o = await chains[to].getOutput(redeemTxid, 0); if (o && o.confirmed) confirmed = true; } catch {}
    }
    if (confirmed) onStatus('done', 'received ' + to, { txid: redeemTxid, coin: to });
    else onStatus('redeeming', 'your ' + to + ' redeem is broadcast but not yet confirmed; keep this tab open until it confirms', { coin: to, txid: redeemTxid });
    return { state: 'redeemed', redeemTxid, recvAddr: dest, recvSats: redeem.outAmount, confirmed, recovery: confirmed ? null : recovery };
  } catch (e) {
    e.recovery = recovery; // taker funded but swap stalled; refundable at T1
    throw e;
  }
}

/**
 * Refund a stalled HTLC swap: spend the taker's own T1 contract back after locktime.
 * The full contract (address + witnessScript + scriptPubKey + locktime) is RE-DERIVED
 * deterministically from the recovery params via takerContractParams, so nothing
 * script-shaped needs to survive JSON (C-1). `recovery` is exactly the blob
 * runHtlcTaker persists via onAfterFund (or e.recovery).
 */
export async function refundHtlc({ sc, chains, recovery, destAddress, feeRate = 2, onStatus = () => {} }) {
  const now = () => Math.floor(Date.now() / 1000);
  if (now() < recovery.t1) throw new Error('refund not yet available (T1 at ' + recovery.t1 + ', now ' + now() + ')');
  const refundPriv = sc.hexToBytes(recovery.refundPrivHex);
  const sendNet = sc.getCoin(recovery.from).network;
  const out = await chains[recovery.from].getOutput(recovery.fundTxid, recovery.fundVout);
  if (!out) throw new Error('taker contract output not found (already spent, or not yet visible)');
  // Re-derive the FULL contract (address/witnessScript/scriptPubKey/locktime); buildRefundTx needs all of it.
  const contract = sc.takerContractParams({ secretHash: sc.hexToBytes(recovery.secretHash), makerRecvPubkey: sc.hexToBytes(recovery.makerRecvPubkey), takerRefundPubkey: sc.getPublicKey(refundPriv), t1: recovery.t1, sendCoin: recovery.from });
  onStatus('refunding', 'refunding your ' + recovery.from + ' contract');
  const refund = sc.buildRefundTx({ contract, utxo: { txid: recovery.fundTxid, vout: recovery.fundVout, amount: out.value }, privkey: refundPriv, destAddress: destAddress || recovery.fundAddr, feeRate, network: sendNet });
  const txid = await chains[recovery.from].broadcast(refund.hex);
  onStatus('done', 'refunded');
  return { state: 'refunded', refundTxid: txid };
}

/* ------------------------------------------------------------ XMR (tXMR -> tBTC) */

/** Ask the maker for a tXMR->tBTC quote. quoteOnly=true previews without starting a swap. */
export async function requestXmrQuote({ transport, fromCoin, toCoin = 'tBTC', sendPico, quoteOnly = false, timeoutMs = 20000 }) {
  transport.send({ type: 'xmr_request_quote', from: fromCoin, to: toCoin, send_pico: Number(sendPico), quote_only: !!quoteOnly });
  return transport.recv('xmr_quote', timeoutMs);
}

/**
 * Drive the taker (Alice) side of a tXMR->tBTC swap. Persists recovery (via the
 * awaited `onBeforeLock`) the instant before XMR is committed, so a maker stall can
 * never strand funds. Returns the driver result { state:'redeemed', redeemTxid, ... }.
 */
export async function runXmrTaker({ x, btc, as, driver, transport, chains, km, params, onBeforeLock, sc, relayFactory }) {
  // M-3: recovery-before-lock is MANDATORY and fail-closed; never lock XMR without a
  // persisted way to reclaim it.
  if (typeof onBeforeLock !== 'function') throw new Error('runXmrTaker requires an onBeforeLock(recovery) hook (recovery must be persisted before any XMR is locked)');
  let bob = null, lockOutpoint = null, refundAdaptor = null, bCancelSig = null, built = false;
  let active = transport; // swapped for a FRESH transport on reconnect (resume path)
  // Resilience: if the relay WS drops during the long POST-LOCK wait for the redeem adaptor, reconnect
  // with a fresh relay and re-request the (already-released, idempotent) adaptor from the maker via an
  // `xmr_resume` authenticated by a signature from Alice's btcKey over (outpoint || new-sid). Purely
  // additive: only wraps the redeem_adaptor recv, only when a relayFactory + sc are supplied (browser).
  // A real maker abort is terminal (surfaces to reclaim); if it can't recover within the redeem budget
  // it also falls back to the persisted reclaim blob. Never releases the adaptor early (maker-gated).
  const canResume = () => typeof relayFactory === 'function' && sc && built && lockOutpoint;
  const signResume = (sid) => x.ecdsa_sign(km.btcKey, xmrResumeChallenge(sc, lockOutpoint.txid, lockOutpoint.vout, sid));
  async function recvRedeemWithResume(totalMs) {
    const deadline = Date.now() + (totalMs || 3_600_000);
    let backoff = 1000, reconnected = false;
    for (;;) {
      const budget = deadline - Date.now();
      if (budget <= 0) throw new Error('timed out waiting for the redeem adaptor after resume attempts');
      try {
        if (reconnected && active && !active.closed) active.send({ type: 'xmr_resume', lockTxid: lockOutpoint.txid, lockVout: lockOutpoint.vout, sig: signResume(active.hello && active.hello.sid) });
        return await active.recv('redeem_adaptor', Math.min(20000, budget));
      } catch (e) {
        if (e && e.relayError) throw e; // real maker abort/error is TERMINAL -> surface to reclaim, do not loop
        const dropped = (active && active.closed) || /relay closed|not open/i.test(String((e && e.message) || ''));
        if (dropped) {
          try { params.onStatus && params.onStatus('resuming', 'The relay connection dropped. Reconnecting and re-syncing with the maker; your swap is safe.'); } catch {}
          try { active.close && active.close(); } catch {}
          await new Promise((r) => setTimeout(r, backoff)); backoff = Math.min(30000, backoff * 2);
          try { active = await relayFactory(); reconnected = true; backoff = 1000; } catch { /* retry next loop */ }
        }
        // a plain recv timeout on a still-open connection just loops and waits (maker sends once matured)
      }
    }
  }
  const obs = {
    get hello() { return active && active.hello; },
    async recv(type, ms) {
      if (type === 'redeem_adaptor' && canResume()) return recvRedeemWithResume(ms);
      const m = await active.recv(type, ms);
      if (type === 'bundle' && m.bundle) bob = m.bundle;
      if (type === 'lock_outpoint') lockOutpoint = { txid: m.txid, vout: m.vout, amount: m.amount };
      if (type === 'cancel_presig' && m.sig) bCancelSig = m.sig;
      return m;
    },
    send(msg) { if (msg && msg.type === 'refund_adaptor') refundAdaptor = msg.adaptor; return active.send(msg); },
    close: () => active.close && active.close(),
  };
  const wrappedXmr = {
    ...chains.xmr,
    lock: async (a) => {
      if (!built) {
        // I-2: guard the captured material BEFORE using it (clear error, not a raw TypeError).
        // bCancelSig (the maker's cancel pre-sig) is REQUIRED before locking: it's what lets Alice
        // broadcast tx_cancel herself during reclaim, so her exit never depends on the maker acting.
        if (!bob || !bob.P || !lockOutpoint || !refundAdaptor || !bCancelSig) throw new Error('refusing to lock XMR: setup material incomplete (bundle/outpoint/adaptor/cancel-presig)');
        const alice = as.publicBundle(x, km);
        const ctx = as.sharedContext(x, btc, { alice, bob, sendCoinNetwork: params.sendCoinNetwork, moneroNetwork: params.moneroNetwork, t1Blocks: params.t1Blocks, t2Blocks: params.t2Blocks });
        // Persist the FULL bob bundle + timelocks so the ctx can be reconstructed for the
        // reclaim-or-punish path (punish needs cancelScriptHex/t2Blocks, not just bob.P). bob is
        // all-public, so this stores no secrets beyond the already-present km.
        const recovery = { kind: 'xmr', lockOutpoint, bob, refundAdaptor, bCancelSig, xmrRestoreHeight: params.xmrRestoreHeight, t1Blocks: params.t1Blocks, t2Blocks: params.t2Blocks, ctx: { combinedViewPriv: ctx.combinedViewPriv, moneroLockAddress: ctx.moneroLockAddress }, km, moneroNetwork: params.moneroNetwork };
        if (!recovery.ctx.combinedViewPriv || !recovery.ctx.moneroLockAddress) throw new Error('refusing to lock XMR: recovery material incomplete');
        await onBeforeLock(recovery); // host persists (awaited); a throw here aborts BEFORE committing XMR
        built = true; // I-1: only mark done AFTER persistence succeeds
      }
      return chains.xmr.lock(a);
    },
  };
  return driver.aliceSwap({ x, btc, transport: obs, chains: { btc: chains.btc, xmr: wrappedXmr }, km, params });
}

/**
 * ALICE forward-resume entry (browser): FINISH a persisted XMR swap forward instead of reclaiming it.
 * Reconnects to the maker over a fresh relay, re-requests the already-released redeem adaptor with an
 * authenticated `xmr_resume`, and broadcasts the settle-coin redeem via driver.aliceResumeRedeem.
 * Returns that call's discriminated result: { state:'redeemed', redeemTxid } or
 * { state:'must_reclaim', reason }. Purely additive; it never touches the live-swap path, and on
 * 'must_reclaim' it leaves the reclaim blob untouched so the backward path remains available.
 *
 * The recv loop distinguishes a live-but-still-maturing maker (`xmr_resume_wait` -> keep waiting) from
 * an unreachable/gone one (no reply over several tries -> give up -> reclaim), so a genuinely dead maker
 * doesn't hang the user for the whole budget. The lock outpoint is public, so re-requesting leaks nothing.
 */
export async function runXmrResume({ x, btc, as, driver, chains, km, persisted, sendCoinNetwork, aliceDest, sc, relayFactory, safetyBlocks, minRevealConf, resumeTimeoutMs = 2_700_000, onStatus = () => {} }) {
  if (typeof relayFactory !== 'function' || !sc) throw new Error('runXmrResume requires relayFactory + sc');
  const lo = persisted && persisted.lockOutpoint;
  if (!lo) return { state: 'must_reclaim', reason: 'incomplete_recovery' };
  const sign = (sid) => x.ecdsa_sign(km.btcKey, xmrResumeChallenge(sc, lo.txid, lo.vout, sid));
  // The maker only releases the adaptor after Alice's XMR matures (~10 Monero blocks, and testnet blocks
  // are erratic), so the budget must comfortably exceed that; a healthy maturing maker must not be
  // mistaken for a gone one. sawWait records that the maker was alive-but-maturing at least once, so a
  // deadline hit after that is reported as 'still_maturing' (retry), not 'no_adaptor' (offline/expired).
  let sawWait = false;
  const recvRedeemAdaptor = async () => {
    const deadline = Date.now() + resumeTimeoutMs;
    let active = null, silent = 0, backoff = 1000;
    try {
      while (Date.now() < deadline) {
        if (!active || active.closed) {
          try { active = await relayFactory(); backoff = 1000; }
          catch { await sleep(backoff); backoff = Math.min(30000, backoff * 2); continue; }
        }
        const sid = active.hello && active.hello.sid;
        try { active.send({ type: 'xmr_resume', lockTxid: lo.txid, lockVout: lo.vout, sig: sign(sid) }); }
        catch { try { active.close && active.close(); } catch {} active = null; continue; }
        // ONE recv per type, sequentially; never two pending at once. Two concurrent recvs would leak a
        // waiter each round (the maker re-sends the adaptor on EVERY resume while released, so a stray
        // waiter would keep stealing it and the loop would never resolve). If the adaptor recv times out,
        // an xmr_resume_wait already sits buffered iff the maker replied, so a short follow-up recv tells
        // a live-but-maturing maker (keep waiting) apart from a silent/gone one (give up -> reclaim).
        const ms = Math.min(15000, Math.max(1000, deadline - Date.now()));
        let adaptor = null;
        try { const m = await active.recv('redeem_adaptor', ms); adaptor = m && m.adaptor; } catch {}
        if (adaptor) return adaptor;
        let alive = false;
        try { await active.recv('xmr_resume_wait', 250); alive = true; } catch {}
        if (alive) { silent = 0; sawWait = true; onStatus('resuming', 'The maker is still maturing your deposit on Monero (~10 blocks); waiting to finish.'); await sleep(3000); continue; }
        if (++silent >= 4) return null; // no adaptor AND no liveness reply over several tries -> reclaim
        try { active.close && active.close(); } catch {}
        active = null; await sleep(backoff); backoff = Math.min(30000, backoff * 2);
      }
    } finally { try { active && active.close && active.close(); } catch {} }
    return null;
  };
  const res = await driver.aliceResumeRedeem({ x, btc, chains, km, persisted, sendCoinNetwork, aliceDest, safetyBlocks, minRevealConf, recvRedeemAdaptor, onStatus });
  // A deadline hit while the maker was still (correctly) replying xmr_resume_wait is NOT "maker gone" -
  // it just hadn't matured yet. Report it as retryable maturing, so the UI doesn't push the slower reclaim.
  if (res && res.state === 'must_reclaim' && res.reason === 'no_adaptor' && sawWait) return { ...res, reason: 'still_maturing' };
  return res;
}

/**
 * Recover after a stalled XMR swap. With the full toolkit (`as`) + send-coin network + a BTC
 * destination + a full-bundle recovery blob, this uses reclaim-or-punish: chase lock->cancel, then
 * either the maker's refund (recover the key, sweep the XMR home) OR, if no refund lands by T2,
 * punish the cancel to claim the maker's BTC. Falls back to the refund-only reclaim otherwise
 * (backward compatible with older callers / recovery blobs).
 */
export async function reclaimXmr({ x, btc, as, driver, chains, recovery, sendCoinNetwork, xmrDest, aliceBtcDest, onProgress = () => {} }) {
  const r = recovery;
  if (as && sendCoinNetwork && aliceBtcDest && r.bob && r.bob.btcPub && r.t2Blocks != null) {
    const alice = as.publicBundle(x, r.km);
    const ctx = as.sharedContext(x, btc, { alice, bob: r.bob, sendCoinNetwork, moneroNetwork: r.moneroNetwork, t1Blocks: r.t1Blocks, t2Blocks: r.t2Blocks });
    // Cross-check the reconstructed lock address against the one persisted before locking.
    if (r.ctx && r.ctx.moneroLockAddress && ctx.moneroLockAddress !== r.ctx.moneroLockAddress) throw new Error('reclaim: reconstructed Monero lock address does not match the saved one; refusing to act');
    return driver.aliceReclaimOrPunish({
      x, btc, chains, km: r.km, ctx,
      lockTxid: r.lockOutpoint.txid, lockVout: r.lockOutpoint.vout, lockAmount: r.lockOutpoint.amount,
      bobPb: r.bob.P, refundAdaptor: r.refundAdaptor, bCancelSig: r.bCancelSig, xmrRestoreHeight: r.xmrRestoreHeight,
      xmrDest, aliceDest: aliceBtcDest, network: sendCoinNetwork, onProgress,
    });
  }
  return driver.aliceReclaimXmr({
    x, btc, chains, km: r.km, ctx: r.ctx,
    lockTxid: r.lockOutpoint.txid, lockVout: r.lockOutpoint.vout,
    bobPb: r.bob.P, refundAdaptor: r.refundAdaptor,
    xmrRestoreHeight: r.xmrRestoreHeight, xmrDest, onProgress,
  });
}
