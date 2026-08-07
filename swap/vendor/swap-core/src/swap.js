// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-core/swap: the swap state machine, timelock policy, and the single source
 * of truth for which party is recipient/refund on which chain.
 *
 * THE LOAD-BEARING SAFETY RULE (do not invert):
 *   The initiator (taker) generates the secret and funds first, so it must have
 *   the LONGER refund window. The participant (maker) funds second and gets the
 *   SHORTER window. If this were inverted, the initiator could reveal the secret
 *   at the last moment, claim, and still refund before the participant could act.
 *   => T1 (taker) > T2 (maker), with a generous gap.
 *
 * Contract role mapping (also easy to get wrong, centralized here):
 *   SEND chain    (taker locks): recipient = maker, refund = taker, locktime = T1
 *   RECEIVE chain (maker locks): recipient = taker, refund = maker, locktime = T2
 */
import { buildContract, verifyContract, verifyFundedOutput } from './htlc.js';
import { getCoin } from './networks.js';

export const SwapState = {
  CREATED: 'created',           // quote accepted; params negotiated
  TAKER_FUNDED: 'taker_funded', // taker broadcast its lock (T1, send chain)
  MAKER_FUNDED: 'maker_funded', // maker broadcast its lock (T2, receive chain); taker may claim
  REDEEMED: 'redeemed',         // taker claimed maker's contract (secret now public)
  COMPLETED: 'completed',       // maker claimed taker's contract; swap fully settled
  REFUNDABLE: 'refundable',     // a locktime passed; our funds are reclaimable
  REFUNDED: 'refunded',
  ABORTED: 'aborted',           // negotiated abort before anyone funded
  FAILED: 'failed',
};

// Allowed forward transitions (terminal states omitted). Refund/abort/fail can
// be reached from most in-flight states; callers check refundability by time.
const TRANSITIONS = {
  [SwapState.CREATED]: [SwapState.TAKER_FUNDED, SwapState.ABORTED, SwapState.FAILED],
  [SwapState.TAKER_FUNDED]: [SwapState.MAKER_FUNDED, SwapState.REFUNDABLE, SwapState.FAILED],
  [SwapState.MAKER_FUNDED]: [SwapState.REDEEMED, SwapState.REFUNDABLE, SwapState.FAILED],
  [SwapState.REDEEMED]: [SwapState.COMPLETED, SwapState.REFUNDABLE, SwapState.FAILED],
  [SwapState.REFUNDABLE]: [SwapState.REFUNDED, SwapState.REDEEMED, SwapState.COMPLETED, SwapState.FAILED],
};

export function canTransition(from, to) {
  return (TRANSITIONS[from] || []).includes(to);
}

export function isTerminal(state) {
  return [SwapState.COMPLETED, SwapState.REFUNDED, SwapState.ABORTED, SwapState.FAILED].includes(state);
}

// ---- timelock policy ----

export const DEFAULT_T2_HOURS = 6;   // participant (maker), receive chain
export const DEFAULT_T1_HOURS = 12;  // initiator (taker), send chain (~2 * T2)
// Safety gap raised from 2h: on testnet4 a single confirmation can take hours, and CLTV
// compares against median-time-past (which lags wall clock ~1h+). The maker must be able
// to see the taker's on-chain secret reveal and get its own claim CONFIRMED on the send
// chain before the taker's refund opens; 4h covers min_confirmations (3) across irregular
// blocks with margin, while staying well under the 6h gap the default t1/t2 (12h/6h) give.
export const MIN_T_GAP_SECS = 4 * 3600; // taker must have >= 4h more than maker
export const MIN_T2_FROM_NOW_SECS = 3 * 3600; // maker's window must be far enough out to act
// Absolute ceilings. MAX_CLTV_TIME (0xffffffff, ~year 2106) is a realistic unix-time cap that
// also fits a 5-byte CScriptNum, so a locktime <= it can never produce a BIP65-invalid (6-byte)
// CLTV operand. MAX_SWAP_SECS caps how far in the future a refund horizon may sit, so a hostile
// maker can't strand the funding party's coins behind an absurd t1. Both are fail-closed bounds.
export const MAX_CLTV_TIME = 4294967295;
export const MAX_SWAP_SECS = 7 * 24 * 3600; // no honest swap needs a > 7-day refund horizon

/** Compute time-based (unix seconds) CLTV locktimes. Throws if the ordering is unsafe. */
export function computeTimelocks(nowSec, { t1Hours = DEFAULT_T1_HOURS, t2Hours = DEFAULT_T2_HOURS } = {}) {
  const now = Math.floor(nowSec);
  if (!Number.isFinite(now) || now < 1500000000) throw new Error('nowSec must be a unix timestamp');
  const t1 = now + Math.round(t1Hours * 3600);
  const t2 = now + Math.round(t2Hours * 3600);
  const chk = validateTimelocks({ t1, t2, nowSec: now });
  if (!chk.ok) throw new Error(chk.reason);
  return { t1, t2 };
}

/** Validate the safety-critical ordering of two timelocks. */
export function validateTimelocks({ t1, t2, nowSec }) {
  if (!Number.isInteger(t1) || !Number.isInteger(t2)) return { ok: false, reason: 'timelocks must be integers' };
  // Upper bound FIRST (fail-closed): an out-of-range locktime yields a 6-byte CLTV operand
  // that is BIP65-consensus-invalid, permanently stranding the funding party's coins.
  if (t1 > MAX_CLTV_TIME || t2 > MAX_CLTV_TIME)
    return { ok: false, reason: `timelocks must be <= ${MAX_CLTV_TIME} (5-byte CLTV / realistic time ceiling)` };
  if (t1 < 1 || t2 < 1) return { ok: false, reason: 'timelocks must be positive' };
  if (!(t2 < t1)) return { ok: false, reason: 'T2 (maker) must be strictly less than T1 (taker)' };
  if (t1 - t2 < MIN_T_GAP_SECS)
    return { ok: false, reason: `T1 must exceed T2 by at least ${MIN_T_GAP_SECS}s (got ${t1 - t2}s)` };
  if (nowSec != null && t2 - nowSec < MIN_T2_FROM_NOW_SECS)
    return { ok: false, reason: `T2 must be at least ${MIN_T2_FROM_NOW_SECS}s in the future` };
  if (nowSec != null && t1 - nowSec > MAX_SWAP_SECS)
    return { ok: false, reason: `T1 must be at most ${MAX_SWAP_SECS}s out (got ${t1 - nowSec}s); refund horizon too far` };
  return { ok: true };
}

// ---- contract role mapping (single source of truth) ----

/**
 * Parameters for the TAKER's contract on the SEND chain.
 * recipient = maker (claims with secret), refund = taker, locktime = T1.
 */
export function takerContractParams({ secretHash, makerRecvPubkey, takerRefundPubkey, t1, sendCoin }) {
  return buildContract({
    secretHash,
    recipientPubkey: makerRecvPubkey,
    refundPubkey: takerRefundPubkey,
    locktime: t1,
    network: getCoin(sendCoin).network,
  });
}

/**
 * Parameters for the MAKER's contract on the RECEIVE chain.
 * recipient = taker (claims with secret), refund = maker, locktime = T2.
 */
export function makerContractParams({ secretHash, takerRecvPubkey, makerRefundPubkey, t2, recvCoin }) {
  return buildContract({
    secretHash,
    recipientPubkey: takerRecvPubkey,
    refundPubkey: makerRefundPubkey,
    locktime: t2,
    network: getCoin(recvCoin).network,
  });
}

/**
 * Taker-side verification of the maker's funded contract before claiming:
 * it must pay the taker, use the agreed secret hash, sit on the receive chain,
 * and carry the shorter locktime T2. Pass `t1` and `nowSec` to also re-check the
 * safety-critical timelock ordering (recommended before revealing the secret).
 */
export function verifyMakerContract({ witnessScript, fundedAddress, secretHash, takerRecvPubkey, makerRefundPubkey, t1, t2, nowSec, recvCoin }) {
  if (t1 != null) {
    const tl = validateTimelocks({ t1, t2, nowSec });
    if (!tl.ok) return { ok: false, reason: `unsafe timelocks: ${tl.reason}` };
  }
  return verifyContract({
    witnessScript,
    expectedAddress: fundedAddress,
    expectedSecretHash: secretHash,
    expectedRecipientPubkey: takerRecvPubkey,
    expectedRefundPubkey: makerRefundPubkey,
    expectedLocktime: t2,
    network: getCoin(recvCoin).network,
  });
}

/**
 * Maker-side verification of the taker's funded contract before the maker locks
 * its own liquidity: it must pay the maker, use the agreed secret hash, sit on
 * the send chain, and carry the longer locktime T1. Pass `t2` and `nowSec` to
 * also re-check the timelock ordering.
 */
export function verifyTakerContract({ witnessScript, fundedAddress, secretHash, makerRecvPubkey, takerRefundPubkey, t1, t2, nowSec, sendCoin }) {
  if (t2 != null) {
    const tl = validateTimelocks({ t1, t2, nowSec });
    if (!tl.ok) return { ok: false, reason: `unsafe timelocks: ${tl.reason}` };
  }
  return verifyContract({
    witnessScript,
    expectedAddress: fundedAddress,
    expectedSecretHash: secretHash,
    expectedRecipientPubkey: makerRecvPubkey,
    expectedRefundPubkey: takerRefundPubkey,
    expectedLocktime: t1,
    network: getCoin(sendCoin).network,
  });
}

// Re-exported for consumers that bind a verified contract to an observed UTXO.
export { verifyFundedOutput };
