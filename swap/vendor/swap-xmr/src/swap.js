// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr/swap: roles, timelock phases, and the state machine for the
 * BTC/LTC <-> XMR adaptor swap. Distinct from the same-curve HTLC in swap-core.
 *
 * ROLES (fixed by the protocol, NOT by who is maker/taker):
 *   ALICE = the XMR provider. Locks XMR, receives BTC/LTC. Can be offline-ish.
 *   BOB   = the BTC/LTC provider. Locks BTC/LTC, receives XMR. LIVENESS-CRITICAL:
 *           after the cancel timelock he must refund in time or be PUNISHED (loses
 *           his BTC while the XMR can be stranded). So the always-online MAKER
 *           should take the Bob role wherever possible.
 *
 * THE TIMING ASYMMETRY (load-bearing): all script/timelock logic is on the
 * BTC/LTC chain (Monero has none). Relative timelocks (BIP68/CSV):
 *   T1 = blocks after tx_lock before tx_cancel is valid.
 *   T2 = blocks after tx_cancel before tx_punish is valid (Bob's refund window).
 * Monero outputs are locked for 10 blocks (~20 min) after being mined, so Bob
 * can only sweep the XMR after that; T1 must leave room for the whole happy path.
 */

export const Role = { ALICE_XMR: 'alice_xmr_provider', BOB_BTC: 'bob_btc_provider' };

const XMR = (c) => c === 'tXMR' || c === 'sXMR';

/**
 * Map a swap direction to protocol roles. `takerSends` is the coin the taker
 * gives up. The taker who SENDS xmr is Alice; the taker who RECEIVES xmr is Bob.
 * We try to keep the always-online maker in the liveness-critical Bob role.
 */
export function assignRoles({ takerSends, takerReceives }) {
  if (XMR(takerSends) === XMR(takerReceives)) throw new Error('exactly one side must be XMR');
  const scriptChain = XMR(takerSends) ? takerReceives : takerSends; // the BTC/LTC chain
  if (XMR(takerSends)) {
    // taker sends XMR -> taker = Alice, maker = Bob (maker is liveness-critical: good)
    return { takerRole: Role.ALICE_XMR, makerRole: Role.BOB_BTC, scriptChain,
             livenessCriticalParty: 'maker', takerIsLivenessCritical: false };
  }
  // taker sends BTC/LTC -> taker = Bob (liveness-critical), maker = Alice
  return { takerRole: Role.BOB_BTC, makerRole: Role.ALICE_XMR, scriptChain,
           livenessCriticalParty: 'taker', takerIsLivenessCritical: true };
}

// ---- timelock policy (relative blocks on the BTC/LTC chain) ----
export const MONERO_LOCK_BLOCKS = 10;          // outputs spendable after 10 confs
export const DEFAULT_T1_BLOCKS = { tBTC: 72, tLTC: 288 }; // ~12h
export const DEFAULT_T2_BLOCKS = { tBTC: 72, tLTC: 288 }; // ~12h refund window for Bob
export const MIN_T_BLOCKS = 12;                // never tighter than this

export function defaultXmrTimelocks(scriptChain) {
  return { t1: DEFAULT_T1_BLOCKS[scriptChain] ?? 72, t2: DEFAULT_T2_BLOCKS[scriptChain] ?? 72 };
}

// T1 must cover the whole happy path before cancel becomes spendable:
// tx_redeem confirms -> s_a recovered -> XMR swept -> Monero 10-block maturity.
export const MIN_T1_BLOCKS = MONERO_LOCK_BLOCKS + MIN_T_BLOCKS; // 22
// Operational upper cap (~7 days at ~10-min blocks), mirroring the HTLC MAX_SWAP_SECS: a hostile
// maker can't strand the funding party's tXMR behind an absurd CSV (audit M2 / NETWORK.md #10).
export const MAX_T_BLOCKS = 1000;

/**
 * Bounds + a basic operational floor on the relative timelocks. NOTE: this checks
 * structural validity and a minimum margin only; the orchestrator MUST still add
 * chain-specific confirmation margins (mempool congestion, reorg depth) on top;
 * passing here does not by itself mean a chosen (t1,t2) is operationally safe.
 */
export function validateXmrTimelocks({ t1, t2 }) {
  if (!Number.isInteger(t1) || !Number.isInteger(t2)) return { ok: false, reason: 't1/t2 must be integers (blocks)' };
  if (t1 > 0xffff || t2 > 0xffff) return { ok: false, reason: 'relative timelock must fit BIP68 (<= 65535 blocks)' };
  if (t1 > MAX_T_BLOCKS || t2 > MAX_T_BLOCKS) return { ok: false, reason: `relative timelock must be <= ${MAX_T_BLOCKS} blocks (operational cap; a longer lock is likely hostile)` };
  if (t2 < MIN_T_BLOCKS) return { ok: false, reason: `T2 must be >= ${MIN_T_BLOCKS} blocks (Bob's refund window)` };
  if (t1 < MIN_T1_BLOCKS) return { ok: false, reason: `T1 must be >= ${MIN_T1_BLOCKS} blocks (redeem + recover + XMR 10-block maturity)` };
  return { ok: true };
}

/**
 * The safety invariants the (separate) maker/taker orchestrator MUST enforce;
 * the tx layer here is a stateless builder and cannot. Surfaced from the
 * adversarial review; build XMR-D against these and never advance on the state
 * enum alone (gate every irreversible action on confirmed on-chain state).
 */
export const ORCHESTRATION_INVARIANTS = [
  'Every adaptor signature MUST be adaptor_verify\'d against the counterparty\'s btcPub and the DLEQ-bound bundle point P (verifyRedeemAdaptor/verifyRefundAdaptor) before the verifier takes any irreversible action; every pre-signed tx_cancel sig MUST be ecdsa_verify\'d (verifyCancelPreSig).',
  'tx_lock is BUILT (txid known via buildFundingTx, unbroadcast) FIRST; cancel/refund are built against that outpoint and the pre-sign handshake completed; tx_lock is BROADCAST LAST. Funding before the handshake inverts the safety ordering.',
  'Before Bob funds tx_lock: Bob has received AND verified Alice\'s pre-signed tx_cancel sig and tx_refund adaptor sig; else his BTC can be frozen with no unwind path.',
  'Before either party funds: both independently derive the SAME lock address/witnessScript (compare scriptPubKey hex); unsorted [A,B] key order must match.',
  'Alice does not lock XMR until tx_lock has N confirmations AND she holds Bob\'s valid pre-signed tx_cancel (her unwind path). She receives+verifies Bob\'s tx_redeem adaptor sig (verifyRedeemAdaptor) AFTER locking XMR, never before: an adaptor sig is immediately usable by its recipient, so releasing it to Alice pre-lock would let her redeem the BTC without ever locking XMR (Alice-side theft). If Bob withholds a valid redeem adaptor after the lock, Alice does not lose funds; she reclaims via cancel->refund->reclaim, or punishes for Bob\'s BTC after T2.',
  'Alice does not broadcast tx_redeem (which reveals s_a) until the maker\'s XMR is locked and matured.',
  'Bob actively watches the script chain for tx_redeem from the moment XMR is locked; on sight he recovers s_a (recoverFromRedeem) and sweeps XMR, with retries and explicit error surfacing, before the T1 cancel window can race him.',
  'Once tx_redeem is seen confirmed, CANCELLED is unreachable; never treat "I broadcast tx_cancel" as terminal for the XMR-claim logic; keep watching for redeem until one side has irreversible confirmations.',
  'On unwind: Bob broadcasts tx_refund immediately after tx_cancel confirms (do not wait), monitors it, and RBF/CPFP fee-bumps as T2 approaches; missing T2 means punish (lose BTC) AND stranded XMR.',
  'tx_punish is signed only strictly after T2 confirms; the punish key is distinct (punishPubA) and kept secret until then.',
  'A taker in the liveness-critical Bob role (taker sends BTC/LTC) must be warned: going offline during the refund window forfeits both BTC and XMR. Prefer routing so the always-online maker is Bob.',
];

// ---- state machine ----
export const XmrSwapState = {
  CREATED: 'created',         // params negotiated, DLEQ + adaptors exchanged
  BTC_LOCKED: 'btc_locked',   // Bob funded tx_lock on the script chain
  XMR_LOCKED: 'xmr_locked',   // Alice funded the XMR to the combined address
  BTC_REDEEMED: 'btc_redeemed', // Alice redeemed BTC (reveals s_a)
  COMPLETED: 'completed',     // Bob swept the XMR with the combined key
  CANCELLED: 'cancelled',     // tx_cancel broadcast (T1 passed, swap unwinding)
  REFUNDED: 'refunded',       // Bob refunded BTC (reveals s_b -> Alice reclaims XMR)
  PUNISHED: 'punished',       // Bob missed T2; Alice took BTC, XMR stranded
  ABORTED: 'aborted',         // negotiated abort before anyone funded
  FAILED: 'failed',
};

const T = {
  [XmrSwapState.CREATED]: [XmrSwapState.BTC_LOCKED, XmrSwapState.ABORTED, XmrSwapState.FAILED],
  [XmrSwapState.BTC_LOCKED]: [XmrSwapState.XMR_LOCKED, XmrSwapState.CANCELLED, XmrSwapState.FAILED],
  [XmrSwapState.XMR_LOCKED]: [XmrSwapState.BTC_REDEEMED, XmrSwapState.CANCELLED, XmrSwapState.FAILED],
  [XmrSwapState.BTC_REDEEMED]: [XmrSwapState.COMPLETED, XmrSwapState.FAILED],
  [XmrSwapState.CANCELLED]: [XmrSwapState.REFUNDED, XmrSwapState.PUNISHED, XmrSwapState.FAILED],
};

export function canTransition(from, to) {
  return (T[from] || []).includes(to);
}
export function isTerminal(s) {
  return [XmrSwapState.COMPLETED, XmrSwapState.REFUNDED, XmrSwapState.PUNISHED, XmrSwapState.ABORTED, XmrSwapState.FAILED].includes(s);
}
