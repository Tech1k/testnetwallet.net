// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr/adaptorswap: the cross-chain swap orchestration toolkit: the step
 * builders that tie the crypto core (DLEQ + adaptor), the BTC/LTC tx suite
 * (btcswap), and the Monero side (monero) into one BTC/LTC <-> XMR swap.
 *
 * Roles: ALICE provides XMR & receives BTC/LTC; BOB provides BTC/LTC & receives
 * XMR (liveness-critical). Each party holds a Monero spend-key SHARE (m) whose
 * secp256k1 image P = m*G is the adaptor encryption key; the DLEQ binds P to the
 * ed25519 share M = m*G_ed. When a 2-of-2 spend carrying the counterparty's
 * adaptor signature is broadcast, the share leaks on-chain and the watcher
 * reconstructs the combined Monero spend key (m_a + m_b) to sweep the XMR.
 *
 *   redeem  : Alice claims BTC; BOB's sig is the adaptor under P_a -> leaks m_a to Bob.
 *   refund  : Bob reclaims BTC after cancel; ALICE's sig is the adaptor under P_b
 *             -> leaks m_b to Alice (she reclaims the XMR).
 *
 * These are builders + verify gates (no chain I/O); the maker/wallet drivers
 * sequence them per ORCHESTRATION_INVARIANTS (swap.js). CRITICAL ORDERING: the
 * funding tx_lock must be BUILT (txid known) but NOT broadcast until BOTH the
 * pre-signed tx_cancel and the counterparty's redeem/refund adaptor sigs have
 * been exchanged AND verified (makeCancelPreSig/verifyCancelPreSig +
 * verifyRedeemAdaptor/verifyRefundAdaptor). Broadcast tx_lock LAST. Build the
 * unbroadcast funding tx with swap-core's buildFundingTx (it returns {hex,txid,vout}).
 */
import * as btcswap from './btcswap.js';
import * as monero from './monero.js';
import { parseDleq } from './crypto.js';
import { validateXmrTimelocks } from './swap.js';

const DUST = 546;
// Canonical fixed fee (sats) for the pre-signed BTC/LTC-side txs. SINGLE SOURCE OF TRUTH: driver.js imports
// this AS its FEE. The two MUST NOT diverge - the driver computes cancelAmount = lockAmount - FEE while the
// templates deduct feeSats; if they differ, the cancel output value and the adaptor sighash desync and EVERY
// swap silently fails. Keeping one constant makes that divergence impossible.
export const FEE_SATS = 1000;
const isHex = (s, bytes) => typeof s === 'string' && /^[0-9a-fA-F]*$/.test(s) && s.length === bytes * 2;
const ED_IDENTITY = '01' + '00'.repeat(31); // compressed ed25519 identity point

// secp scalar (BE hex) -> ed25519 scalar (LE hex): just reverse the bytes.
function secpToEd(hex) { return Buffer.from(hex, 'hex').reverse().toString('hex'); }

/** Generate a party's full key material for one swap (all hex private values). */
export function genKeyMaterial(x) {
  return {
    mSpend: x.gen_secret_share(),       // Monero spend-key share (ed, 252-bit)
    vView: x.gen_secret_share(),        // Monero view-key share (shared openly)
    btcKey: x.gen_secret_share(),       // this party's 2-of-2 key (used as a secp scalar)
    btcPunishKey: x.gen_secret_share(), // Alice's punish key (Bob's unused)
  };
}

/** The public bundle a party sends during setup (view share is intentionally public). */
export function publicBundle(x, km) {
  return {
    M: x.ed_pubkey(km.mSpend),
    Vpub: x.ed_pubkey(km.vView),
    vView: km.vView,                                  // private view share (not fund-secret)
    P: x.secp_pubkey(x.ed_to_secp_scalar(km.mSpend)), // secp adaptor encryption point
    dleq: parseDleq(x.dleq_prove(km.mSpend)),         // binds P <-> M to one scalar
    btcPub: x.secp_pubkey(km.btcKey),
    btcPunishPub: x.secp_pubkey(km.btcPunishKey),
  };
}

/**
 * Verify a counterparty's bundle. TOTAL over attacker-controlled input: validates
 * shapes, rejects a degenerate view point, then checks the DLEQ. Never throws;
 * always returns {ok, reason} so a hostile/malformed bundle is a clean abort.
 */
export function verifyBundle(x, b) {
  try {
    if (!b || typeof b !== 'object' || !b.dleq) return bad('missing bundle/dleq');
    if (!isHex(b.M, 32) || !isHex(b.Vpub, 32) || !isHex(b.vView, 32)) return bad('bad ed field');
    if (!isHex(b.P, 33) || !isHex(b.btcPub, 33) || !isHex(b.btcPunishPub, 33)) return bad('bad secp field');
    // Real proof check (a non-empty, even-length hex string). The previous form
    // isHex(proof, proof.length/2) was a tautology; cryptographic rejection is in
    // dleq_verify below, but reject obvious garbage up front.
    if (typeof b.dleq.proof !== 'string' || b.dleq.proof.length === 0 || b.dleq.proof.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(b.dleq.proof)) return bad('bad dleq proof');
    if (b.dleq.secp !== b.P || b.dleq.ed !== b.M) return bad('bundle points disagree with DLEQ');
    // Reject a degenerate spend share (m_spend = 0). M and P are DLEQ-bound to the same
    // scalar, so a non-identity M guarantees a non-identity P too. A zero share would make
    // the combined spend key one-sided (m_a + 0 = m_a), handing one party sole control.
    if (b.M === ED_IDENTITY) return bad('spend point is identity');
    if (b.Vpub === ED_IDENTITY) return bad('view point is identity'); // joint-randomization defense-in-depth
    if (x.ed_pubkey(b.vView) !== b.Vpub) return bad('view share inconsistent');
    if (!x.dleq_verify(b.dleq.proof, b.P, b.M)) return bad('DLEQ proof invalid');
    return { ok: true };
  } catch (e) {
    return bad('bundle parse/verify error: ' + e.message);
  }
}
const bad = (reason) => ({ ok: false, reason });

/**
 * Shared swap context both parties compute after exchanging+verifying bundles.
 * Throws if the timelocks are unsafe (validateXmrTimelocks).
 */
export function sharedContext(x, btc, { alice, bob, sendCoinNetwork, moneroNetwork = 'testnet', t1Blocks, t2Blocks }) {
  const tl = validateXmrTimelocks({ t1: t1Blocks, t2: t2Blocks });
  if (!tl.ok) throw new Error('unsafe timelocks: ' + tl.reason);
  const lockMonero = monero.lockAddress(x, {
    spendShareAHex: alice.M, spendShareBHex: bob.M,
    viewShareAHex: alice.Vpub, viewShareBHex: bob.Vpub, network: moneroNetwork,
  });
  const combinedViewPriv = x.ed_scalar_add(alice.vView, bob.vView);
  const lock = btcswap.lock2of2(btc, alice.btcPub, bob.btcPub, sendCoinNetwork); // A=Alice, B=Bob
  const cancelScriptHex = btcswap.cancelScript(btc, alice.btcPub, bob.btcPub, alice.btcPunishPub, t2Blocks);
  return {
    moneroLockAddress: lockMonero.address,
    moneroSpendPub: lockMonero.pubSpendHex,
    moneroViewPub: lockMonero.pubViewHex,
    combinedViewPriv,
    btcLock: lock, cancelScriptHex, t1Blocks, t2Blocks,
    // Bind the adaptor/verify points to the shared context so finalize gates can
    // cross-check the driver-supplied values against the verified bundle (I-2).
    alicePa: alice.P, bobPb: bob.P, aliceBtcPub: alice.btcPub, bobBtcPub: bob.btcPub,
  };
}

export function combinedSpendPriv(x, mSelf, mOtherEd) { return x.ed_scalar_add(mSelf, mOtherEd); }

// ---- pre-signed tx_cancel (2-of-2; both must hold each other's sig before locking) ----
export function makeCancelPreSig(x, { btcKey, cancelSighash }) { return x.ecdsa_sign(btcKey, cancelSighash); }
export function verifyCancelPreSig(x, { counterpartyBtcPub, cancelSighash, sig }) { return x.ecdsa_verify(counterpartyBtcPub, cancelSighash, sig); }

// ---- adaptor-sig verify gates (MUST pass before the verifier funds/locks) ----
export function verifyRedeemAdaptor(x, { bobBtcPub, alicePa, redeemSighash, adaptor }) {
  return x.adaptor_verify(bobBtcPub, alicePa, redeemSighash, adaptor);
}
export function verifyRefundAdaptor(x, { aliceBtcPub, bobPb, refundSighash, adaptor }) {
  return x.adaptor_verify(aliceBtcPub, bobPb, refundSighash, adaptor);
}

// ---- spend templates (fee in sats; output must clear dust) ----
function out(prevAmount, feeSats) {
  if (!Number.isInteger(prevAmount) || prevAmount < 0) throw new Error(`invalid prevAmount ${prevAmount}`);
  if (!Number.isInteger(feeSats) || feeSats < 0) throw new Error(`invalid feeSats ${feeSats} (must be a non-negative integer)`);
  const o = prevAmount - feeSats;
  if (o < DUST) throw new Error(`fee ${feeSats} leaves dust from ${prevAmount}`);
  return o;
}

export function redeemTemplate(btc, { ctx, lockTxid, lockVout, lockAmount, aliceDest, network, feeSats = FEE_SATS }) {
  return btcswap.spendTemplate(btc, {
    prevTxid: lockTxid, vout: lockVout, prevAmount: lockAmount,
    prevScriptPubKeyHex: ctx.btcLock.scriptPubKey, witnessScriptHex: ctx.btcLock.witnessScript,
    outAddress: aliceDest, outAmount: out(lockAmount, feeSats), network,
  });
}

export function cancelTemplate(btc, { ctx, lockTxid, lockVout, lockAmount, network, feeSats = FEE_SATS }) {
  const cancelWsh = btc.p2wsh({ script: Uint8Array.from(Buffer.from(ctx.cancelScriptHex, 'hex')) }, network);
  // A lock must fund the WHOLE unwind chain: cancel (one fee) THEN refund OR punish (a second fee), each
  // clearing DUST. Reject a too-small lock here (need lockAmount >= 2*feeSats + DUST) so the BTC can never
  // strand in a cancel output that no refund/punish can spend. (The maker also enforces this via MIN_SETTLE_LOCK_SATS.)
  if (out(lockAmount, feeSats) < feeSats + DUST) throw new Error(`lockAmount ${lockAmount} too small: the cancel output cannot fund a refund/punish spend (need >= ${2 * feeSats + DUST})`);
  return {
    cancelAddress: cancelWsh.address,
    cancelScriptPubKeyHex: Buffer.from(cancelWsh.script).toString('hex'),
    ...btcswap.spendTemplate(btc, {
      prevTxid: lockTxid, vout: lockVout, prevAmount: lockAmount,
      prevScriptPubKeyHex: ctx.btcLock.scriptPubKey, witnessScriptHex: ctx.btcLock.witnessScript,
      outAddress: cancelWsh.address, outAmount: out(lockAmount, feeSats), network,
      sequence: btcswap.relSequenceBlocks(ctx.t1Blocks),
    }),
  };
}

export function refundTemplate(btc, { ctx, cancelTxid, cancelVout, cancelAmount, cancelScriptPubKeyHex, bobDest, network, feeSats = FEE_SATS }) {
  return btcswap.spendTemplate(btc, {
    prevTxid: cancelTxid, vout: cancelVout, prevAmount: cancelAmount,
    prevScriptPubKeyHex: cancelScriptPubKeyHex, witnessScriptHex: ctx.cancelScriptHex,
    outAddress: bobDest, outAmount: out(cancelAmount, feeSats), network,
  });
}

/** Alice's unilateral punish spend (cancel ELSE branch); only valid after T2. */
export function punishTemplate(btc, { ctx, cancelTxid, cancelVout, cancelAmount, cancelScriptPubKeyHex, aliceDest, network, feeSats = FEE_SATS }) {
  return btcswap.spendTemplate(btc, {
    prevTxid: cancelTxid, vout: cancelVout, prevAmount: cancelAmount,
    prevScriptPubKeyHex: cancelScriptPubKeyHex, witnessScriptHex: ctx.cancelScriptHex,
    outAddress: aliceDest, outAmount: out(cancelAmount, feeSats), network,
    sequence: btcswap.relSequenceBlocks(ctx.t2Blocks),
  });
}

// ---- redeem (Alice claims BTC; Bob's adaptor leg leaks m_a) ----

export function makeRedeemAdaptor(x, { bobBtcKey, alicePa, redeemSighash }) {
  return x.adaptor_encrypt(bobBtcKey, alicePa, redeemSighash);
}

/** Alice finalizes redeem. VERIFIES Bob's adaptor first (fail-loud), then decrypts with m_a. */
export function aliceFinalizeRedeem(x, btc, { tx, ctx, aliceBtcKey, aliceMSpend, redeemSighash, bobRedeemAdaptor, bobBtcPub, alicePa }) {
  // Cross-check the points against the verified-bundle values bound into ctx (I-2):
  // a driver bug feeding the wrong point can't slip past the adaptor gate.
  // L4: fail-closed; sharedContext always binds these, so a missing/wrong value is rejected.
  if (bobBtcPub !== ctx.bobBtcPub) throw new Error('redeem: bobBtcPub does not match ctx');
  if (alicePa !== ctx.alicePa) throw new Error('redeem: alicePa does not match ctx');
  if (!x.adaptor_verify(bobBtcPub, alicePa, redeemSighash, bobRedeemAdaptor)) throw new Error('bob redeem adaptor invalid: refuse to lock/redeem');
  const sigAlice = x.ecdsa_sign(aliceBtcKey, redeemSighash);
  const sigBob = x.adaptor_decrypt(x.ed_to_secp_scalar(aliceMSpend), bobRedeemAdaptor);
  return btcswap.finalize2of2(btc, tx, ctx.btcLock.witnessScript, sigAlice, sigBob); // [A,B] order
}

export function bobRecoverFromRedeem(x, { redeemWitnessHex, alicePa, bobRedeemAdaptor, bobMSpend }) {
  const maSecp = btcswap.recoverFromRedeem(x, redeemWitnessHex, alicePa, bobRedeemAdaptor);
  if (!maSecp) return null;
  const maEd = secpToEd(maSecp);
  return { maEd, combinedSpendPriv: x.ed_scalar_add(maEd, bobMSpend) };
}

// ---- refund (Bob reclaims BTC; Alice's adaptor leg leaks m_b) ----

export function makeRefundAdaptor(x, { aliceBtcKey, bobPb, refundSighash }) {
  return x.adaptor_encrypt(aliceBtcKey, bobPb, refundSighash);
}

/** Bob finalizes refund. VERIFIES Alice's adaptor first (fail-loud), then decrypts with m_b. */
export function bobFinalizeRefund(x, btc, { tx, ctx, bobBtcKey, bobMSpend, refundSighash, aliceRefundAdaptor, aliceBtcPub, bobPb }) {
  // L4: fail-closed; sharedContext always binds these.
  if (aliceBtcPub !== ctx.aliceBtcPub) throw new Error('refund: aliceBtcPub does not match ctx');
  if (bobPb !== ctx.bobPb) throw new Error('refund: bobPb does not match ctx');
  if (!x.adaptor_verify(aliceBtcPub, bobPb, refundSighash, aliceRefundAdaptor)) throw new Error('alice refund adaptor invalid: refuse to fund');
  const sigBob = x.ecdsa_sign(bobBtcKey, refundSighash);
  const sigAlice = x.adaptor_decrypt(x.ed_to_secp_scalar(bobMSpend), aliceRefundAdaptor);
  return btcswap.finalizeRefund(btc, tx, ctx.cancelScriptHex, sigAlice, sigBob); // [sigB, sigA] order
}

export function aliceRecoverFromRefund(x, { refundWitnessHex, bobPb, aliceRefundAdaptor, aliceMSpend }) {
  const mbSecp = btcswap.recoverFromRefund(x, refundWitnessHex, bobPb, aliceRefundAdaptor);
  if (!mbSecp) return null;
  const mbEd = secpToEd(mbSecp);
  return { mbEd, combinedSpendPriv: x.ed_scalar_add(aliceMSpend, mbEd) };
}

export const _internal = { secpToEd, DUST };
