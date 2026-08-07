// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr/btcswap: the Bitcoin/Litecoin side of the BTC/LTC <-> XMR adaptor swap
 * (Gugger / xmr-btc-swap construction). All script + timelock logic lives here on
 * the secp256k1 chain; Monero has none. Built with @scure/btc-signer; the adaptor
 * signing/recovery comes from the WASM crypto core (passed in as `x`).
 *
 * Transaction suite (A = XMR provider/receives BTC, B = BTC provider/receives XMR):
 *   tx_lock    : B funds a 2-of-2(A,B) P2WSH.                         [PROVEN on-chain]
 *   tx_redeem  : A spends tx_lock; B's sig is an ADAPTOR sig under S_a.
 *                A completes with s_a -> on broadcast, B learns s_a.  [PROVEN on-chain]
 *   tx_cancel  : either party spends tx_lock after relative T1 (BIP68 nSequence),
 *                both pre-sign; output = cancel script (refund | punish).
 *   tx_refund  : B spends tx_cancel(refund branch); A's sig is an ADAPTOR sig
 *                under S_b -> on broadcast, A learns s_b (can reclaim XMR).
 *   tx_punish  : A spends tx_cancel(punish branch) alone after relative T2.
 *
 * The adaptor mechanism (encrypt under S=s*G, decrypt with s, recover s from the
 * published signature) is what carries the Monero key share across chains; it is
 * proven on testnet4 in tools/btc-adaptor-livetest.mjs. The timelock branches are
 * constructed + unit-tested offline here; live-broadcasting them requires the CSV
 * windows to elapse.
 */

const enc = (u) => Buffer.from(u).toString('hex');
const dec = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const SIGHASH_ALL = 0x01;
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// Assert a 64-byte compact ECDSA sig is canonical low-S (s in [1, n/2]) and r != 0.
// The crypto core already emits low-S; we ASSERT (never negate) because negating s
// would break the adaptor-recovery relationship that leaks the Monero key share.
// This fails loud on any future high-S regression instead of producing a
// non-standard (un-relayable) witness.
function assertLowS(compact64) {
  const b = compact64 instanceof Uint8Array ? compact64 : dec(compact64);
  if (b.length !== 64) throw new Error('compact signature must be 64 bytes');
  let r = 0n, s = 0n;
  for (let i = 0; i < 32; i++) r = (r << 8n) | BigInt(b[i]);
  for (let i = 32; i < 64; i++) s = (s << 8n) | BigInt(b[i]);
  if (r === 0n || r >= SECP_N) throw new Error('signature r out of range');
  if (s === 0n || s > SECP_N >> 1n) throw new Error('signature is not canonical low-S');
  return b;
}

// ---- strict-DER <-> compact(64) for secp256k1 ECDSA signatures ----
export function compactToDer(compact64) {
  const b = compact64 instanceof Uint8Array ? compact64 : dec(compact64);
  const trim = (x) => { let i = 0; while (i < x.length - 1 && x[i] === 0) i++; x = x.slice(i); if (x[0] & 0x80) x = Uint8Array.from([0, ...x]); return x; };
  const r = trim(b.slice(0, 32)), s = trim(b.slice(32, 64));
  const seq = Uint8Array.from([0x02, r.length, ...r, 0x02, s.length, ...s]);
  return Uint8Array.from([0x30, seq.length, ...seq]);
}
export function derToCompact(der) {
  const b = der instanceof Uint8Array ? der : dec(der);
  const pad = (x) => {
    while (x.length > 32 && x[0] === 0) x = x.slice(1);
    if (x.length > 32) throw new Error('der integer too large (> 32 bytes)');
    const o = new Uint8Array(32); o.set(x, 32 - x.length); return o;
  };
  if (b.length < 8 || b[0] !== 0x30 || b[1] !== b.length - 2) throw new Error('malformed DER (header/length)');
  let i = 2; if (b[i] !== 0x02) throw new Error('der r marker'); const rl = b[i + 1]; const r = b.slice(i + 2, i + 2 + rl); i += 2 + rl;
  if (b[i] !== 0x02) throw new Error('der s marker'); const sl = b[i + 1]; const s = b.slice(i + 2, i + 2 + sl); i += 2 + sl;
  if (i !== b.length) throw new Error('der length mismatch');
  return Uint8Array.from([...pad(r), ...pad(s)]);
}
const witSig = (compactHex) => Uint8Array.from([...compactToDer(assertLowS(compactHex)), SIGHASH_ALL]);

// ---- tx_lock: the 2-of-2(A,B) P2WSH ----
export function lock2of2(btc, pubAHex, pubBHex, network) {
  const ms = btc.p2ms(2, [dec(pubAHex), dec(pubBHex)]); // unsorted: sig order = [A, B]
  const wsh = btc.p2wsh(ms, network);
  return { address: wsh.address, witnessScript: enc(ms.script), scriptPubKey: enc(wsh.script) };
}

// ---- the cancel output: refund (2-of-2) OR punish (A alone after relative T2) ----
export function cancelScript(btc, pubAHex, pubBHex, punishPubAHex, t2Blocks) {
  if (!Number.isInteger(t2Blocks) || t2Blocks < 1 || t2Blocks > 0xffff)
    throw new Error(`t2Blocks must be 1..65535 (BIP68 block range), got ${t2Blocks}`);
  return enc(btc.Script.encode([
    'IF',
      dec(pubAHex), 'CHECKSIGVERIFY', dec(pubBHex), 'CHECKSIG',     // refund: A + B
    'ELSE',
      t2Blocks, 'CHECKSEQUENCEVERIFY', 'DROP', dec(punishPubAHex), 'CHECKSIG', // punish: A after T2
    'ENDIF',
  ]));
}

/**
 * Build a spend of a single P2WSH input and return the BIP143 sighash to sign.
 * scriptCode = the witnessScript of the output being spent.
 */
export function spendTemplate(btc, {
  prevTxid, vout, prevAmount, prevScriptPubKeyHex, witnessScriptHex,
  outAddress, outAmount, network, sequence = 0xfffffffd, lockTime = 0,
}) {
  const tx = new btc.Transaction({ allowUnknownOutputs: true, disableScriptCheck: true, lockTime });
  tx.addInput({
    txid: dec(prevTxid), index: vout, sequence,
    witnessUtxo: { amount: BigInt(prevAmount), script: dec(prevScriptPubKeyHex) },
    witnessScript: dec(witnessScriptHex),
  });
  tx.addOutputAddress(outAddress, BigInt(outAmount), network);
  const sighash = tx.preimageWitnessV0(0, dec(witnessScriptHex), btc.SigHash.ALL, BigInt(prevAmount));
  return { tx, sighashHex: enc(sighash) };
}

/** Finalize a 2-of-2 spend (redeem/cancel): witness [OP_0, sigA||01, sigB||01, ws]. */
export function finalize2of2(btc, tx, witnessScriptHex, sigACompactHex, sigBCompactHex) {
  tx.updateInput(0, { finalScriptWitness: [new Uint8Array(0), witSig(sigACompactHex), witSig(sigBCompactHex), dec(witnessScriptHex)] }, true);
  return { hex: tx.hex, txid: tx.id };
}

/** Finalize the cancel REFUND branch (IF): witness [sigB, sigA, OP_1, cancelScript]. */
export function finalizeRefund(btc, tx, cancelScriptHex, sigACompactHex, sigBCompactHex) {
  tx.updateInput(0, { finalScriptWitness: [witSig(sigBCompactHex), witSig(sigACompactHex), new Uint8Array([1]), dec(cancelScriptHex)] }, true);
  return { hex: tx.hex, txid: tx.id };
}

/** Finalize the cancel PUNISH branch (ELSE): witness [sigA, OP_0(empty), cancelScript]. */
export function finalizePunish(btc, tx, cancelScriptHex, sigAPunishCompactHex) {
  tx.updateInput(0, { finalScriptWitness: [witSig(sigAPunishCompactHex), new Uint8Array(0), dec(cancelScriptHex)] }, true);
  return { hex: tx.hex, txid: tx.id };
}

// Which witness item carries the adaptor-completed signature, per spend type.
// Co-located with the finalize functions so the index can't drift from the layout.
export const REDEEM_ADAPTOR_WITNESS_INDEX = 2; // [empty, sigA, sigB(adaptor), ws]
export const REFUND_ADAPTOR_WITNESS_INDEX = 1; // [sigB, sigA(adaptor), OP_1, cancelScript]

/**
 * Recover the adaptor decryption scalar (a Monero key share) from a broadcast
 * spend. `witnessArrayHex` is the spending input's witness (array of hex items);
 * `sigItemIndex` is which witness item is the adaptor-completed signature.
 * Throws on a missing/malformed witness item (so a watcher surfaces+retries);
 * returns null only when the witness is well-formed but the scalar genuinely
 * can't be recovered (wrong encryption point / encrypted sig).
 */
export function recoverScalar(x, witnessArrayHex, sigItemIndex, encPointHex, encSigHex) {
  const der = witnessArrayHex[sigItemIndex];
  if (!der) throw new Error(`no witness item at index ${sigItemIndex}`);
  let compact;
  try { compact = derToCompact(dec(der).slice(0, -1)); } // strip sighash byte
  catch (e) { throw new Error(`malformed witness signature at index ${sigItemIndex}: ${e.message}`); }
  const s = x.adaptor_recover(encPointHex, enc(compact), encSigHex);
  return s || null;
}

/** Recover s_a from a broadcast tx_redeem (Bob watches; encPoint = S_a). */
export const recoverFromRedeem = (x, witnessArrayHex, encSaHex, encSigHex) =>
  recoverScalar(x, witnessArrayHex, REDEEM_ADAPTOR_WITNESS_INDEX, encSaHex, encSigHex);

/** Recover s_b from a broadcast tx_refund (Alice watches; encPoint = S_b). */
export const recoverFromRefund = (x, witnessArrayHex, encSbHex, encSigHex) =>
  recoverScalar(x, witnessArrayHex, REFUND_ADAPTOR_WITNESS_INDEX, encSbHex, encSigHex);

/**
 * relative-timelock nSequence for a block count (BIP68: block-based, type bit 22
 * and disable bit 31 both 0). Throws rather than silently masking out-of-range
 * values, so the nSequence can never diverge from the in-script CSV operand.
 */
export const relSequenceBlocks = (n) => {
  if (!Number.isInteger(n) || n < 1 || n > 0xffff) throw new Error(`relative timelock must be 1..65535 blocks, got ${n}`);
  return n;
};
