// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-core/tx: build the transactions that spend an HTLC contract, and pull
 * the secret back out of a redeem transaction's witness.
 *
 *   buildRedeemTx: spend via the IF branch, revealing the 32-byte secret
 *   buildRefundTx: spend via the ELSE branch, after the CLTV locktime
 *   buildFundingTx: pay coins into a contract address (used by the maker; the
 *                    wallet taker funds via its own coin-control send path)
 *   extractSecret: recover S from a redeem tx's witness (counterparty watching)
 *
 * Witness stacks (the contract tail is P2PKH-style, so the pubkey is required):
 *   redeem: [ sig, pubkey, secret, 0x01 (TRUE -> IF),  witnessScript ]
 *   refund: [ sig, pubkey, <empty> (FALSE -> ELSE),    witnessScript ]
 *
 * Fees are sized by a fixpoint loop: build, measure the real finalized vsize,
 * and bump the fee until it clears ceil(vsize * feeRate); never below the
 * min-relay floor. (ECDSA/DER signature length varies 71-73 bytes with no
 * low-R grinding, so a naive single-pass probe can under-pay and strand a
 * non-relayable tx, fatal on the refund safety path.)
 */
import * as btc from '../vendor/btc-signer.mjs';
import { DUST, MIN_RELAY_FEERATE, sha256, getPublicKey, bytesToHex, hexToBytes, bytesEqual, assertBytes } from './crypto.js';

const SEQUENCE = 0xfffffffd; // RBF-signalling and < 0xfffffffe so CLTV is enabled
const WITNESS_TRUE = new Uint8Array([1]);
const WITNESS_FALSE = new Uint8Array([]);

function validateUtxo(utxo) {
  if (!utxo || typeof utxo.txid !== 'string' || !/^[0-9a-fA-F]{64}$/.test(utxo.txid))
    throw new Error('utxo.txid must be a 64-char hex string');
  if (!Number.isInteger(utxo.vout) || utxo.vout < 0) throw new Error('utxo.vout must be a non-negative integer');
  if (utxo.amount == null) throw new Error('utxo.amount required (sats)');
}

function buildSpend({ branch, contract, utxo, privkey, secret, destAddress, feeRate, network }) {
  validateUtxo(utxo);
  if (!contract || !contract.witnessScript || !contract.scriptPubKey) throw new Error('contract required');
  assertBytes(privkey, 'privkey');
  if (!destAddress) throw new Error('destAddress required');
  if (!network) throw new Error('network required');
  if (branch === 'redeem') {
    assertBytes(secret, 'secret');
    if (secret.length !== 32) throw new Error('secret must be 32 bytes');
    // Fail fast: a wrong secret signs fine but is rejected on-chain (OP_SHA256
    // EQUALVERIFY), and disableScriptCheck means the library won't catch it.
    if (contract.secretHash && !bytesEqual(sha256(secret), contract.secretHash))
      throw new Error('secret does not hash to the contract secretHash');
  }
  const amount = BigInt(utxo.amount);
  const feeR = Math.max(MIN_RELAY_FEERATE, Math.floor(Number(feeRate) || MIN_RELAY_FEERATE));
  const txidBytes = hexToBytes(utxo.txid);

  const mk = (outAmount) => {
    const tx = new btc.Transaction({
      allowUnknownOutputs: true,
      disableScriptCheck: true,
      lockTime: branch === 'refund' ? contract.locktime : 0,
    });
    tx.addInput({
      txid: txidBytes,
      index: utxo.vout,
      sequence: SEQUENCE,
      witnessUtxo: { amount, script: contract.scriptPubKey },
      witnessScript: contract.witnessScript,
    });
    tx.addOutputAddress(destAddress, outAmount, network);
    if (!tx.signIdx(privkey, 0, [btc.SigHash.ALL])) throw new Error('signing failed');
    const partial = tx.getInput(0).partialSig;
    if (!partial || !partial.length) throw new Error('no signature produced (wrong key for this contract path?)');
    const sig = partial[0][1];
    // The contract tail is P2PKH-style (OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG),
    // so the spender must put its pubkey on the stack. Witness, bottom->top:
    //   redeem: [sig, pubkey, secret, TRUE  (-> IF branch),  witnessScript]
    //   refund: [sig, pubkey, FALSE (-> ELSE branch),        witnessScript]
    const pubkey = getPublicKey(privkey);
    const witness = branch === 'redeem'
      ? [sig, pubkey, secret, WITNESS_TRUE, contract.witnessScript]
      : [sig, pubkey, WITNESS_FALSE, contract.witnessScript];
    tx.updateInput(0, { finalScriptWitness: witness }, true);
    return tx;
  };

  // Fixpoint: size the fee against the ACTUAL finalized vsize. Changing the
  // output amount changes the signature length, which changes the vsize, so we
  // iterate to a stable fee that clears ceil(finalVsize * feeR). Converges in
  // 1-3 rounds; the cap is a safety stop.
  let fee = BigInt(Math.ceil(mk(amount > 1000n ? amount - 1000n : amount).vsize * feeR));
  let tx;
  for (let i = 0; i < 6; i++) {
    const outAmount = amount - fee;
    if (outAmount < BigInt(DUST)) {
      if (fee >= amount)
        throw new Error(`fee ${fee} sats exceeds input ${amount} sats (cannot spend this UTXO at feeRate ${feeR})`);
      throw new Error(`input ${amount} sats too small to cover fee ${fee} sats without creating dust`);
    }
    tx = mk(outAmount);
    const need = BigInt(Math.ceil(tx.vsize * feeR));
    if (fee >= need) break; // current fee already clears the final vsize requirement
    fee = need;
  }
  // Final guarantee: never below the min-relay floor for the real tx.
  if (Number(fee) < Math.ceil(tx.vsize * MIN_RELAY_FEERATE))
    throw new Error('internal: fee fell below min-relay after sizing');
  return { tx, hex: tx.hex, txid: tx.id, fee: Number(fee), vsize: tx.vsize, outAmount: Number(amount - fee) };
}

/** Spend an HTLC via the redeem (secret) path. */
export function buildRedeemTx(opts) {
  return buildSpend({ ...opts, branch: 'redeem' });
}

/**
 * Spend an HTLC via the refund (timelock) path. The resulting tx is only valid
 * once the chain's MTP/height has passed contract.locktime; broadcasting earlier
 * returns a non-final/`non-BIP68-final` error.
 */
export function buildRefundTx(opts) {
  return buildSpend({ ...opts, branch: 'refund' });
}

/**
 * Build a funding transaction paying `amount` sats into `contractAddress`,
 * using @scure/btc-signer's coin selector. `utxos` is an array of
 * { inp, key } where `inp` is a btc-signer input descriptor (with witnessUtxo
 * or nonWitnessUtxo) and `key` is the 32-byte private key for it; same shape
 * the wallet's gatherInputs() produces.
 * Returns { hex, txid, fee, vout } where vout is the contract output index,
 * located by address, since the coin selector may place change before it.
 */
export function buildFundingTx({ utxos, contractAddress, amount, changeAddress, feeRate, network }) {
  if (!Array.isArray(utxos) || !utxos.length) throw new Error('utxos required');
  if (!contractAddress) throw new Error('contractAddress required');
  if (!changeAddress) throw new Error('changeAddress required');
  if (contractAddress === changeAddress) throw new Error('contractAddress must differ from changeAddress'); // U-4: avoid ambiguous output match
  if (!network) throw new Error('network required');
  const sats = BigInt(amount);
  const feeR = Math.max(MIN_RELAY_FEERATE, Math.floor(Number(feeRate) || MIN_RELAY_FEERATE));
  // The funded output must be able to pay its own redeem/refund fee AND still clear dust, or
  // the HTLC is unspendable (mints permanently stuck coins). The bare `>= DUST` check is not
  // enough: an output just above dust can't cover the spend fee. Size the floor at the
  // worst-case redeem (32-byte secret + sig, ~175 vbytes) at the funding feeRate.
  const minHtlc = BigInt(DUST) + BigInt(Math.ceil(175 * feeR));
  if (sats < minHtlc) throw new Error(`amount ${amount} below minimum HTLC ${minHtlc} sats (must cover redeem/refund fee + dust at feeRate ${feeR})`);

  const sel = btc.selectUTXO(
    utxos.map((u) => u.inp),
    [{ address: contractAddress, amount: sats }],
    'default',
    { changeAddress, feePerByte: BigInt(feeR), dust: BigInt(DUST), network, createTx: true },
  );
  if (!sel || !sel.tx) throw new Error('not enough coins to fund contract + fee');

  const tx = sel.tx;
  const signed = new Set();
  for (const u of utxos) {
    const kh = bytesToHex(u.key);
    if (signed.has(kh)) continue;
    signed.add(kh);
    try { tx.sign(u.key); } catch { /* not for this input */ }
  }
  tx.finalize();

  // Locate the contract output by address (the selector may order change first).
  // U-4: require EXACTLY ONE match paying EXACTLY `sats`, so an ambiguous/short
  // contract output can never be reported as funded.
  let vout = -1, matches = 0;
  for (let i = 0; i < tx.outputsLength; i++) {
    const o = tx.getOutput(i);
    if (o && o.script && scriptToAddress(o.script, network) === contractAddress) {
      matches++;
      if (BigInt(o.amount) !== sats) throw new Error(`internal: contract output value ${o.amount} != requested ${sats}`);
      vout = i;
    }
  }
  if (matches !== 1) throw new Error(`internal: expected exactly one contract output, found ${matches}`);
  return { hex: tx.hex, txid: tx.id, fee: Number(sel.fee), vout };
}

function scriptToAddress(script, network) {
  try { return btc.Address(network).encode(btc.OutScript.decode(script)); } catch { return null; }
}

// ---- secret extraction ----

// Tolerant byte check: cross-realm / worker Uint8Arrays fail `instanceof`
// (the vendored library guards the same way), and a missed secret would cost
// the maker its claim window, so be permissive here.
function asBytes32(it) {
  if (it instanceof Uint8Array) return it.length === 32 ? it : null;
  if (it && typeof it === 'object' && it.constructor && it.constructor.name === 'Uint8Array' && it.length === 32)
    return Uint8Array.from(it);
  return null;
}

/** Search a single witness stack (array of Uint8Array) for the 32-byte secret. */
export function findSecretInWitness(items, secretHash) {
  if (!Array.isArray(items)) return null;
  for (const it of items) {
    const b = asBytes32(it);
    if (b && bytesEqual(sha256(b), secretHash)) return b;
  }
  return null;
}

/**
 * Recover the secret S from a redeem transaction. Accepts:
 *   - an Esplora tx object ({ vin: [{ witness: [hex...] }] })
 *   - a raw tx hex string
 *   - an array of witness hex strings (a single input's witness)
 * Returns the 32-byte secret (Uint8Array) or null.
 */
export function extractSecret(input, secretHash) {
  assertBytes(secretHash, 'secretHash');
  if (secretHash.length !== 32) throw new Error('secretHash must be 32 bytes');

  // array of already-decoded bytes -> one witness stack
  if (Array.isArray(input) && input.length && (input[0] instanceof Uint8Array ||
      (input[0] && input[0].constructor && input[0].constructor.name === 'Uint8Array'))) {
    return findSecretInWitness(input, secretHash);
  }
  // array of hex strings -> one witness stack
  if (Array.isArray(input) && (input.length === 0 || typeof input[0] === 'string')) {
    return findSecretInWitness(input.map(safeHex).filter(Boolean), secretHash);
  }
  // Esplora tx object
  if (input && typeof input === 'object' && Array.isArray(input.vin)) {
    for (const vin of input.vin) {
      const wit = vin.witness;
      if (Array.isArray(wit)) {
        const found = findSecretInWitness(wit.map(safeHex).filter(Boolean), secretHash);
        if (found) return found;
      }
    }
    return null;
  }
  // raw tx hex
  if (typeof input === 'string') {
    let parsed;
    try { parsed = btc.RawTx.decode(hexToBytes(input)); } catch { return null; }
    const wits = parsed.witnesses || [];
    for (const w of wits) {
      const found = findSecretInWitness(w, secretHash);
      if (found) return found;
    }
    return null;
  }
  return null;
}

function safeHex(h) {
  try { return hexToBytes(h); } catch { return null; }
}

export const _internal = { SEQUENCE, buildSpend };
