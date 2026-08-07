// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-core/htlc: the cross-chain HTLC contract (BIP199 / decred-atomicswap
 * construction), built as a P2WSH witness script with @scure/btc-signer.
 *
 *   OP_IF
 *       OP_SIZE 0x20 OP_EQUALVERIFY        // secret must be exactly 32 bytes
 *       OP_SHA256 <secret_hash> OP_EQUALVERIFY
 *       OP_DUP OP_HASH160 <recipient_pkh>
 *   OP_ELSE
 *       <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *       OP_DUP OP_HASH160 <refund_pkh>
 *   OP_ENDIF
 *   OP_EQUALVERIFY
 *   OP_CHECKSIG
 *
 * Redeem path (IF): reveal a 32-byte secret whose SHA256 == secret_hash, signed
 * by `recipient`. Refund path (ELSE): after `locktime` (CLTV), signed by `refund`.
 *
 * `locktime` is an absolute CLTV value. We default to time-based (unix seconds,
 * >= 500_000_000) elsewhere because testnet block production is too irregular to
 * give predictable refund windows; this module accepts whatever integer it's given.
 */
import * as btc from '../vendor/btc-signer.mjs';
import { assertBytes, bytesEqual } from './crypto.js';

const CLTV_THRESHOLD = 500000000; // < this = block height, >= this = unix time (BIP65)

/**
 * Build the HTLC contract.
 * @param {object} p
 * @param {Uint8Array} p.secretHash   32-byte SHA256(secret)
 * @param {Uint8Array} p.recipientPubkey 33-byte compressed pubkey (claims via secret)
 * @param {Uint8Array} p.refundPubkey    33-byte compressed pubkey (claims after locktime)
 * @param {number} p.locktime         absolute CLTV value
 * @param {object} p.network          a @scure/btc-signer network object
 * @returns {{witnessScript:Uint8Array, scriptPubKey:Uint8Array, address:string,
 *            secretHash:Uint8Array, recipientPubkey:Uint8Array, refundPubkey:Uint8Array,
 *            locktime:number, locktimeKind:'time'|'height'}}
 */
export function buildContract({ secretHash, recipientPubkey, refundPubkey, locktime, network }) {
  assertBytes(secretHash, 'secretHash');
  if (secretHash.length !== 32) throw new Error('secretHash must be 32 bytes');
  assertBytes(recipientPubkey, 'recipientPubkey');
  assertBytes(refundPubkey, 'refundPubkey');
  if (recipientPubkey.length !== 33) throw new Error('recipientPubkey must be 33-byte compressed');
  if (refundPubkey.length !== 33) throw new Error('refundPubkey must be 33-byte compressed');
  if (!Number.isInteger(locktime) || locktime <= 0) throw new Error('locktime must be a positive integer');
  // Fail-closed against a BIP65-invalid contract: a locktime above the max positive 5-byte
  // CScriptNum needs a 6-byte push, which OP_CHECKLOCKTIMEVERIFY rejects; the refund branch
  // would be permanently unexecutable. Never let a caller build such a contract for itself.
  const MAX_CLTV_NLOCKTIME = 0xffffffff; // 4294967295 = max 32-bit nLockTime. A CLTV operand ABOVE this can never be satisfied (no nLockTime reaches it), so the refund branch would be permanently unspendable - a refund-less contract. Tighter than the 5-byte scriptnum max on purpose.
  if (locktime > MAX_CLTV_NLOCKTIME) throw new Error(`locktime ${locktime} exceeds the max nLockTime (${MAX_CLTV_NLOCKTIME}); the refund branch would be permanently unspendable`);
  if (!network) throw new Error('network required');

  const recipientPkh = hash160OfPubkey(recipientPubkey);
  const refundPkh = hash160OfPubkey(refundPubkey);

  const witnessScript = btc.Script.encode([
    'IF',
    'SIZE', new Uint8Array([0x20]), 'EQUALVERIFY',
    'SHA256', secretHash, 'EQUALVERIFY',
    'DUP', 'HASH160', recipientPkh,
    'ELSE',
    locktime, 'CHECKLOCKTIMEVERIFY', 'DROP',
    'DUP', 'HASH160', refundPkh,
    'ENDIF',
    'EQUALVERIFY',
    'CHECKSIG',
  ]);

  const wsh = btc.p2wsh({ script: witnessScript }, network);
  return {
    witnessScript,
    scriptPubKey: wsh.script,
    address: wsh.address,
    secretHash,
    recipientPubkey,
    refundPubkey,
    locktime,
    locktimeKind: locktime >= CLTV_THRESHOLD ? 'time' : 'height',
  };
}

/**
 * Decode an HTLC witness script back into its parameters. Returns null if the
 * script doesn't match the expected template. Used to *verify* a counterparty's
 * contract: recompute the address from the claimed params and check it matches
 * the funded output before trusting it.
 */
export function parseContract(witnessScript) {
  assertBytes(witnessScript, 'witnessScript');
  let d;
  try {
    d = btc.Script.decode(witnessScript);
  } catch {
    return null;
  }
  // Expected token layout (20 tokens):
  // 0:IF 1:SIZE 2:<0x20> 3:EQUALVERIFY 4:SHA256 5:<hash> 6:EQUALVERIFY 7:DUP 8:HASH160 9:<pkhR>
  // 10:ELSE 11:<locktime> 12:CHECKLOCKTIMEVERIFY 13:DROP 14:DUP 15:HASH160 16:<pkhRefund> 17:ENDIF 18:EQUALVERIFY 19:CHECKSIG
  if (d.length !== 20) return null;
  const want = (i, op) => d[i] === op;
  if (!want(0, 'IF') || !want(1, 'SIZE') || !want(3, 'EQUALVERIFY') || !want(4, 'SHA256') ||
      !want(6, 'EQUALVERIFY') || !want(7, 'DUP') || !want(8, 'HASH160') || !want(10, 'ELSE') ||
      !want(12, 'CHECKLOCKTIMEVERIFY') || !want(13, 'DROP') || !want(14, 'DUP') || !want(15, 'HASH160') ||
      !want(17, 'ENDIF') || !want(18, 'EQUALVERIFY') || !want(19, 'CHECKSIG')) return null;
  const size32 = d[2];
  if (!(size32 instanceof Uint8Array) || size32.length !== 1 || size32[0] !== 0x20) return null;
  const secretHash = d[5];
  const recipientPkh = d[9];
  const refundPkh = d[16];
  const locktime = typeof d[11] === 'number' ? d[11] : scriptNumToInt(d[11]);
  if (!(secretHash instanceof Uint8Array) || secretHash.length !== 32) return null;
  if (!(recipientPkh instanceof Uint8Array) || recipientPkh.length !== 20) return null;
  if (!(refundPkh instanceof Uint8Array) || refundPkh.length !== 20) return null;
  if (!Number.isInteger(locktime)) return null;
  return { secretHash, recipientPkh, refundPkh, locktime,
           locktimeKind: locktime >= CLTV_THRESHOLD ? 'time' : 'height' };
}

/**
 * Verify a counterparty's contract matches what we agreed. Recomputes the P2WSH
 * address from the claimed params and checks it equals `expectedAddress`, and
 * that the embedded secretHash / recipient / refund / locktime match expectations.
 * Returns {ok:true} or {ok:false, reason}.
 */
export function verifyContract({ witnessScript, expectedAddress, expectedSecretHash,
                                 expectedRecipientPubkey, expectedRefundPubkey,
                                 expectedLocktime, network }) {
  // Fail CLOSED: a missing expectation must not silently skip its binding check.
  if (!witnessScript) return { ok: false, reason: 'witnessScript required' };
  if (!network) return { ok: false, reason: 'network required' };
  if (!expectedAddress) return { ok: false, reason: 'expectedAddress required' };
  if (!expectedSecretHash) return { ok: false, reason: 'expectedSecretHash required' };
  if (!expectedRecipientPubkey) return { ok: false, reason: 'expectedRecipientPubkey required' };
  if (!expectedRefundPubkey) return { ok: false, reason: 'expectedRefundPubkey required' };
  if (expectedLocktime == null) return { ok: false, reason: 'expectedLocktime required' };

  const parsed = parseContract(witnessScript);
  if (!parsed) return { ok: false, reason: 'script does not match HTLC template' };

  const wsh = btc.p2wsh({ script: witnessScript }, network);
  if (expectedAddress && wsh.address !== expectedAddress)
    return { ok: false, reason: 'address mismatch (script does not fund the agreed address)' };

  if (expectedSecretHash && !bytesEqual(parsed.secretHash, expectedSecretHash))
    return { ok: false, reason: 'secret hash mismatch' };

  if (expectedRecipientPubkey && !bytesEqual(parsed.recipientPkh, hash160OfPubkey(expectedRecipientPubkey)))
    return { ok: false, reason: 'recipient pubkey mismatch (contract would not pay us)' };

  if (expectedRefundPubkey && !bytesEqual(parsed.refundPkh, hash160OfPubkey(expectedRefundPubkey)))
    return { ok: false, reason: 'refund pubkey mismatch' };

  if (expectedLocktime != null && parsed.locktime !== expectedLocktime)
    return { ok: false, reason: `locktime mismatch (got ${parsed.locktime}, expected ${expectedLocktime})` };

  return { ok: true, parsed };
}

/**
 * Bind a verified contract to REAL coins. verifyContract only proves the script
 * hashes to an address; it cannot prove the counterparty actually funded it. The
 * consumer must independently observe the output at (fund_txid, vout) from a
 * trusted chain source and pass its scriptPubKey + value here. This asserts:
 *   - the funded output's scriptPubKey == p2wsh(witnessScript).script, and
 *   - its value is at least expectedSats.
 * Never advance a swap (lock liquidity / reveal the secret) on a counterparty's
 * claimed contract until this passes against an independently-fetched UTXO.
 * @param {Uint8Array|string} fundedScriptPubKey  scriptPubKey of the on-chain output
 * @param {number|bigint} fundedValueSats         value of that output
 * @param {number|bigint} expectedSats            minimum amount we required
 */
export function verifyFundedOutput({ witnessScript, fundedScriptPubKey, fundedValueSats, expectedSats, network }) {
  if (!witnessScript) return { ok: false, reason: 'witnessScript required' };
  if (!network) return { ok: false, reason: 'network required' };
  if (fundedScriptPubKey == null) return { ok: false, reason: 'fundedScriptPubKey required' };
  const spk = typeof fundedScriptPubKey === 'string' ? hexToBytesLocal(fundedScriptPubKey) : fundedScriptPubKey;
  if (!(spk instanceof Uint8Array)) return { ok: false, reason: 'fundedScriptPubKey must be hex or bytes' };
  const expected = btc.p2wsh({ script: witnessScript }, network).script;
  if (!bytesEqual(spk, expected))
    return { ok: false, reason: 'funded output scriptPubKey does not match the contract (wrong/forged contract)' };
  let val, exp;
  try { val = BigInt(fundedValueSats); exp = BigInt(expectedSats); } catch { return { ok: false, reason: 'invalid amounts' }; }
  // Strict positivity: a negative expectedSats (e.g. from an underflowing subtraction upstream)
  // would make `val < exp` false for ANY funded value, silently turning off the amount binding.
  if (exp <= 0n) return { ok: false, reason: 'expectedSats must be positive' };
  if (val < 0n) return { ok: false, reason: 'fundedValueSats must be non-negative' };
  if (val < exp) return { ok: false, reason: `underfunded: output holds ${val} sats, expected >= ${exp}` };
  return { ok: true };
}

// ---- internals ----

function hexToBytesLocal(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-fA-F]*$/.test(hex)) return null;   // reject non-hex up front: parseInt('1z',16)===1 would otherwise silently misread a malformed nibble as a valid byte
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

function hash160OfPubkey(pubkey) {
  return btc.Script.decode(btc.p2pkh(pubkey, btc.NETWORK).script)[2];
}

// Minimal little-endian CScriptNum decode (only used if the decoder hands back
// the locktime as raw bytes rather than a number).
function scriptNumToInt(bytes) {
  if (!(bytes instanceof Uint8Array)) return NaN;
  // CScriptNum is at most 5 bytes for a locktime; reject longer (a hostile script
  // could otherwise push a huge minimal-encoded number and overflow Number).
  if (bytes.length > 5) return NaN;
  if (bytes.length === 0) return 0;
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) n |= BigInt(bytes[i]) << BigInt(8 * i);
  const neg = bytes[bytes.length - 1] & 0x80;
  if (neg) n &= ~(0x80n << BigInt(8 * (bytes.length - 1)));
  const val = neg ? -Number(n) : Number(n);
  return Number.isSafeInteger(val) ? val : NaN;
}

export const _internal = { CLTV_THRESHOLD, scriptNumToInt };
