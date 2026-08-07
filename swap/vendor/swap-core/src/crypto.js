// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-core/crypto: the small set of hashing / key / encoding primitives the
 * HTLC needs. All vendored (@scure/btc-signer + @noble), no build step, usable
 * in the browser (TestnetWallet) and in Node (the maker daemon, the tests).
 *
 * hash160 is derived from @scure/btc-signer's p2pkh script so we don't have to
 * vendor a separate ripemd160; the library already bundles one internally and
 * the 20-byte hash is the third element of the decoded P2PKH script.
 */
import * as btc from '../vendor/btc-signer.mjs';
import { sha256 as _sha256 } from '../vendor/noble-sha256.mjs';
import { getPublicKey as _getPublicKey } from '../vendor/noble-secp256k1.mjs';

export const DUST = 546; // sats; outputs below this are non-standard (matches the wallet)
export const MIN_RELAY_FEERATE = 1; // sat/vByte floor

export function sha256(bytes) {
  return _sha256(bytes);
}

/** HASH160 = RIPEMD160(SHA256(pubkey)), 20 bytes. Network-independent. */
export function hash160(pubkey) {
  assertBytes(pubkey, 'pubkey');
  // p2pkh script = OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
  const decoded = btc.Script.decode(btc.p2pkh(pubkey, btc.NETWORK).script);
  return decoded[2];
}

/** Compressed (33-byte) secp256k1 public key from a 32-byte private key. */
export function getPublicKey(privkey, compressed = true) {
  return _getPublicKey(privkey, compressed);
}

/** 32 random bytes used as the atomic-swap secret S. */
export function randomSecret() {
  const out = new Uint8Array(32);
  const c = globalThis.crypto;
  if (!c || !c.getRandomValues) throw new Error('crypto.getRandomValues unavailable');
  c.getRandomValues(out);
  return out;
}

/** H = SHA256(S). */
export function secretHashOf(secret) {
  assertBytes(secret, 'secret');
  if (secret.length !== 32) throw new Error('secret must be 32 bytes');
  return sha256(secret);
}

// ---- byte helpers (avoid pulling Buffer; works in browser too) ----

export function bytesToHex(bytes) {
  assertBytes(bytes, 'bytes');
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2) throw new Error('invalid hex');
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('invalid hex'); // reject a bad second nibble too (parseInt('0g',16)===0 would slip)
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function assertBytes(v, name = 'value') {
  if (!(v instanceof Uint8Array)) throw new Error(`${name} must be a Uint8Array`);
  return v;
}
