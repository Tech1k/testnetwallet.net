// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Monero (Phase 1, receive-side): key derivation + address/subaddress encoding, pure JS, no backend.
 * Curve math: @noble/ed25519 (Point). Hash: @noble/hashes keccak_256 (NOT sha3_256 - different padding).
 *
 * Keys are derived from the wallet's existing BIP39 seed via a TestnetWallet-specific path
 * (m/44'/128'/0'/0' -> keccak256 -> sc_reduce32), so one recovery phrase covers BTC/LTC/XMR here.
 * This is NOT a portable Monero seed (won't restore in Cake/Feather); a 25-word/Polyseed export is a later phase.
 * Balance, history and spending need the node engine (later phase); this module only makes receive addresses.
 */
import { Point } from './vendor/noble-ed25519.mjs';
import { keccak_256 } from './vendor/noble-keccak.mjs';

const L = 2n ** 252n + 27742317777372353535851937790883648493n;   // ed25519 group order
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ENC = [0, 2, 3, 5, 6, 7, 9, 10, 11];   // encoded chars per 0..8 raw bytes (Monero base58 block sizes)
const DEC = {};                               // inverse: encoded length -> raw byte count
ENC.forEach((e, i) => { DEC[e] = i; });

// testnet-only ethos: ship stagenet + testnet, never mainnet. Prefix bytes verified against monero cryptonote_config.h.
export const XMR_NETS = {
  stagenet: { label: 'Stagenet', primary: 24, subaddress: 36 },
  testnet:  { label: 'Testnet',  primary: 53, subaddress: 63 },
};

/* ---- byte helpers ---- */
const te = new TextEncoder();
function bytesToHex(b){ let s = ''; for(const x of b) s += x.toString(16).padStart(2, '0'); return s; }
function numLE(b){ let n = 0n; for(let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; }   // little-endian bytes -> bigint
function numBE(b){ let n = 0n; for(let i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]); return n; }          // big-endian bytes -> bigint
function leBytes(n, len){ const o = new Uint8Array(len); for(let i = 0; i < len; i++){ o[i] = Number(n & 0xffn); n >>= 8n; } return o; }
function u32le(n){ return leBytes(BigInt(n >>> 0), 4); }
function cat(...arr){ let len = 0; for(const a of arr) len += a.length; const o = new Uint8Array(len); let p = 0; for(const a of arr){ o.set(a, p); p += a.length; } return o; }

/* ---- scalars / hashing ---- */
const scReduce32 = b => numLE(b.slice(0, 32)) % L;        // 32 LE bytes -> scalar mod L
const hashToScalar = data => scReduce32(keccak_256(data)); // Monero Hs()
const pub = s => Point.BASE.multiply(s).toBytes();         // s*G -> 32-byte compressed (ref10/Monero encoding)

/* ---- Monero base58 (block-based; a generic base58 is WRONG here) ---- */
export function b58encode(bytes){
  let out = '';
  for(let i = 0; i < bytes.length; i += 8){
    const block = bytes.subarray(i, Math.min(i + 8, bytes.length));
    const width = ENC[block.length];
    let num = numBE(block);
    const chars = new Array(width).fill('1');
    for(let j = width - 1; j >= 0 && num > 0n; j--){ chars[j] = B58[Number(num % 58n)]; num /= 58n; }
    out += chars.join('');
  }
  return out;
}
export function b58decode(str){
  const out = [];
  for(let i = 0; i < str.length; i += 11){
    const chunk = str.slice(i, i + 11);
    const bytes = DEC[chunk.length];
    if(bytes == null) throw new Error('bad base58 block length');
    let num = 0n;
    for(const ch of chunk){ const v = B58.indexOf(ch); if(v < 0) throw new Error('bad base58 char'); num = num * 58n + BigInt(v); }
    const blk = new Uint8Array(bytes);
    for(let k = bytes - 1; k >= 0; k--){ blk[k] = Number(num & 0xffn); num >>= 8n; }
    if(num !== 0n) throw new Error('base58 block overflow');
    out.push(...blk);
  }
  return Uint8Array.from(out);
}

/* ---- address assembly ---- */
function encodeAddress(prefixByte, spendPub, viewPub){
  const data = cat(Uint8Array.of(prefixByte), spendPub, viewPub);
  const checksum = keccak_256(data).slice(0, 4);
  return b58encode(cat(data, checksum));
}

/* Derive a Monero account (spend+view) from a 32-byte secret taken from the BIP39 tree.
 * spend = sc_reduce32(keccak256(secret));  view = sc_reduce32(keccak256(spend))  (Hs of the spend key). */
export function keysFromSecret(secret32){ return keysFromSpendSecret(keccak_256(secret32)); }   // BIP39 path: one extra keccak before reduce
/* Account keys from a raw 32-byte spend secret (legacy 25-word seed path: spend = sc_reduce32(secret) directly). */
export function keysFromSpendSecret(spend32){
  const spend = scReduce32(spend32);
  const spendBytes = leBytes(spend, 32);
  const view = scReduce32(keccak_256(spendBytes));
  const viewBytes = leBytes(view, 32);
  return { spend, view, spendBytes, viewBytes, spendPub: pub(spend), viewPub: pub(view) };
}

/* Subaddress for (account major, index minor); (0,0) is the standard/primary address. */
export function subaddress(keys, net, major, minor){
  if(major === 0 && minor === 0) return encodeAddress(net.primary, keys.spendPub, keys.viewPub);
  const m = hashToScalar(cat(te.encode('SubAddr\0'), keys.viewBytes, u32le(major), u32le(minor)));
  const D = Point.fromBytes(keys.spendPub).add(Point.BASE.multiply(m, false));   // D = B + m*G
  const Dbytes = D.toBytes();
  const C = Point.fromBytes(Dbytes).multiply(keys.view, false);                   // C = a*D
  return encodeAddress(net.subaddress, Dbytes, C.toBytes());
}

/* Self-test against canonical vectors. Gates the UI: if this fails, no addresses are shown.
 * Guards the two classic silent-failure traps (keccak-vs-sha3, generic-vs-block base58) plus point encoding. */
export function selfTest(){
  const checks = [];
  const chk = (name, fn) => { try { const d = fn(); checks.push({ name, ok:true, detail: d || '' }); } catch(e){ checks.push({ name, ok:false, detail: e.message || String(e) }); } };
  // keccak_256("") - guards against accidentally using sha3_256 (different padding -> different digest).
  chk('keccak_256("") KAT', () => { const h = bytesToHex(keccak_256(new Uint8Array(0))); if(h !== 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470') throw new Error('wrong hash (sha3 instead of keccak?)'); return h.slice(0,16)+'…'; });
  // ed25519 base point encoding - guards Point.toBytes() byte order/sign.
  chk('ed25519 base point encoding', () => { const h = bytesToHex(Point.BASE.toBytes()); if(h !== '5866666666666666666666666666666666666666666666666666666666666666') throw new Error('byte order/sign'); return h.slice(0,12)+'…'; });
  // canonical mainnet address round-trips through base58 + checksum (guards base58 block algo + checksum).
  chk('mainnet address base58 + checksum round-trip', () => {
    const CANON = '4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge';
    const raw = b58decode(CANON);
    if(raw.length !== 69) throw new Error('base58 decode length');
    if(raw[0] !== 18) throw new Error('mainnet prefix byte');
    if(bytesToHex(keccak_256(raw.slice(0, 65)).slice(0, 4)) !== bytesToHex(raw.slice(65, 69))) throw new Error('address checksum');
    if(b58encode(raw) !== CANON) throw new Error('base58 re-encode');
    return CANON.slice(0,8)+'…'+CANON.slice(-6);
  });
  const fails = checks.filter(c => !c.ok).map(c => c.name + (c.detail ? (': ' + c.detail) : ''));
  return { ok: fails.length === 0, fails, checks };
}

export { bytesToHex as hex };
