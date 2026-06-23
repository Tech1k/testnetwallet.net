/* ============================================================================
 * mweb.mjs - Litecoin MWEB (MimbleWimble Extension Blocks), pure-JS, no backend.
 *
 * PHASE 1: keychain + stealth address + output create/scan (receive side).
 * No bulletproofs are needed to RECEIVE: the amount rides in `masked_value`
 * (an XOR mask from HASH64(ECDH)), so scanning is just secp256k1 + hashing.
 *
 * Spec transcribed bit-for-bit from the REFERENCE implementation:
 *   - github.com/ltc-mweb/libmw  (Keychain.cpp, Output.cpp, Hasher.h, Pedersen.cpp,
 *     Crypto.cpp, secp256k1-zkp.h, deps/secp256k1-zkp generators)
 *   - github.com/ltc-mweb/litecoin  (src/hash.h, doc/mweb/stealth_addresses.md)
 * KEY FACTS (verified against source, NOT the docs which wrongly say BLAKE3):
 *   - HASH32(tag,parts...) = doubleSHA256( compactSize(len) || tagByte || parts ),
 *     where libmw's Serializer writes integers BIG-ENDIAN.
 *   - HASH64(e) = single SHA-512( e ), no framing.
 *   - Value generator H and switch generator J are the secp256k1-zkp constants.
 *   - Keychain: scan a=HD(m/1/0/100'), spend b=HD(m/1/0/101');
 *     b_i = b + HASH32('A', u32 i, a);  B_i = b_i*G;  a_i = a*b_i;  A_i = a_i*G.
 *   - Commitment uses a Pedersen "blind switch": C = SWITCH(v, r).
 *
 * Bit-exactness vs. CONSENSUS (compactSize framing, BE integers, J point) is
 * gated two ways: (1) an in-app create->scan round-trip self-test [self-consistent],
 * and (2) the real gate - generate a tmweb address, receive testnet LTC to it, and
 * scan the raw block; if the amount comes back, every byte is right. We never claim
 * correctness from static analysis alone.
 * ========================================================================== */
import * as secp from './vendor/noble-secp256k1.mjs';
import { sha256 } from './vendor/noble-sha256.mjs';
import { sha512 } from './vendor/noble-sha512.mjs';
import { HDKey } from './vendor/bip32.mjs';
import { mnemonicToSeedSync } from './vendor/bip39.mjs';

const P = secp.ProjectivePoint;
const N = secp.CURVE.n;
const G = P.BASE, ZERO = P.ZERO;
const { mod, bytesToNumberBE, numberToBytesBE, concatBytes, hexToBytes, bytesToHex } = secp.etc;

// Value generator H and switch generator J (secp256k1_generator/pubkey store X||Y big-endian).
const H = P.fromHex('0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0');
const J = P.fromHex('02b860f56795fc03f3c21685383d1b5a2f2954f49b7e398b8d2a0193933621155f');

/* ---------------- low-level helpers ---------------- */
const sc = (x) => mod(x, N);                                   // reduce scalar mod curve order
const scAdd = (a, b) => sc(a + b);
const scMul = (a, b) => sc(a * b);
const fromB = (b) => bytesToNumberBE(b);                       // 32-byte BE -> scalar (no reduction)
const to32 = (x) => numberToBytesBE(sc(x), 32);
function mul(point, k) { k = sc(k); return k === 0n ? ZERO : point.multiply(k); }   // k*point, 0-safe
const pub = (point) => point.toRawBytes(true);                 // 33-byte compressed
const u32be = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, false); return b; };
const u64be = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v) & ((1n<<64n)-1n), false); return b; };
const xorBytes = (a, b, off=0, len=a.length) => { const o = a.slice(); for (let i=0;i<len;i++) o[i] = a[i] ^ b[off+i]; return o; };
function compactSize(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n>>8) & 0xff);
  return Uint8Array.of(0xfe, n & 0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>>24)&0xff);
}
const dsha256 = (b) => sha256(sha256(b));

// HASH32 = litecoin SerializeHash (double-SHA256) of compactSize-framed (tagChar || parts...)
function hash32(tagChar, ...parts) {
  const body = concatBytes(Uint8Array.of(tagChar.charCodeAt(0)), ...parts);
  return dsha256(concatBytes(compactSize(body.length), body));
}
const hash32scalar = (tagChar, ...parts) => sc(fromB(hash32(tagChar, ...parts)));   // as a scalar mod n
const hash64 = (e32) => sha512(e32);                            // single SHA-512, no framing

// 33-byte Pedersen-commitment serialization: prefix 0x08|0x09 (y parity) then X (BE).
function commitBytes(point) {
  const a = point.toAffine();
  return concatBytes(Uint8Array.of(0x08 | (a.y & 1n ? 1 : 0)), numberToBytesBE(a.x, 32));
}

/* ---------------- Pedersen commit + blind switch ---------------- */
// commit(value, blind) = blind*G + value*H
function pedersen(value, blindScalar) { return mul(G, blindScalar).add(mul(H, BigInt(value))); }
// SWITCH: r_switch = (r + SHA256( commit(value,r)_33 || (r*J)_33 )) mod n
function blindSwitch(rScalar, value) {
  const Pcommit = pedersen(value, rScalar);
  const rJ = mul(J, rScalar);
  const h = sha256(concatBytes(commitBytes(Pcommit), pub(rJ)));
  return scAdd(rScalar, fromB(h));
}
// output commitment C = SWITCH(value, r)*G + value*H
function switchCommit(value, rScalar) { return pedersen(value, blindSwitch(rScalar, value)); }

/* ---------------- Keychain ---------------- */
// Derive (scan, spend) master secrets from a BIP39 seed (Litecoin MWEB HD paths).
function masterKeysFromSeed(seed) {
  const root = HDKey.fromMasterSeed(seed);
  const scan = root.derive("m/1/0/100'").privateKey;
  const spend = root.derive("m/1/0/101'").privateKey;
  return { scan: fromB(scan), spend: fromB(spend), scanBytes: scan, spendBytes: spend };
}
function masterKeysFromMnemonic(mnemonic, passphrase) {
  return masterKeysFromSeed(mnemonicToSeedSync(mnemonic, passphrase || ''));
}
// one-time spend scalar b_i = b + HASH32('A', u32 i, a)
function spendKeyAt(keys, i) { return scAdd(keys.spend, hash32scalar('A', u32be(i), to32(keys.scan))); }
// stealth address (A_i, B_i): B_i = b_i*G, a_i = a*b_i, A_i = a_i*G
function stealthAddress(keys, i) {
  const bi = spendKeyAt(keys, i);
  const Bi = mul(G, bi);
  const ai = scMul(keys.scan, bi);
  const Ai = mul(G, ai);
  return { i, bi, ai, A: Ai, B: Bi, Abytes: pub(Ai), Bbytes: pub(Bi) };
}

/* ---------------- Output create (sender side) ---------------- */
// Create an output paying `value` to stealth address (A,B given as 33-byte pubkeys or Points).
// ks (sender ephemeral secret scalar) optional - pass for deterministic tests.
function outputCreate(Apub, Bpub, value, ksScalar) {
  const A = (Apub instanceof P) ? Apub : P.fromHex(Apub);
  const B = (Bpub instanceof P) ? Bpub : P.fromHex(Bpub);
  const ks = ksScalar != null ? sc(ksScalar) : fromB(secp.utils.randomPrivateKey());
  const Ks = mul(G, ks);                                        // sender pubkey
  const n = hash32('N', to32(ks)).slice(0, 16);                // 16-byte nonce
  const s = hash32scalar('S', pub(A), pub(B), u64be(value), n);// sending scalar
  const e = hash32('D', pub(mul(A, s)));                       // shared secret e = HASH32('D', s*A)
  const viewTag = e[0];
  const Ko = mul(G, hash32scalar('O', e)).add(B);             // receiver one-time pubkey
  const Ke = mul(B, s);                                        // key-exchange pubkey
  const m = hash64(e);                                         // 64-byte mask
  const r = fromB(m.slice(0, 32));                             // blinding factor
  const maskedValue = xorBytes(u64be(value), m, 32, 8);       // v' = v XOR m[32:40]
  const maskedNonce = xorBytes(n, m, 40, 16);                 // n' = n XOR m[40:56]
  const C = switchCommit(value, r);                           // commitment
  return {
    commitment: commitBytes(C), Ko: pub(Ko), Ke: pub(Ke), viewTag,
    maskedValue, maskedNonce, senderPubkey: pub(Ks),
    // (rangeproof + sender signature are added in later phases)
    _debug: { value: BigInt(value), r, blind: blindSwitch(r, value) },
  };
}

/* ---------------- Output scan (receiver side) ---------------- */
// Try to identify+recover an output for our wallet `keys`. `gap` = address lookahead.
// Returns { value, index, spendKey, blind } or null.
function outputScan(keys, out, gap=50) {
  const Ke = P.fromHex(out.Ke), Ko = P.fromHex(out.Ko);
  const e = hash32('D', pub(mul(Ke, keys.scan)));             // e = HASH32('D', a*Ke)
  if (e[0] !== out.viewTag) return null;                       // cheap view-tag reject
  const Bi = Ko.add(mul(G, hash32scalar('O', e)).negate());   // B_i = Ko - HASH32('O',e)*G
  // find the address index whose spend pubkey equals B_i
  let index = -1;
  for (let i=0;i<gap;i++) { if (mul(G, spendKeyAt(keys, i)).equals(Bi)) { index = i; break; } }
  if (index < 0) return null;
  const addr = stealthAddress(keys, index);
  const m = hash64(e);
  const valueBytes = xorBytes(out.maskedValue, m, 32, 8);     // v = v' XOR m[32:40]
  const value = new DataView(valueBytes.buffer, valueBytes.byteOffset, 8).getBigUint64(0, false);
  const r = fromB(m.slice(0, 32));
  // verify the commitment opens to (value, r)
  if (bytesToHex(commitBytes(switchCommit(value, r))) !== bytesToHex(out.commitment)) return null;
  // recover nonce + re-derive s, verify Ke = s*B_i
  const n = xorBytes(out.maskedNonce, m, 40, 16);
  const s = hash32scalar('S', pub(addr.A), pub(addr.B), u64be(value), n);
  if (!mul(addr.B, s).equals(Ke)) return null;
  // output spend key k_o = HASH32('O',e) + b_i  (Ko = B_i + HASH32('O',e)*G, B_i = b_i*G;
  // the doc's "+ a_i" is a typo - dlog(Ko) is the one-time SPEND scalar b_i, not the scan scalar).
  const spendKey = scAdd(hash32scalar('O', e), addr.bi);
  const blind = blindSwitch(r, value);
  return { value, index, spendKey, blind };
}

/* ---------------- Self-test (run in-browser; gates the feature) ---------------- */
function selfTest() {
  const fails = [];
  // 1) SHA-512 known-answer (empty string)
  try {
    const empty = bytesToHex(sha512(new Uint8Array(0)));
    if (empty !== 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
      fails.push('sha512 KAT');
  } catch (e) { fails.push('sha512: ' + (e.message || e)); }
  // 2) double-SHA256 KAT ("" -> 5df6e0e2...)
  try {
    if (bytesToHex(dsha256(new Uint8Array(0))) !== '5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456')
      fails.push('dsha256 KAT');
  } catch (e) { fails.push('dsha256: ' + (e.message || e)); }
  // 3) generators are valid on-curve points
  try { H.assertValidity(); J.assertValidity(); } catch (e) { fails.push('generators: ' + (e.message || e)); }
  // 4) create -> scan round-trip (self-consistent: validates ALL the algebra/masking)
  try {
    const keys = masterKeysFromSeed(sha512(new TextEncoder().encode('mweb-selftest-seed')).slice(0, 64));
    const addr = stealthAddress(keys, 3);
    const value = 123456789n;
    const out = outputCreate(addr.A, addr.B, value, fromB(sha256(new TextEncoder().encode('ks-fixed'))));
    const found = outputScan(keys, out, 10);
    if (!found) fails.push('round-trip: scan found nothing');
    else {
      if (found.value !== value) fails.push('round-trip: value mismatch ' + found.value);
      if (found.index !== 3) fails.push('round-trip: index mismatch ' + found.index);
      // the recovered spend key must reproduce Ko = spendKey*G  (proves we can spend it)
      if (bytesToHex(pub(mul(G, found.spendKey))) !== bytesToHex(out.Ko)) fails.push('round-trip: spendKey does not reproduce Ko');
    }
    // negative: a different wallet must NOT match
    const other = masterKeysFromSeed(sha512(new TextEncoder().encode('other-wallet')).slice(0, 64));
    if (outputScan(other, out, 10)) fails.push('round-trip: foreign wallet false-positive');
  } catch (e) { fails.push('round-trip: ' + (e.message || e)); }
  return { ok: fails.length === 0, fails };
}

export {
  masterKeysFromSeed, masterKeysFromMnemonic, spendKeyAt, stealthAddress,
  outputCreate, outputScan, switchCommit, blindSwitch, pedersen,
  hash32, hash32scalar, hash64, commitBytes, selfTest,
  H, J, G,
};
