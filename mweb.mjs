/* ============================================================================
 * mweb.mjs - Litecoin MWEB (MimbleWimble Extension Blocks), pure-JS, no backend.
 *
 * Receive side: keychain + tmweb stealth address + output create/scan. No
 * bulletproofs are needed to RECEIVE - the amount rides in `masked_value` (an XOR
 * mask from a tagged hash of the ECDH secret), so scanning is just secp256k1 +
 * hashing. Sending is implemented below (build + sign an MWEB->MWEB transaction): it
 * adds the 64-bit range proof via the lazy WASM prover (vendor/mweb-bp.js), the libmw
 * MW/Grin Schnorr signatures (NOT BIP340), and the tx assembly/serialization.
 *
 * Verified bit-for-bit against the raw reference source at
 * github.com/ltc-mweb/litecoin @ 0.21:
 *   src/libmw/include/mw/crypto/Hasher.h          (hash primitive + tags)
 *   src/libmw/include/mw/models/tx/OutputMask.h   (blind + value/nonce masks)
 *   src/libmw/src/models/tx/Output.cpp            (Output::Create)
 *   src/libmw/src/wallet/Keychain.cpp             (RewindOutput, GetSpendKey)
 *   src/key_io.cpp + chainparams.cpp              (tmweb bech32 address encoding)
 * KEY FACTS (from source - the reference IS BLAKE3; the prose docs are right):
 *   - Hashed(tag, parts...) = BLAKE3( tagByte || parts ), single pass, NO length
 *     framing. Integers serialize LITTLE-ENDIAN (htole32/htole64). Tags (EHashTag):
 *     A address, B blind, D derive, N nonce, O out-key, S send, T view-tag,
 *     X nonce-mask, Y value-mask.
 *   - Shared secret t = H('D', s*A) = H('D', scan*Ke); view_tag = H('T', s*A)[0].
 *   - Masks of t: blind = H('B', t); value_mask = H('Y', t)[0:8] (XOR'd against the
 *     little-endian value); nonce_mask = H('X', t)[0:16].
 *   - One-time keys are MULTIPLICATIVE: Ko = H('O',t)*B_i; spend key k_o =
 *     b_i*H('O',t); scanner recovers B_i = Ko * inv(H('O',t)).
 *   - Keychain: scan = HD(m/1/0/100'), spend = HD(m/1/0/101');
 *     b_i = spend + H('A', le32 i, scan);  B_i = b_i*G;  A_i = scan*B_i.
 *   - Value generator H and switch generator J are the secp256k1-zkp constants;
 *     commitment C = blind-switch(blind, value).
 *
 * Correctness is gated two ways: (1) an in-app create->scan round-trip + a BLAKE3
 * known-answer self-test, and (2) the real gate - generate a tmweb address, receive
 * testnet LTC to it, and scan the block; if the amount comes back, every byte agrees
 * with what litecoind produced. We never claim correctness from static analysis alone.
 * ========================================================================== */
import * as secp from './vendor/noble-secp256k1.mjs';
import { sha256 } from './vendor/noble-sha256.mjs';
import { sha512 } from './vendor/noble-sha512.mjs';
import { blake3 } from './vendor/noble-blake3.mjs';
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
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64le = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v) & ((1n<<64n)-1n), true); return b; };
const xorBytes = (a, b, off=0, len=a.length) => { const o = a.slice(); for (let i=0;i<len;i++) o[i] = a[i] ^ b[off+i]; return o; };

// libmw Hasher: BLAKE3 over (tagByte || raw parts). NO length framing; integers are appended
// little-endian. Verified bit-for-bit against ltc-mweb/litecoin@0.21 src/libmw: crypto/Hasher.h,
// models/tx/OutputMask.h, models/tx/Output.cpp, wallet/Keychain.cpp. (Reference is BLAKE3, not SHA256.)
const htag = (tagChar, ...parts) => blake3(concatBytes(Uint8Array.of(tagChar.charCodeAt(0)), ...parts));
const htagScalar = (tagChar, ...parts) => sc(fromB(htag(tagChar, ...parts)));   // hash as a scalar mod n

// 33-byte Pedersen-commitment serialization (secp256k1_pedersen_commitment_serialize):
// prefix 0x08 if Y is a quadratic residue, else 0x09, then X (BE). This is the QR of Y, NOT
// pubkey parity (0x02/0x03) - Pedersen commitments and pubkeys use different sign conventions.
function commitBytes(point) {
  const a = point.toAffine();
  return concatBytes(Uint8Array.of(isQuad(a.y) ? 0x08 : 0x09), numberToBytesBE(a.x, 32));
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
// keychain spend scalar b_i = b + H('A', le32 i, scan)  (libmw GetSpendKey: SecretKeys::From(spend).Add(mi))
function spendKeyAt(keys, i) { return scAdd(keys.spend, htagScalar('A', u32le(i), keys.scanBytes)); }
// stealth address: B_i = b_i*G, A_i = scan*B_i  (libmw GetStealthAddress: Ai = Bi.Mul(scanSecret))
function stealthAddress(keys, i) {
  const bi = spendKeyAt(keys, i);
  const Bi = mul(G, bi);
  const Ai = mul(Bi, keys.scan);
  return { i, bi, A: Ai, B: Bi, Abytes: pub(Ai), Bbytes: pub(Bi) };
}

/* ---------------- Output create (sender side) ---------------- */
// Create an output paying `value` to stealth address (A,B given as 33-byte pubkeys or Points).
// ks (sender ephemeral secret scalar) optional - pass for deterministic tests.
function outputCreate(Apub, Bpub, value, ksScalar) {
  const A = (Apub instanceof P) ? Apub : P.fromHex(Apub);
  const B = (Bpub instanceof P) ? Bpub : P.fromHex(Bpub);
  const ks = ksScalar != null ? sc(ksScalar) : fromB(secp.utils.randomPrivateKey());
  const Ks = mul(G, ks);                                       // sender ephemeral pubkey Ks = ks*G
  const n = htag('N', to32(ks)).slice(0, 16);                 // nonce n = H('N', ks)[0:16]
  const s = htagScalar('S', pub(A), pub(B), u64le(value), n); // send scalar s = H('S', A, B, le64(v), n)
  const sA = mul(A, s);                                       // shared point s*A
  const t = htag('D', pub(sA));                               // shared secret t = H('D', s*A)
  const Ko = mul(B, htagScalar('O', t));                      // one-time pubkey Ko = H('O',t)*B (multiplicative)
  const Ke = mul(B, s);                                       // key-exchange pubkey Ke = s*B
  const viewTag = htag('T', pub(sA))[0];                      // view tag = H('T', s*A)[0]
  const r = fromB(htag('B', t));                              // blind = H('B', t)
  const valueMask = htag('Y', t);                             // value mask = H('Y', t)[0:8]
  const nonceMask = htag('X', t);                             // nonce mask = H('X', t)[0:16]
  const maskedValue = xorBytes(u64le(value), valueMask, 0, 8);// v' = le64(v) XOR H('Y',t)[0:8]
  const maskedNonce = xorBytes(n, nonceMask, 0, 16);          // n' = n XOR H('X',t)[0:16]
  const C = switchCommit(value, r);                           // commitment C = switch(blind, value)
  return {
    commitment: commitBytes(C), Ko: pub(Ko), Ke: pub(Ke), viewTag,
    maskedValue, maskedNonce, senderPubkey: pub(Ks),
    // (rangeproof + sender signature are added in later phases)
    _debug: { value: BigInt(value), r },
  };
}

/* ---------------- Output scan (receiver side) ---------------- */
// Try to identify+recover an output for our wallet `keys`. `gap` = address lookahead.
// Returns { value, index, spendKey, blind } or null.
function outputScan(keys, out, gap=50) {
  const Ke = P.fromHex(out.Ke), Ko = P.fromHex(out.Ko);
  const shared = mul(Ke, keys.scan);                          // shared point = scan*Ke (= s*A)
  if (htag('T', pub(shared))[0] !== out.viewTag) return null; // cheap view-tag reject
  const t = htag('D', pub(shared));                           // t = H('D', shared)
  const hO = htagScalar('O', t);                              // H('O', t)
  // find our address index: the one-time spend key b_i*H('O',t) must reproduce Ko = (b_i*H('O',t))*G
  let index = -1, spendKey = 0n;
  for (let i=0;i<gap;i++) { const sk = scMul(spendKeyAt(keys, i), hO); if (mul(G, sk).equals(Ko)) { index = i; spendKey = sk; break; } }
  if (index < 0) return null;
  const addr = stealthAddress(keys, index);
  const valueMask = htag('Y', t), nonceMask = htag('X', t);
  const valueBytes = xorBytes(out.maskedValue, valueMask, 0, 8);
  const value = new DataView(valueBytes.buffer, valueBytes.byteOffset, 8).getBigUint64(0, true);   // little-endian
  const r = fromB(htag('B', t));                              // blind = H('B', t)
  // verify the commitment opens to (value, blind)
  if (bytesToHex(commitBytes(switchCommit(value, r))) !== bytesToHex(out.commitment)) return null;
  // recover nonce + re-derive s, verify Ke = s*B_i
  const n = xorBytes(out.maskedNonce, nonceMask, 0, 16);
  const s = htagScalar('S', pub(addr.A), pub(addr.B), u64le(value), n);
  if (!mul(addr.B, s).equals(Ke)) return null;
  return { value, index, spendKey, blind: r };                // spendKey = b_i*H('O',t); blind = raw pre-blind
}

/* ---------------- tmweb stealth address encoding (bech32) ---------------- */
// MWEB addresses: bech32 (NOT bech32m), HRP per network, data symbols =
// [0] ++ convertbits(scanPub33 || spendPub33, 8->5, pad). Verified against
// litecoin/src/key_io.cpp + chainparams MWEB_HRP (ltc-mweb 0.21).
const MWEB_HRP = { mainnet: 'ltcmweb', testnet: 'tmweb', regtest: 'tmweb' };
const B32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const B32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function b32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= B32_GEN[i];
  }
  return chk >>> 0;
}
function b32HrpExpand(hrp) {
  const r = [];
  for (let i = 0; i < hrp.length; i++) r.push(hrp.charCodeAt(i) >> 5);
  r.push(0);
  for (let i = 0; i < hrp.length; i++) r.push(hrp.charCodeAt(i) & 31);
  return r;
}
function b32Checksum(hrp, data) {
  const vals = b32HrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0]);
  const mod = b32Polymod(vals) ^ 1;                 // ^1 = bech32 (not bech32m)
  const r = [];
  for (let i = 0; i < 6; i++) r.push((mod >> (5 * (5 - i))) & 31);
  return r;
}
// No 90-char cap: MWEB addresses (66-byte payload) are ~110 chars.
function bech32Encode(hrp, data) {
  const combined = data.concat(b32Checksum(hrp, data));
  let s = hrp + '1';
  for (const d of combined) s += B32_CHARSET.charAt(d);
  return s;
}
function bech32Decode(str) {
  const lower = str.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) return null;
  const hrp = lower.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < lower.length; i++) {
    const d = B32_CHARSET.indexOf(lower[i]);
    if (d === -1) return null;
    data.push(d);
  }
  if (b32Polymod(b32HrpExpand(hrp).concat(data)) !== 1) return null;
  return { hrp, data: data.slice(0, data.length - 6) };
}
function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0; const ret = [];
  const maxv = (1 << to) - 1, maxacc = (1 << (from + to - 1)) - 1;
  for (const value of data) {
    if (value < 0 || (value >> from) !== 0) return null;
    acc = ((acc << from) | value) & maxacc; bits += from;
    while (bits >= to) { bits -= to; ret.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits > 0) ret.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return ret;
}
// Encode a stealth address from scan pubkey A and spend pubkey B (Point | bytes | hex).
function encodeStealthAddress(Apub, Bpub, net = 'testnet') {
  const norm = (k) => (k instanceof P) ? pub(k) : (k instanceof Uint8Array ? k : hexToBytes(k));
  const words = [0].concat(convertBits(Array.from(concatBytes(norm(Apub), norm(Bpub))), 8, 5, true));
  return bech32Encode(MWEB_HRP[net] || MWEB_HRP.testnet, words);
}
function decodeStealthAddress(addr) {
  const dec = bech32Decode(addr);
  if (!dec) return null;
  const bytes = convertBits(dec.data.slice(1), 5, 8, false);   // drop the leading 0 symbol
  if (!bytes || bytes.length !== 66) return null;
  const b = Uint8Array.from(bytes);
  return { hrp: dec.hrp, scan: b.slice(0, 33), spend: b.slice(33, 66) };
}
// tmweb address string for our wallet at address index i.
function addressFor(keys, i, net = 'testnet') {
  const a = stealthAddress(keys, i);
  return encodeStealthAddress(a.Abytes, a.Bbytes, net);
}

/* ---------------- block output parse + scan adapter ---------------- */
// libmw OutputMessage feature bits.
const STD_FEATURE_BIT = 0x01, EXTRA_DATA_FEATURE_BIT = 0x02;
// Deserialize the OutputMessage hex blob (Core REST: mweb.outputs[].message).
// Layout: features(1) [ if STD: key_exchange_pubkey(33) view_tag(1) masked_value(8) masked_nonce(16) ].
function parseOutputMessage(hex) {
  const b = hexToBytes(hex);
  let p = 0; const features = b[p++];
  const msg = { features };
  if (features & STD_FEATURE_BIT) {
    msg.key_exchange_pubkey = b.slice(p, p + 33); p += 33;
    msg.view_tag = b[p++];
    msg.masked_value = b.slice(p, p + 8); p += 8;
    msg.masked_nonce = b.slice(p, p + 16); p += 16;
  }
  return msg;
}
// Map a Core REST mweb output object to the outputScan() input shape.
function adaptOutput(o) {
  const m = parseOutputMessage(o.message);
  return {
    output_id: o.output_id,
    commitment: hexToBytes(o.commit),
    Ko: o.receiver_pubkey,
    Ke: bytesToHex(m.key_exchange_pubkey),
    viewTag: m.view_tag,
    maskedValue: m.masked_value,
    maskedNonce: m.masked_nonce,
  };
}
// Scan a block's MWEB outputs; return owned outputs as UTXO records (value as string litoshi).
function scanBlockOutputs(keys, outputs, gap = 50) {
  const found = [];
  if (!outputs) return found;
  for (const o of outputs) {
    let a, r;
    try { a = adaptOutput(o); } catch (e) { continue; }
    try { r = outputScan(keys, a, gap); } catch (e) { continue; }
    if (r) found.push({
      output_id: a.output_id,
      commitment: bytesToHex(a.commitment),
      value: r.value.toString(),
      index: r.index,
      spendKey: bytesToHex(to32(r.spendKey)),
      blind: bytesToHex(to32(r.blind)),
    });
  }
  return found;
}

/* ============================================================================
 * SEND SIDE - build + sign an MWEB->MWEB transaction.
 * Built against ltc-mweb/litecoin@0.21 libmw: wallet/TxBuilder, models/tx/{Input,Output,
 * Kernel,Transaction}, crypto/Schnorr (secp256k1-zkp bip-schnorr/aggsig) + the bulletproof
 * range proof (vendor/mweb-bp.js, Emscripten of secp256k1-zkp). The simplest send (MWEB->MWEB,
 * no peg/HogEx) is: signed inputs + recipient/change outputs (each with a 675-byte proof and a
 * Schnorr sig) + one fee kernel, balanced by a kernel offset and a stealth offset.
 * GATE: a constructed tx only counts as correct once litecoind accepts it (testmempoolaccept /
 * sendrawtransaction on testnet). We never claim a send works from static analysis alone.
 * ========================================================================== */
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;   // secp256k1 field prime
function modpow(b, e, m) { b = ((b % m) + m) % m; let r = 1n; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const isQuad = (y) => y !== 0n && modpow(mod(y, FIELD_P), (FIELD_P - 1n) / 2n, FIELD_P) === 1n;   // Legendre symbol == 1 (quadratic residue)
const hashNoTag = (...parts) => blake3(concatBytes(...parts));   // libmw Hasher() with no tag byte

// Bitcoin Core base-128 WriteVarInt (NOT CompactSize) - kernel fee/pegin/lock.
function writeVarInt(value) {
  let n = BigInt(value); const tmp = []; let len = 0;
  for (;;) { tmp[len] = Number(n & 0x7fn) | (len ? 0x80 : 0x00); if (n <= 0x7fn) break; n = (n >> 7n) - 1n; len++; }
  const out = new Uint8Array(len + 1); for (let i = 0; i <= len; i++) out[i] = tmp[len - i]; return out;
}
// Bitcoin CompactSize (std::vector length prefix).
function compactSize(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
}
const u32leB = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
// 33-byte Pedersen commitment (0x08/0x09, QR convention) -> 33-byte secp pubkey (0x02/0x03, Y parity), same point.
function commitmentToPubkey(commit33) {
  const x = bytesToNumberBE(commit33.slice(1));
  let y = modpow((x * x * x + 7n) % FIELD_P, (FIELD_P + 1n) / 4n, FIELD_P);   // a square root of x^3 + 7 (p == 3 mod 4)
  if (!isQuad(y)) y = FIELD_P - y;                  // set_xquad: the quadratic-residue root
  if (commit33[0] & 1) y = FIELD_P - y;             // prefix 0x09 -> non-QR root (negate)
  return concatBytes(Uint8Array.of(0x02 | Number(y & 1n)), numberToBytesBE(x, 32));
}
function byteCmp(a, b) { for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) return a[i] - b[i]; } return 0; }

/* ---- MW/Grin pre-BIP340 Schnorr (secp256k1-zkp bip-schnorr/aggsig) ----
 * k = SHA256(sk||msg); R = k*G; if R.y is NOT a quadratic residue, k = -k; sig = R.x(32) || s(32)
 * with e = SHA256(R.x || compressed33(P) || msg), s = k + e*sk. P = sk*G is embedded COMPRESSED
 * (not x-only), challenge is plain SHA256 (not tagged), R chosen by QR-of-y (not even-y). */
function schnorrSign(secScalar, msg32) {
  const x = sc(secScalar), Ppt = mul(G, x);
  let k = sc(fromB(sha256(concatBytes(to32(x), msg32)))); if (k === 0n) k = 1n;
  let R = mul(G, k);
  if (!isQuad(R.toAffine().y)) { k = sc(N - k); R = mul(G, k); }
  const Rx = numberToBytesBE(R.toAffine().x, 32);
  const e = sc(fromB(sha256(concatBytes(Rx, pub(Ppt), msg32))));
  return concatBytes(Rx, to32(scAdd(k, scMul(e, x))));
}
function schnorrVerify(sig, msg32, pubBytes) {
  try {
    const Rxb = sig.slice(0, 32), s = fromB(sig.slice(32, 64)), Ppt = P.fromHex(pubBytes);
    const e = sc(fromB(sha256(concatBytes(Rxb, pub(Ppt), msg32))));
    const R = mul(G, s).add(mul(Ppt, sc(N - e))); if (R.equals(ZERO)) return false;
    const aff = R.toAffine();
    return byteCmp(numberToBytesBE(aff.x, 32), Rxb) === 0 && isQuad(aff.y);
  } catch (e) { return false; }
}

/* ---- 64-bit range proof via the lazy-loaded WASM prover (vendor/mweb-bp.js) ---- */
let _bpMod = null;
async function loadBP() {
  if (!_bpMod) { const m = await import('./vendor/mweb-bp.js'); _bpMod = await (m.default || m)(); }
  return _bpMod;
}
async function rangeProof(value, switchBlind32, extraBytes) {
  const m = await loadBP();
  const put = (bytes) => { const p = m._malloc(bytes.length); m.HEAPU8.set(bytes, p); return p; };
  const rnd = () => secp.utils.randomPrivateKey();
  const blindPtr = put(switchBlind32), noncePtr = put(rnd()), privPtr = put(rnd());
  const msgPtr = put(new Uint8Array(20)), extraPtr = put(extraBytes), outPtr = m._malloc(675);
  const plen = m.ccall('bp_prove', 'number',
    ['number', 'number', 'number', 'number', 'number', 'number', 'number', 'number'],
    [Number(value), blindPtr, noncePtr, privPtr, msgPtr, extraPtr, extraBytes.length, outPtr]);
  const proof = (plen === 675) ? m.HEAPU8.slice(outPtr, outPtr + 675) : null;
  for (const p of [blindPtr, noncePtr, privPtr, msgPtr, extraPtr, outPtr]) m._free(p);
  if (!proof) throw new Error('range proof failed (bp_prove returned ' + plen + ')');
  return proof;
}

/* ---- send-side output (commitment, Ks, Ko, message, proof, signature) ---- */
function serializeOutputMessage(o) {   // features(1)||Ke(33)||view_tag(1)||masked_value(8)||masked_nonce(16) = 59B
  const ke = (o.Ke instanceof Uint8Array) ? o.Ke : hexToBytes(o.Ke);   // outputCreate gives Ke as bytes; tolerate a hex string too
  return concatBytes(Uint8Array.of(STD_FEATURE_BIT), ke, Uint8Array.of(o.viewTag), o.maskedValue, o.maskedNonce);
}
async function buildSendOutput(scanPub, spendPub, value, ksScalar) {
  const ks = ksScalar != null ? sc(ksScalar) : fromB(secp.utils.randomPrivateKey());
  const o = outputCreate(scanPub, spendPub, value, ks);            // reuse the verified receive algebra
  const message = serializeOutputMessage(o);                       // 59-byte OutputMessage = proof extra_commit
  const switchBlind = blindSwitch(o._debug.r, value);
  const proof = await rangeProof(value, to32(switchBlind), message);
  const msgHash = blake3(message), proofHash = blake3(proof);      // OutputMessage.GetHash(), RangeProof.GetHash()
  const sigMsg = hashNoTag(o.commitment, o.senderPubkey, o.Ko, msgHash, proofHash);
  const signature = schnorrSign(ks, sigMsg);
  const outputId = hashNoTag(o.commitment, o.senderPubkey, o.Ko, msgHash, proofHash, signature);   // ComputeHash
  const serialized = concatBytes(o.commitment, o.senderPubkey, o.Ko, message, proof, signature);
  return { outputId, serialized, ks, switchBlind };
}

/* ---- input spending an owned coin ---- */
// coin = { output_id(hex), value, blind(hex raw pre-blind), spendKey(hex k_o) } - the scanBlockOutputs shape.
function buildInput(coin) {
  const value = BigInt(coin.value);
  const switchBlind = blindSwitch(fromB(hexToBytes(coin.blind)), value);
  const k_o = fromB(hexToBytes(coin.spendKey));                    // output one-time spend key (b_i*H('O',t)) = output_key
  const k_i = fromB(secp.utils.randomPrivateKey());               // ephemeral input key = input_key
  const Ki = pub(mul(G, k_i)), Ko = pub(mul(G, k_o));             // input_pubkey, output_pubkey
  const keyHash = sc(fromB(hashNoTag(Ki, Ko)));                    // key_hash = BLAKE3(K_i||K_o) as a scalar
  const sigKey = scAdd(k_i, scMul(keyHash, k_o));                  // sig_key = k_i + key_hash*k_o (Input::Create)
  const outputId = hexToBytes(coin.output_id);
  const features = 0x01;                                           // STEALTH_KEY_FEATURE_BIT (standard input)
  const sigMsg = hashNoTag(Uint8Array.of(features), outputId);     // msg = BLAKE3(features || output_id)
  const signature = schnorrSign(sigKey, sigMsg);
  const commitment = commitBytes(pedersen(value, switchBlind));    // Commitment::Blinded(switchBlind, value)
  // libmw Input wire order: features || output_id || commitment || output_pubkey(Ko) || input_pubkey(Ki) || signature
  const serialized = concatBytes(Uint8Array.of(features), outputId, commitment, Ko, Ki, signature);
  return { outputId, serialized, switchBlind, totalKey: scAdd(k_i, sc(N - k_o)) };   // stealth-offset contribution k_i - k_o (TxBuilder keys.Add(k_i).Sub(k_o); StealthSumValidator)
}

/* ---- PegOutCoin: a transparent destination (MWEB -> regular LTC address) ---- */
function serializePegOut(p) {   // WriteVarInt(amount) || CScript (compactSize-prefixed scriptPubKey bytes)
  return concatBytes(writeVarInt(p.value), compactSize(p.script.length), p.script);
}
/* ---- kernel (MWEB->MWEB or peg-out; features = FEE | [PEGOUT] | STEALTH_EXCESS) ---- */
function buildKernel(kernelBlind, stealthBlind, fee, pegouts) {
  pegouts = pegouts || [];
  const features = 0x01 | (pegouts.length ? 0x04 : 0x00) | 0x10;   // FEE | [PEGOUT] | STEALTH_EXCESS
  const excessPt = pedersen(0n, kernelBlind);                    // Commitment::Blinded(kernelBlind, 0) = kernelBlind*G
  const excess = commitBytes(excessPt);
  const stealthExcess = pub(mul(G, stealthBlind));
  // h = BLAKE3(PublicKey::From(excess) || stealth_excess); PublicKey::From = parity-compressed excess point = pub(excessPt)
  const h = sc(fromB(hashNoTag(pub(excessPt), stealthExcess)));
  const sigKey = scAdd(scMul(kernelBlind, h), stealthBlind);
  const feeV = writeVarInt(fee);
  const pegBytes = pegouts.length ? concatBytes(compactSize(pegouts.length), ...pegouts.map(serializePegOut)) : new Uint8Array(0);
  // GetSignatureMessage order: features || excess || fee || [pegouts] || stealth_excess
  const sigMsg = hashNoTag(Uint8Array.of(features), excess, feeV, pegBytes, stealthExcess);
  const signature = schnorrSign(sigKey, sigMsg);
  // wire order: features || fee || [pegouts] || stealth_excess || excess || signature
  const serialized = concatBytes(Uint8Array.of(features), feeV, pegBytes, stealthExcess, excess, signature);
  return { serialized };
}

/* ---- assemble + serialize the full transaction; returns the extended raw-tx hex ---- */
// opts: { coins:[selected UTXOs], recipients:[{address: tmweb string | {scan,spend}, value}], fee }
// Caller is responsible for coin selection (sum(coins) == sum(recipients) + fee), incl. a change recipient.
async function buildTransaction({ coins, recipients, fee }) {
  if (!coins || !coins.length) throw new Error('no inputs selected');
  if (!recipients || !recipients.length) throw new Error('no recipients');
  // value invariant (KernelSumValidator H-axis): Sum(in) must equal Sum(recipients incl. change + pegouts) + fee,
  // or the node rejects an otherwise-valid tx as "bad-mweb-txn". Surface a clear error instead of that.
  const vIn = coins.reduce((a, c) => a + BigInt(c.value), 0n), vOut = recipients.reduce((a, r) => a + BigInt(r.value), 0n);
  if (vIn !== vOut + BigInt(fee)) throw new Error('MWEB value imbalance: inputs ' + vIn + ' != recipients ' + vOut + ' + fee ' + BigInt(fee) + ' (coin selection/change is off; node would reject as bad-mweb-txn)');
  const inputs = coins.map(buildInput);
  const outs = [], pegouts = [];
  for (const r of recipients) {
    if (r.script) {   // transparent destination -> a peg-out in the kernel (not an MWEB output)
      pegouts.push({ value: BigInt(r.value), script: (r.script instanceof Uint8Array) ? r.script : hexToBytes(r.script) });
      continue;
    }
    const dest = (typeof r.address === 'string') ? decodeStealthAddress(r.address) : r.address;
    if (!dest || !dest.scan || !dest.spend) throw new Error('invalid MWEB recipient address');
    outs.push(await buildSendOutput(dest.scan, dest.spend, BigInt(r.value)));
  }
  // value balance (kernel): kernel_blind = Sum(out switch-blinds) - Sum(in switch-blinds) - kernel_offset
  const kernelOffset = fromB(secp.utils.randomPrivateKey());
  let sob = 0n; for (const o of outs) sob = scAdd(sob, o.switchBlind);
  let sib = 0n; for (const i of inputs) sib = scAdd(sib, i.switchBlind);
  const kernelBlind = scAdd(sob, scAdd(sc(N - sib), sc(N - kernelOffset)));
  // stealth (owner) balance: stealth_offset = Sum(out ks) + Sum(in k_i - k_o) - stealth_blind  (StealthSumValidator)
  const stealthBlind = fromB(secp.utils.randomPrivateKey());
  let sok = 0n; for (const o of outs) sok = scAdd(sok, o.ks);
  let sik = 0n; for (const i of inputs) sik = scAdd(sik, i.totalKey);
  const stealthOffset = scAdd(sok, scAdd(sik, sc(N - stealthBlind)));
  pegouts.sort((a, b) => a.value !== b.value ? (a.value < b.value ? -1 : 1) : byteCmp(a.script, b.script));   // PegOutCoin canonical order (amount, then script)
  const kernel = buildKernel(kernelBlind, stealthBlind, fee, pegouts);
  // canonical ordering: inputs by output_id, outputs by output hash (single kernel needs no sort)
  inputs.sort((a, b) => byteCmp(a.outputId, b.outputId));
  outs.sort((a, b) => byteCmp(a.outputId, b.outputId));
  const body = concatBytes(
    compactSize(inputs.length), ...inputs.map(i => i.serialized),
    compactSize(outs.length), ...outs.map(o => o.serialized),
    compactSize(1), kernel.serialized);
  const mwTx = concatBytes(to32(kernelOffset), to32(stealthOffset), body);   // kernel_offset||stealth_offset||TxBody
  // canonical extended LTC tx: nVersion(4) || 00 (dummy vin) || 08 (flags) || 00 vin || 00 vout || 01 (mweb set) || mwTx || nLockTime(4)
  const raw = concatBytes(u32leB(2), Uint8Array.of(0x00, 0x08, 0x00, 0x00, 0x01), mwTx, u32leB(0));
  return bytesToHex(raw);
}

/* ---------------- Self-test (run in-browser; gates the feature) ---------------- */
function selfTest() {
  const checks = [];
  const chk = (name, fn) => { try { const d = fn(); checks.push({ name, ok: true, detail: d || '' }); } catch (e) { checks.push({ name, ok: false, detail: e.message || String(e) }); } };
  chk('SHA-512 KAT', () => { const h = bytesToHex(sha512(new Uint8Array(0))); if (h !== 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e') throw new Error('mismatch'); return h.slice(0, 16) + '…'; });
  chk('BLAKE3 KAT (empty) - libmw hash primitive', () => { const h = bytesToHex(blake3(new Uint8Array(0))); if (h !== 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262') throw new Error('mismatch'); return h.slice(0, 16) + '…'; });
  chk('value generators H, J on-curve', () => { H.assertValidity(); J.assertValidity(); return 'valid'; });
  chk('output create -> scan round-trip', () => {
    const keys = masterKeysFromSeed(sha512(new TextEncoder().encode('mweb-selftest-seed')).slice(0, 64));
    const addr = stealthAddress(keys, 3);
    const value = 123456789n;
    const out = outputCreate(addr.A, addr.B, value, fromB(sha256(new TextEncoder().encode('ks-fixed'))));
    const found = outputScan(keys, out, 10);
    if (!found) throw new Error('scan found nothing');
    if (found.value !== value) throw new Error('value mismatch ' + found.value);
    if (found.index !== 3) throw new Error('index mismatch ' + found.index);
    if (bytesToHex(pub(mul(G, found.spendKey))) !== bytesToHex(out.Ko)) throw new Error('spendKey does not reproduce Ko');   // proves we can spend it
    const other = masterKeysFromSeed(sha512(new TextEncoder().encode('other-wallet')).slice(0, 64));
    if (outputScan(other, out, 10)) throw new Error('foreign wallet false-positive');
    return 'recovered ' + (Number(value) / 1e8) + ' LTC at index 3';
  });
  chk('tmweb address encode -> decode round-trip', () => {
    const keys = masterKeysFromSeed(sha512(new TextEncoder().encode('mweb-addr-test')).slice(0, 64));
    const a = stealthAddress(keys, 7);
    const addr = encodeStealthAddress(a.Abytes, a.Bbytes, 'testnet');
    if (!addr.startsWith('tmweb1')) throw new Error('wrong hrp ' + addr.slice(0, 8));
    const dec = decodeStealthAddress(addr);
    if (!dec) throw new Error('decode failed');
    if (bytesToHex(dec.scan) !== bytesToHex(a.Abytes) || bytesToHex(dec.spend) !== bytesToHex(a.Bbytes)) throw new Error('decode mismatch');
    return addr.slice(0, 14) + '…' + addr.slice(-6);
  });
  chk('MW-Schnorr sign -> verify (wrong msg rejected)', () => {
    const sk = fromB(sha256(new TextEncoder().encode('mweb-schnorr-test')));
    const msg = sha256(new TextEncoder().encode('msg'));
    const sig = schnorrSign(sk, msg);
    if (sig.length !== 64) throw new Error('wrong sig length');
    if (!schnorrVerify(sig, msg, pub(mul(G, sk)))) throw new Error('verify failed');
    if (schnorrVerify(sig, sha256(new TextEncoder().encode('other')), pub(mul(G, sk)))) throw new Error('false-accept');
    return 'sig ' + bytesToHex(sig).slice(0, 16) + '…';
  });
  chk('MWEB input: 196B wire format + Schnorr (libmw Input)', () => {
    const seed = (s) => bytesToHex(to32(sc(fromB(sha256(new TextEncoder().encode(s))))));
    const coin = { output_id: bytesToHex(sha256(new TextEncoder().encode('mweb-in-outid'))), value: 5000000, blind: seed('mweb-in-blind'), spendKey: seed('mweb-in-spend') };
    const inp = buildInput(coin);
    if (inp.serialized.length !== 196) throw new Error('len ' + inp.serialized.length + ' want 196 (features byte present?)');
    if (inp.serialized[0] !== 0x01) throw new Error('features=' + inp.serialized[0] + ' want 0x01');
    // fields: features(1) | output_id(32) | commitment(33) | output_pubkey Ko(33) | input_pubkey Ki(33) | sig(64)
    const outId = inp.serialized.slice(1, 33), Ko = inp.serialized.slice(66, 99), Ki = inp.serialized.slice(99, 132), sig = inp.serialized.slice(132, 196);
    if (bytesToHex(outId) !== coin.output_id) throw new Error('output_id misplaced');
    // verify sig vs aggregated owner key K_i + BLAKE3(Ki||Ko)*Ko over BLAKE3(features||output_id) (Input::BuildSignedMsg)
    const keyHash = sc(fromB(hashNoTag(Ki, Ko)));
    const aggKey = pub(P.fromHex(Ki).add(mul(P.fromHex(Ko), keyHash)));
    if (!schnorrVerify(sig, hashNoTag(Uint8Array.of(0x01), outId), aggKey)) throw new Error('input signature does not verify');
    return 'input 196B, Ko before Ki, sig ok';
  });
  const fails = checks.filter(c => !c.ok).map(c => c.name + (c.detail ? (': ' + c.detail) : ''));
  return { ok: fails.length === 0, fails, checks };
}

export {
  masterKeysFromSeed, masterKeysFromMnemonic, spendKeyAt, stealthAddress,
  outputCreate, outputScan, switchCommit, blindSwitch, pedersen,
  htag, htagScalar, commitBytes, selfTest,
  encodeStealthAddress, decodeStealthAddress, addressFor,
  parseOutputMessage, adaptOutput, scanBlockOutputs,
  bech32Encode, bech32Decode, convertBits, MWEB_HRP,
  schnorrSign, schnorrVerify, buildSendOutput, buildInput, buildKernel,
  buildTransaction, rangeProof, loadBP, serializeOutputMessage,
  writeVarInt, compactSize, hashNoTag, isQuad, commitmentToPubkey,
  H, J, G,
};
