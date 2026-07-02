// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * BIP-322 "simple" message signing + verification for SegWit v0 (P2WPKH, nested P2SH-P2WPKH) and
 * Taproot key-path (P2TR) addresses - so a message can be signed FROM a bech32/taproot address, not
 * just a legacy one (legacy stays on the BIP137 path in app.js).
 *
 * Signing delegates entirely to @scure/btc-signer's Transaction (so the per-type sighash + witness are
 * the library's, well-tested). Verification is hand-rolled because the bundle exports no message
 * verifier and noble-secp256k1 has no schnorr: it rebuilds the BIP-322 to_spend/to_sign virtual txs and
 * checks the witness directly - BIP143 sighash + ECDSA (secp.verify) for v0, BIP341 sighash + a
 * hand-rolled BIP-340 schnorr verify for taproot key-path.
 *
 * selfTest() gates the UI (state.bip322Ok): if any of this is wrong at runtime, the feature disables
 * itself rather than producing wrong results. Tagged-hash form verified against the vendored bundle:
 *   messageHash = sha256( T || T || utf8(message) ),  T = sha256("BIP0322-signed")
 *   KATs:  ''            -> 888bab9b0d983d5058a18821fa257f99d05105d3fa0a01f162666e905c4cebc1
 *          'Hello World' -> a8b6c7515051928c83e7e0ff14083c2ec67bc4ff9b8ba8db4d0155696d02aa50
 */
import * as btc from './vendor/btc-signer.mjs';
import * as secp from './vendor/noble-secp256k1.mjs';
import { sha256 } from './vendor/noble-sha256.mjs';

const CURVE = secp.CURVE;             // { p, n, ... }
const Point = secp.ProjectivePoint;

/* ---- byte helpers (self-contained) ---- */
const te = new TextEncoder();
const utf8 = s => te.encode(s);
function concat(...arr){ let n=0; for(const a of arr) n+=a.length; const o=new Uint8Array(n); let p=0; for(const a of arr){ o.set(a,p); p+=a.length; } return o; }
function bytesToHex(b){ let s=''; for(const x of b) s+=x.toString(16).padStart(2,'0'); return s; }
function hexToBytes(h){ h=String(h).replace(/^0x/,''); const a=new Uint8Array(h.length/2); for(let i=0;i<a.length;i++) a[i]=parseInt(h.slice(i*2,i*2+2),16); return a; }
const dsha256 = b => sha256(sha256(b));
function beNum(b){ let n=0n; for(const x of b) n=(n<<8n)|BigInt(x); return n; }
function le32(n){ return Uint8Array.of(n&0xff,(n>>>8)&0xff,(n>>>16)&0xff,(n>>>24)&0xff); }
function le64(n){ const o=new Uint8Array(8); let v=BigInt(n); for(let i=0;i<8;i++){ o[i]=Number(v&0xffn); v>>=8n; } return o; }
function varint(n){ if(n<0xfd) return Uint8Array.of(n); if(n<=0xffff) return Uint8Array.of(0xfd,n&0xff,(n>>8)&0xff); if(n>0xffffffff) throw new Error('varint out of range'); return Uint8Array.of(0xfe,n&0xff,(n>>8)&0xff,(n>>16)&0xff,(n>>>24)&0xff); }
function b64encode(b){ let s=''; for(const x of b) s+=String.fromCharCode(x); return btoa(s); }
function b64decode(str){ const s=atob(String(str).trim()); const a=new Uint8Array(s.length); for(let i=0;i<s.length;i++) a[i]=s.charCodeAt(i); return a; }
function eqBytes(a,b){ if(!a || !b || a.length!==b.length) return false; let d=0; for(let i=0;i<a.length;i++) d|=a[i]^b[i]; return d===0; }

/* ---- BIP-322 message hash (single sha256 of T||T||message; message raw, no framing) ---- */
const TAG = sha256(utf8('BIP0322-signed'));
export function messageHash(message){ return sha256(concat(TAG, TAG, utf8(message))); }

/* address scriptPubKey + per-type input extras for a compressed pubkey */
function spkFor(addrType, pub, net){
  if(addrType==='wpkh') return { spk: btc.p2wpkh(pub, net).script };
  if(addrType==='sh-wpkh'){ const w = btc.p2sh(btc.p2wpkh(pub, net), net); return { spk: w.script, redeem: w.redeemScript }; }
  if(addrType==='tr'){ const xo = pub.slice(1); return { spk: btc.p2tr(xo, undefined, net).script, xo }; }
  throw new Error('BIP-322 supports SegWit and Taproot addresses only');
}
export function addressFor(addrType, pub, net){
  if(addrType==='wpkh') return btc.p2wpkh(pub, net).address;
  if(addrType==='sh-wpkh') return btc.p2sh(btc.p2wpkh(pub, net), net).address;
  if(addrType==='tr') return btc.p2tr(pub.slice(1), undefined, net).address;
  throw new Error('unsupported address type');
}

/* the to_spend virtual tx's txid, in INTERNAL (little-endian) byte order. Serialized by hand - feeding @scure a
 * coinbase-style null input (no prevout) trips its signer, so BIP-322 builds the two virtual txs itself. */
function toSpendTxidInternal(spk, mh){
  const scriptSig = concat(Uint8Array.of(0x00, 0x20), mh);          // OP_0 PUSH32 <messageHash>
  const ser = concat(
    le32(0), Uint8Array.of(0x01),                                  // version 0, 1 input
    new Uint8Array(32), le32(0xffffffff),                          // prevout: 32 zero bytes, vout 0xFFFFFFFF
    varint(scriptSig.length), scriptSig, le32(0),                  // scriptSig, sequence 0
    Uint8Array.of(0x01), le64(0), varint(spk.length), spk,         // 1 output: value 0, scriptPubKey = address spk
    le32(0));                                                      // lockTime 0
  return dsha256(ser);                                             // internal order; display order is the reverse
}

/* ---- generic primitives for the hand-rolled signers ---- */
const N = CURVE.n;
function tagged(tag, data){ const h = sha256(utf8(tag)); return sha256(concat(h, h, data)); }   // BIP-340 tagged hash
function num32(n){ const o = new Uint8Array(32); for(let i=31;i>=0;i--){ o[i] = Number(n & 0xffn); n >>= 8n; } return o; }
function hmacSha256(key, msg){                                      // RFC 2104 HMAC-SHA256 over the vendored sha256
  const B = 64; let k = key.length > B ? sha256(key) : key;
  if(k.length < B){ const t = new Uint8Array(B); t.set(k); k = t; }
  const ip = new Uint8Array(B), op = new Uint8Array(B);
  for(let i=0;i<B;i++){ ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
  return sha256(concat(op, sha256(concat(ip, msg))));
}
try { if(secp.etc && typeof secp.etc.hmacSha256Sync !== 'function')   // lets secp.sign() (RFC6979) run synchronously
  secp.etc.hmacSha256Sync = (key, ...msgs) => hmacSha256(key, concat(...msgs)); } catch(_){}

/* compact (r||s, 32+32) -> DER */
function derFromCompact(rs){
  const enc = v => { let i=0; while(i<v.length-1 && v[i]===0) i++; let b=v.slice(i);
    if(b[0] & 0x80){ const t=new Uint8Array(b.length+1); t.set(b,1); b=t; } return b; };
  const r = enc(rs.slice(0,32)), s = enc(rs.slice(32,64));
  const body = concat(Uint8Array.of(0x02, r.length), r, Uint8Array.of(0x02, s.length), s);
  return concat(Uint8Array.of(0x30, body.length), body);
}
/* BIP-340 schnorr signature (deterministic aux=0) of msg32 with scalar d0. */
function bip340Sign(d0, msg){
  let d = (Point.BASE.multiply(d0).toAffine().y & 1n) ? (N - d0) : d0;   // force even-Y pubkey
  const Px = num32(Point.BASE.multiply(d).toAffine().x);
  const dB = num32(d), aux = tagged('BIP0340/aux', new Uint8Array(32));
  const masked = new Uint8Array(32); for(let i=0;i<32;i++) masked[i] = dB[i] ^ aux[i];
  let k = beNum(tagged('BIP0340/nonce', concat(masked, Px, msg))) % N;
  if(k === 0n) throw new Error('schnorr: nonce is zero');
  const Raff = Point.BASE.multiply(k).toAffine();
  if(Raff.y & 1n) k = N - k;                                         // force even-Y R
  const Rx = num32(Raff.x);
  const e = beNum(tagged('BIP0340/challenge', concat(Rx, Px, msg))) % N;
  return concat(Rx, num32((k + e * d) % N));
}
/* Taproot key-path signature: apply the BIP-86 tweak (empty merkle root) then BIP-340 sign. */
function taprootKeyPathSign(privKey, digest){
  let d0 = beNum(privKey) % N; if(d0 === 0n) throw new Error('bad key');
  const d = (Point.BASE.multiply(d0).toAffine().y & 1n) ? (N - d0) : d0;   // even-Y internal key
  const Px = num32(Point.BASE.multiply(d).toAffine().x);
  const t = beNum(tagged('TapTweak', Px)) % N;
  return bip340Sign((d + t) % N, digest);
}

/* ---- SIGN: build the BIP-322 witness for a SegWit/Taproot address, base64'd ---- */
export function sign(net, addrType, privKey, message){
  const pub = secp.getPublicKey(privKey, true);          // 33-byte compressed
  const { spk } = spkFor(addrType, pub, net);
  const ts = toSpendTxidInternal(spk, messageHash(message));   // internal-order to_spend txid
  if(addrType === 'tr'){
    const sig = taprootKeyPathSign(privKey, taprootSighash(ts, spk));   // 64-byte schnorr, SIGHASH_DEFAULT
    return b64encode(btc.RawWitness.encode([ sig ]));
  }
  // wpkh / sh-wpkh: ECDSA over the BIP143 sighash; BIP-322 simple is the witness only ([DERsig||0x01, pubkey])
  const h160 = btc.p2wpkh(pub, net).script.slice(2, 22);
  const dsig = secp.sign(bip143Sighash(ts, h160), privKey);            // low-S, RFC6979 (sync HMAC wired above)
  const der = derFromCompact(dsig.toCompactRawBytes());
  return b64encode(btc.RawWitness.encode([ concat(der, Uint8Array.of(0x01)), pub ]));
}

/* ---- DER (r,s) -> 64-byte compact ---- */
function derToCompact(der){
  try {
    if(der[0]!==0x30) return null;
    let i = 2;
    if(der[i]!==0x02) return null; const rlen = der[i+1]; i += 2; const r = der.slice(i, i+rlen); i += rlen;
    if(der[i]!==0x02) return null; const slen = der[i+1]; i += 2; const s = der.slice(i, i+slen);
    const norm = x => { let j=0; while(j<x.length-1 && x[j]===0) j++; x = x.slice(j); if(x.length>32) return null; const o=new Uint8Array(32); o.set(x, 32-x.length); return o; };
    const R = norm(r), S = norm(s); if(!R || !S) return null;
    return concat(R, S);
  } catch(_){ return null; }
}

/* ---- BIP143 sighash of to_sign input 0 (P2WPKH implied script, SIGHASH_ALL) ---- */
function bip143Sighash(prevTxidLE, h160){
  const scriptCode  = concat(Uint8Array.of(0x19,0x76,0xa9,0x14), h160, Uint8Array.of(0x88,0xac));
  const outpoint    = concat(prevTxidLE, le32(0));
  const hashPrevouts= dsha256(outpoint);
  const hashSequence= dsha256(le32(0));
  const hashOutputs = dsha256(concat(le64(0), varint(1), Uint8Array.of(0x6a)));   // 1 output: value 0, OP_RETURN
  const preimage    = concat(le32(0), hashPrevouts, hashSequence, outpoint, scriptCode, le64(0), le32(0), hashOutputs, le32(0), le32(1));
  return dsha256(preimage);
}

/* ---- BIP341 key-path sighash (hash_type DEFAULT, single input) ---- */
function taprootSighash(prevTxidLE, spk){
  const outpoint = concat(prevTxidLE, le32(0));
  const sigMsg = concat(
    Uint8Array.of(0x00),                                   // epoch
    Uint8Array.of(0x00),                                   // hash_type = SIGHASH_DEFAULT
    le32(0), le32(0),                                      // nVersion, nLockTime
    sha256(outpoint),                                      // sha_prevouts
    sha256(le64(0)),                                       // sha_amounts (one input, amount 0)
    sha256(concat(varint(spk.length), spk)),               // sha_scriptpubkeys
    sha256(le32(0)),                                       // sha_sequences
    sha256(concat(le64(0), varint(1), Uint8Array.of(0x6a))),// sha_outputs
    Uint8Array.of(0x00),                                   // spend_type (key path, no annex)
    le32(0));                                              // input_index
  const T = sha256(utf8('TapSighash'));
  return sha256(concat(T, T, sigMsg));
}

/* ---- BIP-340 schnorr verify (hand-rolled; noble-secp256k1 ships no schnorr) ---- */
function schnorrVerify(sig, msg, pubX){
  try {
    const p = CURVE.p, n = CURVE.n;
    const r = beNum(sig.slice(0,32)), s = beNum(sig.slice(32,64));
    if(r >= p || s >= n || s === 0n) return false;
    let P; try { P = Point.fromHex(concat(Uint8Array.of(0x02), pubX)); } catch(_){ return false; }   // lift_x, even Y
    const Tc = sha256(utf8('BIP0340/challenge'));
    const e = beNum(sha256(concat(Tc, Tc, sig.slice(0,32), pubX, msg))) % n;
    if(e === 0n) return false;
    const R = Point.BASE.multiply(s).add(P.multiply(e).negate());   // s*G - e*P
    if(R.equals(Point.ZERO)) return false;                           // BIP-340: fail if is_infinite(R)
    const aff = R.toAffine();
    if((aff.y & 1n) !== 0n) return false;                            // R must have even Y
    return aff.x === r;
  } catch(_){ return false; }
}

/* ---- VERIFY ---- */
export function verify(net, address, message, sigB64){
  try {
    const a = btc.Address(net).decode(address);            // throws on wrong-network HRP/version
    const spk = btc.OutScript.encode(a);
    const dec = btc.OutScript.decode(spk);                 // { type, hash | pubkey }
    const mh = messageHash(message);
    let stack;
    try { stack = btc.RawWitness.decode(b64decode(sigB64)); } catch(_){ return false; }
    if(!Array.isArray(stack)) return false;

    const prevTxidLE = toSpendTxidInternal(spk, mh);   // already internal byte order

    if(dec.type==='wpkh' || dec.type==='sh'){
      if(stack.length !== 2) return false;
      const sig = stack[0], pub = stack[1];
      if(pub.length !== 33 || (pub[0] !== 2 && pub[0] !== 3)) return false;   // compressed only
      if(sig.length < 9 || sig[sig.length-1] !== 0x01) return false;          // SIGHASH_ALL
      const rs = derToCompact(sig.slice(0, sig.length-1));
      if(!rs) return false;
      const wp = btc.p2wpkh(pub, net);                     // re-derive program from the witness pubkey
      if(dec.type==='wpkh'){ if(!eqBytes(wp.script, spk)) return false; }
      else { if(!eqBytes(btc.p2sh(wp, net).script, spk)) return false; }     // must be nested-wpkh
      const h160 = wp.script.slice(2, 22);                 // 0x00 0x14 <20-byte hash160>
      const digest = bip143Sighash(prevTxidLE, h160);
      return secp.verify(rs, digest, pub, { lowS: false });
    }
    if(dec.type==='tr'){
      if(stack.length !== 1) return false;
      let sig = stack[0];
      if(sig.length === 65){ if(sig[64] === 0x00) return false; sig = sig.slice(0,64); }   // explicit ALL ok; 0x00 not
      else if(sig.length !== 64) return false;
      const digest = taprootSighash(prevTxidLE, spk);
      return schnorrVerify(sig, digest, dec.pubkey);       // dec.pubkey = 32-byte tweaked output key
    }
    return false;                                          // legacy / unknown is not BIP-322 "simple"
  } catch(_){ return false; }
}

/* ---- self-test: gates the UI. KAT + sign->verify round-trip + negatives for each type ---- */
export function selfTest(net){
  const checks = [];
  const chk = (name, fn) => { try { const d = fn(); checks.push({ name, ok:true, detail: d || '' }); } catch(e){ checks.push({ name, ok:false, detail: e.message || String(e) }); } };
  chk('messageHash("") KAT', () => { const h = bytesToHex(messageHash('')); if(h !== '888bab9b0d983d5058a18821fa257f99d05105d3fa0a01f162666e905c4cebc1') throw new Error('mismatch'); return h.slice(0,16)+'…'; });
  chk('messageHash("Hello World") KAT', () => { const h = bytesToHex(messageHash('Hello World')); if(h !== 'a8b6c7515051928c83e7e0ff14083c2ec67bc4ff9b8ba8db4d0155696d02aa50') throw new Error('mismatch'); return h.slice(0,16)+'…'; });
  const k = hexToBytes('1111111111111111111111111111111111111111111111111111111111111111');
  const pub = secp.getPublicKey(k, true);
  const k2 = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222');   // a different key, for same-type negatives
  const pub2 = secp.getPublicKey(k2, true);
  for(const type of ['wpkh','sh-wpkh','tr']){
    chk(type + ' sign -> verify (wrong msg/addr/key rejected)', () => {
      const addr = addressFor(type, pub, net);
      const sig = sign(net, type, k, 'Hello World');
      if(!verify(net, addr, 'Hello World', sig)) throw new Error('round-trip verify=false');
      if(verify(net, addr, 'Tampered message', sig)) throw new Error('accepted wrong message');
      if(verify(net, addressFor(type==='tr'?'wpkh':'tr', pub, net), 'Hello World', sig)) throw new Error('accepted wrong address');
      if(verify(net, addressFor(type, pub2, net), 'Hello World', sig)) throw new Error('accepted wrong key (same type)');   // key/script binding + sighash
      return addr;
    });
  }
  // wpkh and sh-wpkh share a 2-item witness - the script binding + sighash must still distinguish them
  chk('wpkh/sh-wpkh not cross-accepted', () => {
    if(verify(net, addressFor('sh-wpkh', pub, net), 'Hello World', sign(net, 'wpkh', k, 'Hello World'))) throw new Error('wpkh sig accepted for sh-wpkh address');
    if(verify(net, addressFor('wpkh', pub, net), 'Hello World', sign(net, 'sh-wpkh', k, 'Hello World'))) throw new Error('sh-wpkh sig accepted for wpkh address');
    return 'distinct script + sighash';
  });
  const fails = checks.filter(c => !c.ok).map(c => c.name + (c.detail ? (': ' + c.detail) : ''));
  return { ok: fails.length===0, fails, checks };
}
