// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Monero legacy 25-word mnemonic (Electrum-style base-1626 + CRC32 checksum word).
 * Lets the wallet's Monero spend key be exported as a PORTABLE seed: those 25 words restore the
 * same wallet in monero-wallet-cli / Cake / Feather, which is also the definitive way to validate
 * that our key derivation + address encoding match the reference implementation.
 *
 * Encode/decode follow monero-project src/mnemonics/electrum-words.cpp exactly. Self-test checks the
 * whole chain against a real wallet (monero-ts's fixed test mnemonic -> its testnet primary address).
 */
import { moneroWords as W } from './vendor/monero-wordlist.mjs';
import { keccak_256 } from './vendor/noble-keccak.mjs';
import { keysFromSpendSecret, subaddress, XMR_NETS, b58decode } from './monero.mjs';   // self-test runs the PRODUCTION derivation

const N = 1626;
const PFX = 3;                                   // English unique-prefix length
const prefixIndex = {};                          // first-3-chars -> word index (also accepts abbreviated words)
W.forEach((w, i) => { prefixIndex[w.slice(0, PFX)] = i; });

/* CRC32 (IEEE 802.3, same as boost::crc_32_type) over an ASCII string */
const CRC_TBL = (() => { const t = new Uint32Array(256);
  for(let n=0;n<256;n++){ let c=n; for(let k=0;k<8;k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n]=c>>>0; }
  return t; })();
function crc32(str){ let c = 0xFFFFFFFF; for(let i=0;i<str.length;i++) c = CRC_TBL[(c ^ str.charCodeAt(i)) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
function checksumWord(words24){                  // the 25th word repeats one of the 24, chosen by CRC32 of their 3-char prefixes
  const trimmed = words24.map(w => w.slice(0, PFX)).join('');
  return words24[crc32(trimmed) % words24.length];
}

/* 32 raw bytes -> 25 words */
export function encode25(seed){
  if(seed.length !== 32) throw new Error('seed must be 32 bytes');
  const words = [];
  for(let i=0;i<32;i+=4){
    const val = ((seed[i] | (seed[i+1]<<8) | (seed[i+2]<<16)) >>> 0) + seed[i+3]*0x1000000;   // u32 little-endian
    const w1 = val % N;
    const w2 = (Math.floor(val / N) + w1) % N;
    const w3 = (Math.floor(val / N / N) + w2) % N;
    words.push(W[w1], W[w2], W[w3]);
  }
  words.push(checksumWord(words));
  return words.join(' ');
}

/* 24 or 25 words -> 32 raw bytes (validates the checksum word when 25 are given) */
export function decode25(mnemonic){
  const all = String(mnemonic).trim().toLowerCase().split(/\s+/);
  if(all.length !== 25 && all.length !== 24) throw new Error('expected a 25-word Monero seed');
  const data = all.length === 25 ? all.slice(0, 24) : all;
  if(all.length === 25 && checksumWord(data) !== all[24]) throw new Error('checksum word does not match');
  const idx = data.map(w => { const j = prefixIndex[w.slice(0, PFX)]; if(j == null) throw new Error('unknown seed word: ' + w); return j; });
  const out = new Uint8Array(32);
  for(let g=0; g<8; g++){
    const w1 = idx[g*3], w2 = idx[g*3+1], w3 = idx[g*3+2];
    const val = (w1 + N * (((w2 - w1) % N + N) % N) + N * N * (((w3 - w2) % N + N) % N)) >>> 0;
    out[g*4] = val & 0xff; out[g*4+1] = (val >>> 8) & 0xff; out[g*4+2] = (val >>> 16) & 0xff; out[g*4+3] = (val >>> 24) & 0xff;
  }
  return out;
}

/* Validate the codec + the whole derivation chain against a real wallet (gate before exposing in UI). */
export function selfTest(){
  const fails = [];
  const hex = b => { let s = ''; for(const x of b) s += x.toString(16).padStart(2, '0'); return s; };
  // 1. codec round-trip
  try {
    const probe = new Uint8Array(32); for(let i=0;i<32;i++) probe[i] = (i*7 + 1) & 0xff;
    if(hex(decode25(encode25(probe))) !== hex(probe)) fails.push('25-word encode/decode round-trip');
  } catch(e){ fails.push('round-trip threw: ' + (e.message || e)); }
  // 2. full chain through the PRODUCTION derive + subaddress: monero-ts test wallet mnemonic -> its testnet primary address.
  //    Gating receive on this (state.xmrOk) means a regression in keysFromSpendSecret/subaddress/encodeAddress disables Monero.
  const MN = 'silk mocked cucumber lettuce hope adrenalin aching lush roles fuel revamp baptism wrist long tender teardrop midst pastry pigment equip frying inbound pinched ravine frying';
  const ADDR = 'A1y9sbVt8nqhZAVm3me1U18rUVXcjeNKuBd1oE2cTs8biA9cozPMeyYLhe77nPv12JA3ejJN3qprmREriit2fi6tJDi99RR';
  try {
    const keys = keysFromSpendSecret(decode25(MN));                       // legacy seed: the 32 decoded bytes ARE the spend secret
    if(subaddress(keys, XMR_NETS.testnet, 0, 0) !== ADDR) fails.push('test-vector: primary address mismatch');
    const sub = subaddress(keys, XMR_NETS.testnet, 0, 1);                 // exercise the (major,minor)!=0 branch: D=B+m*G, C=a*D
    const raw = b58decode(sub);
    if(raw.length !== 69 || raw[0] !== XMR_NETS.testnet.subaddress) fails.push('subaddress prefix/length');
    else if(hex(keccak_256(raw.slice(0, 65)).slice(0, 4)) !== hex(raw.slice(65))) fails.push('subaddress checksum');
    if(sub === ADDR) fails.push('subaddress equals primary');
  } catch(e){ fails.push('test-vector threw: ' + (e.message || e)); }
  return { ok: fails.length === 0, fails };
}
