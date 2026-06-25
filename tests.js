// SPDX-License-Identifier: AGPL-3.0-or-later
// Crypto known-answer tests for TestnetWallet. Imports the SAME vendored libraries + first-party crypto
// modules the wallet ships, re-runs their exported selfTest()s, and checks address derivation against
// published vectors. See tests.html.
import { HDKey } from './vendor/bip32.mjs';
import { mnemonicToSeedSync } from './vendor/bip39.mjs';
import * as btc from './vendor/btc-signer.mjs';
import * as bip322 from './bip322.mjs';
import * as xmr from './monero.mjs';
import * as xmrSeed from './monero-mnemonic.mjs';
import * as mweb from './mweb.mjs';

const results = document.getElementById('results');
let pass = 0, fail = 0;
function group(title){ const g = document.createElement('div'); g.className='grp';
  const h = document.createElement('h2'); h.textContent = title; g.appendChild(h); results.appendChild(g); return g; }
function row(g, ok, name, detail){
  const r = document.createElement('div'); r.className = 'row ' + (ok?'ok':'bad');
  const i = document.createElement('span'); i.className='ic'; i.textContent = ok?'✓':'✗';
  const n = document.createElement('span'); n.className='name'; n.textContent = name;
  const d = document.createElement('span'); d.className='detail'; d.textContent = detail||'';
  r.append(i,n,d); g.appendChild(r); ok ? pass++ : fail++;
}
function eq(g, name, actual, expected){ row(g, actual===expected, name, actual===expected ? String(actual) : ('got '+actual+'  ≠  want '+expected)); }

const MN = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// ---------- 1. Module self-tests (the exact gates the app runs at boot) ----------
function groupSelfTests(){
  const g = group('1. Module self-tests (same as the app boots with)');
  try { const r = bip322.selfTest(btc.TEST_NETWORK); row(g, !!r.ok, 'BIP-322 message signing', r.ok?'pass':JSON.stringify(r.fails)); }
  catch(e){ row(g, false, 'BIP-322 message signing', String(e)); }
  try { const r = xmr.selfTest(); row(g, !!r.ok, 'Monero key derivation / address encoding', r.ok?'pass':JSON.stringify(r.fails)); }
  catch(e){ row(g, false, 'Monero key derivation', String(e)); }
  try { const r = xmrSeed.selfTest(); row(g, !!r.ok, 'Monero 25-word portable seed', r.ok?'pass':JSON.stringify(r.fails)); }
  catch(e){ row(g, false, 'Monero 25-word seed', String(e)); }
  try { const r = mweb.selfTest(); row(g, !!r.ok, 'Litecoin MWEB crypto (scan + tmweb address + Schnorr)', r.ok?'pass':JSON.stringify(r.fails)); }
  catch(e){ row(g, false, 'Litecoin MWEB crypto', String(e)); }
}

// ---------- 2. BIP39 seed + BIP44/49/84/86 address KATs (mainnet published vectors) ----------
function groupBip(){
  const g = group('2. BIP44/49/84/86 address vectors - "abandon…about" (mainnet)');
  const seed = mnemonicToSeedSync(MN, '');
  const seedHex = [...seed].map(b=>b.toString(16).padStart(2,'0')).join('');
  row(g, seedHex.startsWith('5eb00bbddcf06908'), 'BIP39 seed (mnemonicToSeedSync)', seedHex.slice(0,16)+'…');
  const root = HDKey.fromMasterSeed(seed);                       // default = mainnet version bytes
  const N = btc.NETWORK;
  eq(g, "BIP44  m/44'/0'/0'/0/0  P2PKH", btc.p2pkh(root.derive("m/44'/0'/0'/0/0").publicKey, N).address, '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');
  eq(g, "BIP49  m/49'/0'/0'/0/0  P2SH-P2WPKH", btc.p2sh(btc.p2wpkh(root.derive("m/49'/0'/0'/0/0").publicKey, N), N).address, '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf');
  eq(g, "BIP84  m/84'/0'/0'/0/0  P2WPKH", btc.p2wpkh(root.derive("m/84'/0'/0'/0/0").publicKey, N).address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  eq(g, "BIP86  m/86'/0'/0'/0/0  P2TR", btc.p2tr(root.derive("m/86'/0'/0'/0/0").publicKey.slice(1), undefined, N).address, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
}

// ---------- 3. Electrum seed import KATs (independent re-derivation of the wallet's scheme) ----------
function elNorm(s){ return String(s||'').normalize('NFKD').toLowerCase().replace(/\p{M}/gu,'').replace(/\s+/g,' ').trim(); }
async function elHmacHex(seed){
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey('raw', enc.encode('Seed version'), {name:'HMAC',hash:'SHA-512'}, false, ['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(seed)))].map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function elRoot(seed){
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(seed), 'PBKDF2', false, ['deriveBits']);
  return HDKey.fromMasterSeed(new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-512',salt:enc.encode('electrum'),iterations:2048}, km, 512)));
}
async function groupElectrum(){
  const g = group('3. Electrum seed import (standard + segwit)');
  try {
    const N = btc.NETWORK;
    const segS = elNorm('bitter grass shiver impose acquire brush forget axis eager alone wine silver');
    row(g, (await elHmacHex(segS)).startsWith('100'), 'segwit seed detects as 100', '');
    eq(g, "Electrum segwit  m/0'/0/0  P2WPKH", btc.p2wpkh((await elRoot(segS)).derive("m/0'/0/0").publicKey, N).address, 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af');
    const stdS = elNorm('cycle rocket west magnet parrot shuffle foot correct salt library feed song');
    row(g, (await elHmacHex(stdS)).startsWith('01'), 'standard seed detects as 01', '');
    eq(g, 'Electrum standard  m/0/0  P2PKH', btc.p2pkh((await elRoot(stdS)).derive('m/0/0').publicKey, N).address, '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf');
  } catch(e){ row(g, false, 'Electrum derivation', String(e)); }
}

// ---------- 4. Multisig descriptor checksum (BIP380) + sortedmulti address ----------
function groupMultisig(){
  const g = group('4. Multisig (BIP380 descriptor checksum + P2WSH sortedmulti)');
  const INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
  const CHK = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  function polymod(symbols){ const GEN=[0xf5dee51989n,0xa9fdca3312n,0x1bab10e32dn,0x3706b1677an,0x644d626ffdn]; let chk=1n;
    for(const v of symbols){ const top=chk>>35n; chk=((chk&0x7ffffffffn)<<5n)^BigInt(v); for(let i=0;i<5;i++) if((top>>BigInt(i))&1n) chk^=GEN[i]; } return chk; }
  function checksum(s){ const sym=[],gr=[]; for(const ch of s){ const v=INPUT.indexOf(ch); if(v<0) throw new Error('bad char'); sym.push(v&31); gr.push(v>>5);
      if(gr.length===3){ sym.push(gr[0]*9+gr[1]*3+gr[2]); gr.length=0; } } if(gr.length===1) sym.push(gr[0]); else if(gr.length===2) sym.push(gr[0]*3+gr[1]);
    for(let i=0;i<8;i++) sym.push(0); const c=polymod(sym)^1n; let o=''; for(let i=0;i<8;i++) o+=CHK[Number((c>>BigInt(5*(7-i)))&31n)]; return o; }
  eq(g, 'BIP380 checksum  raw(deadbeef)', checksum('raw(deadbeef)'), '89f8spxm');
  try {
    const root = HDKey.fromMasterSeed(mnemonicToSeedSync(MN, ''));
    const pubs = [0,1,2].map(a => root.derive("m/48'/1'/"+a+"'/2'/0/0").publicKey);
    const ms = btc.sortedMultisig(2, pubs, true, btc.TEST_NETWORK);
    row(g, /^tb1q[0-9a-z]{58,}$/.test(ms.address) && !!ms.witnessScript, '2-of-3 P2WSH sortedmulti address', ms.address);
  } catch(e){ row(g, false, '2-of-3 P2WSH sortedmulti', String(e)); }
}

function finalize(){
  const s = document.getElementById('summary');
  s.textContent = fail===0 ? ('✓ All '+pass+' checks passed') : ('✗ '+fail+' of '+(pass+fail)+' checks FAILED');
  s.className = fail===0 ? 'pass-all' : 'fail-any';
}

// Run synchronous groups, then the async Electrum group, then finalize.
try { groupSelfTests(); groupBip(); groupMultisig(); }
catch(e){ const g = group('error'); row(g, false, 'a synchronous group threw', String(e)); }
groupElectrum()
  .catch(e => { const g = group('error'); row(g, false, 'Electrum group threw', String(e)); })
  .finally(finalize);
