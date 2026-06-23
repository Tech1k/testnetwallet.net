// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * TestnetWallet: an HD wallet and dev playground for testnet coins.
 * Part of the CypherToshi / TestnetPool family. Keys stay in the browser. Testnet only.
 *
 * Crypto: @scure/btc-signer (addresses, PSBT), @scure/bip32 (HD), @scure/bip39 (mnemonic),
 *         @noble/secp256k1 + sha256 (message signing). All vendored, no build step, no CDN.
 * Data:   public Esplora APIs (mempool.space/testnet4, litecoinspace.org/testnet).
 */
import * as btc from './vendor/btc-signer.mjs';
import { HDKey } from './vendor/bip32.mjs';
import { generateMnemonic, validateMnemonic, mnemonicToSeedSync } from './vendor/bip39.mjs';
import { wordlist } from './vendor/wordlist-english.mjs';
import * as secp from './vendor/noble-secp256k1.mjs';
import { sha256 } from './vendor/noble-sha256.mjs';
import * as bip322 from './bip322.mjs';                 // BIP-322 message signing for segwit/taproot
import * as xmr from './monero.mjs';
import * as xmrSeed from './monero-mnemonic.mjs';
import * as moneroEngine from './monero-engine.mjs';   // lazy: only fetches the ~6MB bundle on first balance/send

/* Clickjacking guard. A frame-ancestors directive in a <meta> CSP is ignored by browsers,
 * so for static hosting we bust out of frames here (a key-revealing wallet shouldn't be embeddable). */
if(window.self !== window.top){
  try { window.top.location.replace(location.href); } catch(_){}
  document.documentElement.style.display = 'none';
  throw new Error('TestnetWallet may not be embedded in a frame');
}

/* ----------------------------- config ----------------------------- */
const LTC_TESTNET = { bech32:'tltc', pubKeyHash:0x6f, scriptHash:0x3a, wif:0xef,
  bip32:{ public:0x043587cf, private:0x04358394 } };

// Temporary kill-switch: while the Monero testnet/stagenet nodes are being stabilised, Monero stays disabled
// (its coin pill greys out). Flip to true to re-enable once the testnet/stagenet nodes are stable.
const MONERO_ENABLED = false;
const COINS = {
  btc:{ name:'Bitcoin', ticker:'tBTC', priceSym:'BTC', color:'#f7931a', enabled:true, uri:'bitcoin',
        msgPrefix:'Bitcoin Signed Message:\n',
        net: btc.TEST_NETWORK, api:'https://mempool.space/testnet4/api',
        explorer:'https://mempool.space/testnet4' },
  ltc:{ name:'Litecoin', ticker:'tLTC', priceSym:'LTC', color:'#345d9d', enabled:true, uri:'litecoin',
        msgPrefix:'Litecoin Signed Message:\n',
        net: LTC_TESTNET, api:'https://litecoinspace.org/testnet/api',
        explorer:'https://litecoinspace.org/testnet' },
  xmr:{ name:'Monero', ticker:'XMR', color:'#ff6600', enabled:false, uri:'monero', addrModel:'monero',
        explorers:{ stagenet:'https://xmr-stagenet.librenode.com', testnet:'https://xmr-testnet.librenode.com' } }, // keys are pure-JS; balance/history/send/sign run through the lazy-loaded node engine. enabled set true at boot iff self-test passes.
};
const TYPES = { pkh:{ label:'Legacy', purpose:44 }, 'sh-wpkh':{ label:'Nested', purpose:49 }, wpkh:{ label:'SegWit', purpose:84 }, tr:{ label:'Taproot', purpose:86 } };
const FIATS = { USD:'$', EUR:'€', GBP:'£', CAD:'$', JPY:'¥', CNY:'¥' };
const DUST = 546;            // sats; outputs below this are non-standard
const LS_KEY = 'testnetwallet.v1';

/* ----------------------------- tiny utils ----------------------------- */
const $ = id => document.getElementById(id);
function el(tag, props, ...kids){
  const e = document.createElement(tag);
  if(props) for(const [k,v] of Object.entries(props)){
    if(v==null) continue;
    if(k==='class') e.className = v;
    else if(k==='text') e.textContent = v;            // text content is always set safely
    else if(k.slice(0,2)==='on' && typeof v==='function') e.addEventListener(k.slice(2).toLowerCase(), v);
    else if(k==='disabled'||k==='checked'||k==='selected') { if(v) e[k]=true; }
    else e.setAttribute(k, v);
  }
  for(const k of kids.flat()){ if(k==null||k===false) continue; e.append(k.nodeType ? k : document.createTextNode(String(k))); }
  return e;
}
function clear(node){ while(node.firstChild) node.removeChild(node.firstChild); return node; }
function uid(){
  try { return crypto.randomUUID(); } catch(_){}
  const a = new Uint8Array(16); crypto.getRandomValues(a);
  return [...a].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function fmt(sats){ return (sats/1e8).toFixed(8).replace(/\.?0+$/,''); }
function timeAgo(sec){
  if(!sec) return 'pending';
  let d = Math.max(1, Math.floor(Date.now()/1000 - sec));
  for(const [n,s] of [['y',31536000],['mo',2592000],['d',86400],['h',3600],['m',60]]){
    const v = Math.floor(d/s); if(v>=1) return v+n+' ago';
  }
  return d+'s ago';
}
function normalizePhrase(p){ return p.trim().toLowerCase().replace(/\s+/g,' '); }
let _clipClearTimer = null;
// attrs that keep secret text out of cloud spellcheck / autofill / autocapitalize
const SECRET_ATTRS = { spellcheck:'false', autocapitalize:'none', autocorrect:'off', autocomplete:'off' };
function copyText(text, srcEl, secret){
  if(_clipClearTimer){ clearTimeout(_clipClearTimer); _clipClearTimer = null; }   // any newer copy supersedes a pending secret-clear
  const done = () => {
    if(srcEl){ const t = srcEl.textContent; srcEl.textContent='✓ copied'; srcEl.classList.add('copied');
      setTimeout(()=>{ srcEl.textContent = t; srcEl.classList.remove('copied'); }, 1100); }
    if(secret && navigator.clipboard && navigator.clipboard.writeText){             // auto-wipe a copied seed/key after 60s
      _clipClearTimer = setTimeout(()=>{ _clipClearTimer = null;
        const tryWipe = ()=>{                                                       // only clear if the clipboard STILL holds our secret - never clobber unrelated content
          if(!navigator.clipboard.readText) return;
          navigator.clipboard.readText().then(cur => { if(cur === text) navigator.clipboard.writeText('').catch(()=>{}); }, ()=>{});
        };
        if(document.hasFocus()) tryWipe();
        else window.addEventListener('focus', ()=>tryWipe(), { once:true });        // readText needs focus - retry when the tab regains it
      }, 60000);
    }
  };
  if(navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, ()=>{});
  else { try { const ta=el('textarea',{}); ta.value=text; document.body.append(ta); ta.select();
    document.execCommand('copy'); ta.remove(); done(); } catch(_){} }
}

/* ----------------------------- persistence ----------------------------- */
/* Optional encryption-at-rest (opt-in): the store blob (which holds the seed) and the Monero key/cache are
 * encrypted with AES-256-GCM under a key derived from the user's password via PBKDF2 (Web Crypto, no new dep).
 * _cryptoKey is held only in memory while unlocked; locking wipes it. A plaintext wallet works exactly as before. */
const KDF_ITER = 600000;                 // PBKDF2-HMAC-SHA256 rounds (OWASP-tier)
let _cryptoKey = null;                   // AES-GCM CryptoKey while unlocked; null when plaintext OR locked
let _vaultSalt = null;                   // Uint8Array salt for the derived key (per-wallet)
let _vaultIter = KDF_ITER;
let _encOn = false;                      // true once encryption is enabled (vault on disk)
let _locked = false;                     // true when encryption is on but not yet unlocked this session
let _pin = null;                         // optional in-memory session PIN (never persisted); enables fast "soft lock"
let _softLocked = false;                 // soft-locked: key + decrypted seed stay in memory, gated behind the PIN
function isEncrypted(){ return _encOn; }
function isLocked(){ return _encOn && (_locked || _softLocked || !_cryptoKey); }

async function deriveKey(password, saltBytes, iter){
  const base = await crypto.subtle.importKey('raw', utf8(String(password)), { name:'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name:'PBKDF2', salt: saltBytes, iterations: iter||KDF_ITER, hash:'SHA-256' },
    base, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
async function encWith(key, plaintext){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, utf8(plaintext)));
  return { iv: b64encode(iv), ct: b64encode(ct) };
}
async function decWith(key, ivB64, ctB64){
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv: b64decode(ivB64) }, key, b64decode(ctB64));
  return new TextDecoder().decode(pt);
}

function loadStore(){ try { return JSON.parse(localStorage.getItem(LS_KEY)) || {}; } catch(_){ return {}; } }   // plaintext path only
// All persistence is serialized through one chain so overlapping async encrypted writes apply in order (last write = latest state).
let _writeChain = Promise.resolve();
async function saveStoreNow(){          // awaitable; encrypts when unlocked, no-op while locked (never writes plaintext over a vault)
  if(_encOn && !_cryptoKey) return;
  if(_encOn && _cryptoKey){
    const e = await encWith(_cryptoKey, JSON.stringify(store));
    localStorage.setItem(LS_KEY, JSON.stringify({ tnwvault:1, kdf:'PBKDF2', iter:_vaultIter, salt:b64encode(_vaultSalt), iv:e.iv, ct:e.ct, theme:(store.settings&&store.settings.theme)||'dark' }));
  } else {
    try { const cur = JSON.parse(localStorage.getItem(LS_KEY));   // another tab may have enabled encryption - never clobber a vault with plaintext
      if(cur && cur.tnwvault){ _encOn = true; _locked = true; _cryptoKey = null; try { render(); } catch(_){} return; } } catch(_){}
    localStorage.setItem(LS_KEY, JSON.stringify(store));
  }
}
let _saveWarnAt = 0;
function saveStore(){ _writeChain = _writeChain.then(saveStoreNow).catch(e => {   // surface persistence failure (quota etc.) - it's a data-loss class bug if silent
  console.warn('[storage] save failed (quota?):', e);
  const now = Date.now();
  if(now - _saveWarnAt > 20000){ _saveWarnAt = now; try { toast('Couldn’t save to this browser’s storage (it may be full). Recent changes may not persist - back up your wallet.', 'bad'); } catch(_){} }
}); }

/* Migrate Monero key/cache blobs between plaintext and encrypted form. On the ENCRYPT pass, a blob that can't be
 * encrypted is DELETED rather than left as a plaintext spend key (recoverable - it re-derives + re-syncs). */
async function migrateXmrCaches(toEncrypted, key){
  const keys = [];
  try { for(let i=0;i<localStorage.length;i++){ const k=localStorage.key(i); if(k && k.indexOf(XMR_DATA_PREFIX)===0) keys.push(k); } } catch(_){ return; }
  for(const k of keys){
    let raw; try { raw = JSON.parse(localStorage.getItem(k)); } catch(_){ continue; }
    if(toEncrypted && raw && raw.k && raw.c && !raw.tnwvault){
      try { const e = await encWith(key, JSON.stringify({ k:raw.k, c:raw.c })); localStorage.setItem(k, JSON.stringify({ tnwvault:1, iv:e.iv, ct:e.ct })); }
      catch(err){ console.warn('[storage] could not encrypt a Monero cache; dropping it (will re-sync):', k, err); try { localStorage.removeItem(k); } catch(_){} }
    } else if(!toEncrypted && raw && raw.tnwvault){
      try { const j = JSON.parse(await decWith(key, raw.iv, raw.ct)); localStorage.setItem(k, JSON.stringify({ k:j.k, c:j.c })); }
      catch(err){ console.warn('[storage] Monero cache decrypt failed on disable; dropping (will re-sync):', k, err); try { localStorage.removeItem(k); } catch(_){} }
    }
  }
}
// Run a state-transition as a CRITICAL SECTION on the write-chain, so saveStore/saveXmrData can't interleave
// (no plaintext write can sneak in during the slow key-derivation window). Returns a promise the caller awaits.
function runExclusive(fn){ const p = _writeChain.then(fn); _writeChain = p.catch(()=>{}); return p; }

/* Enable encryption. Self-tests the round-trip, then encrypts the SEED first before the Monero caches. */
function enableEncryption(password){
  return runExclusive(async ()=>{
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt, KDF_ITER);
    const probe = 'tnw-encryption-self-test';
    const e = await encWith(key, probe);
    if(await decWith(key, e.iv, e.ct) !== probe) throw new Error('encryption self-test failed');   // gate: never enable broken crypto
    const ev = await encWith(key, JSON.stringify(store));   // persist the encrypted seed vault FIRST (with the freshly-derived key)
    localStorage.setItem(LS_KEY, JSON.stringify({ tnwvault:1, kdf:'PBKDF2', iter:KDF_ITER, salt:b64encode(salt), iv:ev.iv, ct:ev.ct, theme:(store.settings&&store.settings.theme)||'dark' }));
    _vaultSalt = salt; _vaultIter = KDF_ITER; _cryptoKey = key; _encOn = true; _locked = false;   // commit flags only AFTER the encrypted seed landed (a setItem throw leaves us plaintext-consistent)
    await migrateXmrCaches(true, key);                   // then the caches (recoverable if any fail)
  });
}
/* Re-key to a NEW password WITHOUT ever writing plaintext: re-encrypt the in-memory store + caches in place. */
function changePassword(newPassword){
  if(!_cryptoKey) return Promise.reject(new Error('unlock first'));
  return runExclusive(async ()=>{
    const oldKey = _cryptoKey;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const newKey = await deriveKey(newPassword, salt, KDF_ITER);
    const probe = 'tnw-encryption-self-test';
    const e = await encWith(newKey, probe);
    if(await decWith(newKey, e.iv, e.ct) !== probe) throw new Error('encryption self-test failed');
    const keys = []; try { for(let i=0;i<localStorage.length;i++){ const k=localStorage.key(i); if(k && k.indexOf(XMR_DATA_PREFIX)===0) keys.push(k); } } catch(_){}
    for(const k of keys){ let raw; try { raw = JSON.parse(localStorage.getItem(k)); } catch(_){ continue; }
      if(raw && raw.tnwvault){ try { const j = await decWith(oldKey, raw.iv, raw.ct); const ee = await encWith(newKey, j); localStorage.setItem(k, JSON.stringify({ tnwvault:1, iv:ee.iv, ct:ee.ct })); }
        catch(err){ console.warn('[storage] cache re-key failed; dropping (will re-sync):', k, err); try { localStorage.removeItem(k); } catch(_){} } } }
    const ev = await encWith(newKey, JSON.stringify(store));   // persist the seed vault under the NEW key FIRST
    localStorage.setItem(LS_KEY, JSON.stringify({ tnwvault:1, kdf:'PBKDF2', iter:KDF_ITER, salt:b64encode(salt), iv:ev.iv, ct:ev.ct, theme:(store.settings&&store.settings.theme)||'dark' }));
    _vaultSalt = salt; _vaultIter = KDF_ITER; _cryptoKey = newKey;   // commit only after it landed; on a throw above, oldKey stays live + consistent with disk
  });
}
/* Turn encryption off (must be unlocked). Rewrites everything as plaintext - the intended end state here. */
function disableEncryption(){
  if(!_cryptoKey) return Promise.reject(new Error('unlock first'));
  return runExclusive(async ()=>{
    await migrateXmrCaches(false, _cryptoKey);
    _encOn = false; _cryptoKey = null; _vaultSalt = null; _locked = false;
    await saveStoreNow();   // writes plaintext (intended)
  });
}
/* Decrypt the vault with a password and load the store. Returns true on success. */
async function unlockVault(vault, password){
  const salt = b64decode(vault.salt);
  const key = await deriveKey(password, salt, vault.iter || KDF_ITER);
  const json = await decWith(key, vault.iv, vault.ct);   // throws on wrong password (GCM auth fail)
  store = JSON.parse(json);
  _vaultSalt = salt; _vaultIter = vault.iter || KDF_ITER; _cryptoKey = key; _encOn = true; _locked = false;
  try { await migrateXmrCaches(true, key); } catch(_){}   // re-encrypt any plaintext Monero cache left by a crash mid-enable (idempotent: skips already-encrypted blobs)
  return true;
}
/* Soft lock: keep the key + decrypted seed in memory, gate the UI behind the session PIN (fast re-entry). */
function softLock(){ if(!_pin || !_cryptoKey){ lockWallet(); return; } _softLocked = true; closeModal(); render(); }
function lockWallet(){   // FULL lock: wipe the in-memory key + decrypted seed + PIN + sensitive state, require the password
  _cryptoKey = null; _locked = true; _pin = null; _softLocked = false;
  _discoverTok++; state.refreshSeq++;   // abort any in-flight gap-scan / refresh fetches so the locked wallet stops emitting address queries
  state.master = null; state.wallet = null; state.xmrKeys = null; state.addresses = [];
  state.xmr = { wallet:null, syncing:false, synced:false, pct:0, restoreHeight:0, start:0, height:0, endHeight:0, balance:null, unlocked:null, txs:[], accounts:[], error:null, node:null };
  store = {};   // drop the only reference to the decrypted mnemonics/passphrases; unlockVault repopulates it
  state.balances = {}; state.txs = []; state.totalSats = 0; state.confirmedSats = 0; state.price = null;   // public residue, cleared for symmetry
  closeModal();
  render();
}
let store = {};   // { wallets:[{id,name,mnemonic}], activeId, settings:{theme,coin,addrType,fiat}, counts:{[id]:{'btc.wpkh':n}} }
// --- animation feedback state (purely cosmetic; see index.html @keyframes) ---
let _lastBal = null;            // last-shown BTC/LTC total (sats) for the balance-change flash
let _newAddrIdx = -1;           // index of a just-derived address to highlight once
let _lastPending = new Set();   // txids that were pending at the previous history render (for the settle flash)
function skel(w){ return el('span',{class:'skel',style:'width:'+(w||'64px')+';height:1em'}, ' '); }
function shakeEl(node){ if(!node) return; node.classList.remove('shake'); void node.offsetWidth; node.classList.add('shake'); }

/* ----------------------------- crypto ----------------------------- */
function pathFor(type, index, change=0){
  if(state.scheme && ELECTRUM_SCHEMES[state.scheme]) return state.scheme==='electrum-segwit' ? `m/0'/${change}/${index}` : `m/${change}/${index}`;
  return `m/${TYPES[type].purpose}'/1'/${state.account}'/${change}/${index}`;
}
function deriveNode(type, index, change=0){ return state.master.derive(pathFor(type, index, change)); }
function addrFromPub(pub, coin, type){
  const net = COINS[coin].net;
  if(type==='pkh')  return btc.p2pkh(pub, net).address;
  if(type==='wpkh') return btc.p2wpkh(pub, net).address;
  if(type==='sh-wpkh') return btc.p2sh(btc.p2wpkh(pub, net), net).address;   // P2SH-wrapped SegWit (BIP49)
  if(type==='tr'){ const xonly = pub.length===33 ? pub.slice(1) : pub; return btc.p2tr(xonly, undefined, net).address; } // net is the 3rd arg (2nd is scriptTree)
}
function wifFor(node, coin){ return btc.WIF(COINS[coin].net).encode(node.privateKey); }
function isValidAddress(addr, coin){
  try { btc.Address(COINS[coin].net).decode(addr); return true; } catch(_){ return false; }
}

/* ----------------------------- Esplora data layer ----------------------------- */
// Base URL for a coin's Esplora API: a user-set self-hosted override (Settings) or the built-in default.
function apiBase(coin){ return (store.settings && store.settings.api && store.settings.api[coin]) || COINS[coin].api; }
async function apiGet(coin, path){
  const ac = new AbortController(); const t = setTimeout(()=>ac.abort('timeout'), 12000);
  try {
    const r = await fetch(apiBase(coin) + path, { signal: ac.signal });
    if(!r.ok) throw new Error('HTTP '+r.status);
    const ct = r.headers.get('content-type') || '';
    if(!ct.includes('json')) throw new Error('unexpected response');
    return await r.json();
  } finally { clearTimeout(t); }
}
async function getStats(coin, addr){
  const s = await apiGet(coin, '/address/'+encodeURIComponent(addr));
  const cs = s.chain_stats || {}, ms = s.mempool_stats || {};
  const confirmed = (cs.funded_txo_sum||0) - (cs.spent_txo_sum||0);
  const pending   = (ms.funded_txo_sum||0) - (ms.spent_txo_sum||0);
  return { confirmed, total: confirmed + pending };
}
const TX_PAGE_CAP = 5;          // Esplora returns ~25 confirmed txs per chain page; cap pages/address to bound requests
async function getTxs(coin, addr){
  let all = [], lastSeen = null;
  for(let page=0; page<TX_PAGE_CAP; page++){
    const txs = await apiGet(coin, '/address/'+encodeURIComponent(addr)+'/txs'+(lastSeen ? '/chain/'+lastSeen : ''));
    if(!Array.isArray(txs)) throw new Error('bad tx response');
    all = all.concat(txs);
    const confirmed = txs.filter(t => t.status && t.status.confirmed);
    if(confirmed.length < 25){ all.truncated = false; return all; }    // partial page = last page
    lastSeen = confirmed[confirmed.length-1].txid;                     // cursor must be a confirmed txid
  }
  all.truncated = true;                          // hit the page cap - older history not fetched (per-call flag, no shared global)
  return all;
}
async function getUtxos(coin, addr){
  const u = await apiGet(coin, '/address/'+encodeURIComponent(addr)+'/utxo');
  if(!Array.isArray(u)) throw new Error('bad utxo response');
  return u;
}
async function broadcast(coin, hex){
  const ac = new AbortController(); const t = setTimeout(()=>ac.abort('timeout'), 15000);
  try {
    const r = await fetch(apiBase(coin) + '/tx', { method:'POST', body: hex, signal: ac.signal });
    const txt = (await r.text()).trim();
    if(!r.ok) throw new Error(txt || ('HTTP '+r.status));
    return txt;
  } finally { clearTimeout(t); }
}
/* CypherFaucet API (the sibling faucet) - keyless, rate-limited, CORS-friendly. One-click in-wallet claiming. */
const FAUCET = 'https://cypherfaucet.com';
function faucetSlug(coin, xmrNet){
  if(coin === 'btc') return 'btc-testnet';
  if(coin === 'ltc') return 'ltc-testnet';
  if(coin === 'xmr') return xmrNet === 'testnet' ? 'xmr-testnet' : 'xmr-stagenet';
  return null;
}
async function faucetClaim(network, address){
  const ac = new AbortController(); const t = setTimeout(()=>ac.abort('timeout'), 20000);
  try {
    const r = await fetch(FAUCET + '/api/v1/claim', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ network, address }), signal: ac.signal });
    let j = null; try { j = await r.json(); } catch(_){}
    if(r.ok && j && j.ok) return j;                              // { ok, network, amount, txid, tx_key? }
    const e = new Error((j && (j.message || j.error)) || ('HTTP ' + r.status));
    e.code = j && j.error; e.retryAfter = j && j.retry_after; throw e;
  } finally { clearTimeout(t); }
}
// Reusable "Get test coins" block: claims via the API (with a faucet-page link fallback).
function renderFaucet(address){
  const slug = faucetSlug(state.coin, state.xmrNet); if(!slug || !address) return null;
  const prefill = FAUCET + '/' + slug + '?address=' + encodeURIComponent(address);
  const out = el('div',{style:'margin-top:4px'});
  const btn = el('button',{class:'btn ghost sm'},'Get test coins');
  btn.addEventListener('click', async ()=>{
    btn.disabled = true; btn.textContent = 'Requesting…'; clear(out);
    try {
      const j = await faucetClaim(slug, address);
      const fc = COINS[state.coin];
      const okMsg = el('div',{class:'msg ok'}, '✓ ' + (j.amount ? (j.amount + ' ' + fc.ticker + ' ') : '') + 'sent from the faucet. It will appear in your balance shortly.');
      if(j.txid) okMsg.append(el('div',{class:'sub',style:'margin-top:4px'}, 'Transaction: ',
        el('a',{class:'addr',href:fc.explorer + '/tx/' + encodeURIComponent(j.txid),target:'_blank',rel:'noopener'}, String(j.txid).slice(0,24) + '…')));
      clear(out).append(okMsg);
      // the faucet tx takes a few seconds to broadcast and get indexed; poll a few times so the balance updates without a manual refresh
      [3000, 9000, 20000, 40000].forEach(ms => setTimeout(()=>{ if(state.wallet && !isLocked()) refresh(); }, ms));
    } catch(e){
      const rate = e.code === 'rate_limited' || e.code === 'ip_rate_limited' || e.code === 'daily_cap';
      clear(out).append(el('div',{class:'msg ' + (rate ? 'warn' : 'bad')},
        (e.retryAfter ? ('Already claimed - try again in ~' + Math.max(1, Math.ceil(e.retryAfter/60)) + ' min. ') : ((e.message || 'Faucet request failed') + ' ')),
        el('a',{href:prefill,target:'_blank',rel:'noopener'},'open the faucet page ↗')));
    } finally { btn.disabled = false; btn.textContent = 'Get test coins'; }
  });
  return el('div',{style:'flex:0'}, el('div',{class:'row',style:'flex:0'}, btn, el('a',{class:'btn ghost sm',href:prefill,target:'_blank',rel:'noopener'},'Faucet page ↗')), out);
}
/* mainnet price for the fiat estimate. CoinGecko's keyless API is browser/CORS-friendly (CryptoCompare's min-api is not);
 * Coinbase is a CORS-friendly fallback for BTC/LTC. Cached so coin-switching/refreshes don't hammer the rate limit. */
const CG_IDS = { BTC:'bitcoin', LTC:'litecoin', XMR:'monero' };
const _priceCache = {};   // 'SYM/FIAT' -> { ts, value }
async function fetchJson(url, ms){
  const ac = new AbortController(); const t = setTimeout(()=>ac.abort('timeout'), ms || 12000);
  try {
    const r = await fetch(url, { signal: ac.signal });
    if(!r.ok) return null;
    if(!(r.headers.get('content-type') || '').includes('json')) return null;
    return await r.json();
  } catch(_){ return null; } finally { clearTimeout(t); }
}
async function getPrice(sym, fiat){
  const key = sym + '/' + fiat, now = Date.now();
  const c = _priceCache[key];
  if(c && (now - c.ts) < 120000) return c.value;                 // 2-minute cache
  let v = null;
  const id = CG_IDS[sym];
  if(id){                                                        // primary: CoinGecko keyless
    const d = await fetchJson(`https://api.coingecko.com/api/v3/simple/price?ids=${id}&vs_currencies=${fiat.toLowerCase()}`);
    if(d && d[id]) v = d[id][fiat.toLowerCase()] ?? null;
  }
  if(v == null){                                                 // fallback: Coinbase spot (BTC/LTC)
    const d = await fetchJson(`https://api.coinbase.com/v2/prices/${sym}-${fiat}/spot`);
    if(d && d.data && d.data.amount){ const n = parseFloat(d.data.amount); if(isFinite(n)) v = n; }
  }
  if(v != null) _priceCache[key] = { ts: now, value: v };
  return v;
}
async function getTipHeight(coin){
  const ac = new AbortController(); const t = setTimeout(()=>ac.abort('timeout'), 10000);
  try { const r = await fetch(apiBase(coin) + '/blocks/tip/height', { signal: ac.signal });
    if(!r.ok) return null; return parseInt((await r.text()).trim(), 10) || null; } catch(_){ return null; } finally { clearTimeout(t); }
}
function txNet(tx, addrSet){
  let inSum=0, outSum=0;
  (tx.vin||[]).forEach(v => { const a = v.prevout && v.prevout.scriptpubkey_address; if(a && addrSet.has(a)) inSum += v.prevout.value; });
  (tx.vout||[]).forEach(o => { if(o.scriptpubkey_address && addrSet.has(o.scriptpubkey_address)) outSum += o.value; });
  return outSum - inSum;
}

/* ----------------------------- state ----------------------------- */
const state = {
  coin:'btc', addrType:'wpkh', fiat:'USD', account:0, xmrNet:'stagenet', xmrAccount:0,
  wallet:null, master:null, scheme:'bip39', xmrKeys:null, xmrOk:null, xmrSeedOk:null, bip322Ok:null,
  xmr:{ wallet:null, syncing:false, synced:false, pct:0, restoreHeight:0, start:0, height:0, endHeight:0, balance:null, unlocked:null, txs:[], accounts:[], error:null, node:null },   // Monero engine sync state
  addresses:[],          // [{index, path, address}]
  balances:{},           // address -> {confirmed,total}
  totalSats:0, confirmedSats:0, price:null, hideBalance:false, refreshMs:30000, feePref:'medium',
  txs:[],                // merged, normalized (per-tx detail: fee/vsize/block_height/vin/vout)
  tab:'receive', advTab:'tools', expandedTx:null, tipHeight:null,
  refreshSeq:0, loading:false, error:null,
  // form state for the Receive / Send / Tools / Dev tabs (persists across re-renders)
  recv:{ amount:'', label:'' },
  send:{ recipients:[{address:'',amount:''}], opReturn:'', opReturnHex:false, feeRate:null, advanced:false, utxos:null, selected:{}, busy:false },
  tools:{ signIndex:0, signType:'', keyIndex:0, message:'', signature:'', signAddr:'', vAddr:'', vMsg:'', vSig:'', vResult:null, showKey:false, valAddr:'', valResult:null, sweepWif:'', sweepDest:'', sweepFee:'' },
  dev:{ decodeInput:'', decoded:null, decodeErr:null, rawTx:'', qrAddr:'', qrAmount:'', qrLabel:'', xpub:'', xpubType:'wpkh', psbt:'' },
};

/* ----------------------------- wallet lifecycle ----------------------------- */
function countKey(){ return state.coin+'.'+state.addrType+'.'+state.account; }
function addrCount(){
  return (store.counts && store.counts[state.wallet.id] && store.counts[state.wallet.id][countKey()]) || 1;
}
function setAddrCount(n){
  store.counts = store.counts || {};
  store.counts[state.wallet.id] = store.counts[state.wallet.id] || {};
  store.counts[state.wallet.id][countKey()] = n;
  saveStore();
}
function buildAddresses(){
  if(COINS[state.coin].addrModel === 'monero') return buildMoneroAddresses();
  const n = addrCount();
  state.balances = {}; state.totalSats = 0; state.confirmedSats = 0; state.txs = []; state.error = null;
  if(state.send){ state.send.utxos = null; state.send.selected = {}; }   // address set changed → stale coin-control cache
  state.expandedTx = null;
  try {                                         // if a @scure call ever throws, don't brick boot
    const addrs = [];
    for(let i=0;i<n;i++){
      const node = deriveNode(state.addrType, i);
      addrs.push({ index:i, path:pathFor(state.addrType,i), address:addrFromPub(node.publicKey, state.coin, state.addrType) });
    }
    state.addresses = addrs;
  } catch(e){
    state.addresses = [];
    state.error = 'Could not derive '+TYPES[state.addrType].label+' addresses: '+(e.message||e);
  }
}
function buildMoneroAddresses(){
  state.balances = {}; state.totalSats = 0; state.confirmedSats = 0; state.txs = []; state.error = null; state.expandedTx = null;
  if(state.send){ state.send.utxos = null; state.send.selected = {}; }
  if(state.xmrOk !== true || !state.xmrKeys){
    state.addresses = []; state.error = state.xmrOk === false ? 'Monero self-test failed; receive disabled.' : 'Monero keys unavailable.'; return;
  }
  const net = xmr.XMR_NETS[state.xmrNet] || xmr.XMR_NETS.stagenet, major = state.xmrAccount || 0;
  const n = addrCount(), addrs = [];
  try { for(let i=0;i<n;i++) addrs.push({ index:i, path:'account '+major+'/subaddress '+i, address: xmr.subaddress(state.xmrKeys, net, major, i) }); state.addresses = addrs; }   // major = selected Monero account (default 0)
  catch(e){ state.addresses = []; state.error = 'Could not derive Monero addresses: '+(e.message||e); }
}
function openWallet(w){
  _lastBal = null; _lastPending = new Set();                 // don't flash/settle across a wallet switch
  state.wallet = w;
  state.scheme = isElectrum(w) ? w.scheme : 'bip39';
  if(state.scheme !== 'bip39'){                              // Electrum wallet: root cached at import (sync), no Monero
    state.master = HDKey.fromExtendedKey(w.xprv);
    state.addrType = ELECTRUM_SCHEMES[state.scheme].addrType; state.account = 0; state.xmrKeys = null;
    state.xmr = { wallet:null, syncing:false, synced:false, pct:0, restoreHeight:0, start:0, height:0, endHeight:0, balance:null, unlocked:null, txs:[], accounts:[], error:null, node:null };
    state.xmrAccount = 0; store.activeId = w.id; saveStore(); buildAddresses(); render(); refresh(); return;
  }
  state.master = HDKey.fromMasterSeed(mnemonicToSeedSync(w.mnemonic, w.passphrase || ''));
  state.addrType = (store.settings && TYPES[store.settings.addrType]) ? store.settings.addrType : (TYPES[state.addrType] ? state.addrType : 'wpkh');   // don't inherit a prior Electrum wallet's locked type
  try { state.xmrKeys = state.xmrOk === true ? xmr.keysFromSecret(state.master.derive("m/44'/128'/0'/0'").privateKey) : null; } catch(_){ state.xmrKeys = null; }
  state.xmr = { wallet:null, syncing:false, synced:false, pct:0, restoreHeight:0, start:0, height:0, endHeight:0, balance:null, unlocked:null, txs:[], accounts:[], error:null, node:null };   // reset Monero sync on wallet switch
  state.xmrAccount = 0;
  store.activeId = w.id; saveStore();
  buildAddresses(); render(); refresh();
}
function saveSettings(){
  store.settings = Object.assign({}, store.settings, { theme: document.documentElement.getAttribute('data-theme'),
    coin: state.coin, addrType: state.addrType, fiat: state.fiat, account: state.account,
    hideBalance: state.hideBalance, refreshMs: state.refreshMs, feePref: state.feePref, xmrNet: state.xmrNet });   // spread keeps extra keys (e.g. custom api)
  saveStore();
}
function addWallet(name, mnemonic, passphrase){
  const w = { id: uid(), name: name || ('Wallet '+((store.wallets||[]).length+1)), mnemonic };
  if(passphrase) w.passphrase = passphrase;
  store.wallets = store.wallets || []; store.wallets.push(w); saveStore();
  closeModal(); openWallet(w);
}

/* ===================== Electrum seed import (single-sig) =====================
 * Electrum's scheme is NOT BIP39/BIP44. Seed type = prefix of HMAC-SHA512("Seed version", seed);
 * root = PBKDF2-HMAC-SHA512(seed, "electrum"+passphrase, 2048, 64B); paths: segwit m/0'/{0,1}/i (P2WPKH),
 * standard m/{0,1}/i (P2PKH). Testnet uses IDENTICAL paths - only the address encoding differs.
 * Detection + seed->root use Web Crypto (async); the derived root xprv is cached on the wallet record so
 * openWallet/pathFor stay synchronous. Gated by electrumSelfTest() against Electrum's published vectors.
 * Verified against electrum/mnemonic.py, keystore.py, version.py + tests/test_wallet_vertical.py. */
const ELECTRUM_SCHEMES = { 'electrum-segwit':{ addrType:'wpkh', label:'Native SegWit (Electrum)', acct:"m/0'" },
                           'electrum-legacy':{ addrType:'pkh',  label:'Legacy (Electrum)',         acct:'m' } };
function isElectrum(w){ return !!(w && w.scheme && ELECTRUM_SCHEMES[w.scheme]); }
let _electrumOk = null;                                       // cached self-test result (null until first run)

// Electrum normalize_text: NFKD -> lowercase -> strip combining marks -> collapse whitespace (CJK-space rule
// omitted; it only affects CJK seeds and never English ones).
function electrumNormalize(s){
  return String(s||'').normalize('NFKD').toLowerCase().replace(/\p{M}/gu,'').replace(/\s+/g,' ').trim();
}
async function electrumHmacHex(normSeed){
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode('Seed version'), { name:'HMAC', hash:'SHA-512' }, false, ['sign']);
  return bytesToHex(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(normSeed))));
}
async function electrumSeedToRoot(normSeed, passphrase){
  const enc = new TextEncoder();
  const salt = enc.encode('electrum' + electrumNormalize(passphrase || ''));
  const km = await crypto.subtle.importKey('raw', enc.encode(normSeed), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', hash:'SHA-512', salt, iterations:2048 }, km, 512);
  return HDKey.fromMasterSeed(new Uint8Array(bits));
}
function electrumLooksOld(normSeed){                          // heuristic, only for a friendlier message
  if(/^[0-9a-f]{32}$/.test(normSeed) || /^[0-9a-f]{64}$/.test(normSeed)) return true;
  const w = normSeed.split(' ').filter(Boolean).length;
  return (w === 12 || w === 24) && !validateMnemonic(normSeed, wordlist);
}
// Detect seed type from the normalized seed. Returns {ok, scheme, seed} or {ok:false, reason}.
async function electrumDetect(rawSeed){
  const seed = electrumNormalize(rawSeed);
  if(!seed) return { ok:false, reason:'Enter your Electrum seed.' };
  const h = await electrumHmacHex(seed);
  if(h.startsWith('100')) return { ok:true, scheme:'electrum-segwit', seed };
  if(h.startsWith('101') || h.startsWith('102')) return { ok:false, reason:'This is an Electrum 2FA seed - a 2-of-3 multisig that needs Electrum’s TrustedCoin service, so it can’t be imported as a single-sig wallet.' };
  if(h.startsWith('01')) return { ok:true, scheme:'electrum-legacy', seed };
  if(electrumLooksOld(seed)) return { ok:false, reason:'This looks like an old (pre-2.0) Electrum seed, which uses a different non-BIP32 derivation that isn’t supported.' };
  if(validateMnemonic(seed, wordlist)) return { ok:false, reason:'That’s a BIP39 recovery phrase - use “Import recovery phrase” instead.' };
  return { ok:false, reason:'Not a recognised Electrum seed (check spelling and word order).' };
}

// Validate the full chain (normalize -> PBKDF2 -> HDKey -> path -> address) against Electrum's published
// mainnet vectors. Cached; gates import so a broken environment never derives wrong addresses.
async function electrumSelfTest(){
  const seg = electrumNormalize('bitter grass shiver impose acquire brush forget axis eager alone wine silver');
  const std = electrumNormalize('cycle rocket west magnet parrot shuffle foot correct salt library feed song');
  if(!(await electrumHmacHex(seg)).startsWith('100')) return false;
  if(!(await electrumHmacHex(std)).startsWith('01')) return false;
  const segAddr = btc.p2wpkh((await electrumSeedToRoot(seg,'')).derive("m/0'/0/0").publicKey, btc.NETWORK).address;
  if(segAddr !== 'bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af') return false;
  const stdAddr = btc.p2pkh((await electrumSeedToRoot(std,'')).derive('m/0/0').publicKey, btc.NETWORK).address;
  if(stdAddr !== '1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf') return false;
  return true;
}
async function electrumSelfTestOk(){
  if(_electrumOk === null){ try { _electrumOk = await electrumSelfTest(); } catch(_){ _electrumOk = false; } }
  return _electrumOk;
}

// Import an Electrum seed as a new wallet (caches the derived root xprv for sync derivation).
async function electrumImport(rawSeed, name, passphrase){
  const det = await electrumDetect(rawSeed);
  if(!det.ok) throw new Error(det.reason);
  if(!(await electrumSelfTestOk())) throw new Error('The Electrum derivation self-test failed in this browser, so import is disabled to avoid showing wrong addresses. Please report this.');
  const root = await electrumSeedToRoot(det.seed, passphrase);
  const rec = { id: uid(), name: name || ('Electrum '+((store.wallets||[]).length+1)), scheme: det.scheme,
    mnemonic: det.seed, xprv: root.privateExtendedKey };
  if(passphrase) rec.passphrase = passphrase;
  store.wallets = store.wallets || []; store.wallets.push(rec); saveStore();
  if(COINS[state.coin].addrModel === 'monero'){ state.coin = 'btc'; saveSettings(); }   // Electrum is a Bitcoin wallet
  closeModal(); openWallet(rec);
  toast('Imported '+ELECTRUM_SCHEMES[det.scheme].label, 'ok');
}

/* ---- full backup snapshot: every wallet + contacts + tx notes + derived-address counts + settings ---- */
function snapshotData(){
  return {
    type:'testnetwallet-backup', version:2, exportedAt: new Date().toISOString(),
    wallets: (store.wallets||[]).map(w => ({ id:w.id, name:w.name, mnemonic:w.mnemonic, ...(w.passphrase?{passphrase:w.passphrase}:{}), ...(w.scheme?{scheme:w.scheme,xprv:w.xprv}:{}) })),
    activeId: store.activeId || null,
    counts: store.counts || {},
    txNotes: store.txNotes || {},
    contacts: store.contacts || [],
    multisig: (store.multisig || []).filter(msValidRecord),
    settings: store.settings || {},
  };
}
function exportSnapshot(){
  const pw = el('input',{type:'password',placeholder:'Password (recommended)',autocomplete:'new-password'});
  const out = el('div',{});
  const dl = el('button',{class:'btn'},'Download backup');
  const name = ()=> 'testnetwallet-backup-' + new Date().toISOString().slice(0,10) + '.json';
  dl.addEventListener('click', async ()=>{
    const json = JSON.stringify(snapshotData(), null, 2);
    if(pw.value){
      if(pw.value.length < 8){ clear(out).append(el('div',{class:'msg bad'},'Use at least 8 characters, or leave blank for an unencrypted file.')); return; }
      dl.disabled = true; dl.textContent = 'Encrypting…';
      try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const e = await encWith(await deriveKey(pw.value, salt, KDF_ITER), json);
        downloadBlob(new Blob([JSON.stringify({ tnwbackup:1, kdf:'PBKDF2', iter:KDF_ITER, salt:b64encode(salt), iv:e.iv, ct:e.ct }, null, 2)],{type:'application/json'}), name());
        closeModal();
      } catch(err){ clear(out).append(el('div',{class:'msg bad'},'Encrypt failed: '+(err.message||err))); dl.disabled=false; dl.textContent='Download backup'; }
    } else {
      downloadBlob(new Blob([json],{type:'application/json'}), name()); closeModal();
    }
  });
  showModal(el('div',{},
    el('div',{class:'card-h'},'Export backup'),
    el('div',{class:'card-b stack'},
      el('div',{class:'sub'},'This file contains your recovery phrase(s). Set a password to encrypt it (AES-256-GCM) - strongly recommended. Leave blank to download an unencrypted file (anyone who opens it can read your seed).'),
      el('div',{class:'field'}, el('label',{class:'fld'},'Encryption password'), pw),
      el('div',{class:'row',style:'flex:0'}, dl, el('button',{class:'btn ghost',onclick:()=>actSettings()},'Cancel')), out)));
  setTimeout(()=>{ try{ pw.focus(); }catch(_){} }, 30);
}
// Restore a backup of any known shape (v2 full snapshot, old all-wallets, or single wallet). Non-destructive:
// a fresh browser adopts the whole snapshot; an existing store merges in what's new without deleting anything.
function importBackup(data){
  if(!data || typeof data !== 'object') throw new Error('not a backup file');
  const incoming = Array.isArray(data.wallets) ? data.wallets : (data.mnemonic ? [data] : null);
  if(!incoming) throw new Error('no wallets found in this file');
  const norm = w => {
    if(w && w.scheme && ELECTRUM_SCHEMES[w.scheme]){                    // Electrum wallet: validate the cached xprv, not BIP39
      if(typeof w.xprv !== 'string') return null;
      try { HDKey.fromExtendedKey(w.xprv); } catch(_){ return null; }
      return { id:(typeof w.id==='string' && w.id) || uid(), name:(typeof w.name==='string' && w.name.trim()) || '',
        scheme:w.scheme, mnemonic: typeof w.mnemonic==='string' ? w.mnemonic : '', xprv:w.xprv,
        passphrase: typeof w.passphrase==='string' ? w.passphrase : '' };
    }
    const m = normalizePhrase((w && w.mnemonic) || '');
    if(!validateMnemonic(m, wordlist)) return null;
    return { id:(typeof w.id==='string' && w.id) || uid(),
      name:(typeof w.name==='string' && w.name.trim()) || '',
      mnemonic:m, passphrase: typeof w.passphrase==='string' ? w.passphrase : '' };
  };
  const valid = incoming.map(norm).filter(Boolean);
  if(!valid.length) throw new Error('no valid recovery phrases in this file');

  const fresh = !(store.wallets && store.wallets.length);
  store.wallets = store.wallets || [];
  const sig = w => (w.xprv || w.mnemonic || '') + '\n' + (w.passphrase || '');
  const have = new Set(store.wallets.map(sig));
  let addedW = 0, addedC = 0;
  for(const w of valid){
    if(have.has(sig(w))) continue;
    if(store.wallets.some(x => x.id === w.id)) w.id = uid();            // keep ids (so counts/notes line up), but never collide
    const rec = { id:w.id, name: w.name || ('Wallet '+(store.wallets.length+1)), mnemonic:w.mnemonic };
    if(w.passphrase) rec.passphrase = w.passphrase;
    if(w.scheme && ELECTRUM_SCHEMES[w.scheme]){ rec.scheme = w.scheme; rec.xprv = w.xprv; }
    store.wallets.push(rec); have.add(sig(w)); addedW++;
  }
  if(data.counts && typeof data.counts === 'object'){ store.counts = store.counts || {};
    for(const k of Object.keys(data.counts)) if(store.counts[k] == null) store.counts[k] = data.counts[k]; }
  if(data.txNotes && typeof data.txNotes === 'object'){ store.txNotes = store.txNotes || {};
    for(const k of Object.keys(data.txNotes)) store.txNotes[k] = Object.assign({}, data.txNotes[k], store.txNotes[k]); }
  if(Array.isArray(data.contacts)){ store.contacts = store.contacts || [];
    const addrs = new Set(store.contacts.map(c => c.address));
    for(const ct of data.contacts){ if(ct && ct.name && ct.address && !addrs.has(ct.address)){
      store.contacts.push({ name:String(ct.name), address:String(ct.address) }); addrs.add(ct.address); addedC++; } } }
  if(Array.isArray(data.multisig)){ store.multisig = store.multisig || [];          // watch-only multisig configs (no secrets)
    const haveIds = new Set(store.multisig.map(w=>w.id));
    const haveDesc = new Set(store.multisig.map(w=>{ try { return msExportDescriptor(w); } catch(_){ return w.id; } }));
    for(const w of data.multisig){ if(!msValidRecord(w)) continue;
      let dsc=null; try { dsc = msExportDescriptor(w); } catch(_){}
      if(dsc && haveDesc.has(dsc)) continue;                                          // already have this exact wallet
      const rec = Object.assign({}, w);
      if(haveIds.has(rec.id)) rec.id = uid();
      store.multisig.push(rec); haveIds.add(rec.id); if(dsc) haveDesc.add(dsc); } }
  if(fresh){                                                            // only adopt settings/active wallet onto an empty store
    if(data.settings && typeof data.settings === 'object'){             // whitelist keys: never adopt a custom `api` endpoint from a file
      const ALLOWED = ['theme','coin','addrType','fiat','account','hideBalance','refreshMs','feePref'];
      const s = {}; for(const k of ALLOWED) if(k in data.settings) s[k] = data.settings[k];
      store.settings = s;
    }
    if(typeof data.activeId === 'string') store.activeId = data.activeId;
  }
  saveStore();
  return { wallets: addedW, contacts: addedC };
}
function finishImport(res){
  toast('Imported '+res.wallets+' wallet'+(res.wallets===1?'':'s')+(res.contacts?(' · '+res.contacts+' contact'+(res.contacts===1?'':'s')):''), 'ok');
  if(store.settings && store.settings.theme) applyTheme(store.settings.theme);
  closeModal();
  const active = (store.wallets||[]).find(w => w.id === store.activeId) || (store.wallets||[])[0];
  if(active && !state.wallet) openWallet(active); else render();
}

// Concurrency-limited map - bounds the burst of Esplora calls on a wide (discovered) wallet.
async function pmap(items, fn, limit){
  const out = new Array(items.length); let i = 0;
  const worker = async ()=>{ while(i < items.length){ const idx = i++; out[idx] = await fn(items[idx], idx); } };
  await Promise.all(Array.from({ length: Math.min(limit, items.length || 1) }, worker));
  return out;
}

/* Gap-limit address discovery (BIP44): the wallet only derives addrCount() addresses, so coins received on
 * a higher index, common after importing a seed/Electrum wallet used elsewhere, would be invisible and
 * unspendable. This walks ahead in parallel windows until GAP_LIMIT consecutive UNUSED addresses, then bumps
 * the persisted count to cover every used one. Runs once per (wallet,coin,type,account) per session. */
const GAP_LIMIT = 20;
let _discoverTok = 0;
const _discovered = new Set();
async function discoverAddresses(ck){
  if(!state.wallet || !state.master || COINS[state.coin].addrModel === 'monero'){ _discovered.delete(ck); return; }
  // Capture the FULL context up front (incl. account + scheme + master + wallet id) and derive against it
  // explicitly - never read live state.account across an await, so an account/coin/type switch can't mis-key
  // the write or scan a mix of accounts.
  const tok = ++_discoverTok, coin = state.coin, type = state.addrType, account = state.account, scheme = state.scheme, master = state.master, wid = state.wallet.id;
  const cKey = coin+'.'+type+'.'+account;
  const curCount = () => (store.counts && store.counts[wid] && store.counts[wid][cKey]) || 1;
  const pathAt = (i) => (scheme && ELECTRUM_SCHEMES[scheme])
    ? (scheme==='electrum-segwit' ? `m/0'/0/${i}` : `m/0/${i}`)
    : `m/${TYPES[type].purpose}'/1'/${account}'/0/${i}`;
  const WIN = 10;
  let start = 0, highestUsed = -1, consecUnused = 0;
  // Write the extended count for the CAPTURED context (the token guards against a wallet switch, since
  // openWallet→refresh bumps it) and repaint, but only if the user is still viewing this exact context.
  // Called incrementally so an imported wallet's balance shows as soon as funds are found, not after the
  // whole gap scan completes.
  const commit = () => {
    if(tok !== _discoverTok || highestUsed + 1 <= curCount()) return;
    store.counts = store.counts || {}; store.counts[wid] = store.counts[wid] || {}; store.counts[wid][cKey] = highestUsed + 1; saveStore();
    if(state.wallet && state.wallet.id===wid && state.coin===coin && state.addrType===type && state.account===account){ buildAddresses(); render(); refresh(); }
  };
  while(start < 250 && consecUnused < GAP_LIMIT){
    let addrs;
    try { addrs = Array.from({length:WIN}, (_,k)=> addrFromPub(master.derive(pathAt(start+k)).publicKey, coin, type)); }
    catch(_){ _discovered.delete(ck); return; }            // let this context retry on a later refresh
    const used = await Promise.all(addrs.map(a => apiGet(coin, '/address/'+encodeURIComponent(a))
      .then(s => (((s.chain_stats&&s.chain_stats.tx_count)||0) + ((s.mempool_stats&&s.mempool_stats.tx_count)||0)) > 0).catch(()=>false)));
    if(tok !== _discoverTok){ _discovered.delete(ck); return; }   // superseded by a newer scan - retry later
    const prevHighest = highestUsed;
    for(let k=0;k<WIN;k++){ if(used[k]){ highestUsed = Math.max(highestUsed, start+k); consecUnused = 0; } else consecUnused++; }
    if(highestUsed > prevHighest) commit();                // repaint the moment new used addresses appear
    start += WIN;
  }
  commit();                                                // final pass (covers the last extension)
}

/* ----------------------------- data refresh (race-guarded) ----------------------------- */
async function refresh(){
  if(!state.wallet) return;
  if(COINS[state.coin].addrModel === 'monero'){ state.loading = false; state.error = null; renderStatus(); return; }   // no backend yet (Phase 1)
  const ck = state.wallet.id+'|'+state.coin+'|'+state.addrType+'|'+state.account;
  if(!_discovered.has(ck)){ _discovered.add(ck); discoverAddresses(ck); }   // one-time gap-limit discovery per context (retries itself if superseded)
  const seq = ++state.refreshSeq;
  state.loading = true; renderStatus();
  const addrs = state.addresses.map(a => a.address);
  const addrSet = new Set(addrs);
  try {
    const statsList = await pmap(addrs, a => getStats(state.coin, a).then(s=>[a,s]).catch(()=>[a,null]), 8);
    if(seq !== state.refreshSeq) return;                 // a newer refresh superseded us
    let total = 0, confirmed = 0, ok = 0;
    for(const [a,s] of statsList){ if(!s) continue; ok++; state.balances[a] = s; total += s.total; confirmed += s.confirmed; }
    state.totalSats = total; state.confirmedSats = confirmed;
    if(ok === 0 && addrs.length) throw new Error('network unreachable');

    const txLists = await pmap(addrs, a => getTxs(state.coin, a).catch(()=>[]), 8);
    if(seq !== state.refreshSeq) return;
    const seen = new Map();
    for(const list of txLists) for(const tx of list){
      if(seen.has(tx.txid)) continue;
      seen.set(tx.txid, {
        txid: tx.txid,
        confirmed: !!(tx.status && tx.status.confirmed),
        time: (tx.status && tx.status.block_time) || null,
        block_height: (tx.status && tx.status.block_height) || null,
        net: txNet(tx, addrSet),
        fee: tx.fee || 0,
        vsize: tx.weight ? Math.ceil(tx.weight/4) : (tx.size || null),
        vin: (tx.vin||[]).map(v=>({ address:(v.prevout && v.prevout.scriptpubkey_address) || null,
          value: v.prevout ? v.prevout.value : null, mine: !!(v.prevout && addrSet.has(v.prevout.scriptpubkey_address)) })),
        vout: (tx.vout||[]).map(o=>({ address: o.scriptpubkey_address || null, value: o.value, mine: addrSet.has(o.scriptpubkey_address) })),
      });
    }
    state.txs = [...seen.values()].sort((a,b)=>(b.time||2e9)-(a.time||2e9));
    state.histTruncated = txLists.some(l => l && l.truncated);   // per-refresh (no shared global race)
    state.error = null;
    autoRotateReceiveAddress();   // once the shown receive address has been used, advance to a fresh one (Cake/Electrum-style)
  } catch(e){
    if(seq !== state.refreshSeq) return;
    state.error = e.message || String(e);
  } finally {
    if(seq === state.refreshSeq){ state.loading = false; render(); }
  }
  getPrice(COINS[state.coin].priceSym, state.fiat).then(p => { if(seq===state.refreshSeq){ state.price = p; render(); } });
  getTipHeight(state.coin).then(h => { if(seq===state.refreshSeq && h){ state.tipHeight = h; render(); } });
}

/* ============================== RENDER ============================== */
function render(){
  const view = $('view');
  const lb = $('lock-toggle'); if(lb) lb.style.display = (isEncrypted() && !isLocked()) ? 'inline-flex' : 'none';
  if(isLocked()){ clear(view).append((_softLocked && _cryptoKey) ? renderPinScreen() : renderLockScreen()); a11yify(); return; }
  if(!state.wallet){ clear(view).append(renderOnboarding()); return; }
  const parts = [renderControls(), renderBalance()];
  if(state.addresses.length) parts.push(renderTabs(), renderPanel());
  else parts.push(el('div',{class:'card'}, el('div',{class:'card-b'}, el('p',{class:'bad'}, state.error || 'No addresses available.'))));
  clear(view).append(...parts);
  a11yify();
}
// Make the div-based pills/tabs/copy links keyboard-operable (role + tabindex; Enter/Space handled globally below).
function a11yify(){
  document.querySelectorAll('.pill,.tab,.copy').forEach(e=>{
    e.setAttribute('role', e.classList.contains('tab') ? 'tab' : 'button');
    e.setAttribute('tabindex', e.classList.contains('disabled') ? '-1' : '0');
  });
}
document.addEventListener('keydown', e=>{
  if(e.key!=='Enter' && e.key!==' ') return;
  const t = e.target;
  if(t && t.classList && (t.classList.contains('pill')||t.classList.contains('tab')||t.classList.contains('copy')) && !t.classList.contains('disabled')){
    e.preventDefault(); t.click();
  }
});
function renderStatus(){ const s = $('status'); if(s) clear(s).append(statusContent()); }
function statusContent(){
  if(state.loading) return el('span',{class:'sub'},'updating…');
  if(state.error) return el('span',{class:'sub bad'},'⚠ '+state.error+' (showing last data)');
  return el('span',{class:'sub'},' ');
}

/* ---- onboarding ---- */
function renderOnboarding(){
  const learn = el('details',{class:'card',style:'margin:14px 0 0'},
    el('summary',{style:'padding:13px 18px;cursor:pointer;font-weight:600;font-size:14px'},'New to crypto? Start here'),
    el('div',{class:'card-b stack'},
      el('p',{class:'sub'},'This is a wallet for ', el('b',{},'testnet'), ', the free practice versions of Bitcoin, Litecoin and Monero. The coins have ', el('b',{},'no real value'), ', so you can learn how addresses, sending, confirmations and privacy actually work without risking real money.'),
      el('p',{class:'sub'},'A good first run: 1) Create a wallet. You’ll get a 12-word recovery phrase; write it down, it’s your only backup. 2) Copy your receive address. 3) Get free test coins from the faucet. 4) Send some and watch it confirm. 5) When you’re curious, explore message signing and the developer tools.'),
      el('p',{class:'sub faint'},'Your recovery phrase and keys never leave this browser, and it’s open source. One rule: a testnet phrase is for practice. Never reuse it on a real (mainnet) wallet.')));
  return el('div',{},
    el('div',{class:'card'},
      el('div',{class:'card-h'},'Welcome to TestnetWallet'),
      el('div',{class:'card-b'},
        el('p',{class:'muted'},'A safe place to learn and build on the Bitcoin, Litecoin and Monero testnets. Practice with crypto where real value is never at risk. Your recovery phrase and keys stay in this browser.'),
        el('div',{class:'row',style:'margin-top:8px'},
          el('button',{class:'btn',onclick:actCreate},'Create new wallet'),
          el('button',{class:'btn ghost',onclick:actImport},'Import recovery phrase')),
        el('p',{class:'sub',style:'margin-top:16px'},'Need coins to practice with? Grab free test coins from ',
          el('a',{href:'https://cypherfaucet.com',target:'_blank',rel:'noopener'},'CypherFaucet'),'.'))),
    learn);
}

/* ---- controls (wallet name, coin, address type) ---- */
function renderControls(){
  const coinPills = el('div',{class:'pills'});
  for(const [key,c] of Object.entries(COINS)){
    const p = el('div',{class:'pill'+(key===state.coin?' active':'')+(c.enabled?'':' disabled'),
      title:c.enabled?'':((key==='xmr'&&!MONERO_ENABLED)?'Monero is temporarily unavailable while the nodes are being set up':'Temporarily unavailable (a startup self-test failed in this browser)')},
      el('img',{class:'coin-ico',src:'icons/'+key+'.svg',alt:''}), c.name);
    if(c.enabled) p.addEventListener('click', ()=>switchCoin(key));
    coinPills.append(p);
  }
  const TYPE_HELP = {
    pkh: 'Legacy (P2PKH). The original address format (m…/n… on testnet). Works everywhere, but costs the most to spend.',
    'sh-wpkh': 'Nested SegWit (P2SH-P2WPKH, 2…). SegWit wrapped in a legacy-looking address for older-wallet compatibility.',
    wpkh: 'Native SegWit (bech32, tb1q…). The modern default - lower fees, widely supported.',
    tr: 'Taproot (bech32m, tb1p…). Newest format - best privacy and efficiency; needs a recent wallet to receive from.',
  };
  const typePills = el('div',{class:'pills'});
  for(const [key,t] of Object.entries(TYPES)){
    const p = el('div',{class:'pill'+(key===state.addrType?' active':''),title:TYPE_HELP[key]||''}, t.label);
    p.addEventListener('click', ()=>switchType(key));
    typePills.append(p);
  }
  const xmrMode = COINS[state.coin].addrModel === 'monero';
  const electrum = !!(state.scheme && ELECTRUM_SCHEMES[state.scheme]);
  let netPills = null;
  if(xmrMode){ netPills = el('div',{class:'pills'});
    for(const [k,nn] of Object.entries(xmr.XMR_NETS)){ const p = el('div',{class:'pill'+(state.xmrNet===k?' active':'')}, nn.label);
      if(state.xmrNet!==k) p.addEventListener('click', ()=>switchXmrNet(k)); netPills.append(p); } }
  return el('div',{class:'card'},
    el('div',{class:'card-h'},
      el('span',{}, state.wallet.name),
      el('div',{class:'row',style:'flex:1;justify-content:flex-end;gap:8px'},
        el('button',{class:'btn ghost sm',onclick:actBackup},'Backup'),
        el('button',{class:'btn ghost sm',onclick:()=>actContacts(null)},'Contacts'),
        el('button',{class:'btn ghost sm',onclick:actWallets},'Wallets'),
        el('button',{class:'btn ghost sm',onclick:actSettings},'Settings'),
      )),
    el('div',{class:'card-b stack'},
      el('div',{class:'between'}, el('span',{class:'sub'},'Coin'), coinPills),
      el('div',{class:'between'}, el('span',{class:'sub',title:xmrMode?'Stagenet and testnet are two independent Monero test networks.':'Different address formats from the same recovery phrase. Hover each for details.'}, xmrMode?'Network':(electrum?'Wallet type':'Address type')),
        xmrMode?netPills:(electrum ? el('span',{class:'sub'}, ELECTRUM_SCHEMES[state.scheme].label) : typePills)),
      electrum ? el('div',{class:'sub faint',style:'margin-top:-2px;font-size:12px'},'Imported from an Electrum seed. The address type and derivation are fixed to match Electrum.') : null,
      (xmrMode||electrum) ? null : el('div',{class:'sub faint',style:'margin-top:2px;font-size:12px'},'Different formats from your one recovery phrase. SegWit (tb1q…) is the default; Taproot (tb1p…) is newest.'),
      (xmrMode||electrum) ? null : el('div',{class:'between'},
        el('span',{class:'sub',title:'BIP-44 account index (advanced): a separate, independent set of addresses derived from the same recovery phrase. Leave at 0 unless you want to keep funds in distinct accounts.'},'Account index'),
        el('input',{type:'number',min:'0',value:state.account,style:'max-width:80px','aria-label':'BIP account index',title:'Advanced: BIP account index. Leave at 0 unless you want a separate set of addresses.',
          onchange:e=>{ const a=Math.max(0,parseInt(e.target.value)||0); if(a===state.account){ render(); return; } state.account=a; saveSettings(); buildAddresses(); render(); refresh(); }})),
      (xmrMode||electrum) ? null : el('div',{class:'sub faint',style:'margin-top:-2px;font-size:12px'},'A separate set of addresses under the same recovery phrase. Most people leave this at 0.'),
    ));
}

/* ---- balance ---- */
function renderMoneroHero(c){
  const net = xmr.XMR_NETS[state.xmrNet] || xmr.XMR_NETS.stagenet;
  const sx = state.xmr, nodeUrl = xmrNodeUrl();
  if(nodeUrl && !sx.syncing && !sx.synced && !moneroEngine.isLoaded()) moneroEngine.load().catch(()=>{});   // warm the ~6 MB engine while the user is on the Monero screen, so Connect & sync is instant
  if(nodeUrl && !sx.syncing) probeXmrNode();                // refresh the node-status line (cheap /get_info, cached 30s, in-flight-guarded)
  const balLine = (sx.synced && sx.balance != null) ? (fmtXmr(sx.balance) + ' XMR') : '- XMR';
  let status;
  if(sx.syncing) status = el('div',{id:'xmr-sync',class:'fiat'}, ...xmrStatusInner());
  else if(sx.synced) status = el('div',{class:'fiat'}, sx.txs.length + ' transaction' + (sx.txs.length===1?'':'s') + ' · testnet, no real value');
  else if(!nodeUrl) status = el('div',{class:'fiat'}, 'Set a Monero node in Settings to load your balance.');
  else status = el('div',{class:'fiat'}, 'Balance loads on demand (downloads a ~6 MB engine, then scans the chain)');
  const actions = [ el('button',{class:'btn ghost',onclick:()=>{ state.tab='receive'; render(); }}, '↓ Receive') ];
  if(nodeUrl && !sx.syncing) actions.unshift(el('button',{class:'btn',onclick:moneroSync}, sx.synced ? '↻ Re-sync' : '⇅ Connect & sync'));
  const hero = el('div',{class:'card hero'},
    el('div',{class:'card-b',style:'text-align:center'},
      el('div',{class:'between',style:'text-align:left'},
        el('span',{class:'sub',style:'display:inline-flex;align-items:center;gap:7px'}, el('img',{class:'coin-ico',src:'icons/xmr.svg',alt:''}), c.name+' · '+net.label),
        el('div',{})),
      el('div',{class:'balance',style:'margin:16px 0 2px'}, balLine),
      status,
      nodeUrl ? el('div',{id:'xmr-node',class:'sub faint',style:'margin-top:6px'}, ...xmrNodeLineInner()) : null,
      sx.error ? el('div',{class:'msg bad',style:'text-align:left'}, sx.error) : null,
      el('div',{class:'hero-actions'}, ...actions),
    ));
  if(!nodeUrl || sx.syncing) return hero;                  // restore-height control only when a node is set and not mid-scan
  const frag = document.createDocumentFragment();
  frag.append(hero, renderXmrRestore());
  return frag;
}
/* Cake-style "scan from height/date": only the FIRST scan walks the chain, so starting near where this wallet
 * first received funds (or the current tip for a new wallet) makes that one-time scan short. */
function renderXmrRestore(){
  const sx = state.xmr, walletId = state.wallet.id, net = state.xmrNet;
  const cur = getXmrRestore(walletId, net);
  const hInput = el('input',{type:'number',min:'0',step:'1',style:'max-width:150px',placeholder:'block height',value: cur!=null ? String(cur) : ''});
  const tipBtn = el('button',{class:'btn ghost sm'},'Use current tip');
  tipBtn.addEventListener('click', async ()=>{
    tipBtn.disabled=true; const orig=tipBtn.textContent; tipBtn.textContent='…';
    try { const h = await moneroEngine.getDaemonHeight(xmrNodeUrl()); if(h) hInput.value = String(Math.max(0, Number(h))); else toast('Could not fetch height','warn'); }
    catch(_){ toast('Could not fetch height','warn'); }
    finally { tipBtn.disabled=false; tipBtn.textContent=orig; }
  });
  const dInput = el('input',{type:'date',style:'max-width:170px'});
  dInput.addEventListener('change', async ()=>{
    if(!dInput.value) return;
    try {
      const h = await moneroEngine.getDaemonHeight(xmrNodeUrl());
      if(!h){ toast('Could not fetch height for the date estimate','warn'); return; }
      const chosen = new Date(dInput.value + 'T00:00:00').getTime();
      const back = Math.max(0, Math.floor((Date.now() - chosen) / 1000 / 120));   // ~120s per Monero block (all nets)
      hInput.value = String(Math.max(0, Number(h) - back));
    } catch(_){ toast('Could not estimate a height for that date','warn'); }
  });
  const applyBtn = el('button',{class:'btn sm'}, (sx.synced || sx.wallet) ? 'Re-scan from here' : 'Save');
  applyBtn.addEventListener('click', ()=>{
    const v = hInput.value.trim();
    const h = v==='' ? null : Math.max(0, parseInt(v,10) || 0);
    setXmrRestore(walletId, net, h);
    if(sx.synced || sx.wallet){                            // a scan cache exists -> a new start height needs a fresh scan
      try { localStorage.removeItem(xmrDataKey(walletId, net)); } catch(_){}
      state.xmr = { wallet:null, syncing:false, synced:false, pct:0, restoreHeight:0, start:0, height:0, endHeight:0, balance:null, unlocked:null, txs:[], accounts:[], error:null, node:null };
      toast('Restore height set. Re-scanning…','ok');
      moneroSync();
    } else { toast(h==null ? 'Cleared. Next sync uses the default.' : 'Saved. Used on next sync.','ok'); render(); }
  });
  return el('details',{class:'card',style:'margin:14px 0'},
    el('summary',{style:'padding:13px 18px;cursor:pointer;font-weight:600;font-size:14px'}, 'Scan from height' + (cur!=null ? (' · ' + cur.toLocaleString()) : ' (auto)')),
    el('div',{class:'card-b stack'},
      el('div',{class:'sub'},'Only the first scan walks the chain. Set this near where this wallet first received funds. A brand-new wallet can use the current tip for a near-instant sync. Leave blank for the default (recent window).'),
      el('div',{class:'row',style:'flex:0;align-items:center'}, hInput, tipBtn),
      el('div',{class:'row',style:'flex:0;align-items:center'}, el('span',{class:'sub'},'or from date'), dInput),
      el('div',{}, applyBtn)));
}
function renderBalance(){
  const c = COINS[state.coin];
  if(c.addrModel === 'monero') return renderMoneroHero(c);
  const fiat = state.price!=null
    ? el('div',{class:'fiat'},'≈ '+FIATS[state.fiat]+((state.totalSats/1e8)*state.price).toFixed(2)+' '+state.fiat+' · testnet, no real value')
    : el('div',{class:'fiat'},'testnet coins, no real value');
  const recvBtn = el('button',{class:'btn ghost',onclick:()=>{ state.tab='receive'; render(); }}, '↓ Receive');
  const sendBtn = el('button',{class:'btn',onclick:()=>{ state.tab='send'; render(); }}, '↑ Send');
  const eye = el('button',{class:'btn ghost sm',title:'Hide/show balance','aria-label':'Toggle balance visibility'}, state.hideBalance?'Show':'Hide');
  eye.addEventListener('click', ()=>{ state.hideBalance=!state.hideBalance; saveSettings(); render(); });
  const pending = state.totalSats - state.confirmedSats;
  const flashCls = (!state.hideBalance && _lastBal !== null && state.totalSats !== _lastBal) ? (state.totalSats > _lastBal ? ' up' : ' down') : '';
  _lastBal = state.totalSats;
  const bal = el('div',{class:'balance'+(state.hideBalance?' blurred':'')+flashCls,style:'margin:16px 0 2px'}, fmt(state.totalSats)+' '+c.ticker);
  if(state.hideBalance) bal.addEventListener('click', ()=>{ state.hideBalance=false; saveSettings(); render(); });
  return el('div',{class:'card hero'},
    el('div',{class:'card-b',style:'text-align:center'},
      el('div',{class:'between',style:'text-align:left'},
        el('span',{class:'sub',style:'display:inline-flex;align-items:center;gap:7px'}, el('img',{class:'coin-ico',src:'icons/'+state.coin+'.svg',alt:''}), c.name+' · '+TYPES[state.addrType].label),
        el('div',{class:'row',style:'flex:1;justify-content:flex-end;align-items:center;gap:8px'}, eye,
          el('button',{class:'btn ghost sm',onclick:refresh,title:'Refresh','aria-label':'Refresh balance'},'↻'))),
      bal,
      state.hideBalance ? null : fiat,
      (pending>0 && !state.hideBalance) ? el('div',{class:'sub warn',style:'margin-top:4px'}, fmt(pending)+' '+c.ticker+' pending · '+fmt(state.confirmedSats)+' '+c.ticker+' available') : null,
      el('div',{id:'status',class:'mt-2','aria-live':'polite'}, statusContent()),
      el('div',{class:'hero-actions'}, recvBtn, sendBtn),
    ));
}

/* ---- tabs ---- */
function renderTabs(){
  if(COINS[state.coin].addrModel === 'monero'){
    const bar = el('div',{class:'tabbar'});
    for(const [k,l] of [['receive','Receive'],['send','Send'],['history','History'],['advanced','Tools']]){
      const t = el('div',{class:'tab'+(k===state.tab?' active':'')}, l);
      t.addEventListener('click', ()=>{ state.tab = k; render(); }); bar.append(t);
    }
    return bar;
  }
  const tabs = [['receive','Receive'],['send','Send'],['history','History'],['advanced','Advanced']];
  const bar = el('div',{class:'tabbar'});
  for(const [key,label] of tabs){
    const t = el('div',{class:'tab'+(key===state.tab?' active':'')}, label);
    t.addEventListener('click', ()=>{ state.tab=key; render(); });
    bar.append(t);
  }
  return bar;
}
function renderPanel(){
  if(COINS[state.coin].addrModel === 'monero'){
    if(state.tab==='send') return renderMoneroSend();
    if(state.tab==='history') return renderMoneroHistory();
    if(state.tab==='advanced') return renderMoneroTools();
    return renderMoneroReceive();
  }
  if(state.tab==='receive') return renderReceive();
  if(state.tab==='history') return renderHistory();
  if(state.tab==='send')  return renderSend();
  if(state.tab==='advanced') return renderAdvanced();
}
// Tools + Developer tools live under one "Advanced" tab with a sub-toggle, to keep the main flow clean.
function renderAdvanced(){
  const frag = document.createDocumentFragment();
  const pills = el('div',{class:'pills',style:'margin:6px 0 2px'});
  for(const [k,l] of [['tools','Tools'],['dev','Developer'],['multisig','Multisig']]){
    const p = el('div',{class:'pill'+(state.advTab===k?' active':'')}, l);
    if(state.advTab!==k) p.addEventListener('click', ()=>{ state.advTab=k; render(); });
    pills.append(p);
  }
  frag.append(pills, state.advTab==='multisig' ? renderMultisig() : state.advTab==='dev' ? renderDev() : renderTools());
  return frag;
}
function placeholder(title, msg){
  return el('div',{class:'card'}, el('div',{class:'card-h'}, title),
    el('div',{class:'card-b'}, el('p',{class:'muted'}, msg)));
}

/* ---- QR helper: error-correction level H (tolerates a centered coin logo) ---- */
function qrEl(text, opts){
  if(!globalThis.qrcode) return null;
  try {
    const qr = qrcode(0, 'H'); qr.addData(text); qr.make();
    const box = el('div',{class:'qr'}, el('img',{src:qr.createDataURL(6,8), alt:'QR'}));
    if(opts && opts.coin) box.append(el('div',{class:'qr-logo'}, el('img',{src:'icons/'+opts.coin+'.svg', alt:''})));
    return box;
  } catch(_){ return null; }
}

function bip21(coin, address, amount, label){
  const params=[]; if(amount) params.push('amount='+encodeURIComponent(amount)); if(label) params.push('label='+encodeURIComponent(label));
  return COINS[coin].uri+':'+address+(params.length?'?'+params.join('&'):'');
}
function zoomQR(text, coin){
  const q = qrEl(text, {coin}); if(!q) return; const im = q.querySelector('img'); if(im){ im.style.width='280px'; im.style.height='280px'; }
  showModal(el('div',{}, el('div',{class:'card-b',style:'text-align:center'}, q,
    el('div',{class:'addr',style:'margin-top:10px;font-size:12px'}, text),
    el('div',{style:'margin-top:12px'}, el('button',{class:'btn ghost',onclick:closeModal},'Close')))));
}
/* ---- receive ---- */
function renderReceive(){
  const c = COINS[state.coin], rc = state.recv;
  const primary = state.addresses[state.addresses.length-1];      // newest derived address
  const uri = () => bip21(state.coin, primary.address, rc.amount, rc.label);
  const qrWrap = el('div',{style:'text-align:center'});
  const renderQR = ()=>{ clear(qrWrap); const q = qrEl(uri(), {coin:state.coin}); if(q){ q.style.cursor='zoom-in'; q.title='Tap to enlarge';
    q.addEventListener('click', ()=>zoomQR(uri(), state.coin)); qrWrap.append(q); } };
  renderQR();
  const amtIn = el('input',{type:'number',min:'0',step:'0.00000001',value:rc.amount,placeholder:'request amount (optional)',oninput:e=>{ rc.amount=e.target.value; renderQR(); }});
  const labIn = el('input',{type:'text',value:rc.label,placeholder:'label (optional)',oninput:e=>{ rc.label=e.target.value; renderQR(); }});
  const list = el('table',{}, el('thead',{}, el('tr',{}, el('th',{},'#'), el('th',{},'Address ('+TYPES[state.addrType].label+')'), el('th',{class:'amt'},'Balance'))));
  const tb = el('tbody',{});
  for(const a of state.addresses){
    const bal = state.balances[a.address];
    const copyEl = el('span',{class:'copy'},'copy');
    copyEl.addEventListener('click', ()=>copyText(a.address, copyEl));
    tb.append(el('tr',{...(a.index===_newAddrIdx?{class:'row-new'}:{})},
      el('td',{class:'mono faint'}, a.index),
      el('td',{}, el('div',{class:'addr'}, a.address), copyEl),
      el('td',{class:'amt'}, bal ? fmt(bal.total)+' '+c.ticker : (state.loading ? skel('70px') : '…'))));
  }
  _newAddrIdx = -1;                                          // highlight only once
  list.append(tb);
  const copyAddr = el('button',{class:'btn ghost sm'},'Copy address');
  copyAddr.addEventListener('click', ()=>copyText(primary.address, copyAddr));
  const copyReq = el('button',{class:'btn ghost sm'},'Copy request');
  copyReq.addEventListener('click', ()=>copyText(uri(), copyReq));
  const shareBtn = (navigator.share) ? el('button',{class:'btn ghost sm',onclick:()=>{ navigator.share({title:'Receive '+c.ticker, text:uri()}).catch(()=>{}); }},'Share') : null;
  return el('div',{class:'card'},
    el('div',{class:'card-h'}, 'Receive '+c.ticker,
      el('a',{class:'sub',href:c.explorer+'/address/'+primary.address,target:'_blank',rel:'noopener'},'explorer ↗')),
    el('div',{class:'card-b stack'},
      el('div',{class:'sub faint'},'Share this address to receive testnet '+c.ticker+'. It stays yours, and for privacy you can hand out a fresh one each time. They all belong to this wallet.'),
      qrWrap,
      el('div',{class:'sub'}, 'Latest address · '+primary.path),
      el('div',{class:'addr',style:'font-size:14px'}, primary.address),
      el('div',{class:'row'}, amtIn, labIn),
      el('div',{class:'row',style:'flex:0;margin:6px 0 4px'}, copyAddr, copyReq, shareBtn,
        el('button',{class:'btn ghost sm',onclick:deriveNext},'Derive next address')),
      renderFaucet(primary.address),
      el('hr',{class:'hr'}),
      el('div',{class:'sub'},'Your addresses'), list,
    ));
}
function deriveNext(){ _newAddrIdx = addrCount(); setAddrCount(addrCount()+1); buildAddresses(); render(); refresh(); }
// Keep a fresh, unused receive address on display: once the newest one has received funds (or shows up in
// history), derive the next so the next payment uses a new address. Used addresses stay in the list below.
function autoRotateReceiveAddress(){
  if(isLocked() || !state.addresses.length) return;
  const last = state.addresses[state.addresses.length-1].address;
  const bal = state.balances[last];
  const used = (bal && bal.total !== 0) || state.txs.some(t =>
    (t.vout||[]).some(o=>o.address===last) || (t.vin||[]).some(v=>v.address===last));
  if(used){ _newAddrIdx = addrCount(); setAddrCount(addrCount()+1); buildAddresses(); }   // advance by one; the new last is unused so it won't re-trigger
}
/* ---- Monero receive (Phase 1: pure-JS keygen, no backend) ---- */
// local per-wallet/network/account subaddress labels (kept client-side, not in the Monero cache)
function xmrLabelKey(idx){ return (state.xmrAccount||0) + '.' + idx; }
function getXmrLabel(idx){ const o = store.xmrLabels && store.xmrLabels[state.wallet.id] && store.xmrLabels[state.wallet.id][state.xmrNet]; return (o && o[xmrLabelKey(idx)]) || ''; }
function setXmrLabel(idx, label){
  store.xmrLabels = store.xmrLabels || {};
  const w = store.xmrLabels[state.wallet.id] = store.xmrLabels[state.wallet.id] || {};
  const n = w[state.xmrNet] = w[state.xmrNet] || {};
  const k = xmrLabelKey(idx);
  if(label && label.trim()) n[k] = label.trim(); else delete n[k];
  saveStore();
}
function renderMoneroReceive(){
  const c = COINS[state.coin], net = xmr.XMR_NETS[state.xmrNet] || xmr.XMR_NETS.stagenet;
  const primary = state.addresses[state.addresses.length-1];
  const uri = 'monero:'+primary.address;
  const qrWrap = el('div',{style:'text-align:center'});
  const q = qrEl(uri, {coin:'xmr'}); if(q){ q.style.cursor='zoom-in'; q.title='Tap to enlarge'; q.addEventListener('click',()=>zoomQR(uri,'xmr')); qrWrap.append(q); }
  const list = el('table',{}, el('thead',{}, el('tr',{}, el('th',{},'#'), el('th',{},'Subaddress'), el('th',{},'Label'), el('th',{},''))));
  const tb = el('tbody',{});
  for(const a of state.addresses){ const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click', ()=>copyText(a.address, cp));
    const lbl = el('input',{type:'text',value:getXmrLabel(a.index),placeholder:'label',style:'max-width:120px;font-size:12px;padding:.3em .5em'});
    lbl.addEventListener('input', e=>setXmrLabel(a.index, e.target.value));
    tb.append(el('tr',{}, el('td',{class:'mono faint'}, a.index===0?'main':a.index), el('td',{}, el('div',{class:'addr'}, a.address)), el('td',{}, lbl), el('td',{}, cp))); }
  list.append(tb);
  const copyAddr = el('button',{class:'btn ghost sm'},'Copy address'); copyAddr.addEventListener('click', ()=>copyText(primary.address, copyAddr));
  const keyHolder = el('div',{});
  const revealK = el('button',{class:'btn ghost sm'},'Show secret keys');
  revealK.addEventListener('click', ()=>{ const k = state.xmrKeys; if(!k) return;
    const cp = t => { const s = el('span',{class:'copy'},'copy'); s.addEventListener('click',()=>copyText(t,s,true)); return s; };
    const sHex = xmr.hex(k.spendBytes), vHex = xmr.hex(k.viewBytes);
    clear(keyHolder).append(el('div',{class:'msg warn'},
      el('div',{class:'sub'},'Private spend key ', cp(sHex)), el('div',{class:'addr'}, sHex),
      el('div',{class:'sub',style:'margin-top:6px'},'Private view key ', cp(vHex)), el('div',{class:'addr'}, vHex),
      el('div',{class:'sub',style:'margin-top:6px'},'To verify: restore these in monero-wallet-cli ('+net.label.toLowerCase()+', --generate-from-keys); it should reproduce the primary address above.')));
    revealK.remove(); });
  const seedHolder = el('div',{});
  const revealS = el('button',{class:'btn ghost sm'},'Show 25-word seed');
  revealS.addEventListener('click', ()=>{ if(!state.xmrKeys) return;
    let words; try { words = xmrSeed.encode25(state.xmrKeys.spendBytes); } catch(e){ clear(seedHolder).append(el('div',{class:'msg bad'},'Seed export failed: '+(e.message||e))); return; }
    const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(words,cp,true));
    clear(seedHolder).append(el('div',{class:'msg warn'},
      el('div',{class:'sub'},'Portable Monero seed - legacy 25-word ', cp), el('div',{class:'addr'}, words),
      el('div',{class:'sub',style:'margin-top:6px'},'Restores this exact wallet in monero-wallet-cli / Cake / Feather. Keep it secret.')));
    revealS.remove(); });
  // account selector (post-sync): pick/create Monero accounts; account 0 is the default
  let acctBar = null;
  const sx = state.xmr;
  if(sx.synced && sx.accounts && sx.accounts.length){
    const sel = el('select',{onchange:e=>{ const k=parseInt(e.target.value,10)||0; if(k===(state.xmrAccount||0)) return;
      state.xmrAccount=k; const a=sx.accounts.find(x=>x.index===k); sx.balance = a?a.balance:0n; sx.unlocked = a?a.unlocked:0n; buildMoneroAddresses(); render(); }});
    sx.accounts.forEach(a=> sel.append(el('option',{value:a.index,...(a.index===(state.xmrAccount||0)?{selected:true}:{})}, 'Account '+a.index+(a.label?(' · '+a.label):'')+' · '+fmtXmr(a.balance)+' XMR')));
    const newBtn = el('button',{class:'btn ghost sm'},'+ New account');
    newBtn.addEventListener('click', async ()=>{
      newBtn.disabled=true; newBtn.textContent='Creating…';
      try { const idx = await moneroEngine.createAccount(sx.wallet);
        sx.accounts = await moneroEngine.getAccounts(sx.wallet);
        try { const d = await moneroEngine.getData(sx.wallet); if(d&&d[0]&&d[1]) saveXmrData(state.wallet.id, state.xmrNet, d[0], d[1]); } catch(_){}
        if(idx!=null){ state.xmrAccount=idx; const a=sx.accounts.find(x=>x.index===idx); sx.balance = a?a.balance:0n; sx.unlocked = a?a.unlocked:0n; buildMoneroAddresses(); }
        render();
      } catch(e){ toast('Create account failed: '+(e.message||e),'bad'); newBtn.disabled=false; newBtn.textContent='+ New account'; }
    });
    acctBar = el('div',{class:'row',style:'flex:0;align-items:center;gap:10px;margin-bottom:2px'}, el('span',{class:'sub'},'Account'), sel, newBtn);
  }
  return el('div',{class:'card'},
    el('div',{class:'card-h'}, 'Receive '+c.ticker, el('span',{class:'sub'}, net.label+' · derived from your recovery phrase')),
    el('div',{class:'card-b stack'},
      acctBar,
      qrWrap,
      el('div',{class:'sub'}, primary.index===0 ? 'Primary address' : ('Subaddress '+primary.index)),
      el('div',{class:'addr',style:'font-size:14px'}, primary.address),
      el('div',{class:'row',style:'flex:0;margin:6px 0 4px'}, copyAddr,
        el('button',{class:'btn ghost sm',onclick:deriveNext},'Derive next subaddress')),
      renderFaucet(primary.address),
      el('div',{class:'sub faint'},'Keys come from your recovery phrase via a TestnetWallet-specific scheme. Use “Show 25-word seed” below to back this up in any Monero wallet. Balance and sending happen on the Send tab once your wallet syncs.'),
      el('hr',{class:'hr'}),
      el('div',{class:'sub'},'Your subaddresses'), list,
      el('hr',{class:'hr'}),
      revealK, keyHolder,
      (state.xmrSeedOk ? revealS : null), seedHolder,
    ));
}
/* ---- Monero send (build + sign locally via the engine, broadcast through the node) ---- */
function xmrToAtomic(s){   // exact XMR-string -> piconero bigint (no float rounding); null if invalid or >12 decimals
  const t = String(s).trim();
  if(t==='' || t==='.' || !/^\d*\.?\d*$/.test(t)) return null;
  const [i, f=''] = t.split('.');
  if(f.length > 12) return null;
  return BigInt(i || '0') * 1000000000000n + BigInt((f + '000000000000').slice(0, 12) || '0');
}
function parseMoneroUri(uri){   // monero:ADDR?tx_amount=1.5&tx_description=...
  const m = String(uri).match(/^monero:([^?]*)(\?(.*))?$/i);
  if(!m) return { address: String(uri).trim(), amount:'' };
  const p = new URLSearchParams(m[3] || '');
  return { address: decodeURIComponent(m[1]).trim(), amount: p.get('tx_amount') || p.get('amount') || '' };
}
function renderMoneroSend(){
  const c = COINS[state.coin], sx = state.xmr;
  if(!sx.synced || !sx.wallet) return placeholder('Send '+c.ticker, 'Connect & sync first. Your wallet has to finish scanning before it can build a transaction.');
  const ms = (state.xmrSend && state.xmrSend.recipients) ? state.xmrSend : (state.xmrSend = { recipients:[{to:'',amount:''}], priority:'', error:null });
  const rows = el('div',{class:'stack'});
  const renderRows = ()=>{
    clear(rows);
    ms.recipients.forEach((r, i)=>{
      const toIn = el('input',{type:'text',value:r.to,placeholder:'Destination address or monero: URI'});
      toIn.addEventListener('input', e=>{
        const v = e.target.value;
        if(v.trim().toLowerCase().startsWith('monero:')){ const u = parseMoneroUri(v); r.to = u.address; if(u.amount) r.amount = u.amount; renderRows(); }
        else r.to = v;
      });
      const amtIn = el('input',{type:'number',min:'0',step:'0.000000000001',value:r.amount,placeholder:'amount XMR',style:'max-width:160px'});
      amtIn.addEventListener('input', e=>{ r.amount = e.target.value; });
      const rm = ms.recipients.length>1 ? el('button',{class:'btn ghost sm',title:'Remove',onclick:()=>{ ms.recipients.splice(i,1); renderRows(); }},'✕') : null;
      rows.append(el('div',{class:'field'}, el('label',{class:'fld'}, 'Recipient '+(i+1)), el('div',{class:'row'}, toIn, amtIn, rm)));
    });
  };
  renderRows();
  const addBtn = el('button',{class:'btn ghost sm',onclick:()=>{ ms.recipients.push({to:'',amount:''}); renderRows(); }},'+ Add recipient');
  const prioSel = el('select',{style:'max-width:150px',onchange:e=>{ ms.priority=e.target.value; }});
  for(const [v,l] of [['','Automatic fee'],['1','Slow'],['2','Normal'],['3','Fast']]) prioSel.append(el('option',{value:v,...(v===ms.priority?{selected:true}:{})}, l));
  const reviewBtn = el('button',{class:'btn'},'Review & send');
  reviewBtn.addEventListener('click', ()=>moneroReviewSend(reviewBtn, false));
  const sweepBtn = el('button',{class:'btn ghost'},'Send max (sweep)');
  sweepBtn.addEventListener('click', ()=>moneroReviewSend(sweepBtn, true));
  return el('div',{class:'card'},
    el('div',{class:'card-h'}, 'Send '+c.ticker, el('span',{class:'sub',title:'Unlocked (spendable) balance. Monero outputs are locked for ~10 blocks after they arrive, so freshly-received coins aren\'t spendable yet.'}, fmtXmr(sx.unlocked!=null?sx.unlocked:sx.balance)+' available')),
    el('div',{class:'card-b stack'},
      rows,
      el('div',{class:'row',style:'flex:0;align-items:center;gap:10px'}, addBtn, el('span',{class:'sub'},'Fee'), prioSel),
      el('div',{class:'row',style:'flex:0'}, reviewBtn, sweepBtn),
      ms.error ? el('div',{class:'msg bad'}, ms.error) : null,
      el('div',{class:'sub faint'},'Built and signed in your browser, then broadcast through your node. "Send max" sends your whole unlocked balance to the first recipient. Testnet only.'),
    ));
}
async function moneroReviewSend(btn, sweep){
  const sx = state.xmr, ms = state.xmrSend;
  ms.error = null;
  const priority = ms.priority==='' ? undefined : parseInt(ms.priority, 10);
  const acct = state.xmrAccount || 0;
  let sweepTo = '', destinations = [];
  if(sweep){
    sweepTo = (ms.recipients[0] && ms.recipients[0].to || '').trim();
    if(!sweepTo){ ms.error = 'Enter a destination address for the sweep.'; render(); return; }
  } else {
    for(const r of ms.recipients){
      const to = (r.to||'').trim(), amt = xmrToAtomic(r.amount);
      if(!to){ ms.error = 'Each recipient needs an address.'; render(); return; }
      if(amt == null){ ms.error = 'Enter a valid amount (up to 12 decimal places).'; render(); return; }
      if(amt <= 0n){ ms.error = 'Each recipient needs an amount greater than 0.'; render(); return; }
      destinations.push({ address: to, amount: amt });
    }
  }
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = sweep ? 'Building sweep…' : 'Building…';
  try {
    const txs = sweep ? await moneroEngine.sweep(sx.wallet, sweepTo, { accountIndex: acct, priority })
                      : [ await moneroEngine.createTx(sx.wallet, { accountIndex: acct, destinations, priority }) ];
    if(!txs.length) throw new Error('Nothing to send - no unlocked balance.');
    let sent = 0n, fee = 0n;
    for(const tx of txs){ try { sent += BigInt(tx.getOutgoingAmount() || 0); } catch(_){} try { fee += BigInt(tx.getFee() || 0); } catch(_){} }
    if(!sweep){ const total = destinations.reduce((s,d)=>s+d.amount, 0n); if(sent === 0n) sent = total; }
    showMoneroSendConfirm(sweep ? sweepTo : destinations, sent, fee, txs, sweep);
  } catch(e){ ms.error = e.message || String(e); render(); }
  finally { btn.disabled = false; btn.textContent = orig; }
}
function showMoneroSendConfirm(dest, amount, fee, txs, sweep){
  const list = Array.isArray(txs) ? txs : [txs];
  const toRows = sweep
    ? [ el('tr',{}, el('td',{class:'muted'},'To'), el('td',{class:'addr'}, dest)) ]
    : dest.map((d,i)=> el('tr',{}, el('td',{class:'muted'}, dest.length>1?('To #'+(i+1)):'To'),
        el('td',{}, el('div',{class:'addr'}, d.address), el('div',{class:'sub'}, fmtXmr(d.amount)+' XMR'))));
  const bcBtn = el('button',{class:'btn'}, sweep ? 'Broadcast sweep' : 'Broadcast');
  const msg = el('div',{});
  bcBtn.addEventListener('click', async ()=>{
    bcBtn.disabled = true; bcBtn.textContent = 'Broadcasting…';
    try {
      const hashes = await moneroEngine.relayAll(state.xmr.wallet, list);
      try { const d = await moneroEngine.getData(state.xmr.wallet); if(d && d[0] && d[1]) saveXmrData(state.wallet.id, state.xmrNet, d[0], d[1]); } catch(_){}   // persist updated cache (spent outputs)
      toast('Monero transaction'+(hashes.length>1?'s':'')+' broadcast','ok');
      clear(msg).append(el('div',{class:'msg ok'}, el('div',{},'✓ Sent. Your balance updates once it confirms.'),
        ...hashes.map(h=>el('div',{class:'addr'}, String(h)))));
      state.xmrSend = { recipients:[{to:'',amount:''}], priority:'', error:null }; bcBtn.remove();
      setTimeout(()=>{ if(!state.xmr.syncing) moneroSync(); }, 1500);   // refresh balance from the chain
    } catch(e){ clear(msg).append(el('div',{class:'msg bad'}, e.message || String(e))); bcBtn.disabled=false; bcBtn.textContent='Broadcast'; }
  });
  showModal(el('div',{},
    el('div',{class:'card-h'}, sweep ? 'Confirm Monero sweep' : 'Confirm Monero transaction'),
    el('div',{class:'card-b stack'},
      el('div',{class:'msg warn'},'Review carefully. A broadcast Monero transaction cannot be undone.'),
      el('table',{}, el('tbody',{}, ...toRows,
        el('tr',{}, el('td',{class:'muted'}, sweep?'Amount swept':'Amount'), el('td',{class:'amt'}, fmtXmr(amount)+' XMR')),
        el('tr',{}, el('td',{class:'muted'},'Network fee'), el('td',{class:'amt'}, fmtXmr(fee)+' XMR')),
        list.length>1 ? el('tr',{}, el('td',{class:'muted'},'Transactions'), el('td',{class:'amt'}, String(list.length))) : null,
        el('tr',{}, el('td',{}, el('strong',{},'Total')), el('td',{class:'amt'}, el('strong',{}, fmtXmr(amount+fee)+' XMR'))))),
      el('div',{class:'row',style:'margin-top:6px'}, bcBtn, el('button',{class:'btn ghost',onclick:closeModal},'Cancel')), msg,
    )));
}

/* ---- Monero history ---- */
function xmrTxView(tx){
  const g = (name, d) => { try { const f = tx && tx['get'+name]; const v = f ? f.call(tx) : undefined; return (v==null) ? d : v; } catch(_){ return d; } };
  const big = v => (typeof v==='bigint') ? v : (v!=null ? BigInt(v) : 0n);
  const outgoing = !!g('IsOutgoing', false);
  return {
    hash: String(g('Hash','') || g('Id','')),
    outgoing,
    amount: outgoing ? big(g('OutgoingAmount',0n)) : big(g('IncomingAmount',0n)),
    fee: big(g('Fee',0n)),
    height: Number(g('Height',0) || 0),
    confirmed: !!g('IsConfirmed', false),
    inPool: !!g('InTxPool', false),
    failed: !!g('IsFailed', false),
    locked: !!g('IsLocked', false),
    confirmations: Number(g('NumConfirmations',0) || 0),
    timestamp: Number(g('Timestamp',0) || 0),
    paymentId: g('PaymentId', null),
  };
}
function xmrExplorerTx(hash){ const b = (COINS.xmr.explorers && COINS.xmr.explorers[state.xmrNet]) || ''; return b ? (b.replace(/\/+$/,'') + '/tx/' + hash) : ''; }
function xmrTxStatus(t){ return t.failed ? 'failed' : t.inPool ? 'in mempool' : !t.confirmed ? 'pending' : t.locked ? (t.confirmations+' conf · locked') : (t.confirmations+' confirmation'+(t.confirmations===1?'':'s')); }
function renderMoneroHistory(){
  const sx = state.xmr;
  if(!sx.synced) return placeholder('History', sx.syncing ? 'Syncing… your transactions appear once the scan finishes.' : 'Connect & sync first to load your transaction history.');
  const txs = (sx.txs || []).map(xmrTxView).sort((a,b)=> (b.height||9e15) - (a.height||9e15));   // newest (and pending) first
  if(!txs.length) return el('div',{class:'card'}, el('div',{class:'card-h'},'History'), el('div',{class:'card-b'}, el('p',{class:'muted'},'No transactions yet.')));
  const list = el('div',{class:'tx-list'});
  for(const t of txs){
    const out = t.outgoing, note = getTxNote(t.hash);
    const when = t.timestamp ? new Date(t.timestamp*1000).toLocaleString() : (t.confirmed ? ('block '+t.height.toLocaleString()) : '-');
    const main = el('div',{class:'tx-main'},
      el('div',{class:'t1'}, out?'Sent':'Received'),
      el('div',{class:'t2'}, when+' · '+xmrTxStatus(t)));
    if(note) main.append(el('div',{class:'t2',style:'font-style:italic'}, note));
    const row = el('div',{class:'tx-item',tabindex:'0'},
      el('div',{class:'tx-ico '+(out?'out':'in')}, out?'↑':'↓'), main,
      el('div',{class:'tx-amt '+(out?'bad':'ok')}, (out?'−':'+')+fmtXmr(t.amount)+' XMR'));
    const open = ()=>showMoneroTxDetail(t);
    row.addEventListener('click', open);
    row.addEventListener('keydown', e=>{ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); open(); } });
    list.append(row);
  }
  return el('div',{class:'card'},
    el('div',{class:'card-h'},'History', el('span',{class:'sub'}, txs.length+' transaction'+(txs.length===1?'':'s') + ((sx.accounts && sx.accounts.length>1) ? ' · all accounts' : ''))),
    el('div',{class:'card-b'}, list));
}
function showMoneroTxDetail(t){
  const url = xmrExplorerTx(t.hash);
  const copyHash = el('span',{class:'copy'},'copy'); copyHash.addEventListener('click',()=>copyText(t.hash, copyHash));
  showModal(el('div',{},
    el('div',{class:'card-h'}, (t.outgoing?'Sent':'Received')+' '+fmtXmr(t.amount)+' XMR'),
    el('div',{class:'card-b stack'},
      el('table',{}, el('tbody',{},
        el('tr',{}, el('td',{class:'muted'},'Status'), el('td',{}, xmrTxStatus(t))),
        el('tr',{}, el('td',{class:'muted'},'Amount'), el('td',{class:'amt'}, fmtXmr(t.amount)+' XMR')),
        t.outgoing ? el('tr',{}, el('td',{class:'muted'},'Fee'), el('td',{class:'amt'}, fmtXmr(t.fee)+' XMR')) : null,
        t.height ? el('tr',{}, el('td',{class:'muted'},'Height'), el('td',{class:'amt'}, t.height.toLocaleString())) : null,
        t.timestamp ? el('tr',{}, el('td',{class:'muted'},'Time'), el('td',{}, new Date(t.timestamp*1000).toLocaleString())) : null,
        (t.paymentId && /[^0]/.test(String(t.paymentId))) ? el('tr',{}, el('td',{class:'muted'},'Payment ID'), el('td',{class:'addr'}, String(t.paymentId))) : null)),
      el('div',{class:'sub'},'Transaction ID', copyHash),
      el('div',{class:'addr'}, t.hash),
      el('div',{class:'field',style:'margin:6px 0 0'}, el('label',{class:'fld'},'Note (private)'),
        el('input',{type:'text',value:getTxNote(t.hash),placeholder:'Add a note',oninput:e=>setTxNote(t.hash, e.target.value)})),
      url ? el('a',{class:'btn ghost sm',href:url,target:'_blank',rel:'noopener'},'View on explorer ↗') : null,
      el('div',{class:'mt-2'}, el('button',{class:'btn ghost',onclick:closeModal},'Close')),
    )));
}

/* ---- Monero tools: message sign/verify + payment proof (all via the engine) ---- */
function renderMoneroTools(){
  const sx = state.xmr;
  if(!sx.synced || !sx.wallet) return placeholder('Tools', 'Connect & sync your Monero wallet first. Signing and proofs need your synced wallet.');
  const t = state.xmrTools || (state.xmrTools = { msg:'', viewKey:false, sig:'', vAddr:'', vMsg:'', vSig:'', vRes:null, pTxid:'', pAddr:'', pMsg:'', pSig:'', cTxid:'', cAddr:'', cMsg:'', cSig:'', cRes:null });
  const net = xmr.XMR_NETS[state.xmrNet] || xmr.XMR_NETS.stagenet;
  const signingAddr = state.xmrKeys ? xmr.subaddress(state.xmrKeys, net, 0, 0) : '';

  // --- sign ---
  const sMsg = el('textarea',{placeholder:'Message to sign'}); sMsg.value=t.msg; sMsg.addEventListener('input',e=>{ t.msg=e.target.value; });
  const vkChk = el('input',{type:'checkbox',...(t.viewKey?{checked:true}:{})}); vkChk.addEventListener('change',e=>{ t.viewKey=e.target.checked; });
  const sOut = el('div',{});
  const renderSOut = ()=>{ clear(sOut); if(t.sig){ const cp=el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(t.sig,cp));
    sOut.append(el('div',{class:'sub',style:'margin-top:8px'},'Signature ', cp), el('div',{class:'addr'}, t.sig)); } };
  renderSOut();
  const signBtn = el('button',{class:'btn'},'Sign'); signBtn.addEventListener('click', async ()=>{
    if(!t.msg){ toast('Enter a message','warn'); return; }
    signBtn.disabled=true; signBtn.textContent='Signing…';
    try { t.sig = await moneroEngine.signMessage(sx.wallet, t.msg, t.viewKey); renderSOut(); }
    catch(e){ toast('Sign failed: '+(e.message||e),'bad'); }
    finally { signBtn.disabled=false; signBtn.textContent='Sign'; }
  });

  // --- verify ---
  const vAddr=el('input',{type:'text',placeholder:'Signing address',value:t.vAddr}); vAddr.addEventListener('input',e=>{t.vAddr=e.target.value;});
  const vMsg=el('textarea',{placeholder:'Message'}); vMsg.value=t.vMsg; vMsg.addEventListener('input',e=>{t.vMsg=e.target.value;});
  const vSig=el('input',{type:'text',placeholder:'Signature (SigV…)',value:t.vSig}); vSig.addEventListener('input',e=>{t.vSig=e.target.value;});
  const vOut=el('div',{}); const renderVOut=()=>{ clear(vOut); if(t.vRes) vOut.append(el('div',{class:'msg '+(t.vRes.good?'ok':'bad')}, t.vRes.good ? ('✓ Valid signature'+(t.vRes.viewKey?' (view key)':' (spend key)')) : '✗ Invalid signature')); };
  renderVOut();
  const verifyBtn=el('button',{class:'btn ghost'},'Verify'); verifyBtn.addEventListener('click', async ()=>{
    if(!t.vAddr.trim()||!t.vSig.trim()){ toast('Address and signature are required','warn'); return; }
    verifyBtn.disabled=true;
    try { t.vRes = await moneroEngine.verifyMessage(sx.wallet, t.vMsg, t.vAddr.trim(), t.vSig.trim()); renderVOut(); }
    catch(_){ t.vRes={good:false}; renderVOut(); }
    finally { verifyBtn.disabled=false; }
  });

  // --- payment proof (generate) ---
  const pTxid=el('input',{type:'text',placeholder:'Transaction ID',value:t.pTxid}); pTxid.addEventListener('input',e=>{t.pTxid=e.target.value;});
  const pAddr=el('input',{type:'text',placeholder:'Recipient address that was paid',value:t.pAddr}); pAddr.addEventListener('input',e=>{t.pAddr=e.target.value;});
  const pMsg=el('input',{type:'text',placeholder:'Optional message',value:t.pMsg}); pMsg.addEventListener('input',e=>{t.pMsg=e.target.value;});
  const pOut=el('div',{}); const renderPOut=()=>{ clear(pOut); if(t.pSig){ const cp=el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(t.pSig,cp)); pOut.append(el('div',{class:'sub',style:'margin-top:8px'},'Proof ', cp), el('div',{class:'addr'}, t.pSig)); } };
  renderPOut();
  const proofBtn=el('button',{class:'btn'},'Generate proof'); proofBtn.addEventListener('click', async ()=>{
    if(!t.pTxid.trim()||!t.pAddr.trim()){ toast('Transaction ID and address are required','warn'); return; }
    proofBtn.disabled=true; proofBtn.textContent='Generating…';
    try { t.pSig = await moneroEngine.getTxProof(sx.wallet, t.pTxid.trim(), t.pAddr.trim(), t.pMsg); renderPOut(); }
    catch(e){ toast('Proof failed: '+(e.message||e),'bad'); }
    finally { proofBtn.disabled=false; proofBtn.textContent='Generate proof'; }
  });

  // --- payment proof (check) ---
  const cTxid=el('input',{type:'text',placeholder:'Transaction ID',value:t.cTxid}); cTxid.addEventListener('input',e=>{t.cTxid=e.target.value;});
  const cAddr=el('input',{type:'text',placeholder:'Recipient address',value:t.cAddr}); cAddr.addEventListener('input',e=>{t.cAddr=e.target.value;});
  const cMsg=el('input',{type:'text',placeholder:'Optional message (must match)',value:t.cMsg}); cMsg.addEventListener('input',e=>{t.cMsg=e.target.value;});
  const cSig=el('input',{type:'text',placeholder:'Proof signature (OutProofV…)',value:t.cSig}); cSig.addEventListener('input',e=>{t.cSig=e.target.value;});
  const cOut=el('div',{}); const renderCOut=()=>{ clear(cOut); if(t.cRes){ const r=t.cRes;
    cOut.append(el('div',{class:'msg '+(r.good?'ok':'bad')}, r.good ? ('✓ Valid · received '+fmtXmr(r.received)+' XMR · '+(r.inPool?'in mempool':r.confirmations+' confirmation'+(r.confirmations===1?'':'s'))) : '✗ Invalid proof')); } };
  renderCOut();
  const checkBtn=el('button',{class:'btn ghost'},'Check proof'); checkBtn.addEventListener('click', async ()=>{
    if(!t.cTxid.trim()||!t.cAddr.trim()||!t.cSig.trim()){ toast('Transaction ID, address and signature are required','warn'); return; }
    checkBtn.disabled=true;
    try { t.cRes = await moneroEngine.checkTxProof(sx.wallet, t.cTxid.trim(), t.cAddr.trim(), t.cMsg, t.cSig.trim()); renderCOut(); }
    catch(_){ t.cRes={good:false,received:0n,confirmations:0,inPool:false}; renderCOut(); }
    finally { checkBtn.disabled=false; }
  });

  // --- coin control (outputs): list + freeze/thaw ---
  const ccOut = el('div',{});
  const loadOutputs = async (btn)=>{
    if(btn){ btn.disabled=true; btn.textContent='Loading…'; }
    try {
      const outs = (await moneroEngine.getOutputs(sx.wallet)).filter(o=>!o.spent && o.accountIndex === (state.xmrAccount||0));
      clear(ccOut);
      if(!outs.length){ ccOut.append(el('div',{class:'sub'},'No spendable outputs yet.')); }
      else {
        const tbl = el('table',{}, el('thead',{}, el('tr',{}, el('th',{},'Amount'), el('th',{},'Status'), el('th',{},'Key image'), el('th',{},''))));
        const body = el('tbody',{});
        for(const o of outs){
          const status = o.frozen ? 'frozen' : o.locked ? 'locked' : 'unlocked';
          const toggle = el('button',{class:'btn ghost sm'}, o.frozen ? 'Thaw' : 'Freeze');
          toggle.addEventListener('click', async ()=>{
            if(!o.keyImage){ toast('No key image for this output','warn'); return; }
            toggle.disabled=true;
            try {
              if(o.frozen) await moneroEngine.thawOutput(sx.wallet, o.keyImage); else await moneroEngine.freezeOutput(sx.wallet, o.keyImage);
              try { const d = await moneroEngine.getData(sx.wallet); if(d&&d[0]&&d[1]) saveXmrData(state.wallet.id, state.xmrNet, d[0], d[1]); } catch(_){}
              await loadOutputs();
            } catch(e){ toast('Freeze/thaw failed: '+(e.message||e),'bad'); toggle.disabled=false; }
          });
          body.append(el('tr',{},
            el('td',{class:'amt'}, fmtXmr(o.amount)),
            el('td',{class:(o.frozen?'warn':o.locked?'muted':'ok')}, status),
            el('td',{class:'mono faint',style:'font-size:11px'}, o.keyImage ? (o.keyImage.slice(0,10)+'…') : '-'),
            el('td',{}, o.keyImage ? toggle : null)));
        }
        tbl.append(body);
        ccOut.append(el('div',{class:'sub'}, outs.length+' spendable output'+(outs.length===1?'':'s')+' · freeze to exclude from sends'), tbl);
      }
    } catch(e){ clear(ccOut).append(el('div',{class:'msg bad'},'Could not load outputs: '+(e.message||e))); }
    finally { if(btn){ btn.disabled=false; btn.textContent='Refresh outputs'; } }
  };
  const ccBtn = el('button',{class:'btn ghost'},'Load outputs'); ccBtn.addEventListener('click', ()=>loadOutputs(ccBtn));

  const card = (title, sub, ...body) => el('div',{class:'card'}, el('div',{class:'card-h'}, title, sub?el('span',{class:'sub'},sub):null), el('div',{class:'card-b stack'}, ...body));
  const frag = document.createDocumentFragment();
  frag.append(
    card('Sign message', signingAddr ? ('signs with your primary address ('+signingAddr.slice(0,10)+'…)') : null,
      el('div',{class:'field'}, el('label',{class:'fld'},'Message'), sMsg),
      el('label',{class:'row',style:'flex:0;gap:7px;cursor:pointer'}, vkChk, el('span',{class:'sub'},'Sign with view key instead of spend key')),
      el('div',{}, signBtn), sOut),
    card('Verify message', null,
      el('div',{class:'field'}, el('label',{class:'fld'},'Address'), vAddr),
      el('div',{class:'field'}, el('label',{class:'fld'},'Message'), vMsg),
      el('div',{class:'field'}, el('label',{class:'fld'},'Signature'), vSig),
      el('div',{}, verifyBtn), vOut),
    card('Generate payment proof', 'prove a transaction paid an address',
      el('div',{class:'field'}, el('label',{class:'fld'},'Transaction ID'), pTxid),
      el('div',{class:'field'}, el('label',{class:'fld'},'Recipient address'), pAddr),
      el('div',{class:'field'}, el('label',{class:'fld'},'Message (optional)'), pMsg),
      el('div',{}, proofBtn), pOut),
    card('Check payment proof', null,
      el('div',{class:'field'}, el('label',{class:'fld'},'Transaction ID'), cTxid),
      el('div',{class:'field'}, el('label',{class:'fld'},'Recipient address'), cAddr),
      el('div',{class:'field'}, el('label',{class:'fld'},'Message (optional)'), cMsg),
      el('div',{class:'field'}, el('label',{class:'fld'},'Proof signature'), cSig),
      el('div',{}, checkBtn), cOut),
    card('Coin control', 'freeze/thaw individual outputs to control which coins a send spends',
      el('div',{}, ccBtn), ccOut),
  );
  return frag;
}

/* ---- tx notes (private, per wallet) + history export ---- */
function getTxNote(txid){ return (store.txNotes && store.txNotes[state.wallet.id] && store.txNotes[state.wallet.id][txid]) || ''; }
function setTxNote(txid, note){ store.txNotes = store.txNotes || {}; store.txNotes[state.wallet.id] = store.txNotes[state.wallet.id] || {};
  if(note && note.trim()) store.txNotes[state.wallet.id][txid] = note.trim(); else delete store.txNotes[state.wallet.id][txid]; saveStore(); }
function downloadBlob(blob, name){ const url=URL.createObjectURL(blob); const a=el('a',{href:url,download:name}); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url); }
function exportHistory(kind){
  const c = COINS[state.coin];
  const rows = state.txs.map(t=>({ txid:t.txid, direction:t.net>=0?'received':'sent', amount:(t.net/1e8), unit:c.ticker,
    confirmed:t.confirmed, time: t.time? new Date(t.time*1000).toISOString():'', fee_sats:t.fee||0, note:getTxNote(t.txid) }));
  if(kind==='csv'){
    const esc=v=>{ let s=String(v==null?'':v); if(/^[=+\-@\t\r]/.test(s)) s="'"+s; return '"'+s.replace(/"/g,'""')+'"'; };   // quote + neutralize formula injection
    const head=['txid','direction','amount','unit','confirmed','time','fee_sats','note'];
    const csv=[head.join(',')].concat(rows.map(r=>head.map(h=>esc(r[h])).join(','))).join('\n');
    downloadBlob(new Blob([csv],{type:'text/csv'}), 'history-'+state.coin+'.csv');
  } else downloadBlob(new Blob([JSON.stringify(rows,null,2)],{type:'application/json'}), 'history-'+state.coin+'.json');
}

/* ---- history ---- */
function renderHistory(){
  const c = COINS[state.coin];
  const card = el('div',{class:'card'},
    el('div',{class:'card-h'},'Transactions',
      el('div',{class:'row',style:'flex:1;justify-content:flex-end;align-items:center;gap:10px'},
        state.txs.length ? el('span',{class:'copy',onclick:()=>exportHistory('csv')},'CSV') : null,
        state.txs.length ? el('span',{class:'copy',onclick:()=>exportHistory('json')},'JSON') : null,
        el('a',{class:'sub',href:c.explorer+'/address/'+state.addresses[state.addresses.length-1].address,target:'_blank',rel:'noopener'},'Full history ↗'))));
  const body = el('div',{class:'card-b'});
  if(!state.txs.length){ body.append(el('p',{class:'muted'},'No transactions yet. Grab some from ',
    el('a',{href:'https://cypherfaucet.com',target:'_blank',rel:'noopener'},'CypherFaucet'),'.')); card.append(body); return card; }
  const list = el('div',{class:'tx-list'});
  for(const t of state.txs){
    const incoming = t.net >= 0;
    const open = state.expandedTx === t.txid;
    const settle = t.confirmed && _lastPending.has(t.txid);    // just confirmed since the last render
    list.append(el('div',{class:'tx-item'+(settle?' settle':''), onclick:()=>{ state.expandedTx = open ? null : t.txid; render(); }},
      el('div',{class:'tx-ico '+(incoming?'in':'out')+(t.confirmed?'':' pending')}, incoming?'↓':'↑'),
      el('div',{class:'tx-main'},
        el('div',{class:'t1'}, incoming?'Received':'Sent'),
        el('div',{class:'t2'}, t.confirmed ? timeAgo(t.time) : el('span',{class:'warn'},'pending'), getTxNote(t.txid) ? (' · '+getTxNote(t.txid)) : '')),
      el('div',{class:'tx-amt '+(incoming?'ok':'bad')}, (incoming?'+':'')+fmt(t.net)+' '+c.ticker),
      el('div',{class:'faint',style:'flex:none'}, open?'▾':'▸')));
    if(open) list.append(el('div',{style:'padding:2px 8px 12px'}, txDetail(t, c)));
  }
  _lastPending = new Set(state.txs.filter(t=>!t.confirmed).map(t=>t.txid));   // remember for the next render's settle flash
  if(state.histTruncated) body.append(el('div',{class:'sub warn',style:'margin:4px 0 8px'},'Showing recent transactions only. Use “Full history ↗” above or export for the full record.'));
  body.append(list); card.append(body); return card;
}
function txDetail(t, c){
  const confs = (t.confirmed && state.tipHeight && t.block_height) ? (state.tipHeight - t.block_height + 1) : null;
  const status = t.confirmed
    ? 'Confirmed'+(t.block_height?(' · block '+t.block_height):'')+(confs?(' · '+confs+' confirmation'+(confs===1?'':'s')):'')
    : 'Pending, waiting to be confirmed (0 confirmations)';
  let when = '-'; try { if(t.time) when = new Date(t.time*1000).toLocaleString(); } catch(_){}
  const feeRate = (t.fee && t.vsize) ? (' · '+(t.fee/t.vsize).toFixed(1)+' sat/vB') : '';
  const ioRows = arr => { const tb = el('tbody',{});
    arr.forEach(x => tb.append(el('tr',{},
      el('td',{class:'txid'}, x.address || '(non-address script)', x.mine ? el('span',{class:'pill',style:'margin-left:6px'},'you') : null),
      el('td',{class:'amt'}, x.value!=null ? (fmt(x.value)+' '+c.ticker) : '-'))));
    return el('table',{}, tb); };
  const copyId = el('span',{class:'copy'},'copy');
  copyId.addEventListener('click', e=>{ e.stopPropagation(); copyText(t.txid, copyId); });
  return el('div',{class:'stack',style:'padding:8px 2px'},
    el('div',{class:'between'}, el('span',{class:'sub'},'Status'), el('span',{class:(t.confirmed?'ok':'warn')}, status)),
    el('div',{class:'between'}, el('span',{class:'sub'},'Time'), el('span',{}, when)),
    el('div',{class:'between'}, el('span',{class:'sub'},'Net to your wallet'), el('span',{class:'amt '+(t.net>=0?'ok':'bad')}, (t.net>=0?'+':'')+fmt(t.net)+' '+c.ticker)),
    el('div',{class:'between'}, el('span',{class:'sub'},'Fee'), el('span',{class:'amt'}, fmt(t.fee||0)+' '+c.ticker+feeRate)),
    t.vsize ? el('div',{class:'between'}, el('span',{class:'sub'},'Size'), el('span',{}, t.vsize+' vB')) : null,
    el('div',{}, el('span',{class:'sub'},'Transaction ID '), copyId, el('div',{class:'addr'}, t.txid)),
    el('div',{class:'field',style:'margin:6px 0 0'}, el('label',{class:'fld'},'Note (private, stays in this browser)'),
      el('input',{type:'text',value:getTxNote(t.txid),placeholder:'Add a note',oninput:e=>{ setTxNote(t.txid, e.target.value); }})),
    el('div',{class:'sub',style:'margin-top:4px'}, 'Inputs ('+(t.vin?t.vin.length:0)+')'), ioRows(t.vin||[]),
    el('div',{class:'sub',style:'margin-top:4px'}, 'Outputs ('+(t.vout?t.vout.length:0)+')'), ioRows(t.vout||[]),
    txActions(t, c),
  );
}
function txActions(t, c){
  const wrap = el('div',{class:'row',style:'margin-top:8px;flex:0;align-items:center'},
    el('a',{class:'btn ghost sm',href:c.explorer+'/tx/'+t.txid,target:'_blank',rel:'noopener'},'Open in explorer'));
  if(!t.confirmed && t.net > 0){                                   // pending incoming -> offer CPFP
    const out = el('span',{class:'sub'});
    const su = el('button',{class:'btn ghost sm'},'Speed up (CPFP)');
    su.addEventListener('click', async ()=>{
      su.disabled = true; su.textContent = 'Building…'; clear(out);
      try { const rate = (await getFeeRate(state.coin)) * 3;
        const txid = await cpfpSpeedUp(state.coin, state.addrType, t.txid, rate);
        out.append(el('span',{class:'ok'},' sent ' + txid.slice(0,16) + '…')); refresh(); }
      catch(e){ out.append(el('span',{class:'bad'},' ' + (e.message||e))); su.disabled=false; su.textContent='Speed up (CPFP)'; }
    });
    wrap.append(su, out);
  }
  if(!t.confirmed && t.net < 0){                                  // pending OUTGOING (we sent it) -> offer RBF fee-bump
    const out = el('span',{class:'sub'});
    const bb = el('button',{class:'btn ghost sm'},'Bump fee (RBF)');
    bb.addEventListener('click', async ()=>{
      bb.disabled=true; bb.textContent='Building…'; clear(out);
      try {
        const est = await getFeeEstimates(state.coin);
        const rate = Math.max(est.fast||2, Math.ceil(((t.fee||0)/(t.vsize||1)) + 1));   // beat the stuck tx's own rate
        const { tx, oldFee, newFee } = await bumpFeeRBF(state.coin, t.txid, rate);
        bb.disabled=false; bb.textContent='Bump fee (RBF)';
        confirmModal('Replace this transaction with a higher fee? Old '+fmt(oldFee)+' to new '+fmt(newFee)+' '+c.ticker+' (the extra comes out of your change; same inputs and recipients).', async ()=>{
          try { const txid = await broadcast(state.coin, tx.hex); toast('Replacement broadcast '+txid.slice(0,12)+'…','ok'); refresh(); }
          catch(e){ toast('Broadcast failed: '+(e.message||e),'bad'); }
        }, { yes:'Broadcast replacement', title:'Bump fee (RBF)' });
      } catch(e){ out.append(el('span',{class:'bad'},' '+(e.message||e))); bb.disabled=false; bb.textContent='Bump fee (RBF)'; }
    });
    wrap.append(bb, out);
  }
  return wrap;
}

/* ----------------------------- coin / type switching ----------------------------- */
function switchCoin(coin){ if(!COINS[coin].enabled||coin===state.coin) return; state.coin=coin; _lastBal=null; _lastPending=new Set(); saveSettings(); buildAddresses(); render(); refresh(); }
function switchType(type){ if(type===state.addrType) return; state.addrType=type; saveSettings(); buildAddresses(); render(); refresh(); }
function switchXmrNet(net){ if(net===state.xmrNet || !xmr.XMR_NETS[net]) return; state.xmrNet=net; state.xmrAccount=0; saveSettings(); buildAddresses(); render(); }   // re-encodes addresses with the network prefix; no backend call

/* ----------------------------- Monero engine (balance/spend via monero-ts, lazy) ----------------------------- */
const DEFAULT_XMR_NODE = { testnet:'https://xmr-testnet-node.librenode.com', stagenet:'' };   // HTTPS + permissive CORS + restricted RPC, so it works directly from the browser. Stagenet: add your own HTTPS node in Settings.
function xmrNodeUrl(){ const o = store.settings && store.settings.xmrNode; return (o && o[state.xmrNet]) || DEFAULT_XMR_NODE[state.xmrNet] || ''; }
function fmtXmr(atomic){ const n = Number(atomic)/1e12; return n.toFixed(12).replace(/\.?0+$/,'') || '0'; }   // piconero -> XMR
let _xmrT0 = 0, _xmrTick = null;   // sync elapsed-timer anchor + 1s ticker, so the indicator keeps moving through the event-less hash walk
function fmtDur(s){ return s >= 3600 ? (Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm') : s >= 60 ? (Math.floor(s/60) + 'm ' + (s%60) + 's') : (s + 's'); }
function xmrHost(){ try { return new URL(xmrNodeUrl()).host; } catch(_){ return ''; } }
function xmrStatusInner(){
  const x = state.xmr;
  const secs = _xmrT0 ? Math.floor((Date.now() - _xmrT0) / 1000) : 0;
  const elapsed = secs ? (' · ' + fmtDur(secs)) : '';
  let label, pct = 0, indet = true;
  if(x.phase === 'engine') label = 'Loading Monero engine (~6 MB)…';
  else if(x.phase === 'connecting') label = 'Connecting to ' + (xmrHost() || 'the node') + '…';
  else {
    const tip = x.endHeight || 0, start = x.start || 0, h = x.height || 0;
    const span = tip - start, done = Math.max(0, h - start);
    if(h && tip && h >= start){                              // real block position: precise count + bar + ETA
      pct = Math.min(100, x.pct || (span > 0 ? Math.round(done/span*100) : 0));
      label = 'Scanning block ' + h.toLocaleString() + ' / ' + tip.toLocaleString();
      if(span > 0) label += ' · ' + done.toLocaleString() + ' of ' + span.toLocaleString() + ' (' + pct + '%)';
      if(secs > 2 && done > 0 && span > done){ const rem = Math.ceil(secs * (span - done) / done); if(rem > 0 && rem < 86400) label += ' · ~' + fmtDur(rem) + ' left'; }
      indet = false;
    } else if(tip){                                          // hash-walk phase: target known, no block position yet
      label = 'Locating blocks' + (start ? (' from ' + start.toLocaleString()) : '') + ', up to ' + tip.toLocaleString() + '…';
    } else {
      label = 'Scanning the chain' + (x.restoreHeight ? (' from ' + x.restoreHeight.toLocaleString()) : '') + '… locating blocks';
    }
  }
  return [ el('div',{}, label + elapsed),
    el('div',{class:'pbar' + (indet ? ' indet' : '')}, indet ? el('span',{}) : el('span',{style:'width:'+pct+'%'})) ];
}
function renderXmrStatus(){ const e = $('xmr-sync'); if(!e) return; clear(e); for(const n of xmrStatusInner()) e.append(n); }
// Compact node-status line for the Monero hero: host, reachability, the node's own height and whether the
// node itself is synced + on the right network. Probed cheaply via /get_info (no engine load), cached 30s.
let _xmrNodeProbing = false;
function probeXmrNode(force){
  const sx = state.xmr, url = xmrNodeUrl();
  if(!url || _xmrNodeProbing || sx.syncing) return;
  if(!force && sx.node && sx.node.url === url && (Date.now() - (sx.node.at || 0) < 30000)) return;   // still fresh
  _xmrNodeProbing = true;
  moneroEngine.getDaemonInfo(url)
    .then(info => { state.xmr.node = { url, at:Date.now(), ...info }; })
    .catch(()=>{ state.xmr.node = { url, at:Date.now(), ok:false, height:0 }; })
    .finally(()=>{ _xmrNodeProbing = false; renderXmrNodeLine(); if(xmrNodeUrl() !== url) probeXmrNode(); });   // node URL changed mid-probe (net toggle): re-probe the current one
}
function xmrNodeLineInner(){
  const sx = state.xmr, url = xmrNodeUrl(); if(!url) return [];
  let host = ''; try { host = new URL(url).host; } catch(_){ host = url; }
  const n = (sx.node && sx.node.url === url) ? sx.node : null;
  if(!n) return [ el('span',{}, 'Node ' + host + ' · checking…') ];
  if(!n.ok) return [ el('span',{class:'bad'}, '✗ Node ' + host + ' unreachable (offline, or blocking browser access)') ];
  let txt = 'Node ' + host + ' · block ' + (n.height || 0).toLocaleString();
  if(n.synchronized === false && n.targetHeight) txt += ' (node syncing → ' + n.targetHeight.toLocaleString() + ')';
  if(n.nettype && state.xmrNet && n.nettype.toLowerCase() !== state.xmrNet.toLowerCase()) txt += ' · ⚠ node is ' + n.nettype;
  return [ el('span',{}, txt) ];
}
function renderXmrNodeLine(){ const e = $('xmr-node'); if(!e) return; clear(e); for(const c of xmrNodeLineInner()) e.append(c); }
const XMR_FALLBACK_HEIGHT = { testnet: 3000000, stagenet: 1800000 };   // recent-ish floors so a failed height lookup never scans from genesis
// persist the synced wallet (keys + block cache) per wallet/network so re-sync only scans NEW blocks
// Monero keys+cache live in their OWN localStorage keys, not the main store blob (the cache is multi-MB;
// keeping it out keeps saveStore() small and stops an oversized cache from making every save throw on quota).
const XMR_DATA_PREFIX = 'testnetwallet.xmr.';
function xmrDataKey(walletId, net){ return XMR_DATA_PREFIX + walletId + '.' + net; }
async function loadXmrData(walletId, net){
  try {
    const s = localStorage.getItem(xmrDataKey(walletId, net)); if(!s) return null;
    let d = JSON.parse(s);
    if(d && d.tnwvault){ if(!_cryptoKey) return null; d = JSON.parse(await decWith(_cryptoKey, d.iv, d.ct)); }   // encrypted cache
    if(d && d.k && d.c) return { keysData: b64decode(d.k), cacheData: b64decode(d.c) };
  } catch(_){}
  return null;
}
function saveXmrData(walletId, net, keysData, cacheData){
  if(_encOn && !_cryptoKey) return;       // locked: don't write the spend key in any form
  const plain = { k: b64encode(keysData), c: b64encode(cacheData) };   // snapshot the args now; persist in order
  _writeChain = _writeChain.then(async ()=>{
    if(_encOn && !_cryptoKey) return;     // re-check: a lock/disable may have landed before this ran
    try {
      if(_encOn && _cryptoKey){ const e = await encWith(_cryptoKey, JSON.stringify(plain)); localStorage.setItem(xmrDataKey(walletId, net), JSON.stringify({ tnwvault:1, iv:e.iv, ct:e.ct })); }
      else localStorage.setItem(xmrDataKey(walletId, net), JSON.stringify(plain));
    } catch(e){ console.warn('[monero] cache not persisted (storage limit?):', e); }
  }).catch(()=>{});
}
function deleteXmrData(walletId){   // purge every network's cache for a wallet (on Forget)
  try { for(let i = localStorage.length - 1; i >= 0; i--){ const k = localStorage.key(i); if(k && k.indexOf(XMR_DATA_PREFIX + walletId + '.') === 0) localStorage.removeItem(k); } } catch(_){}
}
// user-chosen "scan from" height (Cake-style restore height), per wallet+network; null = use the auto default
function getXmrRestore(walletId, net){ const o = store.settings && store.settings.xmrRestore; return (o && o[walletId] && o[walletId][net] != null) ? o[walletId][net] : null; }
function setXmrRestore(walletId, net, height){
  store.settings = store.settings || {};
  store.settings.xmrRestore = store.settings.xmrRestore || {};
  store.settings.xmrRestore[walletId] = store.settings.xmrRestore[walletId] || {};
  if(height == null) delete store.settings.xmrRestore[walletId][net]; else store.settings.xmrRestore[walletId][net] = height;
  saveStore();
}
async function moneroSync(){
  const sx = state.xmr; if(sx.syncing) return;
  const nodeUrl = xmrNodeUrl();
  if(!nodeUrl){ sx.error = 'Set a Monero node in Settings first.'; render(); return; }
  if(!state.xmrKeys){ sx.error = 'Monero keys unavailable.'; render(); return; }
  const walletId = state.wallet.id, net = state.xmrNet, netCfg = xmr.XMR_NETS[net] || xmr.XMR_NETS.stagenet;
  sx.syncing = true; sx.error = null; sx.pct = 0; sx.start = 0; sx.height = 0; sx.endHeight = 0; sx.phase = moneroEngine.isLoaded() ? 'connecting' : 'engine';   // reset progress so a re-sync doesn't inherit the prior scan's window
  _xmrT0 = Date.now(); clearInterval(_xmrTick); _xmrTick = setInterval(renderXmrStatus, 1000); render();
  try {
    let wallet = null, fresh = true;
    let info = null;   // node status + chain tip up front, so the progress bar has a target before monero-ts emits events
    try { info = await moneroEngine.getDaemonInfo(nodeUrl); sx.node = { url:nodeUrl, at:Date.now(), ...info }; if(info.ok && info.height){ sx.endHeight = info.height; renderXmrNodeLine(); } } catch(_){}
    const saved = await loadXmrData(walletId, net);
    if(saved){                                              // resume from the saved cache (only scans new blocks)
      try { wallet = await moneroEngine.openSaved({ network:net, nodeUrl, keysData:saved.keysData, cacheData:saved.cacheData }); fresh = false; sx.restoreHeight = 0; render(); }
      catch(e){ console.warn('[monero] saved cache unusable, doing a fresh sync:', e); wallet = null; }
    }
    if(!wallet){                                            // first sync: derive from keys, scan from the chosen (or a recent) height
      const primary = xmr.subaddress(state.xmrKeys, netCfg, 0, 0);
      let restoreHeight = getXmrRestore(walletId, net);     // user-chosen "scan from" height wins
      if(restoreHeight == null){                            // otherwise default to a recent window (tip - 5000, with a floor)
        restoreHeight = XMR_FALLBACK_HEIGHT[net] || 0;
        if(info && info.ok && info.height) restoreHeight = Math.max(0, info.height - 5000);   // reuse the tip we already fetched
        else { try { const h = await moneroEngine.getDaemonHeight(nodeUrl); if(h) restoreHeight = Math.max(0, Number(h) - 5000); } catch(_){} }
      }
      sx.restoreHeight = restoreHeight; sx.start = restoreHeight; sx.height = 0;
      if(!sx.endHeight && info && info.height) sx.endHeight = info.height;
      render();
      console.log('[monero] node', nodeUrl, '· fresh sync from', restoreHeight);
      wallet = await moneroEngine.openFromKeys({ network:net, nodeUrl, primaryAddress:primary,
        privateViewKey: xmr.hex(state.xmrKeys.viewBytes), privateSpendKey: xmr.hex(state.xmrKeys.spendBytes), restoreHeight });
    }
    sx.wallet = wallet;
    sx.phase = 'scanning'; renderXmrStatus();
    await moneroEngine.sync(wallet, (pct, height, endHeight, startHeight) => {
      if(startHeight != null && !sx.start) sx.start = Number(startHeight);   // resume path: real scan start arrives with the first event
      if(endHeight) sx.endHeight = Number(endHeight);
      if(height) sx.height = Number(height);
      const span = sx.endHeight - sx.start;
      const blkPct = (span > 0 && sx.height > sx.start) ? Math.round((sx.height - sx.start) / span * 100) : 0;
      sx.pct = Math.min(100, Math.max(sx.pct, blkPct, Math.round((pct||0)*100)));   // monotonic; prefer block-based, fall back to engine pct
      renderXmrStatus();
    }, fresh ? sx.restoreHeight : undefined);
    try { sx.accounts = await moneroEngine.getAccounts(wallet); } catch(_){ sx.accounts = []; }
    const acct = sx.accounts.find(a => a.index === (state.xmrAccount || 0));
    if(acct){ sx.balance = acct.balance; sx.unlocked = acct.unlocked; }   // unlocked = spendable now; balance = incl. locked
    else { const big = v => (typeof v==='bigint') ? v : BigInt(v || 0);
      sx.balance = big(await wallet.getBalance(state.xmrAccount || 0));
      sx.unlocked = big(await wallet.getUnlockedBalance(state.xmrAccount || 0)); }
    try { sx.txs = await wallet.getTxs(); } catch(_){ sx.txs = []; }
    sx.synced = true;
    try { const d = await moneroEngine.getData(wallet); if(d && d[0] && d[1]) saveXmrData(walletId, net, d[0], d[1]); }   // persist for fast re-sync
    catch(e){ console.warn('[monero] getData failed:', e); }
  } catch(e){ sx.error = e.message || String(e); }
  finally { clearInterval(_xmrTick); _xmrTick = null; sx.syncing = false; render(); }
}

/* ============================== MODALS ============================== */
let _lastFocus = null, _scanStop = null;
function showModal(node){
  _lastFocus = document.activeElement;
  const modal = el('div',{class:'modal',role:'dialog','aria-modal':'true'}, node);
  clear($('overlay-mount')).append(
    el('div',{class:'overlay',onclick:e=>{ if(e.target.classList.contains('overlay')) closeModal(); }}, modal));
  a11yify();
  const focusable = () => [...modal.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),textarea,select')];
  const first = focusable()[0]; if(first) try{ first.focus(); }catch(_){}
  modal.addEventListener('keydown', e=>{                 // simple Tab focus trap
    if(e.key!=='Tab') return;
    const f = focusable(); if(!f.length) return;
    const a = f[0], z = f[f.length-1];
    if(e.shiftKey && document.activeElement===a){ e.preventDefault(); z.focus(); }
    else if(!e.shiftKey && document.activeElement===z){ e.preventDefault(); a.focus(); }
  });
}
function closeModal(){ if(_scanStop){ try{ _scanStop(); }catch(_){} _scanStop=null; } clear($('overlay-mount')); if(_lastFocus){ try{ _lastFocus.focus(); }catch(_){} _lastFocus=null; } }
document.addEventListener('keydown', e=>{ if(e.key==='Escape' && $('overlay-mount').firstChild) closeModal(); });

// Announce a message to screen readers via the dedicated visually-hidden live region (for in-place
// results that aren't in an aria-live container, e.g. modal broadcast outcomes).
function announce(msg){ const n = $('sr-live'); if(!n) return; n.textContent=''; setTimeout(()=>{ n.textContent = String(msg); }, 30); }
function toast(msg, kind){
  const t = el('div',{class:'toast '+(kind||'ok')}, msg);
  $('toast-wrap').append(t);
  setTimeout(()=>{ t.style.transition='opacity .3s'; t.style.opacity='0'; setTimeout(()=>t.remove(), 320); }, 2600);
}
function confirmModal(message, onYes, opts){
  opts = opts || {};
  const yes = el('button',{class:'btn'+(opts.danger?' danger':'')}, opts.yes || 'Confirm');
  yes.addEventListener('click', ()=>{ closeModal(); onYes(); });
  const no = el('button',{class:'btn ghost'}, opts.no || 'Cancel');
  no.addEventListener('click', ()=>{ if(opts.onNo){ opts.onNo(); } else closeModal(); });   // re-open the parent modal if any
  showModal(el('div',{},
    el('div',{class:'card-h'}, opts.title || 'Please confirm'),
    el('div',{class:'card-b stack'}, el('p',{}, message),
      el('div',{class:'row',style:'flex:0'}, yes, no))));
}

/* ---- camera QR scanner (jsQR) ---- */
function scanModal(onResult){
  if(!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)){ toast('Camera not available in this browser','bad'); return; }
  if(!globalThis.jsQR){ toast('QR scanner failed to load','bad'); return; }
  const video = el('video',{playsinline:'',muted:'',style:'width:100%;border-radius:var(--r-sm);background:#000'});
  const canvas = document.createElement('canvas');
  const status = el('div',{class:'sub',style:'margin-top:8px'},'Point your camera at a QR code…');
  let stream=null, raf=null, stopped=false;
  const stop = ()=>{ stopped=true; if(raf) cancelAnimationFrame(raf); if(stream) stream.getTracks().forEach(t=>t.stop()); };
  _scanStop = stop;
  showModal(el('div',{}, el('div',{class:'card-h'},'Scan QR code'),
    el('div',{class:'card-b stack'}, video, status, el('div',{}, el('button',{class:'btn ghost',onclick:closeModal},'Cancel')))));
  navigator.mediaDevices.getUserMedia({ video:{ facingMode:'environment' } }).then(s=>{
    if(stopped){ s.getTracks().forEach(t=>t.stop()); return; }    // modal was closed before the camera opened
    stream = s; video.srcObject = s; video.setAttribute('autoplay',''); video.play().catch(()=>{});
    const tick = ()=>{
      if(stopped) return;
      if(video.readyState === video.HAVE_ENOUGH_DATA && video.videoWidth){
        canvas.width = video.videoWidth; canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d'); ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(img.data, img.width, img.height);
        if(code && code.data){ closeModal(); onResult(code.data); return; }
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
  }).catch(e=>{ clear(status).append(el('span',{class:'bad'}, 'Camera error: ' + (e.message||e))); });
}

function seedGrid(mnemonic){
  const g = el('div',{class:'seed-grid'});
  mnemonic.split(' ').forEach((w,i)=> g.append(el('div',{class:'seed-word'}, el('b',{}, (i+1)+'.'), w)));
  return g;
}

function showSeedQuiz(mnemonic, onPass){
  const words = mnemonic.split(' ');
  const positions = [];
  while(positions.length < 3){ const p = Math.floor(Math.random()*words.length); if(!positions.includes(p)) positions.push(p); }
  positions.sort((a,b)=>a-b);
  const picked = {};
  const createBtn = el('button',{class:'btn',disabled:true},'Create wallet');
  const checkDone = ()=>{ createBtn.disabled = !positions.every(p=>picked[p]===words[p]); };
  const quiz = el('div',{class:'stack'});
  for(const p of positions){
    const opts = new Set([words[p]]);
    while(opts.size < 4){ opts.add(wordlist[Math.floor(Math.random()*wordlist.length)]); }
    const optArr = [...opts].sort(()=>Math.random()-0.5);
    const row = el('div',{class:'pills'}); const buttons = [];
    for(const w of optArr){ const b = el('div',{class:'pill'}, w);
      b.addEventListener('click', ()=>{ picked[p]=w; buttons.forEach(x=>x.classList.remove('active')); b.classList.add('active'); checkDone(); });
      buttons.push(b); row.append(b); }
    quiz.append(el('div',{}, el('div',{class:'sub'},'Word #'+(p+1)), row));
  }
  createBtn.addEventListener('click', ()=>onPass());
  showModal(el('div',{},
    el('div',{class:'card-h'},'Verify your recovery phrase'),
    el('div',{class:'card-b stack'},
      el('p',{class:'sub'},'Pick the correct word for each position to confirm you wrote your phrase down.'),
      quiz, el('div',{class:'row',style:'margin-top:8px'}, createBtn, el('button',{class:'btn ghost',onclick:()=>actCreate(words.length, mnemonic)},'Back')))));
}

/* create */
function actCreate(words, existing){
  words = words === 24 ? 24 : 12;
  const mnemonic = existing || generateMnemonic(wordlist, words === 24 ? 256 : 128);
  const nameInput = el('input',{type:'text',placeholder:'Wallet name (optional)'});
  const passInput = el('input',{...SECRET_ATTRS,type:'text',placeholder:'Passphrase (optional, advanced)'});
  const chk = el('input',{type:'checkbox'});
  const contBtn = el('button',{class:'btn',disabled:true},'Continue');
  chk.addEventListener('change', ()=>{ contBtn.disabled = !chk.checked; });
  contBtn.addEventListener('click', ()=>{ const name=nameInput.value.trim(), pass=passInput.value;
    showSeedQuiz(mnemonic, ()=> addWallet(name, mnemonic, pass)); });
  const copyEl = el('span',{class:'copy'},'copy phrase');
  copyEl.addEventListener('click', ()=>copyText(mnemonic, copyEl, true));
  const lenPills = el('div',{class:'pills'});
  for(const w of [12,24]){ const p = el('div',{class:'pill'+(w===words?' active':'')}, w+' words');
    if(w!==words) p.addEventListener('click', ()=>actCreate(w)); lenPills.append(p); }
  showModal(el('div',{},
    el('div',{class:'card-h'},'Your recovery phrase', copyEl),
    el('div',{class:'card-b'},
      el('div',{class:'between'}, el('span',{class:'sub'},'Length'), lenPills),
      el('div',{class:'msg warn',style:'margin-top:10px'},'Write these '+words+' words down in order and keep them safe. Anyone with this phrase (plus the passphrase, if you set one) controls the wallet.'),
      seedGrid(mnemonic),
      el('div',{class:'field'}, el('label',{class:'fld'},'Name'), nameInput),
      el('div',{class:'field'}, el('label',{class:'fld'},'Passphrase (optional) - a 25th word that creates a separate hidden wallet. You will need it to restore.'), passInput),
      el('label',{class:'fld',style:'display:flex;gap:8px;align-items:center;cursor:pointer'}, chk, 'I have saved my recovery phrase'),
      el('div',{class:'row',style:'margin-top:12px'}, contBtn, el('button',{class:'btn ghost',onclick:closeModal},'Cancel')),
    )));
}

/* import */
function actImport(){
  const ta = el('textarea',{...SECRET_ATTRS,placeholder:'Enter your 12, 15, 18, 21 or 24 word recovery phrase, separated by spaces'});
  const nameInput = el('input',{type:'text',placeholder:'Wallet name (optional)'});
  const passInput = el('input',{...SECRET_ATTRS,type:'text',placeholder:'Passphrase (optional, if the wallet had one)'});
  const msg = el('div',{});
  const btn = el('button',{class:'btn'},'Import wallet');
  btn.addEventListener('click', ()=>{
    const m = normalizePhrase(ta.value);
    if(!validateMnemonic(m, wordlist)){ clear(msg).append(el('div',{class:'msg bad'},'That phrase is not a valid BIP39 mnemonic (check spelling and word order).')); return; }
    addWallet(nameInput.value.trim(), m, passInput.value);
  });
  const elLink = el('button',{class:'btn ghost sm'},'Have an Electrum seed?');
  elLink.addEventListener('click', actImportElectrum);
  showModal(el('div',{},
    el('div',{class:'card-h'},'Import recovery phrase'),
    el('div',{class:'card-b'},
      el('div',{class:'field'}, el('label',{class:'fld'},'Recovery phrase'), ta),
      el('div',{class:'field'}, el('label',{class:'fld'},'Name'), nameInput),
      el('div',{class:'field'}, el('label',{class:'fld'},'Passphrase (optional)'), passInput),
      el('div',{class:'row'}, btn, el('button',{class:'btn ghost',onclick:closeModal},'Cancel')), msg,
      el('div',{class:'sub faint',style:'margin-top:8px'},'Coming from Electrum instead of a BIP39 wallet? ', elLink),
    )));
}
function actImportElectrum(){
  const ta = el('textarea',{...SECRET_ATTRS,placeholder:'Your Electrum seed phrase (standard or SegWit)'});
  const nameInput = el('input',{type:'text',placeholder:'Wallet name (optional)'});
  const passInput = el('input',{...SECRET_ATTRS,type:'text',placeholder:'Seed extension (optional, if the wallet had one)'});
  const msg = el('div',{});
  const btn = el('button',{class:'btn'},'Import Electrum wallet');
  btn.addEventListener('click', async ()=>{ clear(msg); btn.disabled=true; const o=btn.textContent; btn.textContent='Checking…';
    try { await electrumImport(ta.value, nameInput.value.trim(), passInput.value); }
    catch(e){ msg.append(el('div',{class:'msg bad'}, e.message||e)); btn.disabled=false; btn.textContent=o; } });
  showModal(el('div',{},
    el('div',{class:'card-h'},'Import Electrum seed'),
    el('div',{class:'card-b'},
      el('p',{class:'sub'},'Imports a standard (legacy) or SegWit Electrum wallet; the type is detected automatically. Old (pre-2.0) and 2FA seeds aren’t supported. Testnet addresses use Electrum’s exact derivation.'),
      el('div',{class:'field'}, el('label',{class:'fld'},'Electrum seed'), ta),
      el('div',{class:'field'}, el('label',{class:'fld'},'Name'), nameInput),
      el('div',{class:'field'}, el('label',{class:'fld'},'Seed extension (optional)'), passInput),
      el('div',{class:'row'}, btn, el('button',{class:'btn ghost',onclick:actImport},'Back')), msg,
    )));
}

// Shared backup-file importer: handles plaintext AND encrypted ({tnwbackup}) files (prompting for the password).
function handleBackupFile(text, msgEl, inputEl){
  clear(msgEl);
  let data; try { data = JSON.parse(text); } catch(_){ msgEl.append(el('div',{class:'msg bad'},'Not a valid backup file.')); if(inputEl) inputEl.value=''; return; }
  if(data && data.tnwbackup){                                  // encrypted backup -> prompt for its password
    const pwIn = el('input',{type:'password',placeholder:'Backup password',autocomplete:'off'});
    const go = el('button',{class:'btn sm'},'Decrypt & import');
    const err = el('div',{});
    const tryDecrypt = async ()=>{
      clear(err); go.disabled=true; go.textContent='Decrypting…';
      let json; try { json = await decWith(await deriveKey(pwIn.value, b64decode(data.salt), data.iter || KDF_ITER), data.iv, data.ct); }
      catch(_){ err.append(el('div',{class:'msg bad'},'Wrong password or corrupt file.')); go.disabled=false; go.textContent='Decrypt & import'; return; }
      try { finishImport(importBackup(JSON.parse(json))); }     // decrypt succeeded; surface import errors distinctly
      catch(e){ err.append(el('div',{class:'msg bad'},'Import failed: '+(e.message||e))); go.disabled=false; go.textContent='Decrypt & import'; }
    };
    go.addEventListener('click', tryDecrypt);
    pwIn.addEventListener('keydown', e=>{ if(e.key==='Enter') tryDecrypt(); });
    msgEl.append(el('div',{class:'sub'},'This backup is encrypted - enter its password.'), el('div',{class:'row',style:'flex:0;margin-top:6px'}, pwIn, go), err);
    try{ pwIn.focus(); }catch(_){}
  } else {
    try { finishImport(importBackup(data)); } catch(e){ msgEl.append(el('div',{class:'msg bad'},'Import failed: '+(e.message||e))); }
  }
  if(inputEl) inputEl.value='';
}
/* backup (reveal phrase + export/import file) */
function actBackup(){
  const revealBtn = el('button',{class:'btn ghost sm'},'Reveal recovery phrase');
  const holder = el('div',{});
  revealBtn.addEventListener('click', ()=>{ clear(holder).append(seedGrid(state.wallet.mnemonic));
    if(state.wallet.passphrase) holder.append(el('div',{class:'msg warn'},'This wallet also has a passphrase set. You need both the phrase and the passphrase to restore it.'));
    revealBtn.remove(); });
  const exportFull = el('button',{class:'btn'},'Export full backup');
  exportFull.addEventListener('click', exportSnapshot);
  const exportOne = el('button',{class:'btn ghost'},'This wallet only');
  exportOne.addEventListener('click', ()=>{
    const data = { type:'testnetwallet-backup', version:1, name:state.wallet.name, mnemonic:state.wallet.mnemonic, passphrase:state.wallet.passphrase || '',
      ...(isElectrum(state.wallet) ? { scheme:state.wallet.scheme, xprv:state.wallet.xprv } : {}) };
    downloadBlob(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}), 'testnetwallet-'+state.wallet.name.replace(/\W+/g,'_')+'.json');
  });
  const fileInput = el('input',{type:'file',accept:'application/json,.json',style:'display:none'});
  const importBtn = el('button',{class:'btn ghost'},'Import backup file');
  const msg = el('div',{});
  importBtn.addEventListener('click', ()=>fileInput.click());
  fileInput.addEventListener('change', ()=>{
    const f = fileInput.files[0]; if(!f) return;
    const reader = new FileReader();
    reader.onload = ()=> handleBackupFile(reader.result, msg, fileInput);
    reader.readAsText(f);
  });
  showModal(el('div',{},
    el('div',{class:'card-h'},'Backup & restore'),
    el('div',{class:'card-b stack'},
      el('div',{class:'msg warn'},'Your recovery phrase is the only way to restore a wallet. A backup file holds your recovery phrases in plain text, so keep it private.'),
      revealBtn, holder,
      el('hr',{class:'hr'}),
      el('div',{class:'sub'},'A full backup is one file with every wallet, your contacts, transaction notes, address counts and settings. Restore it in another browser to pick up where you left off.'),
      el('div',{class:'row'}, exportFull, exportOne, importBtn), fileInput, msg,
      el('div',{class:'row',style:'margin-top:8px'}, el('button',{class:'btn ghost',onclick:closeModal},'Close')),
    )));
}

/* wallets list / switch / rename / forget / add */
function actWallets(editId){
  const listWrap = el('div',{class:'stack'});
  for(const w of (store.wallets||[])){
    const isActive = w.id===store.activeId;
    let left;
    if(w.id===editId){
      const input = el('input',{type:'text',value:w.name});
      const save = el('button',{class:'btn sm'},'Save');
      save.addEventListener('click', ()=>{ const n=input.value.trim(); if(n){ w.name=n; saveStore(); if(isActive) render(); } actWallets(); });
      left = el('div',{class:'row',style:'flex:1;align-items:center'}, input, save);
    } else {
      const rename = el('button',{class:'btn ghost sm'},'Rename');
      rename.addEventListener('click', ()=>actWallets(w.id));
      const forget = el('button',{class:'btn ghost sm'},'Forget');
      forget.addEventListener('click', ()=>{ confirmModal('Forget "'+w.name+'"? Make sure you have its recovery phrase saved. This only removes it from this browser.', ()=>{
        store.wallets = (store.wallets||[]).filter(x=>x.id!==w.id);
        if(store.counts) delete store.counts[w.id];
        if(store.txNotes) delete store.txNotes[w.id];
        deleteXmrData(w.id);                                   // purge the wallet's Monero keys+cache too
        saveStore();
        if(state.wallet && state.wallet.id===w.id){
          const next = (store.wallets||[])[0];
          if(next){ openWallet(next); actWallets(); }
          else { store.activeId=null; saveStore(); state.wallet=null; state.master=null; closeModal(); render(); }
        } else { actWallets(); }
      }, {danger:true, yes:'Forget', title:'Forget wallet', onNo:()=>actWallets()}); });
      left = el('div',{class:'row',style:'align-items:center;flex:1;gap:8px'}, el('span',{style:'flex:1'}, w.name), rename, forget);
    }
    const useBtn = el('button',{class:'btn ghost sm',...(isActive?{disabled:true}:{})}, isActive?'Active':'Use');
    if(!isActive) useBtn.addEventListener('click', ()=>{ closeModal(); openWallet(w); });
    listWrap.append(el('div',{class:'between',style:'border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 12px;gap:8px'},
      left, useBtn));
  }
  showModal(el('div',{},
    el('div',{class:'card-h'},'Wallets'),
    el('div',{class:'card-b stack'}, listWrap,
      el('div',{class:'row',style:'margin-top:8px'},
        el('button',{class:'btn',onclick:()=>{ closeModal(); actCreate(); }},'+ Create new'),
        el('button',{class:'btn ghost',onclick:()=>{ closeModal(); actImport(); }},'Import phrase'),
      ),
      el('div',{class:'row',style:'margin-top:4px'}, el('button',{class:'btn ghost',onclick:closeModal},'Close')),
    )));
}

/* ============================== byte / crypto helpers ============================== */
function hexToBytes(h){ h=String(h).trim().replace(/^0x/,''); if(h.length%2) throw new Error('odd-length hex'); if(!/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const a=new Uint8Array(h.length/2); for(let i=0;i<a.length;i++) a[i]=parseInt(h.substr(i*2,2),16); return a; }
function bytesToHex(b){ let s=''; for(const x of b) s+=x.toString(16).padStart(2,'0'); return s; }
function utf8(s){ return new TextEncoder().encode(s); }
function dsha256(b){ return sha256(sha256(b)); }
function concatBytes(...arr){ let n=0; for(const a of arr) n+=a.length; const o=new Uint8Array(n); let p=0; for(const a of arr){ o.set(a,p); p+=a.length; } return o; }
function varint(n){ if(n<0xfd) return Uint8Array.of(n); if(n<=0xffff) return Uint8Array.of(0xfd,n&0xff,n>>8&0xff);
  return Uint8Array.of(0xfe,n&0xff,n>>8&0xff,n>>16&0xff,n>>24&0xff); }
function b64encode(b){ let s=''; for(const x of b) s+=String.fromCharCode(x); return btoa(s); }
function b64decode(str){ const s=atob(str.trim()); const a=new Uint8Array(s.length); for(let i=0;i<s.length;i++) a[i]=s.charCodeAt(i); return a; }

/* ---- legacy "Signed Message" (BIP137-style, compressed P2PKH) ---- */
function msgDigest(coin, message){
  const p = utf8(COINS[coin].msgPrefix), m = utf8(message);
  return dsha256(concatBytes(varint(p.length), p, varint(m.length), m));
}
async function signMessage(coin, node, message){
  const sig = await secp.signAsync(msgDigest(coin, message), node.privateKey);  // recovered Signature
  const header = 27 + sig.recovery + 4;                                          // +4 = compressed pubkey
  return b64encode(concatBytes(Uint8Array.of(header), sig.toCompactRawBytes()));
}
function verifyMessage(coin, address, message, sigB64){
  try {
    const raw = b64decode(sigB64);
    if(raw.length !== 65) return false;
    const rec = (raw[0]-27) & 3, compressed = ((raw[0]-27) & 4) !== 0;
    const sig = secp.Signature.fromCompact(raw.slice(1)).addRecoveryBit(rec);
    const pub = sig.recoverPublicKey(msgDigest(coin, message)).toRawBytes(compressed);
    return btc.p2pkh(pub, COINS[coin].net).address === address;
  } catch(_){ return false; }
}

/* ---- transaction / script decoding (shapes vary, so be defensive) ---- */
function addrFromScript(script, net){ try { return btc.Address(net).encode(btc.OutScript.decode(script)); } catch(_){ return null; } }
function txOutsList(tx){ const n = tx.outputsLength ?? (tx.outputs ? tx.outputs.length : 0); const a=[];
  for(let i=0;i<n;i++) a.push(tx.getOutput ? tx.getOutput(i) : tx.outputs[i]); return a; }
function txInsList(tx){ const n = tx.inputsLength ?? (tx.inputs ? tx.inputs.length : 0); const a=[];
  for(let i=0;i<n;i++) a.push(tx.getInput ? tx.getInput(i) : tx.inputs[i]); return a; }
function looksPSBT(s){ s=s.trim(); return s.startsWith('cHNidP') || s.toLowerCase().startsWith('70736274'); }
function decodeAnyTx(coin, input){
  const net = COINS[coin].net; input = input.trim();
  let tx, kind;
  if(looksPSBT(input)){ tx = btc.Transaction.fromPSBT(/^[0-9a-fA-F]+$/.test(input) ? hexToBytes(input) : b64decode(input)); kind='PSBT'; }
  else { tx = btc.Transaction.fromRaw(hexToBytes(input), { allowUnknownOutputs:true, disableScriptCheck:true }); kind='raw transaction'; }
  const safe = fn => { try { return fn(); } catch(_){ return null; } };
  return { kind, version: safe(()=>tx.version), locktime: safe(()=>tx.lockTime), id: safe(()=>tx.id), vsize: safe(()=>tx.vsize),
    inputs: txInsList(tx).map(i=>({ txid: i.txid?bytesToHex(i.txid):'', index: i.index })),
    outputs: txOutsList(tx).map(o=>({ amount: typeof o.amount==='bigint'?Number(o.amount):(o.amount||0), address: o.script?addrFromScript(o.script,net):null, script: o.script?bytesToHex(o.script):'' })) };
}

/* ---- extra data-layer calls ---- */
async function getPrevTxHex(coin, txid){
  const ac=new AbortController(); const t=setTimeout(()=>ac.abort('timeout'),12000);
  try { const r=await fetch(apiBase(coin)+'/tx/'+encodeURIComponent(txid)+'/hex',{signal:ac.signal});
    if(!r.ok) throw new Error('HTTP '+r.status); return (await r.text()).trim(); } finally { clearTimeout(t); }
}
// Standard-Esplora fallback: GET /fee-estimates -> { "1": satvB, "2":…, "6":…, "144":… } (confirm-target -> rate).
async function feeEstimatesFallback(coin){
  const d = await apiGet(coin, '/fee-estimates');
  const at = targets => { for(const k of targets){ const v = d && d[k]; if(typeof v === 'number' && v > 0) return Math.max(1, Math.round(v)); } return null; };
  return { fast: at(['1','2']) || 2, medium: at(['3','6','4']) || 1, slow: at(['6','12','144']) || 1 };
}
async function getFeeEstimates(coin){
  try { const d = await apiGet(coin, '/v1/fees/recommended');        // mempool.space extension (richer)
    return { slow: d.economyFee||d.hourFee||1, medium: d.halfHourFee||d.hourFee||1, fast: d.fastestFee||d.halfHourFee||2 }; }
  catch(_){ try { return await feeEstimatesFallback(coin); }          // vanilla Blockstream-Esplora self-hosts
    catch(_e){ return { slow:1, medium:1, fast:2 }; } }
}
async function getFeeRate(coin){ try { return (await getFeeEstimates(coin)).medium || 1; } catch(_){ return 1; } }

/* ============================== SEND (P2) ============================== */
function parseBip21(uri){
  const m = String(uri).match(/^[a-zA-Z]+:([^?]*)(\?(.*))?$/);
  if(!m) return { address: String(uri) };
  const p = new URLSearchParams(m[3] || '');
  return { address: decodeURIComponent(m[1]), amount: p.get('amount') || '', label: p.get('label') || '' };
}
// Build the candidate input set across the current coin+type addresses (with the key that signs each).
async function gatherInputs(coin, type){
  const net = COINS[coin].net; const out = [];
  for(const a of state.addresses){
    const node = deriveNode(type, a.index), pub = node.publicKey;
    const utxos = await getUtxos(coin, a.address);
    for(const u of utxos){
      const base = { txid: u.txid, index: u.vout, sequence: 0xfffffffd };   // signal RBF (replaceable)
      let inp;
      if(type==='wpkh') inp = { ...base, witnessUtxo:{ script: btc.p2wpkh(pub, net).script, amount: BigInt(u.value) } };
      else if(type==='sh-wpkh'){ const wrapped = btc.p2sh(btc.p2wpkh(pub, net), net); inp = { ...base, witnessUtxo:{ script: wrapped.script, amount: BigInt(u.value) }, redeemScript: wrapped.redeemScript }; }
      else if(type==='tr'){ const xo = pub.slice(1); inp = { ...base, tapInternalKey: xo, witnessUtxo:{ script: btc.p2tr(xo, undefined, net).script, amount: BigInt(u.value) } }; }
      else { inp = { ...base, nonWitnessUtxo: hexToBytes(await getPrevTxHex(coin, u.txid)) }; }
      out.push({ inp, key: node.privateKey, outpoint: u.txid+':'+u.vout, value: u.value, address: a.address, confirmed: !!(u.status && u.status.confirmed) });
    }
  }
  return out;
}
function opReturnScript(send){
  if(!send.opReturn.trim()) return null;
  const data = send.opReturnHex ? hexToBytes(send.opReturn) : utf8(send.opReturn);
  if(data.length > 80) throw new Error('OP_RETURN data exceeds 80 bytes');
  return btc.Script.encode(['RETURN', data]);
}
// Select inputs + outputs for the current send form (does NOT sign). Returns {tx, cand, fee, totalOut, feeRate, net}.
async function buildSelection(){
  const coin = state.coin, type = state.addrType, send = state.send, net = COINS[coin].net;
  const recips = send.recipients.map(r=>({ address:r.address.trim(), amount:r.amount })).filter(r=>r.address || r.amount);
  if(!recips.length) throw new Error('Add at least one recipient');
  const outputs = [];
  let totalOut = 0n;
  for(const r of recips){
    if(!isValidAddress(r.address, coin)) throw new Error('Invalid '+COINS[coin].name+' address: '+(r.address||'(empty)'));
    const sats = Math.round(parseFloat(r.amount) * 1e8);
    if(!(sats > 0)) throw new Error('Invalid amount for '+r.address);
    if(sats < DUST) throw new Error('Amount below dust threshold ('+DUST+' sats) for '+r.address);
    outputs.push({ address: r.address, amount: BigInt(sats) }); totalOut += BigInt(sats);
  }
  const opScript = opReturnScript(send);
  if(opScript) outputs.push({ script: opScript, amount: 0n });
  const feeRate = Math.max(1, Math.round(parseFloat(send.feeRate) || 1));

  let cand = await gatherInputs(coin, type);
  const chosen = Object.keys(send.selected).filter(k=>send.selected[k]);
  if(send.advanced && chosen.length){
    cand = cand.filter(c=>send.selected[c.outpoint]);                  // explicit coin control may opt into unconfirmed coins
  } else {
    const confirmed = cand.filter(c=>c.confirmed);                     // default: spend confirmed UTXOs only
    if(confirmed.length) cand = confirmed;
    else if(cand.length) throw new Error('Only unconfirmed coins are available - use Coin control to spend them.');
  }
  if(!cand.length) throw new Error('No spendable coins selected');

  const sel = btc.selectUTXO(cand.map(c=>c.inp), outputs, 'default', {
    changeAddress: state.addresses[0].address, feePerByte: BigInt(feeRate), dust: BigInt(DUST),
    network: net, createTx: true, allowUnknownOutputs: !!opScript,
  });
  if(!sel || !sel.tx) throw new Error('Not enough coins to cover amount + fee');
  return { tx: sel.tx, cand, fee: Number(sel.fee), totalOut: Number(totalOut), feeRate, net };
}
// Build + sign (does NOT broadcast). Returns {tx, fee, change, totalOut}.
async function buildSend(){
  const b = await buildSelection();
  const signed = new Set();
  for(const c of b.cand){ const kh = bytesToHex(c.key); if(signed.has(kh)) continue; signed.add(kh); try { b.tx.sign(c.key); } catch(_){} }
  b.tx.finalize();
  // sel.change is just a boolean has-change flag, so read the real change amount back from the finalized tx
  const changeAddr = state.addresses[0].address; let change = 0;
  try { for(let i=0;i<(b.tx.outputsLength||0);i++){ const o = b.tx.getOutput(i); if(o && o.script && addrFromScript(o.script, b.net) === changeAddr) change += Number(o.amount); } } catch(_){}
  return { tx: b.tx, fee: b.fee, change, totalOut: b.totalOut, feeRate: b.feeRate };
}
// Build the same transaction but export it UNSIGNED as a base64 PSBT (for offline/multi-party signing).
async function buildUnsignedPSBT(){ const b = await buildSelection(); return b64encode(b.tx.toPSBT()); }

/* ---- CPFP: spend our unconfirmed output(s) from a parent tx at a high fee ---- */
async function cpfpSpeedUp(coin, type, parentTxid, feeRate){
  const net = COINS[coin].net;
  const cand = (await gatherInputs(coin, type)).filter(c => c.outpoint.indexOf(parentTxid+':')===0 && !c.confirmed);
  if(!cand.length) throw new Error('No spendable unconfirmed output from this transaction to bump');
  const dest = state.addresses[0].address;
  let total = 0n; for(const c of cand) total += BigInt(c.value);
  const rate = Math.max(1, Math.round(parseFloat(feeRate) || 1));
  const build = fee => { const tx = new btc.Transaction({}); for(const c of cand) tx.addInput(c.inp);
    tx.addOutputAddress(dest, total - fee, net);
    const signed = new Set(); for(const c of cand){ const kh = bytesToHex(c.key); if(signed.has(kh)) continue; signed.add(kh); try { tx.sign(c.key); } catch(_){} }
    tx.finalize(); return tx; };
  let tx = build(0n);
  const fee = BigInt(Math.max(1, Math.ceil((tx.vsize + cand.length) * rate)));   // +1 vB/input margin
  if(total - fee <= BigInt(DUST)) throw new Error('Output too small to bump');
  tx = build(fee);
  return broadcast(coin, tx.hex);
}
// Replace-by-fee: rebuild a pending OUTGOING tx of ours at a higher fee (taken from change), re-sign, re-broadcast.
async function bumpFeeRBF(coin, txid, feeRate){
  const net = COINS[coin].net;
  const orig = await apiGet(coin, '/tx/'+encodeURIComponent(txid));         // need the full prevouts (state.txs.vin is lossy)
  const mine = {};                                                          // our address -> {type, node}
  for(const type of Object.keys(TYPES)){ for(let i=0;i<Math.max(addrCount(),20);i++){ try { const node=deriveNode(type,i); mine[addrFromPub(node.publicKey, coin, type)] = { type, node }; } catch(_){} } }
  const inputs = []; let inSum = 0n;
  for(const vi of (orig.vin||[])){
    const pa = vi.prevout && vi.prevout.scriptpubkey_address, m = pa && mine[pa];
    if(!m) throw new Error('This wallet doesn’t hold every input of that transaction - it can’t be replaced here.');
    const value = BigInt(vi.prevout.value); inSum += value;
    const pub = m.node.publicKey, type = m.type, base = { txid: vi.txid, index: vi.vout, sequence: 0xfffffffd };   // keep RBF-signalling
    let inp;
    if(type==='wpkh') inp = { ...base, witnessUtxo:{ script: btc.p2wpkh(pub, net).script, amount: value } };
    else if(type==='sh-wpkh'){ const w=btc.p2sh(btc.p2wpkh(pub,net),net); inp = { ...base, witnessUtxo:{ script:w.script, amount:value }, redeemScript:w.redeemScript }; }
    else if(type==='tr'){ const xo=pub.slice(1); inp = { ...base, tapInternalKey:xo, witnessUtxo:{ script: btc.p2tr(xo,undefined,net).script, amount:value } }; }
    else inp = { ...base, nonWitnessUtxo: hexToBytes(await getPrevTxHex(coin, vi.txid)) };
    inputs.push({ inp, key: m.node.privateKey });
  }
  const recipients = []; const change = []; let outSum = 0n;                 // recipients fixed; our outputs = change we can shrink
  for(const vo of (orig.vout||[])){ outSum += BigInt(vo.value); const a = vo.scriptpubkey_address;
    if(a && mine[a]) change.push(BigInt(vo.value)); else recipients.push({ script: hexToBytes(vo.scriptpubkey), value: BigInt(vo.value) }); }
  if(!change.length) throw new Error('That transaction has no change back to this wallet, so there’s nothing to take the extra fee from.');
  const changeSum = change.reduce((s,v)=>s+v, 0n);
  const changeAddr = state.addresses[state.addresses.length-1].address;
  const oldFee = inSum - outSum, rate = Math.max(1, Math.round(parseFloat(feeRate)||1));
  const build = changeTotal => {
    const tx = new btc.Transaction({ allowUnknownOutputs:true, disableScriptCheck:true });
    for(const x of inputs) tx.addInput(x.inp);
    for(const r of recipients) tx.addOutput({ script:r.script, amount:r.value });
    if(changeTotal > 0n) tx.addOutputAddress(changeAddr, changeTotal, net);
    const seen=new Set(); for(const x of inputs){ const kh=bytesToHex(x.key); if(seen.has(kh)) continue; seen.add(kh); try { tx.sign(x.key); } catch(_){} }
    tx.finalize(); return tx;
  };
  let tx = build(changeSum);
  const minBump = oldFee + BigInt(Math.ceil(tx.vsize));                      // BIP125: new fee >= old fee + replacement vsize * 1 sat/vB
  let newFee = BigInt(Math.ceil(tx.vsize * rate)); if(newFee < minBump) newFee = minBump;
  const newChange = changeSum - (newFee - oldFee);
  if(newChange <= BigInt(DUST)) throw new Error('The change is too small to raise the fee that much - try a lower rate.');
  tx = build(newChange);
  return { tx, oldFee: Number(oldFee), newFee: Number(newFee) };
}
async function reviewSend(btnEl){
  const c = COINS[state.coin];
  btnEl.disabled = true; const label = btnEl.textContent; btnEl.textContent = 'Building…';
  try {
    const built = await buildSend();
    showSendConfirm(built);
  } catch(e){ state.send.error = e.message || String(e); render(); }
  finally { btnEl.disabled = false; btnEl.textContent = label; }
}
function showSendConfirm(built){
  const c = COINS[state.coin]; const { tx, fee, change, totalOut, feeRate } = built;
  const rows = state.send.recipients.filter(r=>r.address.trim()).map(r=>
    el('tr',{}, el('td',{class:'addr'}, r.address.trim()), el('td',{class:'amt'}, r.amount+' '+c.ticker)));
  if(state.send.opReturn.trim()){
    let orLen = 0; try { orLen = (state.send.opReturnHex ? hexToBytes(state.send.opReturn) : utf8(state.send.opReturn)).length; } catch(_){}
    rows.push(el('tr',{}, el('td',{}, el('span',{class:'muted'},'OP_RETURN data'), el('span',{class:'sub'},' · '+orLen+' byte'+(orLen===1?'':'s'))), el('td',{class:'amt'},'0 '+c.ticker)));
  }
  const ownAddr = state.send.recipients.some(r=>r.address.trim() && state.addresses.some(x=>x.address===r.address.trim()));
  const nearAll = state.totalSats>0 && (totalOut+fee) >= state.totalSats*0.99;
  const msg = el('div',{});
  const bcBtn = el('button',{class:'btn'},'Broadcast');
  bcBtn.addEventListener('click', async ()=>{
    bcBtn.disabled = true; bcBtn.textContent = 'Broadcasting…';
    try {
      const txid = await broadcast(state.coin, tx.hex);
      toast('Transaction broadcast','ok'); announce('Transaction broadcast successfully. Transaction ID '+txid);
      clear(msg).append(el('div',{class:'msg ok'}, el('div',{},'✓ Sent. Your balance will update shortly.'),
        el('a',{class:'addr',href:c.explorer+'/tx/'+txid,target:'_blank',rel:'noopener'}, txid)));
      state.send.recipients = [{address:'',amount:''}]; state.send.opReturn=''; state.send.selected={}; state.send.utxos=null;
      bcBtn.remove(); refresh();
    } catch(e){ const em = '✗ '+(e.message||e); clear(msg).append(el('div',{class:'msg bad'}, em)); announce('Broadcast failed. '+(e.message||e)); bcBtn.disabled=false; bcBtn.textContent='Broadcast'; }
  });
  showModal(el('div',{},
    el('div',{class:'card-h'},'Confirm transaction'),
    el('div',{class:'card-b stack'},
      el('div',{class:'msg warn'},'Review carefully. Once broadcast, a transaction cannot be undone.'),
      ownAddr ? el('div',{class:'msg warn'},'One recipient is your own address.') : null,
      nearAll ? el('div',{class:'msg warn'},'This sends nearly your entire balance.') : null,
      el('table',{}, el('thead',{}, el('tr',{}, el('th',{},'To'), el('th',{class:'amt'},'Amount'))), el('tbody',{}, ...rows)),
      el('div',{class:'between'}, el('span',{class:'muted'},'Network fee'), el('span',{class:'amt'}, fmt(fee)+' '+c.ticker+' ('+feeRate+' sat/vB, '+tx.vsize+' vB)')),
      el('div',{class:'between'}, el('span',{class:'muted'},'Change back to you'), el('span',{class:'amt'}, fmt(change)+' '+c.ticker)),
      el('div',{class:'between'}, el('strong',{},'Total spent'), el('strong',{class:'amt'}, fmt(totalOut+fee)+' '+c.ticker)),
      el('div',{class:'row',style:'margin-top:6px'}, bcBtn, el('button',{class:'btn ghost',onclick:closeModal},'Cancel')), msg,
    )));
}
async function loadCoinControl(btnEl){
  btnEl.disabled = true; const lbl = btnEl.textContent; btnEl.textContent='Loading…';
  try {
    const lists = await Promise.all(state.addresses.map(a => getUtxos(state.coin, a.address).then(u=>u.map(x=>({...x, address:a.address}))).catch(()=>[])));
    state.send.utxos = lists.flat();
  } catch(e){ state.send.error = e.message||String(e); }
  finally { btnEl.disabled=false; btnEl.textContent=lbl; render(); }
}
function inputVbytes(type){ return type==='pkh'?148 : type==='sh-wpkh'?91 : type==='tr'?58 : 68; }
async function maxFill(i){
  const s = state.send;
  try {
    let cand = await gatherInputs(state.coin, state.addrType);
    const chosen = Object.keys(s.selected).filter(k=>s.selected[k]);
    if(s.advanced && chosen.length) cand = cand.filter(c=>s.selected[c.outpoint]);
    else { const confirmed = cand.filter(c=>c.confirmed); if(confirmed.length) cand = confirmed; else if(cand.length){ toast('Only unconfirmed coins available. Turn on Coin control to spend them.','warn'); return; } }   // match buildSelection
    if(!cand.length){ toast('No spendable coins','warn'); return; }
    const total = cand.reduce((a,c)=>a+c.value,0);
    const rate = Math.max(1, Math.round(parseFloat(s.feeRate)||1));
    const fee = Math.ceil((cand.length*inputVbytes(state.addrType) + 34 + 11) * rate);  // ~1-output estimate
    const max = total - fee;
    if(max <= DUST){ toast('Balance too low to send','warn'); return; }
    s.recipients[i].amount = fmt(max);
    if(state.price) s.recipients[i].fiatAmount = (max/1e8*state.price).toFixed(2);
    render();
  } catch(e){ toast('Max failed: '+(e.message||e),'bad'); }
}
function renderSend(){
  const c = COINS[state.coin], s = state.send;
  s.denom = s.denom || 'coin';
  const inFiat = s.denom==='fiat' && state.price!=null;
  const recipWrap = el('div',{class:'stack'});
  s.recipients.forEach((r,i)=>{
    const vbadge = el('span',{class:'sub'});
    const setBadge = v=>{ clear(vbadge); const a=(v||'').trim(); if(!a) return;
      if(isValidAddress(a, state.coin)){ const own = state.addresses.some(x=>x.address===a);
        vbadge.append(el('span',{class:own?'warn':'ok'}, own?'✓ your own address':'✓ valid address')); }
      else vbadge.append(el('span',{class:'bad'}, '✗ not a valid '+c.name+' testnet address')); };
    const addr = el('input',{type:'text',value:r.address,placeholder:c.name+' address or '+c.uri+': URI',oninput:e=>{
      const v=e.target.value;
      if(/^[a-zA-Z][a-zA-Z0-9.+-]*:/.test(v)){ const p=parseBip21(v); s.recipients[i].address=p.address; if(p.amount){ s.recipients[i].amount=p.amount; s.recipients[i].fiatAmount = state.price ? (parseFloat(p.amount)*state.price).toFixed(2) : ''; } render(); return; }
      s.recipients[i].address=v; setBadge(v);
    }});
    setBadge(r.address);
    const amt = el('input',{type:'number',min:'0',step:inFiat?'0.01':'0.00000001',value:inFiat?(r.fiatAmount||''):(r.amount||''),placeholder:inFiat?('amount in '+state.fiat):'amount',style:'max-width:150px',oninput:e=>{
      const v=e.target.value;
      if(inFiat){ r.fiatAmount=v; r.amount = v ? (parseFloat(v)/state.price).toFixed(8) : ''; }
      else { r.amount=v; r.fiatAmount = (v && state.price) ? (parseFloat(v)*state.price).toFixed(2) : ''; }
    }});
    const maxBtn = el('button',{class:'btn ghost sm',title:'Send maximum',onclick:()=>maxFill(i)},'Max');
    const pick = (store.contacts && store.contacts.length)   // only offer "Pick" once there are contacts to pick from
      ? el('button',{class:'btn ghost sm',title:'Pick from contacts',onclick:()=>actContacts(a=>{ s.recipients[i].address=a; closeModal(); render(); })},'Pick')
      : null;
    const scan = el('button',{class:'btn ghost sm',title:'Scan QR',onclick:()=>scanModal(text=>{ const p=parseBip21(text); s.recipients[i].address=p.address; if(p.amount){ s.recipients[i].amount=p.amount; s.recipients[i].fiatAmount = state.price ? (parseFloat(p.amount)*state.price).toFixed(2) : ''; } render(); })},'Scan');
    const rm = el('button',{class:'btn ghost sm',title:'Remove recipient','aria-label':'Remove recipient',onclick:()=>{ s.recipients.splice(i,1); if(!s.recipients.length) s.recipients.push({address:'',amount:''}); render(); }},'✕');
    const hint = el('span',{class:'sub'}, inFiat ? (r.amount ? '≈ '+fmt(Math.round(parseFloat(r.amount)*1e8))+' '+c.ticker : '') : (r.fiatAmount ? '≈ '+FIATS[state.fiat]+r.fiatAmount+' '+state.fiat : ''));
    // address on its own line; amount + actions below; keeps each recipient legible on narrow screens
    recipWrap.append(el('div',{class:'stack',style:'gap:8px'+(i?';border-top:1px solid var(--border);padding-top:12px':'')},
      addr,
      el('div',{class:'row',style:'align-items:center'}, amt, maxBtn, pick, scan, rm),
      el('div',{class:'between'}, vbadge, hint)));
  });
  const denomPills = el('div',{class:'pills'});
  for(const [k,lbl] of [['coin',c.ticker],['fiat',state.fiat]]){
    const dis = k==='fiat' && state.price==null;
    const p = el('div',{class:'pill'+(s.denom===k?' active':'')+(dis?' disabled':'')}, lbl);
    if(!dis && s.denom!==k) p.addEventListener('click', ()=>{ s.denom=k; render(); });
    denomPills.append(p);
  }
  const feeInput = el('input',{type:'number',min:'1',step:'1',value:s.feeRate||'',placeholder:'sat/vB',style:'max-width:120px',title:'Fee rate in satoshis per virtual byte. Higher confirms faster. Minimum is 1 sat/vB; suggestions come from recent blocks.',oninput:e=>{ s.feeRate=e.target.value; }});
  const suggestBtn = el('button',{class:'btn ghost sm'},'Suggest');
  suggestBtn.addEventListener('click', async ()=>{ suggestBtn.disabled=true; s.feeRate=String(await getFeeRate(state.coin)); suggestBtn.disabled=false; render(); });
  const FEE_ETA = { slow:'≈ 1 hour', medium:'≈ 30 min', fast:'≈ next blocks' };
  if((!s._feeEst || s._feeEstCoin !== state.coin) && !s._feeEstLoading){      // fetch live tiers once per coin, for the labels + auto-fill
    s._feeEstLoading = true;
    getFeeEstimates(state.coin).then(e=>{ s._feeEst=e; s._feeEstCoin=state.coin; s._feeEstLoading=false; if(!s.feeRate) s.feeRate=String(e[state.feePref]||e.medium); render(); }).catch(()=>{ s._feeEstLoading=false; });
  }
  const _est = (s._feeEst && s._feeEstCoin===state.coin) ? s._feeEst : null;
  const feePills = el('div',{class:'pills'});
  for(const [k,lbl] of [['slow','Slow'],['medium','Medium'],['fast','Fast']]){
    const rate = _est ? _est[k] : null;
    const p = el('div',{class:'pill'+(state.feePref===k?' active':''),title:(rate?rate+' sat/vB · ':'')+FEE_ETA[k]}, rate ? (lbl+' · '+rate) : lbl);
    p.addEventListener('click', async ()=>{ state.feePref=k; saveSettings(); const e=(s._feeEst&&s._feeEstCoin===state.coin)?s._feeEst:await getFeeEstimates(state.coin); s._feeEst=e; s._feeEstCoin=state.coin; s.feeRate=String(e[k]); render(); });
    feePills.append(p);
  }
  const feePresets = el('div',{class:'stack',style:'gap:4px'}, feePills,
    el('div',{class:'sub faint',style:'font-size:12px'},'Slow ≈ 1 hr · Medium ≈ 30 min · Fast ≈ next blocks. Higher sat/vB confirms sooner.'));

  const advToggle = el('label',{class:'fld',style:'display:flex;gap:8px;align-items:center;cursor:pointer'},
    el('input',{type:'checkbox',checked:s.advanced,onchange:e=>{ s.advanced=e.target.checked; render(); }}), 'Coin control: choose which coins may be spent');
  const advBlock = el('div',{});
  if(s.advanced){
    if(!s.utxos){ const lb=el('button',{class:'btn ghost sm'},'Load coins'); lb.addEventListener('click',()=>loadCoinControl(lb)); advBlock.append(lb); }
    else if(!s.utxos.length){ advBlock.append(el('p',{class:'muted'},'No coins found for this coin type.')); }
    else {
      const t=el('table',{}, el('thead',{}, el('tr',{}, el('th',{},''), el('th',{},'UTXO'), el('th',{class:'amt'},'Value'))));
      const tb=el('tbody',{});
      for(const u of s.utxos){ const op=u.txid+':'+u.vout;
        const cb=el('input',{type:'checkbox',checked:!!s.selected[op],onchange:e=>{ s.selected[op]=e.target.checked; }});
        tb.append(el('tr',{}, el('td',{},cb), el('td',{class:'addr'}, op + (u.status&&u.status.confirmed?'':' (unconfirmed)')), el('td',{class:'amt'}, fmt(u.value)+' '+c.ticker))); }
      t.append(tb); advBlock.append(el('p',{class:'sub'},'Only checked coins may be spent; the wallet picks the smallest set that covers the amount and fee. Leave all unchecked to choose coins automatically.'), t);
    }
  }
  const reviewBtn = el('button',{class:'btn'},'Review transaction');
  reviewBtn.addEventListener('click', ()=>{ s.error=null; reviewSend(reviewBtn); });
  const psbtOut = el('div',{});
  const psbtBtn = el('button',{class:'btn ghost'},'Export unsigned PSBT');
  psbtBtn.addEventListener('click', async ()=>{ psbtBtn.disabled=true; clear(psbtOut);
    try { const p = await buildUnsignedPSBT(); const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(p,cp));
      psbtOut.append(el('div',{class:'msg ok'}, el('div',{class:'sub'},'Unsigned PSBT (base64) ', cp), el('div',{class:'addr'}, p))); }
    catch(e){ psbtOut.append(el('div',{class:'msg bad'}, e.message||e)); } finally { psbtBtn.disabled=false; } });
  return el('div',{class:'card'},
    el('div',{class:'card-h'}, 'Send '+c.ticker, el('span',{class:'sub'}, TYPES[state.addrType].label+' · balance '+fmt(state.totalSats)+' '+c.ticker)),
    el('div',{class:'card-b stack'},
      el('div',{class:'between'}, el('span',{class:'sub'},'Recipients'),
        el('div',{class:'row',style:'flex:1;justify-content:flex-end;align-items:center;gap:6px'}, el('span',{class:'sub'},'amount in'), denomPills)), recipWrap,
      el('button',{class:'btn ghost sm',style:'align-self:flex-start',onclick:()=>{ s.recipients.push({address:'',amount:''}); render(); }},'+ Add recipient'),
      el('div',{class:'field'}, el('label',{class:'fld',title:'OP_RETURN attaches a small (≤80-byte) note to the transaction, such as a message or marker. It spends no coins beyond the fee and stays on-chain forever.'},'OP_RETURN data (optional)'),
        el('div',{class:'row',style:'align-items:center'},
          el('input',{type:'text',value:s.opReturn,placeholder:s.opReturnHex?'hex bytes (≤80)':'text message (≤80 bytes)',oninput:e=>{ s.opReturn=e.target.value; }}),
          el('label',{class:'fld',style:'display:flex;gap:6px;align-items:center;flex:0;white-space:nowrap;margin:0'},
            el('input',{type:'checkbox',checked:s.opReturnHex,onchange:e=>{ s.opReturnHex=e.target.checked; render(); }}),'hex'))),
      el('div',{class:'field'},
        el('div',{class:'between'}, el('label',{class:'fld',style:'margin:0'},'Fee'), feePresets),
        el('div',{class:'row',style:'align-items:center;flex:0;margin-top:6px'}, feeInput, el('span',{class:'sub'},'sat/vB'), suggestBtn)),
      advToggle, advBlock,
      el('div',{class:'row',style:'flex:0'}, reviewBtn, psbtBtn), psbtOut,
      s.error ? el('div',{class:'msg bad'}, s.error) : null,
    ));
}

/* ---- sweep an external private key (WIF) into a destination address ---- */
async function sweepKey(coin, wif, dest, feeRate){
  const net = COINS[coin].net;
  let priv; try { priv = btc.WIF(net).decode(wif.trim()); } catch(_){ throw new Error('Invalid WIF for this network'); }
  if(!isValidAddress(dest, coin)) throw new Error('Invalid destination address');
  const pub = secp.getPublicKey(priv, true), xo = pub.slice(1);
  const cands = [
    { type:'pkh',     addr: btc.p2pkh(pub, net).address },
    { type:'sh-wpkh', addr: btc.p2sh(btc.p2wpkh(pub, net), net).address },
    { type:'wpkh',    addr: btc.p2wpkh(pub, net).address },
    { type:'tr',      addr: btc.p2tr(xo, undefined, net).address },
  ];
  const inputs = []; let total = 0n;
  for(const cand of cands){
    let utxos = []; try { utxos = await getUtxos(coin, cand.addr); } catch(_){}
    for(const u of utxos){
      let inp;
      if(cand.type==='pkh') inp = { txid:u.txid, index:u.vout, nonWitnessUtxo: hexToBytes(await getPrevTxHex(coin, u.txid)) };
      else if(cand.type==='sh-wpkh'){ const w = btc.p2sh(btc.p2wpkh(pub, net), net); inp = { txid:u.txid, index:u.vout, witnessUtxo:{ script:w.script, amount:BigInt(u.value) }, redeemScript:w.redeemScript }; }
      else if(cand.type==='wpkh') inp = { txid:u.txid, index:u.vout, witnessUtxo:{ script:btc.p2wpkh(pub, net).script, amount:BigInt(u.value) } };
      else inp = { txid:u.txid, index:u.vout, tapInternalKey:xo, witnessUtxo:{ script:btc.p2tr(xo, undefined, net).script, amount:BigInt(u.value) } };
      inputs.push(inp); total += BigInt(u.value);
    }
  }
  if(!inputs.length) throw new Error('No funds found on that key (checked legacy, nested, SegWit and Taproot)');
  const rate = Math.max(1, Math.round(parseFloat(feeRate) || 1));
  const build = fee => { const tx = new btc.Transaction({}); for(const inp of inputs) tx.addInput(inp);
    tx.addOutputAddress(dest, total - fee, net); tx.sign(priv); tx.finalize(); return tx; };
  let tx = build(0n);                                            // pass 1: get an accurate vsize
  const fee = BigInt(Math.max(1, Math.ceil((tx.vsize + inputs.length) * rate)));   // +1 vB/input margin (ECDSA sig length varies)
  if(total - fee <= BigInt(DUST)) throw new Error('Balance ('+fmt(Number(total))+') is too low to cover the fee');
  tx = build(fee);                                              // pass 2: real fee
  const txid = await broadcast(coin, tx.hex);
  return { txid, swept: Number(total - fee), fee: Number(fee) };
}

/* ---- account-level extended public key (tpub) for the current type/account ---- */
function accountXpub(type){
  if(state.scheme && ELECTRUM_SCHEMES[state.scheme]) return state.master.derive(ELECTRUM_SCHEMES[state.scheme].acct).publicExtendedKey;
  const seed = mnemonicToSeedSync(state.wallet.mnemonic, state.wallet.passphrase || '');
  const m = HDKey.fromMasterSeed(seed, { public:0x043587cf, private:0x04358394 });   // testnet tpub version bytes
  return m.derive(`m/${TYPES[type].purpose}'/1'/${state.account}'`).publicExtendedKey;
}

/* ---- derive + fetch balances for the first N addresses of an extended public key ---- */
async function exploreXpub(coin, xpub, type, count){
  const s = xpub.trim();
  let acct;                                                       // try testnet tpub version bytes first, then mainnet
  try { acct = HDKey.fromExtendedKey(s, { public:0x043587cf, private:0x04358394 }); }
  catch(_){ try { acct = HDKey.fromExtendedKey(s); } catch(__){ throw new Error('Invalid extended public key'); } }
  const chain = acct.deriveChild(0);                            // external (receive) chain
  const rows = [];
  for(let i=0;i<count;i++){
    const child = chain.deriveChild(i);
    const address = addrFromPub(child.publicKey, coin, type);
    let bal = null; try { bal = await getStats(coin, address); } catch(_){}
    rows.push({ index:i, address, balance: bal ? bal.total : null });
  }
  return rows;
}

/* ---- m-of-n P2WSH multisig address from compressed public keys ---- */
function buildMultisig(coin, m, pubkeyHexes){
  const net = COINS[coin].net;
  const pubkeys = pubkeyHexes.map(h=>{ try { return hexToBytes(h); } catch(_){ return null; } }).filter(b=>b && b.length===33);
  if(pubkeys.length < 2) throw new Error('Need at least 2 valid 33-byte compressed public keys');
  if(!(m >= 1 && m <= pubkeys.length)) throw new Error('Required signatures must be between 1 and '+pubkeys.length);
  const ms = btc.sortedMultisig(m, pubkeys, true, net);     // witness=true -> P2WSH, BIP67-sorted
  return { address: ms.address, witnessScript: ms.witnessScript ? bytesToHex(ms.witnessScript) : '', n: pubkeys.length };
}

/* ===================== BIP48 P2WSH multisig (descriptor wallet) =====================
 * Watch-only m-of-n native-SegWit multisig. Cosigners are BIP48 account xpubs at
 * m/48'/1'/account'/2' (script-type 2' = P2WSH). Addresses are BIP67-sorted sortedmulti,
 * RE-DERIVED per (chain,index) - BIP67 order varies by index so nothing is cached across
 * indices. Spends are coordinated as PSBTs: build unsigned -> each cosigner signs ->
 * combine partials -> finalize -> broadcast. Pure in-browser; no backend.
 * The crypto is gated behind msSelfTest() at boot (see _msigOk). */
const MS_TPUB = { public:0x043587cf, private:0x04358394 };   // testnet extended-key versions (BTC + LTC share these)
const MS_HARD = 0x80000000;                                  // hardened-derivation flag
const MS_GAP  = 10;                                          // BIP-style gap limit when scanning a chain
let _msigOk = null;                                          // multisig crypto self-test result (set at boot)
let _msScanToken = 0;                                        // guards against stale async scans

function msFpHex(node){ return (node.fingerprint >>> 0).toString(16).padStart(8,'0'); }   // master fingerprint -> 8 hex
function msBytesEq(a, b){ if(!a || !b || a.length !== b.length) return false; for(let k=0;k<a.length;k++) if(a[k] !== b[k]) return false; return true; }

// Parse a cosigner account xpub/tpub -> public HDKey node (tries testnet then mainnet versions, like exploreXpub).
function msParseXpub(s){
  s = String(s||'').trim();
  if(!s) throw new Error('Empty extended public key');
  try { return HDKey.fromExtendedKey(s, MS_TPUB); }
  catch(_){ try { return HDKey.fromExtendedKey(s); } catch(__){ throw new Error('Invalid extended public key'); } }
}

// This wallet's own BIP48 multisig account (to contribute as a cosigner). Needs an open seed wallet.
function msMyAccount(account){
  if(!state.wallet || !state.master) throw new Error('Open a seed wallet first');
  account = Math.max(0, account|0);
  const path = `48'/1'/${account}'/2'`;
  if(state.scheme && ELECTRUM_SCHEMES[state.scheme])             // Electrum: derive from the cached root (the tree the signer uses), NOT BIP39 of the words
    return { fingerprint: msFpHex(state.master), origin:'m/'+path, account, xpub: state.master.derive('m/'+path).publicExtendedKey };
  const seed = mnemonicToSeedSync(state.wallet.mnemonic, state.wallet.passphrase || '');
  const root = HDKey.fromMasterSeed(seed, MS_TPUB);
  return { fingerprint: msFpHex(root), origin:'m/'+path, account, xpub: root.derive('m/'+path).publicExtendedKey };
}

// Derive the P2WSH sortedmulti scripts + address at (change,index) from pre-parsed cosigner account nodes.
function msDeriveAt(coin, m, acctNodes, change, index){
  const net = COINS[coin].net;
  const pubs = acctNodes.map(a => a.deriveChild(change).deriveChild(index).publicKey);
  const ms = btc.sortedMultisig(m, pubs, true, net);         // P2WSH, BIP67-sorted (recomputed per index)
  return { address: ms.address, witnessScript: ms.witnessScript, script: ms.script };
}
function msAcctNodes(rec){ return rec.cosigners.map(c => msParseXpub(c.xpub)); }

// PSBT bip32Derivation for one input: [pubkey, {fingerprint(number), path(number[] from master)}] per cosigner,
// so any wallet (incl. external ones) can recognise which key signs. @scure: fingerprint is a uint32, path uint32[].
function msBip32Derivation(rec, acctNodes, change, index){
  return rec.cosigners.map((c, k) => {
    const node = acctNodes[k].deriveChild(change).deriveChild(index);
    const fp = (parseInt(c.fingerprint || '0', 16) >>> 0);
    const path = String(c.origin || '').replace(/^m\//,'').split('/').filter(Boolean)
      .map(p => (parseInt(p, 10) >>> 0) + (/['h]$/.test(p) ? MS_HARD : 0));
    path.push(change >>> 0, index >>> 0);
    return [node.publicKey, { fingerprint: fp, path }];
  });
}

/* ---- BIP380 output-descriptor checksum (reference algorithm; 40-bit GENERATOR needs BigInt) ---- */
const MS_DESC_INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const MS_DESC_CHK = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function msDescPolymod(symbols){
  const GEN = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
  let chk = 1n;
  for(const v of symbols){
    const top = chk >> 35n;
    chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(v);
    for(let i=0;i<5;i++) if((top >> BigInt(i)) & 1n) chk ^= GEN[i];
  }
  return chk;
}
function msDescChecksum(s){
  const symbols = []; const groups = [];
  for(const ch of s){
    const v = MS_DESC_INPUT.indexOf(ch);
    if(v < 0) throw new Error('Invalid descriptor character');
    symbols.push(v & 31); groups.push(v >> 5);
    if(groups.length === 3){ symbols.push(groups[0]*9 + groups[1]*3 + groups[2]); groups.length = 0; }
  }
  if(groups.length === 1) symbols.push(groups[0]);
  else if(groups.length === 2) symbols.push(groups[0]*3 + groups[1]);
  for(let i=0;i<8;i++) symbols.push(0);
  const chk = msDescPolymod(symbols) ^ 1n;
  let out = '';
  for(let i=0;i<8;i++) out += MS_DESC_CHK[Number((chk >> BigInt(5*(7-i))) & 31n)];
  return out;
}

// Export a canonical wsh(sortedmulti(...))#checksum descriptor (Core importdescriptors-compatible).
function msExportDescriptor(rec){
  const keys = rec.cosigners.map(c => {
    const origin = String(c.origin || ('m/48\'/1\'/'+(c.account||0)+'\'/2\'')).replace(/^m\//,'').replace(/'/g,'h');
    return `[${c.fingerprint||'00000000'}/${origin}]${c.xpub}/<0;1>/*`;
  });
  const body = `wsh(sortedmulti(${rec.m},${keys.join(',')}))`;
  return body + '#' + msDescChecksum(body);
}

// Split a descriptor argument list on TOP-LEVEL commas (ignoring (),[],<>,{} nesting).
function msSplitTop(s){
  const out = []; let depth = 0, cur = '';
  for(const ch of s){
    if(ch==='('||ch==='['||ch==='<'||ch==='{') depth++;
    else if(ch===')'||ch===']'||ch==='>'||ch==='}') depth--;
    if(ch===',' && depth===0){ out.push(cur); cur=''; } else cur += ch;
  }
  if(cur.length) out.push(cur);
  return out;
}
function msParseKeyExpr(expr){
  expr = expr.trim();
  let fingerprint = '', origin = '', account = 0;
  const ob = expr.match(/^\[([0-9a-fA-F]{8})((?:\/\d+['h]?)*)\]/);
  if(ob){
    fingerprint = ob[1].toLowerCase();
    const segs = ob[2].split('/').filter(Boolean);            // e.g. ["48h","1h","0h","2h"]
    origin = 'm/' + segs.map(p => p.replace(/['h]$/,'') + "'").join('/');
    if(segs.length >= 3) account = parseInt(segs[2], 10) || 0;  // BIP48 account = 3rd origin element
    expr = expr.slice(ob[0].length);
  }
  const xm = expr.match(/^([a-km-zA-HJ-NP-Z1-9]+)/);          // base58 xpub up to the '/...' suffix
  if(!xm) throw new Error('Bad key expression (no xpub)');
  const xpub = xm[1];
  msParseXpub(xpub);                                          // validate it parses
  if(!origin) origin = `m/48'/1'/${account}'/2'`;
  return { fingerprint, origin, account, xpub };
}
function msParseDescriptor(text){
  let s = String(text||'').trim();
  if(!s) throw new Error('Empty descriptor');
  const hi = s.lastIndexOf('#');
  if(hi >= 0){
    const body = s.slice(0, hi), sum = s.slice(hi+1);
    if(!/^[a-z0-9]{8}$/.test(sum)) throw new Error('Bad descriptor checksum format');
    if(msDescChecksum(body) !== sum) throw new Error('Descriptor checksum does not match');
    s = body;
  }
  s = s.replace(/\s+/g,'');
  const mw = s.match(/^wsh\(sortedmulti\((\d+),(.+)\)\)$/);
  if(!mw){
    if(/(^|[^t])multi\(/.test(s) && !/sortedmulti\(/.test(s)) throw new Error('Only sortedmulti() is supported (plain multi() is unsorted)');
    throw new Error('Only wsh(sortedmulti(...)) descriptors are supported');
  }
  const m = parseInt(mw[1], 10);
  const cosigners = msSplitTop(mw[2]).map(msParseKeyExpr);
  if(cosigners.length < 2) throw new Error('Need at least 2 cosigners');
  if(!(m >= 1 && m <= cosigners.length)) throw new Error('Invalid threshold (m must be 1..n)');
  return { m, n: cosigners.length, cosigners };
}

function msValidRecord(rec){
  return !!(rec && typeof rec==='object' && rec.id && COINS[rec.coin] && Array.isArray(rec.cosigners)
    && rec.cosigners.length >= 2 && rec.m >= 1 && rec.m <= rec.cosigners.length
    && rec.cosigners.every(c => c && typeof c.xpub === 'string'));
}
function msAllWallets(){ return (store.multisig || []).filter(msValidRecord); }
function msCoinWallets(){ return msAllWallets().filter(w => w.coin === state.coin); }

// Watch-only scan: walk chains 0 (receive) and 1 (change) with a gap limit, collecting balance + UTXOs.
async function msScan(rec){
  const token = ++_msScanToken;
  const acctNodes = msAcctNodes(rec);
  const res = { addresses: [], utxos: [], confirmed: 0, total: 0, nextRecv: 0, nextChange: 0, stale: false };
  for(const change of [0,1]){
    let gap = 0, i = 0, firstUnused = -1;
    while(gap < MS_GAP && i < 500){
      const d = msDeriveAt(rec.coin, rec.m, acctNodes, change, i);
      let raw = null; try { raw = await apiGet(rec.coin, '/address/'+encodeURIComponent(d.address)); } catch(_){}
      if(token !== _msScanToken){ res.stale = true; return res; }
      const cs = (raw && raw.chain_stats) || {}, mp = (raw && raw.mempool_stats) || {};
      const fundedCount = (cs.funded_txo_count||0) + (mp.funded_txo_count||0);
      const conf = (cs.funded_txo_sum||0) - (cs.spent_txo_sum||0);
      const pend = (mp.funded_txo_sum||0) - (mp.spent_txo_sum||0);
      const used = fundedCount > 0;
      res.confirmed += conf; res.total += conf + pend;
      res.addresses.push({ change, index:i, address:d.address, used, confirmed:conf, total:conf+pend });
      if(used){
        let utxos = []; try { utxos = await getUtxos(rec.coin, d.address); } catch(_){}
        if(token !== _msScanToken){ res.stale = true; return res; }
        for(const u of utxos) res.utxos.push({ txid:u.txid, vout:u.vout, value:u.value,
          confirmed: !!(u.status && u.status.confirmed), change, index:i, witnessScript:d.witnessScript, script:d.script });
        gap = 0;
      } else { if(firstUnused < 0) firstUnused = i; gap++; }
      i++;
    }
    const nextUnused = firstUnused >= 0 ? firstUnused : i;
    if(change === 0) res.nextRecv = nextUnused; else res.nextChange = nextUnused;
  }
  return res;
}

// Build an UNSIGNED spend PSBT from a wallet's confirmed UTXOs. Manual builder (selectUTXO can't carry
// witnessScript/derivations). Fee from an estimated P2WSH vsize (we can't finalize unsigned to measure it).
function msBuildUnsignedPSBT(rec, recipients, feeRate, scan){
  const net = COINS[rec.coin].net;
  const acctNodes = msAcctNodes(rec);
  const outs = []; let totalOut = 0n;
  for(const r of recipients){
    const addr = (r.address||'').trim();
    if(!addr && !r.amount) continue;
    if(!isValidAddress(addr, rec.coin)) throw new Error('Invalid '+COINS[rec.coin].name+' address: '+(addr||'(empty)'));
    const sats = Math.round(parseFloat(r.amount) * 1e8);
    if(!(sats > 0)) throw new Error('Invalid amount for '+addr);
    if(sats < DUST) throw new Error('Amount below dust ('+DUST+' sats) for '+addr);
    outs.push({ address: addr, amount: BigInt(sats) }); totalOut += BigInt(sats);
  }
  if(!outs.length) throw new Error('Add at least one recipient');
  const rate = Math.max(1, Math.round(parseFloat(feeRate) || 1));
  let coins = (scan.utxos || []).filter(u => u.confirmed).slice().sort((a,b) => b.value - a.value);
  if(!coins.length) throw new Error('No confirmed coins to spend');
  const chg = msDeriveAt(rec.coin, rec.m, acctNodes, 1, scan.nextChange || 0);
  // Estimated vsize: P2WSH overhead + per-input (outpoint/seq base + discounted witness) + per-output.
  const nKeys = rec.cosigners.length, wsLen = 3 + nKeys * 34, pushLen = wsLen < 76 ? 1 : 2;
  const perInputVb = 41 + Math.ceil((2 + rec.m * 74 + pushLen + wsLen) / 4);   // ~73-byte sigs, rounded up
  const perOutVb = 43, baseVb = 11;
  const feeFor = (nIn, withChange) => BigInt(Math.ceil((baseVb + nIn*perInputVb + (outs.length + (withChange?1:0))*perOutVb) * rate));
  const chosen = []; let inSum = 0n;
  for(const u of coins){ chosen.push(u); inSum += BigInt(u.value); if(inSum >= totalOut + feeFor(chosen.length, true)) break; }
  if(inSum < totalOut + feeFor(chosen.length, false)) throw new Error('Not enough confirmed coins to cover amount + fee');
  let fee = feeFor(chosen.length, true);
  let changeAmt = inSum - totalOut - fee;
  if(changeAmt <= BigInt(DUST)){ changeAmt = 0n; fee = inSum - totalOut; }   // no viable change -> absorb into fee
  const tx = new btc.Transaction({});
  for(const u of chosen) tx.addInput({ txid:u.txid, index:u.vout, sequence:0xfffffffd,
    witnessUtxo:{ script:u.script, amount:BigInt(u.value) }, witnessScript:u.witnessScript,
    bip32Derivation: msBip32Derivation(rec, acctNodes, u.change, u.index) });
  for(const o of outs) tx.addOutputAddress(o.address, o.amount, net);
  if(changeAmt > 0n) tx.addOutputAddress(chg.address, changeAmt, net);
  return { psbt: b64encode(tx.toPSBT()), fee: Number(fee), change: Number(changeAmt),
    inputs: chosen.length, totalOut: Number(totalOut), changeAddress: changeAmt > 0n ? chg.address : null };
}

// Sign a (multisig) PSBT with the open seed wallet. Primary path is ceiling-free: for every input's
// bip32Derivation entry, derive THIS master along the entry's full path and, only if the derived pubkey
// equals the entry's pubkey (i.e. this wallet is that cosigner), sign - independent of the recorded
// fingerprint (which may be a placeholder). Fallback (foreign PSBTs with no key origins) brute-forces BIP48.
function msSignTx(tx){
  if(!state.master) throw new Error('Open the seed wallet that holds one of the cosigner keys');
  const ins = txInsList(tx);
  let signed = 0, missingOrigins = false;
  for(let i=0;i<ins.length;i++){
    const ders = (ins[i] && ins[i].bip32Derivation) || [];
    if(!ders.length){ missingOrigins = true; continue; }
    for(const entry of ders){
      const pub = entry && entry[0], meta = entry && entry[1];
      if(!pub || !meta || !Array.isArray(meta.path)) continue;
      let node = state.master, ok = true;
      try { for(const p of meta.path) node = node.deriveChild(p >>> 0); } catch(_){ ok = false; }
      if(!ok || !node.privateKey || !msBytesEq(node.publicKey, pub)) continue;   // not one of our keys
      try { signed += tx.signIdx(node.privateKey, i) || 0; } catch(_){}
    }
  }
  if(!signed && missingOrigins){                              // no key origins at all: try common BIP48 paths
    for(let acct=0; acct<6; acct++) for(const change of [0,1]) for(let idx=0; idx<200; idx++){
      try { signed += tx.sign(state.master.derive(`m/48'/1'/${acct}'/2'/${change}/${idx}`).privateKey) || 0; } catch(_){}
    }
  }
  return { signed, inputs: ins.length };
}

// Combine partially-signed PSBTs (signatures accumulate). Requires byte-identical unsigned tx across all.
function msCombine(psbtBytesArr){
  const txs = psbtBytesArr.map(b => btc.Transaction.fromPSBT(b));
  const base = txs[0];
  for(let i=1;i<txs.length;i++) base.combine(txs[i]);
  return base.toPSBT();
}
// Is a PSBT fully signed (>= m per input)? Returns the final raw-tx hex if so.
function msTryFinalize(psbtBytes){
  try { const tx = btc.Transaction.fromPSBT(psbtBytes); tx.finalize(); return { complete:true, hex: tx.hex }; }
  catch(_){ return { complete:false }; }
}

// Boot self-test: descriptor checksum vector + descriptor round-trip + full sign->combine->finalize dry run.
function msSelfTest(){
  const fails = [];
  try { if(msDescChecksum('raw(deadbeef)') !== '89f8spxm') fails.push('descriptor checksum vector'); }
  catch(e){ fails.push('checksum: '+(e.message||e)); }
  try {
    const seed = mnemonicToSeedSync('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', '');
    const root = HDKey.fromMasterSeed(seed, MS_TPUB);
    const fp = msFpHex(root);
    const cos = [0,1,2].map(a => ({ fingerprint:fp, origin:`m/48'/1'/${a}'/2'`, account:a, xpub: root.derive(`m/48'/1'/${a}'/2'`).publicExtendedKey }));
    const rec = { id:'selftest', coin:'btc', m:2, n:3, cosigners:cos };
    const nodes = msAcctNodes(rec);
    const a0 = msDeriveAt('btc', 2, nodes, 0, 0);
    const parsed = msParseDescriptor(msExportDescriptor(rec));    // export -> parse round-trip
    const a0b = msDeriveAt('btc', parsed.m, parsed.cosigners.map(c => msParseXpub(c.xpub)), 0, 0);
    if(a0.address !== a0b.address) fails.push('descriptor round-trip address mismatch');
    const net = COINS.btc.net, tx = new btc.Transaction({});
    tx.addInput({ txid:'00'.repeat(32), index:0, sequence:0xfffffffd,
      witnessUtxo:{ script:a0.script, amount:100000n }, witnessScript:a0.witnessScript,
      bip32Derivation: msBip32Derivation(rec, nodes, 0, 0) });
    tx.addOutputAddress(a0.address, 90000n, net);
    tx.sign(root.derive("m/48'/1'/0'/2'/0/0").privateKey);        // 2 of 3 distinct cosigner keys
    tx.sign(root.derive("m/48'/1'/1'/2'/0/0").privateKey);
    const merged = btc.Transaction.fromPSBT(tx.toPSBT()); merged.finalize();
    if(!merged.hex || merged.hex.length < 40) fails.push('finalize produced no hex');
  } catch(e){ fails.push('flow: '+(e.message||e)); }
  return { ok: fails.length === 0, fails };
}

/* ---- Multisig persistence + UI ---- */
function msHr(){ return el('hr',{class:'hr'}); }
function msSaveWallet(rec){
  store.multisig = store.multisig || [];
  store.multisig.push(rec); saveStore();
  const ms = state.multisig;
  ms.view = 'list'; ms.selId = rec.id; ms.detailTab = 'receive'; ms.scan = null;
  ms.create = { name:'', m:2, xpubs:['',''], fps:['',''], accounts:[0,0], importDesc:'' };
  toast('Multisig wallet created', 'ok'); render();
}

function renderMultisig(){
  const c = COINS[state.coin];
  const ms = state.multisig || (state.multisig = {
    view:'list', selId:null, detailTab:'receive', scan:null,
    create:{ name:'', m:2, xpubs:['',''], fps:['',''], accounts:[0,0], importDesc:'' },
    spend:{ recipients:[{address:'',amount:''}], feeRate:'', work:'' },
  });
  if(_msigOk === false){
    return el('div',{class:'card'}, el('div',{class:'card-h'},'Multisig'),
      el('div',{class:'card-b stack'}, el('div',{class:'msg bad'},'The multisig self-test failed in this browser, so multisig is turned off to keep your coins safe. Please report this.')));
  }
  const frag = document.createDocumentFragment();
  frag.append(el('div',{class:'card'},
    el('div',{class:'card-h'}, c.name+' multisig', el('span',{class:'sub'},'P2WSH · BIP48')),
    el('div',{class:'card-b stack'},
      el('p',{class:'sub faint'},'Watch-only m-of-n multisig, all in your browser. Cosigners are account xpubs; to spend, you build a PSBT (a sharable unsigned transaction), each cosigner signs, then you combine and broadcast.'))));
  if(ms.view === 'create'){ frag.append(msCreateCard()); return frag; }
  frag.append(msListCard());
  const rec = msAllWallets().find(w => w.id === ms.selId && w.coin === state.coin);
  if(rec) frag.append(msDetailCard(rec));
  return frag;
}

function msListCard(){
  const ms = state.multisig, wallets = msCoinWallets();
  const body = el('div',{class:'stack'});
  if(!wallets.length) body.append(el('p',{class:'sub faint'},'No '+COINS[state.coin].name+' multisig wallets yet.'));
  for(const w of wallets){
    const open = el('button',{class:'btn ghost sm'}, ms.selId===w.id ? 'Close' : 'Open');
    open.addEventListener('click', ()=>{ ms.selId = ms.selId===w.id ? null : w.id; ms.scan = null; ms.detailTab='receive'; render(); });
    body.append(el('div',{class:'between',style:'border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 10px'},
      el('div',{}, el('div',{}, w.name), el('div',{class:'sub faint'}, w.m+'-of-'+w.n+' · P2WSH')), open));
  }
  const newBtn = el('button',{class:'btn'},'+ New wallet');
  newBtn.addEventListener('click', ()=>{ ms.view='create'; render(); });
  return el('div',{class:'card'}, el('div',{class:'card-h'},'Your multisig wallets'),
    el('div',{class:'card-b stack'}, body, el('div',{}, newBtn)));
}

function msCreateCard(){
  const ms = state.multisig, cr = ms.create;
  const out = el('div',{});
  const impTa = el('textarea',{placeholder:'wsh(sortedmulti(2,[fingerprint/48h/1h/0h/2h]tpub.../<0;1>/*,...))#checksum',oninput:e=>{ cr.importDesc=e.target.value; }}); impTa.value=cr.importDesc;
  const impBtn = el('button',{class:'btn'},'Import descriptor');
  impBtn.addEventListener('click', ()=>{ clear(out); try {
    const p = msParseDescriptor(cr.importDesc);
    msSaveWallet({ id:uid(), kind:'multisig', coin:state.coin, name:(cr.name.trim() || ('Multisig '+(msAllWallets().length+1))), m:p.m, n:p.n, cosigners:p.cosigners, createdAt:new Date().toISOString() });
  } catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); } });

  const rows = el('div',{class:'stack'});
  cr.xpubs.forEach((xp, idx)=>{
    const xi = el('textarea',{placeholder:'Cosigner '+(idx+1)+' account xpub',oninput:e=>{ cr.xpubs[idx]=e.target.value; }}); xi.value=xp;
    const fi = el('input',{type:'text',placeholder:'fingerprint (8 hex, optional)',value:cr.fps[idx]||'',oninput:e=>{ cr.fps[idx]=e.target.value.trim(); },style:'max-width:210px'});
    const ai = el('input',{type:'number',min:'0',value:cr.accounts[idx]||0,oninput:e=>{ cr.accounts[idx]=Math.max(0,parseInt(e.target.value)||0); },style:'max-width:90px'});
    const mine = el('button',{class:'btn ghost sm'},'Use my key');
    mine.addEventListener('click', ()=>{ clear(out); try { const a=msMyAccount(cr.accounts[idx]||0); cr.xpubs[idx]=a.xpub; cr.fps[idx]=a.fingerprint; cr.accounts[idx]=a.account; render(); } catch(e){ out.append(el('div',{class:'msg bad'},e.message||e)); } });
    const del = cr.xpubs.length > 2 ? el('button',{class:'btn ghost sm',onclick:()=>{ cr.xpubs.splice(idx,1); cr.fps.splice(idx,1); cr.accounts.splice(idx,1); if(cr.m>cr.xpubs.length) cr.m=cr.xpubs.length; render(); }},'remove') : null;
    rows.append(el('div',{class:'stack',style:'border:1px solid var(--border);border-radius:var(--r-sm);padding:8px;gap:6px'},
      el('div',{class:'row',style:'flex:0;align-items:center'}, el('span',{class:'sub'},'Cosigner '+(idx+1)), mine, del),
      xi, el('div',{class:'row',style:'flex:0;align-items:center'}, fi, el('span',{class:'sub'},'account'), ai)));
  });
  const addBtn = el('button',{class:'btn ghost sm'},'+ Add cosigner');
  addBtn.addEventListener('click', ()=>{ cr.xpubs.push(''); cr.fps.push(''); cr.accounts.push(0); render(); });

  const nameIn = el('input',{type:'text',placeholder:'Wallet name',value:cr.name,oninput:e=>{ cr.name=e.target.value; }});
  const mIn = el('input',{type:'number',min:'1',max:String(cr.xpubs.length),value:cr.m,oninput:e=>{ cr.m=Math.max(1,parseInt(e.target.value)||1); },style:'max-width:70px'});
  const createBtn = el('button',{class:'btn'},'Create wallet');
  createBtn.addEventListener('click', ()=>{ clear(out); try {
    const xpubs = cr.xpubs.map(x=>x.trim());
    if(xpubs.some(x=>!x)) throw new Error('Fill in every cosigner xpub (or remove empty rows)');
    if(xpubs.length < 2) throw new Error('Need at least 2 cosigners');
    const m = Math.max(1, Math.min(cr.m, xpubs.length));
    const cosigners = xpubs.map((x,idx)=>{ const node = msParseXpub(x); const acct = cr.accounts[idx]||0;
      let fp = (cr.fps[idx]||'').toLowerCase().replace(/[^0-9a-f]/g,'');
      if(!(fp && fp.length===8) && state.wallet){                       // auto-fill our own fingerprint (version-agnostic pubkey match)
        try { const mine = msMyAccount(acct); if(msBytesEq(msParseXpub(mine.xpub).publicKey, node.publicKey)) fp = mine.fingerprint; } catch(_){}
      }
      return { fingerprint: (fp && fp.length===8) ? fp : '00000000', origin:`m/48'/1'/${acct}'/2'`, account:acct, xpub:x }; });
    if(new Set(cosigners.map(c=>c.xpub)).size !== cosigners.length) throw new Error('Duplicate cosigner xpub');
    msSaveWallet({ id:uid(), kind:'multisig', coin:state.coin, name:(cr.name.trim()||('Multisig '+(msAllWallets().length+1))), m, n:cosigners.length, cosigners, createdAt:new Date().toISOString() });
  } catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); } });
  const back = el('button',{class:'btn ghost'},'Cancel');
  back.addEventListener('click', ()=>{ ms.view='list'; render(); });

  return el('div',{class:'card'},
    el('div',{class:'card-h'}, 'New '+COINS[state.coin].name+' multisig'),
    el('div',{class:'card-b stack'},
      el('p',{class:'sub'},'Import an existing output descriptor, or build one from cosigner xpubs. “Use my key” fills a cosigner from your open wallet.'),
      el('div',{class:'field'}, el('label',{class:'fld'},'Name'), nameIn),
      el('div',{class:'sub'},'Import a descriptor'), impTa, el('div',{}, impBtn),
      msHr(),
      el('div',{class:'row',style:'flex:0;align-items:center'}, el('span',{class:'sub'},'Require'), mIn, el('span',{class:'sub'},'of '+cr.xpubs.length+' cosigners')),
      rows, el('div',{}, addBtn),
      el('div',{class:'row',style:'flex:0'}, createBtn, back), out));
}

function msDetailCard(rec){
  const ms = state.multisig;
  ms.detailTab = ms.detailTab || 'receive';
  const pills = el('div',{class:'pills',style:'margin:2px 0'});
  for(const [k,l] of [['receive','Receive'],['spend','Spend'],['manage','Manage']]){
    const p = el('div',{class:'pill'+(ms.detailTab===k?' active':'')}, l);
    if(ms.detailTab!==k) p.addEventListener('click', ()=>{ ms.detailTab=k; render(); });
    pills.append(p);
  }
  const body = ms.detailTab==='spend' ? msSpendView(rec) : ms.detailTab==='manage' ? msManageView(rec) : msReceiveView(rec);
  return el('div',{class:'card'},
    el('div',{class:'card-h'}, rec.name, el('span',{class:'sub'}, rec.m+'-of-'+rec.n+' · '+COINS[rec.coin].ticker)),
    el('div',{class:'card-b stack'}, pills, body));
}

function msReceiveView(rec){
  const ms = state.multisig, tk = COINS[rec.coin].ticker;
  const wrap = el('div',{class:'stack'});
  const out = el('div',{});
  const sc = ms.scan && ms.scan.recId===rec.id ? ms.scan : null;
  const scanBtn = el('button',{class:'btn'}, sc ? 'Refresh balance' : 'Load balance & addresses');
  scanBtn.addEventListener('click', async ()=>{ scanBtn.disabled=true; const o=scanBtn.textContent; scanBtn.textContent='Scanning…'; clear(out);
    try { const r = await msScan(rec); if(r.stale) return; r.recId=rec.id; ms.scan=r; render(); }
    catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); }
    finally { scanBtn.disabled=false; scanBtn.textContent=o; } });
  wrap.append(el('div',{}, scanBtn), out);
  if(sc){
    const recvAddr = msDeriveAt(rec.coin, rec.m, msAcctNodes(rec), 0, sc.nextRecv).address;
    const qrWrap = el('div',{style:'text-align:center'}); const q = qrEl(recvAddr, {coin:rec.coin}); if(q) qrWrap.append(q);
    const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(recvAddr,cp));
    wrap.append(
      el('div',{class:'between'}, el('span',{class:'sub'},'Balance'), el('span',{class:'amt'}, fmt(sc.total)+' '+tk)),
      qrWrap,
      el('div',{class:'sub'},'Next receive address · index '+sc.nextRecv),
      el('div',{class:'addr'}, recvAddr, ' ', cp));
    const used = sc.addresses.filter(a => a.used || a.total>0);
    if(used.length){
      const tb = el('tbody',{});
      for(const a of used) tb.append(el('tr',{},
        el('td',{class:'mono faint'}, (a.change?'chg ':'')+a.index),
        el('td',{}, el('div',{class:'addr'}, a.address)),
        el('td',{class:'amt'}, fmt(a.total)+' '+tk)));
      wrap.append(el('table',{}, el('thead',{}, el('tr',{}, el('th',{},'#'), el('th',{},'Address'), el('th',{class:'amt'},'Balance'))), tb));
    }
  }
  return wrap;
}

function msSpendView(rec){
  const ms = state.multisig, sp = ms.spend, tk = COINS[rec.coin].ticker;
  const wrap = el('div',{class:'stack'});
  const sc = ms.scan && ms.scan.recId===rec.id ? ms.scan : null;
  if(!sc){
    const b = el('button',{class:'btn'},'Go to Receive');
    b.addEventListener('click', ()=>{ ms.detailTab='receive'; render(); });
    wrap.append(el('p',{class:'sub'},'Load this wallet’s balance on the Receive tab first.'), el('div',{}, b));
    return wrap;
  }
  const confirmedSats = sc.utxos.filter(u=>u.confirmed).reduce((s,u)=>s+u.value, 0);
  wrap.append(el('div',{class:'between'}, el('span',{class:'sub'},'Spendable (confirmed)'), el('span',{class:'amt'}, fmt(confirmedSats)+' '+tk)));
  const recipWrap = el('div',{class:'stack'});
  sp.recipients.forEach((r,idx)=>{
    const ai = el('input',{type:'text',placeholder:COINS[rec.coin].name+' address',value:r.address,oninput:e=>{ r.address=e.target.value; }});
    const vi = el('input',{type:'number',min:'0',step:'0.00000001',placeholder:'amount',value:r.amount,oninput:e=>{ r.amount=e.target.value; },style:'max-width:150px'});
    const del = sp.recipients.length>1 ? el('button',{class:'btn ghost sm',onclick:()=>{ sp.recipients.splice(idx,1); render(); }},'×') : null;
    recipWrap.append(el('div',{class:'row',style:'flex:0'}, ai, vi, del));
  });
  const addR = el('button',{class:'btn ghost sm'},'+ recipient'); addR.addEventListener('click', ()=>{ sp.recipients.push({address:'',amount:''}); render(); });
  const feeIn = el('input',{type:'number',min:'1',placeholder:'auto',value:sp.feeRate||'',oninput:e=>{ sp.feeRate=e.target.value; },style:'max-width:120px'});
  const out = el('div',{});
  const buildBtn = el('button',{class:'btn'},'Build unsigned PSBT');
  buildBtn.addEventListener('click', async ()=>{ clear(out); buildBtn.disabled=true; try {
    let rate = sp.feeRate; if(!rate){ rate = await getFeeRate(rec.coin); }
    const b = msBuildUnsignedPSBT(rec, sp.recipients, rate, sc);
    sp.work = b.psbt;
    toast('Unsigned PSBT · '+b.inputs+' input'+(b.inputs===1?'':'s')+' · fee '+fmt(b.fee)+' '+tk+(b.change?(' · change '+fmt(b.change)):''), 'ok');
    render();
  } catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); buildBtn.disabled=false; } });
  wrap.append(el('div',{class:'sub'},'Recipients'), recipWrap, el('div',{}, addR),
    el('div',{class:'row',style:'flex:0;align-items:center'}, el('span',{class:'sub'},'Fee'), feeIn, el('span',{class:'sub'},'sat/vB')),
    el('div',{}, buildBtn), out, msHr(), msPsbtWorkspace(rec));
  return wrap;
}

function msReadPSBT(s){ s=String(s||'').trim(); if(!s) throw new Error('No PSBT'); return /^[0-9a-fA-F]+$/.test(s) ? hexToBytes(s) : b64decode(s); }
function msPsbtWorkspace(rec){
  const sp = state.multisig.spend, tk = COINS[rec.coin].ticker;
  const wrap = el('div',{class:'stack'});
  const ta = el('textarea',{placeholder:'PSBT (base64), built above or pasted from a cosigner',oninput:e=>{ sp.work=e.target.value; }}); ta.value=sp.work||'';
  const out = el('div',{});
  const signBtn = el('button',{class:'btn'},'Sign with this wallet');
  signBtn.addEventListener('click', ()=>{ clear(out); try {
    const tx = btc.Transaction.fromPSBT(msReadPSBT(sp.work));
    const res = msSignTx(tx);
    if(!res.signed){ out.append(el('div',{class:'msg warn'},'No inputs matched this wallet’s keys. Is one of the cosigner wallets open?')); return; }
    sp.work = b64encode(tx.toPSBT()); ta.value = sp.work;
    const t = msTryFinalize(b64decode(sp.work));
    const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(sp.work,cp));
    const partial = res.signed < res.inputs ? ' (signed '+res.signed+' of '+res.inputs+' inputs)' : '';
    out.append(el('div',{class:'msg ok'}, '✓ Signed '+res.signed+' input'+(res.signed===1?'':'s')+partial+(t.complete?'. Fully signed, ready to broadcast.':'. Partial; pass it to the next cosigner.'), ' ', cp),
      el('div',{style:'margin-top:6px'}, el('button',{class:'btn ghost sm',onclick:()=>downloadBlob(new Blob([sp.work],{type:'text/plain'}),'multisig-signed.psbt')},'Download')));
    if(res.signed < res.inputs) out.append(el('div',{class:'msg warn'}, (res.inputs-res.signed)+' input'+((res.inputs-res.signed)===1?'':'s')+' could not be signed by this wallet (missing key-origin info, or not your key).'));
  } catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); } });
  const combTa = el('textarea',{placeholder:'Paste another cosigner’s signed PSBT to merge'});
  const combBtn = el('button',{class:'btn ghost'},'Combine');
  combBtn.addEventListener('click', ()=>{ clear(out); try {
    if(!combTa.value.trim()) throw new Error('Paste a PSBT to combine');
    const merged = msCombine([msReadPSBT(sp.work), msReadPSBT(combTa.value)]);
    sp.work = b64encode(merged); ta.value = sp.work; combTa.value='';
    const t = msTryFinalize(merged);
    out.append(el('div',{class:'msg ok'}, 'Combined.'+(t.complete?' Fully signed, ready to broadcast.':' Still partial.')));
  } catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); } });
  const bcBtn = el('button',{class:'btn'},'Finalize & broadcast');
  bcBtn.addEventListener('click', ()=>{ clear(out); try {
    const t = msTryFinalize(msReadPSBT(sp.work));
    if(!t.complete) throw new Error('Not fully signed yet. Needs '+rec.m+' signatures per input.');
    confirmModal('Broadcast this '+rec.m+'-of-'+rec.n+' transaction to the '+COINS[rec.coin].name+' network?', async ()=>{
      clear(out); try { const txid = await broadcast(rec.coin, t.hex);
        out.append(el('div',{class:'msg ok'}, el('div',{},'Broadcast'), el('a',{class:'addr',href:COINS[rec.coin].explorer+'/tx/'+txid,target:'_blank',rel:'noopener'},txid)));
        state.multisig.scan = null;
      } catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); }
    }, {yes:'Broadcast'});
  } catch(e){ out.append(el('div',{class:'msg bad'}, e.message||e)); } });
  wrap.append(el('div',{class:'sub'},'Sign, combine, broadcast'), ta,
    el('div',{class:'row',style:'flex:0'}, signBtn, bcBtn),
    el('div',{class:'sub faint'},'To add another signature, paste a cosigner’s signed PSBT, then Combine.'),
    combTa, el('div',{}, combBtn), out);
  return wrap;
}

function msManageView(rec){
  const wrap = el('div',{class:'stack'});
  let desc=''; try { desc = msExportDescriptor(rec); } catch(_){ desc='Could not build the descriptor.'; }
  const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(desc,cp));
  wrap.append(el('div',{class:'sub'},'Output descriptor ', cp), el('div',{class:'addr'}, desc),
    el('div',{}, el('button',{class:'btn ghost sm',onclick:()=>downloadBlob(new Blob([desc],{type:'text/plain'}),'multisig-descriptor.txt')},'Download descriptor')));
  const cl = el('div',{class:'stack'});
  rec.cosigners.forEach((co,idx)=> cl.append(el('div',{class:'stack-lg',style:'border:1px solid var(--border);border-radius:var(--r-sm);padding:6px 8px'},
    el('div',{class:'sub'}, 'Cosigner '+(idx+1)+' · '+(co.fingerprint||'????????')+' · '+(co.origin||'')),
    el('div',{class:'addr faint'}, co.xpub))));
  wrap.append(msHr(), el('div',{class:'sub'},'Cosigners'), cl);
  const myOut = el('div',{}); const myBtn = el('button',{class:'btn ghost sm'},'Show my cosigner xpub');
  myBtn.addEventListener('click', ()=>{ clear(myOut); try { const a=msMyAccount((rec.cosigners[0] && rec.cosigners[0].account) || 0);
    const cpx=el('span',{class:'copy'},'copy'); cpx.addEventListener('click',()=>copyText(a.xpub,cpx));
    myOut.append(el('div',{class:'msg ok'}, el('div',{class:'sub'}, 'fingerprint '+a.fingerprint+' · '+a.origin+' ', cpx), el('div',{class:'addr'}, a.xpub)));
  } catch(e){ myOut.append(el('div',{class:'msg bad'}, e.message||e)); } });
  const forget = el('button',{class:'btn ghost'},'Forget this wallet');
  forget.addEventListener('click', ()=>{ confirmModal('Forget “'+rec.name+'”? This only removes the watch-only setup from this browser. Your coins are safe and you can re-import the descriptor.', ()=>{
    store.multisig = (store.multisig||[]).filter(w=>w.id!==rec.id); saveStore();
    state.multisig.selId=null; state.multisig.scan=null; render();
  }, {danger:true, yes:'Forget'}); });
  wrap.append(msHr(), el('div',{}, myBtn), myOut, msHr(), el('div',{}, forget));
  return wrap;
}

/* ============================== TOOLS (P3) ============================== */
function renderTools(){
  const c = COINS[state.coin], t = state.tools;
  // --- message signing: legacy BIP137 for pkh, BIP-322 for segwit/taproot ---
  const elType = (state.scheme && ELECTRUM_SCHEMES[state.scheme]) ? ELECTRUM_SCHEMES[state.scheme].addrType : null;
  if(!t.signType) t.signType = state.bip322Ok ? 'wpkh' : 'pkh';
  if(t.signType !== 'pkh' && !state.bip322Ok) t.signType = 'pkh';
  if(elType) t.signType = elType;                          // Electrum wallets sign only for their one real address type
  const typeSel = el('select',{style:'max-width:120px',...(elType?{disabled:true}:{}),onchange:e=>{ t.signType=e.target.value; }});
  for(const k of ['pkh','sh-wpkh','wpkh','tr']){
    if(elType ? k!==elType : (k!=='pkh' && !state.bip322Ok)) continue;   // Electrum: only its type; else BIP-322 types iff self-test passed
    typeSel.append(el('option',{value:k,...(k===t.signType?{selected:true}:{})}, TYPES[k].label));
  }
  const idxSel = el('select',{style:'max-width:90px',onchange:e=>{ t.signIndex=+e.target.value; }});
  state.addresses.forEach(a=> idxSel.append(el('option',{value:a.index,...(a.index===t.signIndex?{selected:true}:{})}, '#'+a.index)));
  const sMsg = el('textarea',{placeholder:'Message to sign',oninput:e=>{ t.message=e.target.value; }}); sMsg.value=t.message;
  const sOut = el('div',{});
  const signBtn = el('button',{class:'btn'},'Sign message');
  signBtn.addEventListener('click', async ()=>{
    signBtn.disabled=true;
    try {
      const type = t.signType, node = deriveNode(type, t.signIndex);
      let sig, addr, scheme;
      if(type === 'pkh'){ addr = btc.p2pkh(node.publicKey, c.net).address; sig = await signMessage(state.coin, node, t.message); scheme = 'legacy BIP137'; }
      else { addr = bip322.addressFor(type, node.publicKey, c.net); sig = bip322.sign(c.net, type, node.privateKey, t.message); scheme = 'BIP-322'; }
      const copyS = el('span',{class:'copy'},'copy'); copyS.addEventListener('click',()=>copyText(sig, copyS));
      clear(sOut).append(el('div',{class:'msg ok'}, el('div',{class:'sub'},'Signing address ('+TYPES[type].label+' · '+scheme+'): '), el('div',{class:'addr'},addr),
        el('div',{class:'sub',style:'margin-top:6px'},'Signature ', copyS), el('div',{class:'addr'},sig)));
    } catch(e){ clear(sOut).append(el('div',{class:'msg bad'}, 'Sign failed: '+(e.message||e))); }
    finally { signBtn.disabled=false; }
  });
  const signCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Sign message'),
    el('div',{class:'card-b stack'},
      el('div',{class:'row',style:'align-items:center;flex:0'}, el('span',{class:'sub'},'address'), typeSel, idxSel),
      sMsg, el('div',{}, signBtn), sOut));
  // --- verify ---
  const vAddr=el('input',{type:'text',placeholder:'Address',value:t.vAddr,oninput:e=>{t.vAddr=e.target.value;}});
  const vMsg=el('textarea',{placeholder:'Message',oninput:e=>{t.vMsg=e.target.value;}}); vMsg.value=t.vMsg;
  const vSig=el('input',{type:'text',placeholder:'Signature (base64)',value:t.vSig,oninput:e=>{t.vSig=e.target.value;}});
  const vOut=el('div',{});
  const vBtn=el('button',{class:'btn ghost'},'Verify');
  vBtn.addEventListener('click',()=>{
    const addr=t.vAddr.trim(); let atype=null; try { atype=btc.Address(c.net).decode(addr).type; } catch(_){ }
    const ok = (atype && atype!=='pkh' && state.bip322Ok) ? bip322.verify(c.net, addr, t.vMsg, t.vSig)   // segwit/taproot -> BIP-322
                                                          : verifyMessage(state.coin, addr, t.vMsg, t.vSig);  // legacy BIP137
    clear(vOut).append(el('div',{class:'msg '+(ok?'ok':'bad')}, ok?'Valid signature for this address':'Invalid signature for this address')); });
  const verifyCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Verify message'),
    el('div',{class:'card-b stack'}, vAddr, vMsg, vSig, el('div',{}, vBtn), vOut));
  // --- key inspector ---
  const kSel = el('select',{style:'max-width:90px',onchange:e=>{ t.keyIndex=+e.target.value; render(); }});
  state.addresses.forEach(a=> kSel.append(el('option',{value:a.index,...(a.index===t.keyIndex?{selected:true}:{})}, '#'+a.index)));
  const kNode = deriveNode(state.addrType, t.keyIndex);
  const kInfo = el('div',{class:'stack'});
  kInfo.append(el('div',{}, el('span',{class:'sub'},'Address ('+TYPES[state.addrType].label+'): '), el('div',{class:'addr'}, addrFromPub(kNode.publicKey, state.coin, state.addrType))),
    el('div',{}, el('span',{class:'sub'},'Public key: '), el('div',{class:'addr'}, bytesToHex(kNode.publicKey))));
  const keyHolder = el('div',{});
  const revealK = el('button',{class:'btn ghost sm'},'Reveal private key (WIF)');
  revealK.addEventListener('click',()=>{ const wif=wifFor(kNode, state.coin); const cp=el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(wif,cp,true));
    clear(keyHolder).append(el('div',{class:'msg warn'}, el('div',{class:'sub'},'Private key (WIF). Never share it. ', cp), el('div',{class:'addr'}, wif))); revealK.remove(); });
  const keyCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Key inspector'),
    el('div',{class:'card-b stack'}, el('div',{class:'row',style:'align-items:center;flex:0'}, el('span',{class:'sub'},'address index'), kSel), kInfo, revealK, keyHolder));
  // --- address validator ---
  const valIn=el('input',{type:'text',placeholder:'Address to validate',value:t.valAddr,oninput:e=>{t.valAddr=e.target.value;}});
  const valOut=el('div',{});
  const valBtn=el('button',{class:'btn ghost'},'Validate');
  valBtn.addEventListener('click',()=>{ const a=t.valAddr.trim(); let ok=false, type=null;
    try { const dec=btc.Address(c.net).decode(a); ok=true; type=dec&&dec.type; } catch(_){ ok=false; }
    clear(valOut).append(el('div',{class:'msg '+(ok?'ok':'bad')}, ok ? ('✓ Valid '+c.name+' '+(type||'')+' address') : ('✗ Not a valid '+c.name+' testnet address'))); });
  const valCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Address validator'),
    el('div',{class:'card-b stack'}, valIn, el('div',{}, valBtn), valOut));
  // --- sweep an external private key ---
  const swWif = el('input',{...SECRET_ATTRS,type:'text',placeholder:'Private key (WIF) to sweep',value:t.sweepWif,oninput:e=>{ t.sweepWif=e.target.value; }});
  const swDest = el('input',{type:'text',placeholder:'Destination (defaults to your address)',value:t.sweepDest,oninput:e=>{ t.sweepDest=e.target.value; }});
  const swFee = el('input',{type:'number',min:'1',placeholder:'sat/vB',value:t.sweepFee,style:'max-width:110px',oninput:e=>{ t.sweepFee=e.target.value; }});
  const swOut = el('div',{}); const swBtn = el('button',{class:'btn'},'Sweep');
  swBtn.addEventListener('click', async ()=>{
    swBtn.disabled=true; swBtn.textContent='Sweeping…';
    try {
      const dest = t.sweepDest.trim() || (state.addresses[0] && state.addresses[0].address);
      const fee = t.sweepFee || await getFeeRate(state.coin);
      const r = await sweepKey(state.coin, t.sweepWif, dest, fee);
      clear(swOut).append(el('div',{class:'msg ok'}, el('div',{},'Swept '+fmt(r.swept)+' '+c.ticker+' (fee '+fmt(r.fee)+')'),
        el('a',{class:'addr',href:c.explorer+'/tx/'+r.txid,target:'_blank',rel:'noopener'}, r.txid)));
      refresh();
    } catch(e){ clear(swOut).append(el('div',{class:'msg bad'}, 'Sweep failed: '+(e.message||e))); }
    finally { swBtn.disabled=false; swBtn.textContent='Sweep'; }
  });
  const sweepCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Sweep a private key'),
    el('div',{class:'card-b stack'}, el('p',{class:'sub'},'Move all funds from an outside private key (WIF) into an address. Checks legacy, nested, SegWit and Taproot.'),
      swWif, el('div',{class:'row',style:'align-items:center'}, swDest, el('button',{class:'btn ghost sm',title:'Scan QR',onclick:()=>scanModal(tx=>{ t.sweepDest=parseBip21(tx).address; render(); })},'Scan')),
      el('div',{class:'row',style:'align-items:center;flex:0'}, swFee, el('span',{class:'sub'},'sat/vB'), swBtn), swOut));
  // --- export account xpub ---
  const xpHolder = el('div',{}); const xpBtn = el('button',{class:'btn ghost'},'Show account xpub');
  xpBtn.addEventListener('click', ()=>{
    try { const xp = accountXpub(state.addrType); const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(xp,cp));
      clear(xpHolder).append(el('div',{class:'sub'},'Account '+xp.slice(0,4)+' for '+TYPES[state.addrType].label+((state.scheme && ELECTRUM_SCHEMES[state.scheme])?'':', account '+state.account)+' ', cp), el('div',{class:'addr'}, xp)); }
    catch(e){ clear(xpHolder).append(el('div',{class:'msg bad'}, e.message||e)); }
  });
  const xpubCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Export extended public key'),
    el('div',{class:'card-b stack'}, el('p',{class:'sub'},'A watch-only key for the current address type and account. It can derive addresses and watch balances but cannot spend.'), xpBtn, xpHolder));
  const wrap = document.createDocumentFragment();
  wrap.append(signCard, verifyCard, keyCard, sweepCard, xpubCard, valCard);
  return wrap;
}

/* ============================== DEV (P3) ============================== */
function renderDev(){
  const c = COINS[state.coin], d = state.dev;
  // --- decoder ---
  const dIn = el('textarea',{placeholder:'Paste a raw transaction (hex) or a PSBT (base64/hex)',oninput:e=>{ d.decodeInput=e.target.value; }}); dIn.value=d.decodeInput;
  const dOut = el('div',{});
  const dBtn = el('button',{class:'btn'},'Decode');
  dBtn.addEventListener('click',()=>{
    try { const r=decodeAnyTx(state.coin, d.decodeInput); clear(dOut).append(renderDecoded(r, c)); }
    catch(e){ clear(dOut).append(el('div',{class:'msg bad'},'Could not decode: '+(e.message||e))); }
  });
  const decodeCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Decode transaction / PSBT'),
    el('div',{class:'card-b stack'}, el('p',{class:'sub'},'Paste any raw transaction or PSBT to see its parts in plain terms, a good way to learn how a transaction is built.'), dIn, el('div',{}, dBtn), dOut));
  // --- broadcast ---
  const bIn = el('textarea',{placeholder:'Paste a signed raw transaction (hex) to broadcast',oninput:e=>{ d.rawTx=e.target.value; }}); bIn.value=d.rawTx;
  const bOut = el('div',{});
  const bBtn = el('button',{class:'btn'},'Broadcast');
  bBtn.addEventListener('click', async ()=>{ bBtn.disabled=true; bBtn.textContent='Broadcasting…';
    try { const txid=await broadcast(state.coin, d.rawTx.trim());
      clear(bOut).append(el('div',{class:'msg ok'}, el('div',{},'✓ Broadcast'), el('a',{class:'addr',href:c.explorer+'/tx/'+txid,target:'_blank',rel:'noopener'},txid))); }
    catch(e){ clear(bOut).append(el('div',{class:'msg bad'},'✗ '+(e.message||e))); }
    finally { bBtn.disabled=false; bBtn.textContent='Broadcast'; } });
  const bcCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Broadcast raw transaction'),
    el('div',{class:'card-b stack'}, bIn, el('div',{}, bBtn), bOut));
  // --- QR / BIP21 ---
  const qAddr=el('input',{type:'text',placeholder:'Address',value:d.qrAddr,oninput:e=>{d.qrAddr=e.target.value;}});
  const qAmt=el('input',{type:'number',min:'0',step:'0.00000001',placeholder:'amount (optional)',value:d.qrAmount,style:'max-width:160px',oninput:e=>{d.qrAmount=e.target.value;}});
  const qLabel=el('input',{type:'text',placeholder:'label (optional)',value:d.qrLabel,oninput:e=>{d.qrLabel=e.target.value;}});
  const qOut=el('div',{});
  const qBtn=el('button',{class:'btn'},'Generate QR / URI');
  qBtn.addEventListener('click',()=>{
    const addr=d.qrAddr.trim(); if(!addr){ clear(qOut).append(el('div',{class:'msg bad'},'Enter an address')); return; }
    const params=[]; if(d.qrAmount) params.push('amount='+encodeURIComponent(d.qrAmount)); if(d.qrLabel) params.push('label='+encodeURIComponent(d.qrLabel));
    const uri=c.uri+':'+addr+(params.length?'?'+params.join('&'):'');
    const box=el('div',{class:'stack'});
    const q=qrEl(uri, {coin:state.coin}); if(q) box.append(el('div',{style:'text-align:center'}, q));
    const cp=el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(uri,cp));
    box.append(el('div',{}, el('span',{class:'sub'},'BIP21 URI ', cp), el('div',{class:'addr'}, uri)));
    clear(qOut).append(box);
  });
  const qrCard = el('div',{class:'card'}, el('div',{class:'card-h'},'QR code / payment URI'),
    el('div',{class:'card-b stack'}, qAddr, el('div',{class:'row'}, qAmt, qLabel), el('div',{}, qBtn), qOut));
  // --- xpub explorer ---
  const xeIn = el('input',{type:'text',placeholder:'Extended public key (xpub / tpub)',value:d.xpub,oninput:e=>{ d.xpub=e.target.value; }});
  const xeType = el('select',{onchange:e=>{ d.xpubType=e.target.value; },style:'max-width:140px'});
  for(const [k,tt] of Object.entries(TYPES)) xeType.append(el('option',{value:k,...(k===d.xpubType?{selected:true}:{})}, tt.label));
  const xeOut = el('div',{}); const xeBtn = el('button',{class:'btn'},'Explore');
  xeBtn.addEventListener('click', async ()=>{
    xeBtn.disabled=true; xeBtn.textContent='Deriving…';
    try {
      const rows = await exploreXpub(state.coin, d.xpub, d.xpubType, 5);
      const tb = el('tbody',{}); rows.forEach(r=> tb.append(el('tr',{},
        el('td',{class:'faint'}, r.index), el('td',{class:'txid'}, r.address),
        el('td',{class:'amt'}, r.balance!=null ? (fmt(r.balance)+' '+c.ticker) : '-'))));
      clear(xeOut).append(el('table',{}, el('thead',{}, el('tr',{}, el('th',{},'#'), el('th',{},'Address'), el('th',{class:'amt'},'Balance'))), tb));
    } catch(e){ clear(xeOut).append(el('div',{class:'msg bad'}, e.message||e)); }
    finally { xeBtn.disabled=false; xeBtn.textContent='Explore'; }
  });
  const xpubExplorerCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Explore an extended public key'),
    el('div',{class:'card-b stack'}, el('p',{class:'sub'},'Derive the first addresses of an xpub/tpub and check their balances (watch-only).'),
      xeIn, el('div',{class:'row',style:'align-items:center;flex:0'}, el('span',{class:'sub'},'as'), xeType, xeBtn), xeOut));
  // --- PSBT tool ---
  const psIn = el('textarea',{placeholder:'Paste a PSBT (base64 or hex)',oninput:e=>{ d.psbt=e.target.value; }}); psIn.value=d.psbt;
  const psOut = el('div',{});
  const readPSBT = s => { s=s.trim(); return /^[0-9a-fA-F]+$/.test(s) ? hexToBytes(s) : b64decode(s); };
  const signPs = el('button',{class:'btn'},'Review & sign with this wallet');
  const doSignPsbt = (tx) => {                                 // the actual signing - only reached after the review below
    let signed = 0;                                            // try this wallet's keys across all address types + a range of indices
    for(const type of Object.keys(TYPES)){ for(let i=0;i<Math.max(addrCount(),10);i++){ try { signed += tx.sign(deriveNode(type, i).privateKey) || 0; } catch(_){} } }
    if(!signed){ clear(psOut).append(el('div',{class:'msg warn'},'No inputs matched this wallet’s keys, so nothing was signed. They may belong to a different wallet or account.')); return; }
    let out; try { out = b64encode(tx.toPSBT()); } catch(e){ clear(psOut).append(el('div',{class:'msg bad'},'Could not serialize the signed PSBT: '+(e.message||e))); return; }
    let complete = false; try { const t2 = btc.Transaction.fromPSBT(b64decode(out)); t2.finalize(); complete = true; } catch(_){}
    const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(out,cp));
    clear(psOut).append(el('div',{class:'msg ok'}, '✓ Signed '+signed+' input'+(signed===1?'':'s')+(complete?'. Fully signed and ready to finalize and broadcast below.':'. Partially signed; pass it to the other cosigners.')),
      el('div',{class:'sub',style:'margin-top:6px'},'Signed PSBT (base64) ', cp), el('div',{class:'addr'}, out),
      el('div',{style:'margin-top:6px'}, el('button',{class:'btn ghost sm',onclick:()=>downloadBlob(new Blob([out],{type:'text/plain'}),'signed-psbt.txt')},'Download')));
  };
  signPs.addEventListener('click', ()=>{ clear(psOut);
    let tx; try { tx = btc.Transaction.fromPSBT(readPSBT(d.psbt)); } catch(e){ psOut.append(el('div',{class:'msg bad'},'Not a valid PSBT: '+(e.message||e))); return; }
    const net = COINS[state.coin].net, mine = new Set(state.addresses.map(a=>a.address));
    const rows = []; let outSum = 0n, anyForeign = false;       // decode where the money goes BEFORE signing
    try { for(let i=0;i<(tx.outputsLength||0);i++){ const o = tx.getOutput(i); const amt = BigInt(o.amount||0n); outSum += amt;
      const addr = addrFromScript(o.script, net) || '(non-standard script)'; const ours = mine.has(addr); if(!ours) anyForeign = true;
      rows.push(el('tr',{}, el('td',{}, el('div',{class:'addr'+(ours?'':' bad')}, addr), ours ? el('span',{class:'sub ok'},'your address') : null),
        el('td',{class:'amt'}, fmt(Number(amt))+' '+c.ticker))); } } catch(_){}
    let inSum = 0n, haveFee = (tx.inputsLength||0) > 0;          // fee = inputs − outputs, only if every input carries its prevout amount
    try { for(let i=0;i<(tx.inputsLength||0);i++){ const inp = tx.getInput(i); if(inp && inp.witnessUtxo) inSum += BigInt(inp.witnessUtxo.amount); else haveFee = false; } } catch(_){ haveFee = false; }
    const fee = haveFee ? Number(inSum - outSum) : null;
    const proceed = el('button',{class:'btn'+(anyForeign?' danger':'')},'Confirm & sign');
    proceed.addEventListener('click', ()=> doSignPsbt(tx));
    clear(psOut).append(
      el('div',{class:'msg warn'},'⚠ Review before you sign. A PSBT from an untrusted source can spend your coins, so only sign one you built or are expecting. Signing authorizes spending the inputs below.'),
      el('div',{class:'sub',style:'margin-top:6px'}, (tx.inputsLength||0)+' input'+((tx.inputsLength||0)===1?'':'s')+' · sends to:'),
      el('table',{}, el('thead',{}, el('tr',{}, el('th',{},'To'), el('th',{class:'amt'},'Amount'))), el('tbody',{}, ...rows)),
      el('div',{class:'between',style:'margin-top:4px'}, el('span',{class:'sub'},'Network fee'), el('span',{class:'amt'+(fee!=null&&fee<0?' bad':'')}, fee!=null ? (fmt(fee)+' '+c.ticker) : 'unknown (input amounts not in this PSBT)')),
      anyForeign ? el('div',{class:'sub bad',style:'margin-top:2px'},'Some outputs are NOT your addresses. Make sure you mean to send there.') : null,
      el('div',{class:'row',style:'flex:0;margin-top:8px'}, proceed, el('button',{class:'btn ghost',onclick:()=>clear(psOut)},'Cancel')));
  });
  const finPs = el('button',{class:'btn ghost'},'Finalize & broadcast');
  finPs.addEventListener('click', async ()=>{ clear(psOut); finPs.disabled=true; try {
    const tx = btc.Transaction.fromPSBT(readPSBT(d.psbt)); tx.finalize();
    const txid = await broadcast(state.coin, tx.hex);
    psOut.append(el('div',{class:'msg ok'}, el('div',{},'Broadcast'), el('a',{class:'addr',href:c.explorer+'/tx/'+txid,target:'_blank',rel:'noopener'},txid)));
  } catch(e){ psOut.append(el('div',{class:'msg bad'}, e.message||e)); } finally { finPs.disabled=false; } });
  const psbtCard = el('div',{class:'card'}, el('div',{class:'card-h'},'PSBT tool'),
    el('div',{class:'card-b stack'}, el('p',{class:'sub'},'Sign a PSBT with this wallet, or finalize and broadcast a fully-signed one.'),
      psIn, el('div',{class:'row',style:'flex:0'}, signPs, finPs), psOut));
  // --- multisig address builder ---
  const mM = el('input',{type:'number',min:'1',value:'2',style:'max-width:70px'});
  const mKeys = el('textarea',{placeholder:'Compressed public keys (33-byte hex), one per line'});
  const mOut = el('div',{}); const mBtn = el('button',{class:'btn'},'Build address');
  mBtn.addEventListener('click', ()=>{ clear(mOut); try {
    const keys = mKeys.value.split(/\s+/).map(x=>x.trim()).filter(Boolean);
    const m = parseInt(mM.value) || 2;
    const r = buildMultisig(state.coin, m, keys);
    const cp = el('span',{class:'copy'},'copy'); cp.addEventListener('click',()=>copyText(r.address,cp));
    mOut.append(el('div',{class:'msg ok'}, el('div',{class:'sub'}, m+'-of-'+r.n+' P2WSH ', cp), el('div',{class:'addr'}, r.address),
      el('div',{class:'sub',style:'margin-top:6px'},'witnessScript'), el('div',{class:'addr'}, r.witnessScript)));
  } catch(e){ mOut.append(el('div',{class:'msg bad'}, e.message||e)); } });
  const msCard = el('div',{class:'card'}, el('div',{class:'card-h'},'Multisig address'),
    el('div',{class:'card-b stack'}, el('p',{class:'sub'},'Build an m-of-n P2WSH multisig address from public keys. Spend it via the PSBT tool with each cosigner.'),
      el('div',{class:'row',style:'align-items:center;flex:0'}, el('span',{class:'sub'},'require'), mM, el('span',{class:'sub'},'of the keys below')), mKeys, el('div',{}, mBtn), mOut));
  const testsLink = el('div',{class:'sub faint',style:'text-align:center;margin-top:4px'}, 'Check the vendored crypto against known-answer vectors: ', el('a',{class:'ext',href:'tests.html',target:'_blank',rel:'noopener'},'run the self-tests'));
  const frag = document.createDocumentFragment(); frag.append(decodeCard, psbtCard, msCard, xpubExplorerCard, bcCard, qrCard, testsLink); return frag;
}
function renderDecoded(r, c){
  const box = el('div',{class:'stack'});
  box.append(el('div',{class:'sub'}, r.kind + (r.id ? (' · txid '+r.id) : '') + (r.vsize ? (' · '+r.vsize+' vB') : '')));
  box.append(el('div',{class:'sub'},'version '+r.version+' · locktime '+r.locktime));
  const it = el('table',{}, el('thead',{},el('tr',{},el('th',{title:'Inputs are the coins (outputs of earlier transactions) being spent here. Each points to a previous txid:index.'},'Inputs ('+r.inputs.length+') - coins being spent'))));
  const itb=el('tbody',{}); r.inputs.forEach(i=> itb.append(el('tr',{}, el('td',{class:'addr'}, (i.txid||'?')+':'+i.index)))); it.append(itb);
  const ot = el('table',{}, el('thead',{},el('tr',{},el('th',{title:'Outputs are where the coins go: recipient addresses plus any change back to the sender. Inputs minus outputs is the miner fee.'},'Outputs ('+r.outputs.length+') - where coins go'),el('th',{class:'amt'},'Amount'))));
  const otb=el('tbody',{}); r.outputs.forEach(o=> otb.append(el('tr',{}, el('td',{class:'addr'}, o.address || ('script '+o.script)), el('td',{class:'amt'}, fmt(o.amount)+' '+c.ticker)))); ot.append(otb);
  box.append(it, ot,
    el('div',{class:'sub faint',style:'margin-top:4px'},'A transaction spends whole inputs and creates new outputs; the difference (inputs minus outputs) is the fee paid to miners. version/locktime control format and earliest-valid time.'));
  return box;
}

/* ----------------------------- contacts / address book ----------------------------- */
function actContacts(onPick){
  store.contacts = store.contacts || [];
  const listWrap = el('div',{class:'stack'});
  if(!store.contacts.length) listWrap.append(el('p',{class:'muted'},'No saved contacts yet.'));
  store.contacts.forEach((ct,i)=>{
    const useBtn = onPick ? el('button',{class:'btn ghost sm'},'Use') : null;
    if(useBtn) useBtn.addEventListener('click', ()=>{ onPick(ct.address); });
    const del = el('button',{class:'btn ghost sm',title:'Delete','aria-label':'Delete contact'},'✕');
    del.addEventListener('click', ()=>{ store.contacts.splice(i,1); saveStore(); actContacts(onPick); });
    listWrap.append(el('div',{class:'between',style:'border:1px solid var(--border);border-radius:var(--r-sm);padding:8px 12px;gap:8px'},
      el('div',{style:'flex:1;min-width:0'}, el('div',{}, ct.name), el('div',{class:'addr'}, ct.address)),
      el('div',{class:'row',style:'flex:none;gap:6px'}, useBtn, del)));
  });
  const nm = el('input',{type:'text',placeholder:'Name'});
  const ad = el('input',{type:'text',placeholder:'Address'});
  const addBtn = el('button',{class:'btn'},'Add contact');
  addBtn.addEventListener('click', ()=>{ const n=nm.value.trim(), a=ad.value.trim(); if(n&&a){ store.contacts.push({name:n,address:a}); saveStore(); actContacts(onPick); } });
  showModal(el('div',{},
    el('div',{class:'card-h'},'Contacts'),
    el('div',{class:'card-b stack'}, listWrap,
      el('hr',{class:'hr'}),
      nm, ad, el('div',{class:'row'}, addBtn, el('button',{class:'btn ghost',onclick:closeModal},'Close')))));
}

/* ----------------------------- settings ----------------------------- */
/* password setup / change modal */
function passwordSetupModal(isChange){
  const p1 = el('input',{type:'password',placeholder:isChange?'New password':'Password',autocomplete:'new-password'});
  const p2 = el('input',{type:'password',placeholder:'Confirm password',autocomplete:'new-password'});
  const out = el('div',{});
  const go = el('button',{class:'btn'}, isChange?'Change password':'Enable encryption');
  go.addEventListener('click', async ()=>{
    const a = p1.value, b = p2.value;
    if(a.length < 8){ clear(out).append(el('div',{class:'msg bad'},'Use at least 8 characters.')); return; }
    if(a !== b){ clear(out).append(el('div',{class:'msg bad'},'Passwords do not match.')); return; }
    go.disabled = true; go.textContent = 'Encrypting…';
    try {
      if(isChange) await changePassword(a);               // re-key in memory - never writes plaintext to disk
      else await enableEncryption(a);
      closeModal(); toast(isChange ? 'Password changed' : 'Encryption enabled. Your recovery phrase is now encrypted','ok');
    } catch(e){ clear(out).append(el('div',{class:'msg bad'},'Failed: '+(e.message||e))); go.disabled=false; go.textContent=isChange?'Change password':'Enable encryption'; }
  });
  showModal(el('div',{},
    el('div',{class:'card-h'}, isChange ? 'Change password' : 'Encrypt wallet'),
    el('div',{class:'card-b stack'},
      el('div',{class:'msg warn'},'Back up your 12-word recovery phrase first. If you forget this password, the only way back in is restoring from that phrase. The password cannot be recovered.'),
      el('div',{class:'field'}, el('label',{class:'fld'}, isChange?'New password':'Password'), p1),
      el('div',{class:'field'}, el('label',{class:'fld'},'Confirm'), p2),
      el('div',{class:'row',style:'flex:0'}, go, el('button',{class:'btn ghost',onclick:()=>actSettings()},'Cancel')), out)));
  setTimeout(()=>{ try{ p1.focus(); }catch(_){} }, 30);
}
/* the Security block inside Settings */
function securitySection(){
  const wrap = el('div',{class:'stack'});
  if(!isEncrypted()){
    const b = el('button',{class:'btn'},'Encrypt with a password');
    b.addEventListener('click', ()=> passwordSetupModal(false));
    wrap.append(el('div',{class:'sub faint'},'Encryption is off. Your recovery phrase is stored unencrypted in this browser. Fine for testnet, but anyone with access to this device or profile can read it. Turn it on to require a password (it encrypts your recovery phrase and Monero keys, and auto-locks when idle).'),
      el('div',{}, b));
  } else {
    const lock = el('button',{class:'btn ghost'},'Lock now');
    lock.addEventListener('click', ()=>{ closeModal(); lockWallet(); });
    const change = el('button',{class:'btn ghost'},'Change password');
    change.addEventListener('click', ()=> passwordSetupModal(true));
    const off = el('button',{class:'btn ghost'},'Turn off');
    off.addEventListener('click', ()=> confirmModal('Turn off encryption? Your recovery phrase will be stored unencrypted in this browser again.', async ()=>{
      try { await disableEncryption(); toast('Encryption turned off','ok'); actSettings(); } catch(e){ toast('Failed: '+(e.message||e),'bad'); }
    }, {danger:true, yes:'Turn off', title:'Disable encryption', onNo:()=>actSettings()}));
    const pinBtn = el('button',{class:'btn ghost'}, _pin?'Change quick-unlock PIN':'Set quick-unlock PIN');
    pinBtn.addEventListener('click', pinSetupModal);
    const pinClear = _pin ? el('button',{class:'btn ghost'},'Clear PIN') : null;
    if(pinClear) pinClear.addEventListener('click', ()=>{ _pin=null; toast('Quick-unlock PIN cleared','ok'); actSettings(); });
    wrap.append(el('div',{class:'sub ok'},'✓ Encrypted. Unlock with your password; auto-locks after 15 minutes idle.'),
      el('div',{class:'row',style:'flex:0'}, lock, change, off),
      el('div',{class:'sub faint',style:'margin-top:2px'}, _pin ? 'A quick-unlock PIN is set for this session. The 🔒 button locks quickly, and the PIN reopens it.' : 'Optional: set a quick-unlock PIN for fast lock and unlock (your password is still required after a reload or idle).'),
      el('div',{class:'row',style:'flex:0'}, pinBtn, pinClear));
  }
  return wrap;
}
function actSettings(){
  const sel = (opts, cur, onCh) => { const s = el('select',{style:'width:auto',onchange:e=>onCh(e.target.value)});
    for(const [v,l] of opts) s.append(el('option',{value:v,...(String(v)===String(cur)?{selected:true}:{})}, l)); return s; };
  const themeSel = sel([['dark','Dark'],['light','Light']], document.documentElement.getAttribute('data-theme'), v=>{ applyTheme(v); saveSettings(); });
  const fiatSel = sel(Object.keys(FIATS).map(c=>[c, FIATS[c]+' '+c]), state.fiat, v=>{ state.fiat=v; saveSettings(); refresh(); });
  const feeSel = sel([['slow','Slow'],['medium','Medium'],['fast','Fast']], state.feePref, v=>{ state.feePref=v; saveSettings(); });
  const refSel = sel([[15000,'15s'],[30000,'30s'],[60000,'1m'],[120000,'2m']], state.refreshMs, v=>{ state.refreshMs=parseInt(v); saveSettings(); });
  const hideChk = el('input',{type:'checkbox',checked:state.hideBalance,onchange:e=>{ state.hideBalance=e.target.checked; saveSettings(); }});
  const pingUrl = async (url) => { const ac = new AbortController(); const t = setTimeout(()=>ac.abort('timeout'), 10000);
    try { return await fetch(url, { signal: ac.signal }); } finally { clearTimeout(t); } };
  // Endpoint fields are PREFILLED with the built-in default, so they read as a real, editable value instead of an
  // empty box. A value equal to the default is NOT persisted: the field keeps falling through to the runtime
  // default (apiBase()/xmrNodeUrl()), so a new default in a future release still reaches the user. Only a genuine
  // deviation is saved as an override; "Default" clears it. def='' means there is no built-in default (Monero
  // stagenet), so the field stays empty behind a hint placeholder.
  const endpointField = (placeholder, getVal, onSave, runTest, def='') => {
    const norm = s => s.trim().replace(/\/+$/,'');
    const inp = el('input',{type:'text', style:'flex:1;min-width:0', value: getVal() || def, placeholder});
    const res = el('span',{class:'sub',style:'white-space:nowrap'});
    const mark = el('span',{class:'sub faint',style:'white-space:nowrap'});
    const reset = el('button',{class:'btn ghost sm', title:'Restore the built-in default'},'Default');
    const reflect = ()=>{ const onDef = !!def && norm(inp.value) === def;
      clear(mark); if(onDef) mark.append('default'); reset.style.display = (def && !onDef) ? '' : 'none'; };
    const save = ()=>{ const v = norm(inp.value); onSave(v && v !== def ? v : ''); reflect(); };
    inp.addEventListener('input', reflect);
    inp.addEventListener('change', save);
    reset.addEventListener('click', ()=>{ inp.value = def; save(); });
    const test = el('button',{class:'btn ghost sm'},'Test');
    test.addEventListener('click', async ()=>{ test.disabled=true; clear(res).append(el('span',{class:'sub'},'…'));
      try { const r = await runTest(norm(inp.value) || placeholder); clear(res).append(el('span',{class:'ok'},'✓ '+r)); }
      catch(e){ clear(res).append(el('span',{class:'bad'},'✗ '+(e.message||'failed'))); } finally { test.disabled=false; } });
    reflect();
    return el('div',{class:'row',style:'flex:0;align-items:center'}, inp, mark, test, reset, res);
  };
  const apiField = coin => endpointField(COINS[coin].api,
    ()=>(store.settings && store.settings.api && store.settings.api[coin]) || '',
    v=>{ store.settings = store.settings || {}; store.settings.api = store.settings.api || {}; if(v) store.settings.api[coin]=v; else delete store.settings.api[coin]; saveStore(); if(coin===state.coin) refresh(); },
    async base => { const r = await pingUrl(base + '/blocks/tip/height'); const txt = (await r.text()).trim();
      if(!r.ok || !/^\d+$/.test(txt)) throw new Error('HTTP '+r.status+' (allowed by CSP?)'); return 'block '+Number(txt).toLocaleString(); },
    COINS[coin].api);
  const xmrNodeField = net => endpointField(DEFAULT_XMR_NODE[net] || 'https://your-monero-node:port',
    ()=>(store.settings && store.settings.xmrNode && store.settings.xmrNode[net]) || '',
    v=>{ store.settings = store.settings || {}; store.settings.xmrNode = store.settings.xmrNode || {}; if(v) store.settings.xmrNode[net]=v; else delete store.settings.xmrNode[net]; saveStore(); },
    async base => { if(!base || base.indexOf('http')!==0) throw new Error('set an https URL'); const r = await pingUrl(base + '/get_height'); const j = await r.json();
      if(!r.ok || !j || !j.height) throw new Error('HTTP '+r.status+' (CORS/HTTPS?)'); return 'block '+Number(j.height).toLocaleString(); },
    DEFAULT_XMR_NODE[net] || '');
  const expAll = el('button',{class:'btn ghost'},'Export full backup');
  expAll.addEventListener('click', exportSnapshot);
  const impInput = el('input',{type:'file',accept:'application/json,.json',style:'display:none'});
  const impAll = el('button',{class:'btn ghost'},'Import backup');
  const impMsg = el('div',{});
  impAll.addEventListener('click', ()=>impInput.click());
  impInput.addEventListener('change', ()=>{ const f=impInput.files[0]; if(!f) return; const reader=new FileReader();
    reader.onload=()=> handleBackupFile(reader.result, impMsg, impInput);
    reader.readAsText(f); });
  const clearBtn = el('button',{class:'btn danger'},'Clear all data');
  clearBtn.addEventListener('click', ()=>{ confirmModal('Erase all wallets and settings from this browser? Make sure every recovery phrase is backed up. This cannot be undone.', ()=>{
    // sweep the main store AND every per-wallet Monero key/cache blob (which hold the private spend key - plaintext when encryption is off)
    try { for(let i=localStorage.length-1;i>=0;i--){ const k=localStorage.key(i); if(k===LS_KEY || k.indexOf(XMR_DATA_PREFIX)===0) localStorage.removeItem(k); } }
    catch(_){ try { localStorage.removeItem(LS_KEY); } catch(__){} }
    location.reload();
  }, {danger:true, yes:'Erase everything', title:'Clear all data', onNo:()=>actSettings()}); });
  showModal(el('div',{},
    el('div',{class:'card-h'},'Settings'),
    el('div',{class:'card-b stack'},
      el('div',{class:'between'}, el('span',{class:'sub'},'Theme'), themeSel),
      el('div',{class:'between'}, el('span',{class:'sub'},'Display currency'), fiatSel),
      el('div',{class:'between'}, el('span',{class:'sub'},'Default fee'), feeSel),
      el('div',{class:'between'}, el('span',{class:'sub'},'Refresh interval'), refSel),
      el('label',{class:'fld',style:'display:flex;gap:8px;align-items:center;cursor:pointer;margin:0'}, hideChk, 'Hide balance by default'),
      el('hr',{class:'hr'}),
      el('div',{class:'sub'},'Security'),
      securitySection(),
      el('hr',{class:'hr'}),
      el('div',{class:'sub'},'Full backup (all wallets, contacts, notes, and settings)'),
      el('div',{class:'row'}, expAll, impAll), impInput, impMsg,
      el('hr',{class:'hr'}),
      el('div',{class:'sub'},'Network endpoints (advanced, self-hosted)'),
      el('div',{class:'field'}, el('label',{class:'fld'},'Bitcoin Esplora API'), apiField('btc')),
      el('div',{class:'field'}, el('label',{class:'fld'},'Litecoin Esplora API'), apiField('ltc')),
      el('div',{class:'field'}, el('label',{class:'fld'},'Monero node RPC (stagenet)'), xmrNodeField('stagenet')),
      el('div',{class:'field'}, el('label',{class:'fld'},'Monero node RPC (testnet)'), xmrNodeField('testnet')),
      el('div',{class:'sub faint',style:'margin-top:0'},'Fields are prefilled with the built-in default; leave one as-is to keep using it (it updates with new releases), or enter your own Esplora instance or Monero node and press Default to revert. Stagenet has no public default, so add your own node there. A custom origin must also be allowed by the page Content-Security-Policy (connect-src in _headers), which you control when self-hosting. The Monero node needs CORS (--rpc-access-control-origins), and HTTPS on an https site.'),
      el('div',{class:'sub faint'},'Privacy: each refresh reveals your addresses to the block explorer, and the fiat estimate sends the coin to the price API; both can tie those to your IP. Over Tor that stays a deanonymization surface.'),
      el('hr',{class:'hr'}),
      el('div',{class:'sub'},'Danger zone'), clearBtn,
      el('div',{class:'row',style:'margin-top:8px'}, el('button',{class:'btn ghost',onclick:closeModal},'Close')),
    )));
}

/* ----------------------------- theme + boot ----------------------------- */
function applyTheme(theme){ const t = theme==='light'?'light':'dark'; document.documentElement.setAttribute('data-theme', t);
  const tt = $('theme-toggle'); if(tt) tt.textContent = t==='dark' ? '☀' : '☾'; }   // show the mode you'll switch to
function wireTheme(){
  $('theme-toggle').addEventListener('click', ()=>{
    const next = document.documentElement.getAttribute('data-theme')==='dark' ? 'light' : 'dark';
    applyTheme(next); saveSettings();
  });
  const lb = $('lock-toggle'); if(lb) lb.addEventListener('click', ()=>{ if(isEncrypted() && !isLocked()){ if(_pin) softLock(); else lockWallet(); } });
}
/* Lock screen (shown when encryption is on and the wallet isn't unlocked yet). */
function renderLockScreen(){
  const pw = el('input',{type:'password',placeholder:'Password',autocomplete:'current-password'});
  const out = el('div',{});
  const btn = el('button',{class:'btn'},'Unlock');
  const submit = async ()=>{
    if(!pw.value) return;
    btn.disabled = true; btn.textContent = 'Unlocking…';
    let vault = null; try { vault = JSON.parse(localStorage.getItem(LS_KEY)); } catch(_e){}
    if(!vault || !vault.tnwvault){ clear(out).append(el('div',{class:'msg bad'},'This wallet was changed in another tab. Reload the page.')); btn.disabled=false; btn.textContent='Unlock'; return; }
    try { await unlockVault(vault, pw.value); afterStoreLoaded(); }
    catch(_){ clear(out).append(el('div',{class:'msg bad'},'Wrong password. Try again.')); shakeEl(pw); btn.disabled=false; btn.textContent='Unlock'; pw.value=''; try{ pw.focus(); }catch(_e){} }
  };
  btn.addEventListener('click', submit);
  pw.addEventListener('keydown', e=>{ if(e.key==='Enter') submit(); });
  setTimeout(()=>{ try{ pw.focus(); }catch(_){} }, 30);
  return el('div',{class:'card page-narrow'},
    el('div',{class:'card-h'},'🔒 Wallet locked'),
    el('div',{class:'card-b stack'},
      el('div',{class:'sub'},'Enter your password to unlock this wallet. Forgot it? Your funds are recoverable from your 12-word recovery phrase: restore it after clearing data.'),
      el('div',{class:'field'}, el('label',{class:'fld'},'Password'), pw),
      el('div',{}, btn), out));
}
/* PIN screen for a soft lock (key + seed still in memory; instant unlock with the session PIN). */
function renderPinScreen(){
  const pin = el('input',{type:'password',inputmode:'numeric',placeholder:'PIN',autocomplete:'off'});
  const out = el('div',{});
  const btn = el('button',{class:'btn'},'Unlock');
  const submit = ()=>{ if(pin.value && pin.value === _pin){ _softLocked = false; render(); }
    else { clear(out).append(el('div',{class:'msg bad'},'Wrong PIN.')); shakeEl(pin); pin.value=''; try{ pin.focus(); }catch(_){} } };
  btn.addEventListener('click', submit);
  pin.addEventListener('keydown', e=>{ if(e.key==='Enter') submit(); });
  setTimeout(()=>{ try{ pin.focus(); }catch(_){} }, 30);
  return el('div',{class:'card page-narrow'},
    el('div',{class:'card-h'},'🔒 Quick-unlock PIN'),
    el('div',{class:'card-b stack'},
      el('div',{class:'sub'},'Enter your PIN to unlock. A full reload or 15 minutes idle will need your password instead.'),
      el('div',{class:'field'}, el('label',{class:'fld'},'PIN'), pin),
      el('div',{class:'row',style:'flex:0'}, btn, el('button',{class:'btn ghost',onclick:lockWallet},'Use password instead')), out));
}
/* Set/change the session PIN (in-memory only). */
function pinSetupModal(){
  const p = el('input',{type:'password',inputmode:'numeric',placeholder:'PIN (4-12 digits)',autocomplete:'off'});
  const out = el('div',{});
  const go = el('button',{class:'btn'}, _pin?'Change PIN':'Set PIN');
  go.addEventListener('click', ()=>{
    if(!/^\d{4,12}$/.test(p.value)){ clear(out).append(el('div',{class:'msg bad'},'Use 4-12 digits.')); return; }
    _pin = p.value; closeModal(); toast('Quick-unlock PIN set for this session','ok');
  });
  showModal(el('div',{},
    el('div',{class:'card-h'},'Quick-unlock PIN'),
    el('div',{class:'card-b stack'},
      el('div',{class:'sub'},'A PIN lets you lock and unlock quickly without re-typing your password while the wallet stays open. It is kept only for this browser session. A full reload or 15 minutes idle still needs your password, so a PIN is for convenience, not extra at-rest security.'),
      el('div',{class:'field'}, el('label',{class:'fld'},'PIN'), p),
      el('div',{class:'row',style:'flex:0'}, go, el('button',{class:'btn ghost',onclick:()=>actSettings()},'Cancel')), out)));
  setTimeout(()=>{ try{ p.focus(); }catch(_){} }, 30);
}
/* Idle auto-lock: when encrypted, lock after inactivity (a periodic check avoids per-event timer churn). */
const IDLE_LOCK_MS = 15 * 60 * 1000;
let _lastActivity = 0;
function wireAutoLock(){
  const bump = ()=>{ _lastActivity = Date.now(); };
  ['click','keydown','touchstart','mousemove','wheel'].forEach(ev => document.addEventListener(ev, bump, { passive:true }));
  bump();
  setInterval(()=>{ if(isEncrypted() && _cryptoKey && _lastActivity && (Date.now() - _lastActivity) > IDLE_LOCK_MS) lockWallet(); }, 30000);   // FULL-lock on idle (fires while unlocked OR soft-locked, since both hold the key); also clears a revealed seed/WIF
}
/* Apply settings + open the active wallet once the store is available (plaintext boot OR after unlock). */
function afterStoreLoaded(){
  if(store.counts){ for(const wid of Object.keys(store.counts)){ const m = store.counts[wid];   // migrate pre-account keys: coin.type -> coin.type.0
    for(const k of Object.keys(m)){ if(k.split('.').length === 2){ m[k+'.0'] = m[k]; delete m[k]; } } } saveStore(); }
  const s = store.settings || {};
  applyTheme(s.theme || 'dark');
  if(s.xmrNet && xmr.XMR_NETS[s.xmrNet]) state.xmrNet = s.xmrNet;
  if(s.coin && COINS[s.coin] && COINS[s.coin].enabled) state.coin = s.coin;
  if(s.addrType && TYPES[s.addrType]) state.addrType = s.addrType;
  if(s.fiat && FIATS[s.fiat]) state.fiat = s.fiat;
  if(typeof s.account === 'number' && s.account >= 0) state.account = s.account;
  if(typeof s.hideBalance === 'boolean') state.hideBalance = s.hideBalance;
  if(typeof s.refreshMs === 'number' && s.refreshMs >= 10000) state.refreshMs = s.refreshMs;
  if(s.feePref) state.feePref = s.feePref;
  const active = (store.wallets||[]).find(w=>w.id===store.activeId) || (store.wallets||[])[0];
  if(active) openWallet(active); else render();
  handleDeepLink();
}

// Inbound deep-link / URI router: prefill (NEVER auto-broadcast) the Send tab from a BIP21/monero URI or a
// ?send=/?bip21=/?uri= param (or ?action=receive|send), then strip the URL. Lets the faucet/pool/guides hand
// off into the wallet. Pure client-side.
function handleDeepLink(){
  let raw = '', action = '';
  try {
    const params = new URLSearchParams(location.search || '');
    action = params.get('action') || '';
    raw = (params.get('send') || params.get('bip21') || params.get('uri') || '').trim();
    if(!raw && location.hash){ const h = decodeURIComponent(location.hash.slice(1)); if(/^(bitcoin|litecoin|monero):/i.test(h)) raw = h.trim(); }
  } catch(_){ return; }
  const cleanUrl = ()=>{ try { history.replaceState(null, '', location.pathname); } catch(_){} };
  if(!raw && !action) return;                                  // nothing to route
  if(!state.wallet){ cleanUrl(); return; }                     // no wallet yet - strip so the param doesn't linger/bookmark
  if(!raw){
    if(action==='receive'){ state.tab='receive'; render(); }
    else if(action==='send'){ state.tab='send'; render(); }
    cleanUrl(); return;
  }
  const scheme = (raw.match(/^([a-zA-Z]+):/)||[])[1];
  let coin = state.coin;
  if(scheme){ const sl=scheme.toLowerCase(); coin = sl==='bitcoin'?'btc' : sl==='litecoin'?'ltc' : sl==='monero'?'xmr' : coin; }
  try {
    if(coin==='xmr'){
      if(!COINS.xmr.enabled || !state.xmrKeys){ toast('This wallet has no Monero keys for a Monero send','warn'); cleanUrl(); return; }
      const p = parseMoneroUri(raw);
      if(!p.address || !/^[1-9A-HJ-NP-Za-km-z]{90,110}$/.test(p.address)){ toast('That link had an invalid Monero address','warn'); cleanUrl(); return; }
      if(state.coin!=='xmr'){ state.coin='xmr'; saveSettings(); buildAddresses(); }
      state.xmrSend = { recipients:[{ to:p.address, amount:p.amount||'' }], priority:'', error:null };
      state.tab='send'; render(); toast('Prefilled a Monero send - review before sending','ok');
    } else {
      const p = parseBip21(raw);
      if(!isValidAddress(p.address, coin)){ toast('That link had an invalid address','warn'); cleanUrl(); return; }
      if(state.coin!==coin){ state.coin=coin; _lastBal=null; _lastPending=new Set(); saveSettings(); buildAddresses(); }
      state.send.recipients = [{ address:p.address, amount:p.amount||'' }];
      state.send.advanced=false; state.send.selected={}; state.send.utxos=null;
      state.tab='send'; render(); refresh();
      toast('Prefilled a send from the link - review before broadcasting','ok');
    }
  } catch(_){}
  cleanUrl();
}
function boot(){
  try {                                                  // store-independent self-tests
    const st = xmr.selfTest(), ss = xmrSeed.selfTest();
    state.xmrSeedOk = ss.ok; state.xmrOk = st.ok && ss.ok; COINS.xmr.enabled = MONERO_ENABLED && state.xmrOk;
    if(!state.xmrOk) console.warn('Monero self-test failed; Monero disabled:', st.fails, ss.fails);
  } catch(e){ state.xmrOk = false; state.xmrSeedOk = false; COINS.xmr.enabled = false; console.warn('Monero self-test error:', e); }
  try {
    const bs = bip322.selfTest(COINS.btc.net);
    state.bip322Ok = bs.ok;
    if(!bs.ok) console.warn('BIP-322 self-test failed; segwit/taproot message signing disabled:', bs.fails);
  } catch(e){ state.bip322Ok = false; console.warn('BIP-322 self-test error:', e); }
  try {
    const msr = msSelfTest(); _msigOk = msr.ok;
    if(!msr.ok) console.warn('Multisig self-test failed; multisig disabled:', msr.fails);
  } catch(e){ _msigOk = false; console.warn('Multisig self-test error:', e); }
  wireTheme();
  let parsed = null; try { const raw = localStorage.getItem(LS_KEY); parsed = raw ? JSON.parse(raw) : null; } catch(_){}
  if(parsed && parsed.tnwvault){                          // encrypted on disk -> gate behind the unlock screen
    _encOn = true; _locked = true; _vaultIter = parsed.iter || KDF_ITER;
    applyTheme(parsed.theme || 'dark');
    render();
  } else {
    store = parsed || {};
    afterStoreLoaded();
  }
  // background refresh (paused while hidden / locked / on a form) + idle auto-lock
  const canAutoRefresh = ()=> state.wallet && !document.hidden && !isLocked() && (state.tab==='receive' || state.tab==='history') && !$('overlay-mount').firstChild;
  (function loop(){ setTimeout(()=>{
    if(canAutoRefresh()){
      const ae = document.activeElement;
      if(!(ae && ['SELECT','INPUT','TEXTAREA'].includes(ae.tagName))) refresh();
    }
    loop();
  }, Math.max(10000, state.refreshMs || 30000)); })();
  document.addEventListener('visibilitychange', ()=>{ if(canAutoRefresh()) refresh(); });
  wireAutoLock();
}
boot();
// PWA: register the network-first service worker so the app is installable + works offline (fails silently if unsupported)
if('serviceWorker' in navigator){ try { navigator.serviceWorker.register('sw.js').catch(()=>{}); } catch(_){} }
