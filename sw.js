// SPDX-License-Identifier: AGPL-3.0-or-later
/* TestnetWallet service worker - makes the app installable and usable offline.
 * Strategy: NETWORK-FIRST for same-origin requests (so online users always get the freshest code - important for a
 * wallet), falling back to the cache only when offline. Cross-origin requests (block explorers, the Monero node,
 * price APIs) are never intercepted or cached. Bump CACHE to invalidate old caches on deploy. */
const CACHE = 'tnw-v3';
const SHELL = [
  './', './index.html', './app.js',
  './bip322.mjs', './monero.mjs', './monero-mnemonic.mjs', './monero-engine.mjs',
  './vendor/btc-signer.mjs', './vendor/bip32.mjs', './vendor/bip39.mjs', './vendor/wordlist-english.mjs',
  './vendor/noble-secp256k1.mjs', './vendor/noble-sha256.mjs', './vendor/noble-ed25519.mjs', './vendor/noble-keccak.mjs',
  './vendor/monero-wordlist.mjs', './vendor/qrcode.js', './vendor/jsQR.js',
  './favicon.svg', './manifest.webmanifest',
  './icons/btc.svg', './icons/ltc.svg', './icons/xmr.svg',
];   // the heavy lazy-loaded Monero engine isn't precached - it caches on first use via the fetch handler below.

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => Promise.allSettled(SHELL.map(u => c.add(u)))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if(req.method !== 'GET') return;                              // never touch API POSTs / broadcasts
  let url; try { url = new URL(req.url); } catch(_){ return; }
  if(url.origin !== self.location.origin) return;               // let cross-origin (explorers/node/price) hit the network directly
  e.respondWith(
    fetch(req).then(res => {
      if(res && res.ok && (res.type === 'basic' || res.type === 'default')){
        const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)).catch(()=>{});   // refresh the cache with the latest
      }
      return res;
    }).catch(() => caches.match(req).then(r => r || caches.match('./index.html')))   // offline: serve cache, falling back to the app shell
  );
});
