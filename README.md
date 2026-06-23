# TestnetWallet

An open-source wallet for the Bitcoin, Litecoin and Monero testnets - a safe place to learn crypto and build, where real value is never at risk. Live at [testnetwallet.net](https://testnetwallet.net).

It's one of a few testnet tools: [CypherFaucet](https://cypherfaucet.com) (faucet), [TestnetPool](https://testnetpool.com) (mining pool), and [CypherToshi](https://cyphertoshi.com) (guides and tools).

## Networks
- Bitcoin testnet4, via mempool.space for the explorer and API
- Litecoin testnet, via litecoinspace.org
- (in development - working beta) Monero stagenet/testnet: full wallet - addresses are derived pure-JS from your recovery phrase, and balance, history, sending, sweep, message signing and payment proofs run self-custodially through a lazy-loaded WASM engine talking directly to a node (no light-wallet server)

## Features
- BIP39 HD wallet with a 12-word recovery phrase you can create or import
- Legacy, SegWit (bech32) and Taproot addresses, all derived from one seed
- Saved in your browser, with multiple named wallets and backup via the recovery phrase or an export/import file (the export can be password-encrypted)
- Optional password encryption-at-rest with an unlock screen, idle auto-lock, and a fast session-PIN; installable as an offline-capable PWA
- Receive (address and QR), live balance, and transaction history with per-transaction detail
- Send to multiple recipients, with OP_RETURN, manual fee rate (with sat/vB + ETA presets), and coin control; bump a stuck transaction's fee with RBF, or speed up an incoming one with CPFP
- Automatic gap-limit address discovery, so coins received on a not-yet-shown or imported address still appear
- Import an Electrum wallet (standard or SegWit seed) - Electrum's own seed scheme and derivation, verified against Electrum's published vectors
- Multisig: build or import a P2WSH descriptor wallet (BIP48), watch its balance, and coordinate a spend end-to-end via PSBT (sign → combine → finalize → broadcast)
- Tools: message signing & verification (legacy BIP137 for legacy addresses, BIP-322 for SegWit/Taproot), a key inspector, and an address validator
- Dev: decode a raw transaction or PSBT, broadcast a raw transaction, and build QR / BIP21 payment URIs
- One-click testnet coins from CypherFaucet, inbound payment deep-links (BIP21), and accessible by design (ARIA live regions, reduced-motion-aware feedback animations)
- Monero (stagenet/testnet): primary + subaddresses with QR from the same recovery phrase, plus live balance, transaction history, send, send-max (sweep), message signing/verification, and payment-proof generate/check - all via a self-custodial engine that connects straight to a node; exportable as a portable 25-word seed for any Monero wallet

## How it's built
No build step. It's a handful of static files you can host anywhere:
- `index.html`: markup, inline CSS, and the Content-Security-Policy
- `app.js`: the application, as a single ES module
- `app.js` also pulls in `bip322.mjs` (BIP-322 message signing/verification for SegWit & Taproot) and `monero.mjs` (pure-JS Monero key derivation and address encoding - no backend)
- `vendor/`: the only dependencies, vendored so nothing loads from a CDN at runtime (it works offline and over Tor): @scure/btc-signer, @scure/bip32, @scure/bip39, @noble/secp256k1, @noble/hashes, @noble/ed25519, qrcode-generator, jsQR, the Monero English wordlist, and (lazy-loaded only for Monero balance/sending) a bundled `monero-ts` (`monero-engine.bundle.js` + `monero.worker.js`, built once via `tools/monero-bundle`)
- `icons/`: the coin logos
- `sw.js` + `manifest.webmanifest`: make it an installable, offline-capable PWA (the service worker is network-first, so an online load always fetches the latest code and the cache is only a fallback)

Everything runs in the browser. Your recovery phrase and keys never leave it.

In progress: `mweb.mjs` is a pure-JS implementation of Litecoin **MWEB** (MimbleWimble Extension Blocks) receive-side crypto (keychain, `tmweb` stealth addresses, and output scanning), transcribed bit-for-bit from `libmw` and validated by an in-browser self-test (`mweb-test.html`). It isn't wired into the UI yet: scanning needs a source for MWEB outputs (litecoinspace's `/api/v1/mweb/utxos` endpoint), which the wallet will use once it's available.

## Run locally
It's an ES-module app, so it has to be served over HTTP. Opening `index.html` straight from the filesystem won't work, because browsers block module scripts loaded over `file://`. Any static server does the job:
```sh
python3 -m http.server 8080   # then open http://localhost:8080
```
Anything equivalent works too: `npx serve`, `php -S localhost:8080`, or a live-server editor extension.

## Deploy
It's a static site, so you can drop the folder on any host. Because it holds keys, treat it like a wallet:
- Give it its own origin (testnetwallet.net), not a path under another site. The seed lives in localStorage, which is scoped to the origin, so sharing an origin would expose it to anything else running there.
- Pick one canonical origin. A wallet created on one origin won't show up on another, so redirect any alias to the canonical host instead of running a second copy.
- Send real security headers. The included [`_headers`](_headers) file sets a CSP with `frame-ancestors 'none'`, `X-Frame-Options: DENY`, HSTS, `Referrer-Policy: no-referrer`, and a tight `Permissions-Policy`. (`frame-ancestors` in a `<meta>` CSP is ignored by browsers, so it has to be a real header. The app also has a JS frame-buster as a backup.)
- Keep the domain on auto-renew with a registrar lock. A lapsed wallet domain is a phishing risk.

### Cloudflare Pages
Connect the repo with no build command and the output directory set to the repo root. Cloudflare applies the [`_headers`](_headers) file automatically.

## Security & privacy
- Keys never leave the browser. The recovery phrase is generated locally and kept only in this origin's `localStorage`. By default it's stored in plain text (fine for a testnet playground) - or you can turn on **optional password encryption-at-rest** (Settings → Security): the seed and Monero keys are then encrypted with AES-256-GCM under a key derived from your password via PBKDF2 (Web Crypto), with an unlock screen and idle auto-lock. The password isn't recoverable, so it's a complement to, not a replacement for, backing up your recovery phrase. Either way, don't reuse a testnet phrase on mainnet.
- Tight Content-Security-Policy (`default-src 'none'`, a locked-down `connect-src`, no inline scripts) and the DOM is built without `innerHTML`, so data from an API can't inject markup. One caveat comes with Monero: the bundled `monero-ts` compiles its WebAssembly through `new Function`, so enabling balance/sending requires `'wasm-unsafe-eval'` and `'unsafe-eval'` in `script-src`, and the CSP allows them. The first-party code never uses `eval`/`new Function`; moving the Monero engine to its own origin so the main wallet keeps a no-eval CSP is on the roadmap.
- The Monero engine talks directly to a node over HTTPS. The default testnet node (`https://xmr-testnet-node.librenode.com`, a restricted-RPC node with permissive CORS) is the only Monero origin in `connect-src`. If you self-host a different node, it must be reachable over HTTPS with CORS enabled (mixed content and CORS both require this), and you must add its origin to `connect-src` in both [`index.html`](index.html) and [`_headers`](_headers).
- Real security headers ship in [`_headers`](_headers): `frame-ancestors 'none'`, `X-Frame-Options: DENY`, HSTS, `Referrer-Policy: no-referrer`, and a tight `Permissions-Policy`. A JS frame-buster backs up the framing protection.
- Transactions spend only confirmed UTXOs by default (coin control can opt into unconfirmed ones), enforce a dust threshold on change, floor the fee at 1 sat/vB (the minimum relay fee) with suggested rates pulled from the network, signal RBF, and require a confirmation step before broadcast.
- Privacy: each balance/history refresh sends your addresses to the block explorer, and the fiat estimate sends the coin symbol to the price API - either can associate those with your IP, which over Tor is a deanonymization surface to keep in mind. Polling pauses while the tab is hidden. Self-hosters can point at their own Esplora endpoint in Settings.

## License
TestnetWallet is © 2026 Tech1k, licensed under **AGPL-3.0-or-later** (full text in [`LICENSE`](LICENSE); SPDX headers are in `app.js` and `index.html`). Because it's served as a network application, the AGPL means anyone who runs a modified copy must offer its users the corresponding source.

It began as a fork of [blt-wallet](https://github.com/sereneblue/blt-wallet) by sereneblue (MIT) but has since been rewritten from scratch; no original blt-wallet code remains. The credit is kept as a matter of history.

Block explorer data comes from mempool.space (Bitcoin) and litecoinspace.org (Litecoin); mainnet prices from CoinGecko, with a Coinbase fallback.

### Third-party code
The libraries in `vendor/` are bundled under their own licenses:

- **@scure/btc-signer, @scure/bip32, @scure/bip39, @noble/secp256k1, @noble/hashes, @noble/ed25519** - © Paul Miller (paulmillr.com), MIT
- **qrcode-generator** - © Kazuhiko Arase, MIT
- **jsQR** - © Cosmo Wolfe, Apache-2.0 (full text in [`vendor/jsQR.LICENSE`](vendor/jsQR.LICENSE))
- **Monero English wordlist** (`vendor/monero-wordlist.mjs`) - © The Monero Project, BSD-3-Clause (full text in [`vendor/monero-wordlist.LICENSE`](vendor/monero-wordlist.LICENSE))
- **monero-ts** - © woodser, MIT - bundled (only for Monero balance/sending) into `vendor/monero-engine.bundle.js` and `vendor/monero.worker.js`. Each carries its own third-party notices alongside it ([`vendor/monero-engine.bundle.js.LICENSE.txt`](vendor/monero-engine.bundle.js.LICENSE.txt) and [`vendor/monero.worker.js.LICENSE.txt`](vendor/monero.worker.js.LICENSE.txt)), covering its dependencies (decimal.js, buffer, ieee754, safe-buffer, punycode, and others). The bundle is reproducible via `tools/monero-bundle`.

The MIT-licensed components above are provided under the following notice:

```
MIT License

Copyright (c) Paul Miller (https://paulmillr.com)
Copyright (c) Kazuhiko Arase

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
