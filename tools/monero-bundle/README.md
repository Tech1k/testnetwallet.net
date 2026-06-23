# Monero engine bundle (one-time build)

`monero-ts` is the library that gives TestnetWallet self-custodial, **direct-to-node** Monero
(scanning and signing happen locally in WebAssembly; the node only serves blocks). It imports Node
built-ins (`child_process`/`net`/`tls`), so it can't be auto-bundled by a CDN - it needs one real
bundle step. The output is committed to `vendor/`, after which the deployed wallet stays 100% static
(this is the same idea as the `@scure`/`@noble` files, which were also pre-bundled and committed -
just produced by esm.sh instead of webpack).

You only need to re-run this when upgrading `monero-ts`.

## Build it

Requires Node.js (any recent LTS).

```sh
cd tools/monero-bundle
npm install
npm run build
```

This writes two files into `../../vendor/`:

- `monero-engine.bundle.js` - the bundled monero-ts API (UMD; exposes the global `moneroTs`)
- `monero.worker.js` - the wallet's web worker (copied from `monero-ts/dist`)

Commit both. The wallet lazy-loads them only when a Monero balance/send is requested, so BTC/LTC
users never download them.

## Notes

- Config mirrors the official sample: https://github.com/woodser/xmr-sample-webpack - if a future
  `monero-ts` needs a tweak, that repo is the source of truth.
- The runtime wrapper that consumes these files is `../../monero-engine.mjs`, which calls
  `moneroTs.LibraryUtils.setWorkerDistPath("/vendor/monero.worker.js")` before creating a wallet.
- The wallet's CSP must allow the WASM + worker + your node:
  `script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src … https://your-node-origin`.
