# tools/

Developer + operator tooling. **None of this ships with the wallet** - the Cloudflare `_redirects`
rule `/tools/* -> /` keeps the whole directory off the production origin. These are build inputs and
self-host helpers, not part of the static app.

- **`mweb.php`** - the only *server* component, and it is optional/self-hosted. A small drop-in PHP
  helper that fronts a localhost `litecoind` JSON-RPC for MWEB: it serves block ranges so the browser
  can scan locally (keys never leave the browser) and relays only `sendrawtransaction` /
  `testmempoolaccept`. Deploy it on the same host as your node. Config is in the header comment
  (`LTC_RPC_URL/USER/PASS`, `LTC_ALLOW_ORIGIN`, `MAX_RANGE`, `MAX_BODY`).

- **`mweb-bp-bundle/`** - builds `vendor/mweb-bp.js`, the 64-bit MWEB bulletproof range-proof prover,
  from `main.c` + the `ltcmweb/secp256k1` fork via Emscripten. Run `build.sh` to regenerate; the
  `secp256k1-zkp/` clone it creates is gitignored (re-cloned on demand).

- **`monero-bundle/`** - builds `vendor/monero-engine.bundle.js` (the monero-ts WASM engine) via
  webpack. `node_modules/` is gitignored.

- **`cors-proxy.js`** - a local-only dev helper for testing Monero against a public node that lacks
  CORS/HTTPS. Not used in production (your own node serves CORS + HTTPS directly).
