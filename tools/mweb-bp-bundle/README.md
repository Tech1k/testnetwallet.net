# mweb-bp-bundle

Builds the one piece of MWEB **sending** that can't be done in pure JS: the 64-bit
**Bulletproof range proof** every MWEB output must carry. It compiles only
`secp256k1_bulletproof_rangeproof_prove` (plus its generator/commitment deps) from the
exact `secp256k1-zkp` the Litecoin MWEB node uses, into a single self-contained ES
module that the wallet lazy-loads - exactly like the Monero engine in `tools/monero-bundle`.

Everything else in an MWEB send (stealth outputs, inputs, kernel, balance/offsets, the
MW/Grin Schnorr signatures, serialization, broadcast) is pure JS in `mweb.mjs` /
`mweb.mjs`. This is the only native dependency.

## Why a WASM build (not a JS port or an npm package)

- The node only accepts a **valid** proof over the right commitment + generators +
  extra-data - but those generators and the Fiat-Shamir transcript must match
  secp256k1-zkp's exactly, so compiling the real C is the safe, byte-correct path.
- The only WASM-packaged `secp256k1-zkp` on npm (`@vulpemventures/secp256k1-zkp`) ships
  the *old Borromean* rangeproof, **not** bulletproofs - its proofs are rejected by an
  LTC node. Pure-JS bulletproof libs aren't secp256k1-zkp-compatible. Hence: build the C.

## Build

```sh
cd tools/mweb-bp-bundle
./build.sh        # needs emscripten + autoconf/automake/libtool + git
```

Output: `vendor/mweb-bp.js` (a single `SINGLE_FILE` module). Commit it, like the Monero
bundle. If the build breaks on a newer toolchain, pin a known-good emscripten version
(the `vulpemventures/secp256k1-zkp` Dockerfile is a good reference) and re-check the
`secp256k1_bulletproof_rangeproof_prove` signature in `include/secp256k1_bulletproofs.h`
against `main.c` (forks occasionally reorder args).

## JS load contract (what `mweb.mjs` expects)

```js
const { default: MwebBP } = await import('./vendor/mweb-bp.js');
const m = await MwebBP();                       // instantiate the module
// bp_prove(value, blind32, nonce32, privNonce32, message20, extra, extraLen, out) -> proofLen
const outPtr = m._malloc(675);
const proofLen = m.ccall('bp_prove', 'number',
  ['number','number','number','number','number','number','number','number'],
  [value, blindPtr, noncePtr, privNoncePtr, msg20Ptr, extraPtr, extraLen, outPtr]);
const proof = m.HEAPU8.slice(outPtr, outPtr + 675);   // proofLen should be 675
```

`value` is a JS Number in litoshi (< 2^53, exact for every real amount). `blind32` is the
**switch** blind (`blindSwitch(r, value)` from `mweb.mjs`). `extra` is the 59-byte
serialized OutputMessage. `nonce`/`privNonce` are 32 random bytes each
(`crypto.getRandomValues`) - any valid nonce produces a node-accepted proof.

## Correctness gate

The proof can only be truly validated by the node. Build a testnet MWEB tx, dry-run it
through `testmempoolaccept`, then `sendrawtransaction`; if litecoind accepts it, the proof
(and the rest of the send) is correct. Static analysis is not sufficient - same discipline
the receive side used.
