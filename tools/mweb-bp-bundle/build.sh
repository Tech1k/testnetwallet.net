#!/usr/bin/env bash
#
# Build the MWEB bulletproof prover into ONE self-contained ES module:
#   ../../vendor/mweb-bp.js   (lazy-loaded by the wallet, like the Monero engine)
#
# It compiles only secp256k1_bulletproof_rangeproof_prove (+ its generator/commitment
# deps) from the exact secp256k1-zkp fork the Litecoin MWEB node uses, plus the tiny
# main.c wrapper, to a single MODULARIZE/SINGLE_FILE artifact - no runtime deps, no CDN.
#
# Prereqs: emscripten (emcc, emconfigure, emmake), autoconf, automake, libtool, git.
# If it fails on a newer toolchain, pin a known-good emscripten (the vulpemventures
# secp256k1-zkp repo's Dockerfile is a good reference for a working version).
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../../vendor/mweb-bp.js"
SRC="$HERE/secp256k1-zkp"

# 1. The exact secp256k1-zkp the LTC node uses (its bulletproofs module is what we need).
#    Alternative source if this fork moves: github.com/mimblewimble/secp256k1-zkp
if [ ! -d "$SRC" ]; then
  git clone --depth 1 https://github.com/ltcmweb/secp256k1 "$SRC"
fi
cd "$SRC"

# 2. Configure for Emscripten with ONLY the modules we need, no tests/benches.
[ -x ./autogen.sh ] && ./autogen.sh
emconfigure ./configure \
  --enable-experimental \
  --enable-module-generator \
  --enable-module-commitment \
  --enable-module-bulletproof \
  --disable-tests --disable-benchmark --disable-exhaustive-tests \
  --with-asm=no
emmake make -j"$(nproc)" libsecp256k1.la

# 3. Link the static lib + our one-function wrapper into a single ES module.
LIB="$SRC/.libs/libsecp256k1.a"
[ -f "$LIB" ] || LIB="$(find "$SRC" -name 'libsecp256k1.a' | head -1)"

emcc -O3 \
  -I"$SRC/include" -I"$SRC" \
  "$HERE/main.c" "$LIB" \
  -s MODULARIZE=1 -s EXPORT_ES6=1 -s SINGLE_FILE=1 \
  -s NO_FILESYSTEM=1 -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORT_NAME=MwebBP \
  -s "EXPORTED_FUNCTIONS=['_bp_prove','_malloc','_free']" \
  -s "EXPORTED_RUNTIME_METHODS=['ccall','setValue','getValue','HEAPU8']" \
  -o "$OUT"

echo "Built $OUT ($(wc -c < "$OUT") bytes). Lazy-load it from mweb-tx.mjs; see README."
