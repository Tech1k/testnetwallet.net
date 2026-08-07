// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr/crypto: loads the cross-curve crypto WASM (built from ../crypto) and
 * exposes its hex-in/hex-out API. Works in Node (pkg-node, CommonJS) and the
 * browser (pkg-web, async init). The protocol/tx layer takes the returned module
 * as a dependency so it stays environment-agnostic and testable.
 *
 * API (all hex strings unless noted):
 *   gen_secret_share() -> ed scalar (LE)         secp_pubkey(scalar_be) -> point(33)
 *   ed_to_secp_scalar(ed_le) -> secp scalar(be)  ed_pubkey(scalar_le) -> point(32)
 *   ed_scalar_add(a_le,b_le) -> le               ed_point_add(a,b) -> point(32)
 *   dleq_prove(secret_le) -> JSON{proof,secp,ed} dleq_verify(proof,secp,ed) -> bool
 *   adaptor_encrypt(sk_be, encPoint, msg32) -> encSig
 *   adaptor_verify(vkPoint, encPoint, msg32, encSig) -> bool
 *   adaptor_decrypt(decScalar_be, encSig) -> sig(64)
 *   adaptor_recover(encPoint, sig64, encSig) -> decScalar_be | ''
 *   ecdsa_sign(sk_be, msg32) -> sig(64)          ecdsa_verify(vkPoint, msg32, sig64) -> bool
 */

let _mod = null;

/**
 * Load the WASM crypto module. In Node it requires the prebuilt pkg-node bundle;
 * in the browser it imports pkg-web and runs its async init.
 * @param {object} [opts]; { wasmUrl } for the browser init (optional).
 */
export async function loadXmrCrypto(opts = {}) {
  if (_mod) return _mod;
  const isNode = typeof process !== 'undefined' && !!(process.versions && process.versions.node);
  if (isNode) {
    const { createRequire } = await import('node:module');
    const require = createRequire(import.meta.url);
    _mod = require('../crypto/pkg-node/swap_xmr_crypto.js');
  } else {
    const mod = await import('../crypto/pkg-web/swap_xmr_crypto.js');
    await mod.default(opts.wasmUrl); // wasm-bindgen web init
    _mod = mod;
  }
  return _mod;
}

/** Parse the JSON returned by dleq_prove into {proof, secp, ed}. */
export function parseDleq(json) {
  const o = JSON.parse(json);
  if (!o.proof || !o.secp || !o.ed) throw new Error('bad dleq prove output');
  return o;
}
