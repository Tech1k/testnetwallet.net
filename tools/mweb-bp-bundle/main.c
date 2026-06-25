/* tools/mweb-bp-bundle/main.c
 *
 * Minimal Emscripten wrapper exposing ONE function: a 64-bit MWEB-compatible
 * ORIGINAL Bulletproof range-proof prover from secp256k1-zkp's bulletproofs module.
 *
 * Mirrors libmw Bulletproofs::Generate and ltcmweb/secp256k1 NewRangeProof exactly:
 *   secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, proof, &plen,
 *       tau_x=NULL, t_one=NULL, t_two=NULL, value[], min_value=NULL,
 *       blind[], commits=NULL, n_commits=1, value_gen=&secp256k1_generator_const_h,
 *       nbits=64, nonce, private_nonce, extra_commit, extra_commit_len, message)
 * with generators = secp256k1_bulletproof_generators_create(ctx, &G, 256).
 *
 * The 59-byte serialized MWEB OutputMessage is bound in as `extra`; `message` is the
 * 20-byte (zeroed) proof message. The node verifies with the SAME generators + extra,
 * so byte-exact reproduction is NOT required, only a valid proof - the random nonce
 * and private_nonce are supplied from JS (crypto.getRandomValues) so this stays a pure,
 * deterministic function of its inputs (easy to test).
 *
 * value is passed as a JS Number (double). Litoshi amounts (max ~8.4e15) are < 2^53,
 * so this is exact for every real amount. out must point to >= 675 writable bytes.
 *
 * Returns the proof length (675) on success, or 0 on failure.
 *
 * NOTE: verify the prove() argument list against the header you actually build
 * (include/secp256k1_bulletproofs.h) - forks occasionally reorder/rename; this matches
 * ltcmweb/secp256k1 and ltc-mweb/litecoin @ 0.21.
 */
#include <stdint.h>
#include <stddef.h>
#include "secp256k1.h"
#include "secp256k1_generator.h"
#include "secp256k1_commitment.h"
#include "secp256k1_bulletproofs.h"

static secp256k1_context* g_ctx = NULL;
static secp256k1_bulletproof_generators* g_gens = NULL;

static void bp_init(void) {
  if (g_ctx) return;
  g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  g_gens = secp256k1_bulletproof_generators_create(g_ctx, &secp256k1_generator_const_g, 256);
}

int bp_prove(double value_d,
             const unsigned char* blind32,
             const unsigned char* nonce32,
             const unsigned char* private_nonce32,
             const unsigned char* message20,
             const unsigned char* extra, int extra_len,
             unsigned char* out) {
  bp_init();
  if (g_ctx == NULL || g_gens == NULL) return 0;

  secp256k1_scratch_space* scratch = secp256k1_scratch_space_create(g_ctx, 1 << 15);
  if (scratch == NULL) return 0;

  uint64_t vals[1];
  vals[0] = (uint64_t) value_d;
  const unsigned char* blinds[1];
  blinds[0] = blind32;
  size_t plen = 675;

  int ok = secp256k1_bulletproof_rangeproof_prove(
      g_ctx, scratch, g_gens, out, &plen,
      NULL, NULL, NULL,                     /* tau_x, t_one, t_two (single-party prove) */
      vals, NULL,                           /* value[], min_value[] */
      blinds, NULL, 1,                      /* blind[], commits[], n_commits */
      &secp256k1_generator_const_h, 64,     /* value generator, nbits */
      nonce32, private_nonce32,
      extra, (size_t) extra_len, message20);

  secp256k1_scratch_space_destroy(g_ctx, scratch);
  return ok ? (int) plen : 0;
}
