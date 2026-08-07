// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr: native non-custodial BTC/LTC <-> Monero atomic swaps for TestnetSwap
 * (Gugger adaptor-signature construction). The cross-curve crypto core lives in
 * ../crypto (Rust -> WASM); this is the JS protocol/tx layer.
 *
 *   crypto.js: load + call the WASM crypto (DLEQ, adaptor sigs, key-share math)
 *   btcswap.js: the BTC/LTC tx suite (lock / redeem / cancel / refund / punish)
 *   swap.js: roles, timelock policy, state machine
 *   adapters.js / driver.js: Monero engine + swap driver (bob/alice roles); wired into
 *   the maker daemon (swap-maker) and the in-browser taker (testnetswap-site). See README.
 */
export { loadXmrCrypto, parseDleq } from './crypto.js';
export * as btcswap from './btcswap.js';
export * as monero from './monero.js';
export * as adaptorswap from './adaptorswap.js';
export * as driver from './driver.js';
export * as adapters from './adapters.js';
export {
  Role, assignRoles,
  MONERO_LOCK_BLOCKS, DEFAULT_T1_BLOCKS, DEFAULT_T2_BLOCKS, MIN_T_BLOCKS, MIN_T1_BLOCKS,
  defaultXmrTimelocks, validateXmrTimelocks, ORCHESTRATION_INVARIANTS,
  XmrSwapState, canTransition, isTerminal,
} from './swap.js';

export const VERSION = '0.0.1';
