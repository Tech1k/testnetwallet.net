// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-core: the cross-chain HTLC atomic-swap protocol for TestnetSwap.
 * One implementation of the crypto, two consumers: the wallet taker and the
 * maker daemon both import this. No UI, no server, no keys held here.
 *
 * Vendored deps (no build step, browser + Node): @scure/btc-signer, @noble.
 */
export * as btc from '../vendor/btc-signer.mjs';

export {
  LTC_TESTNET, BTC_TESTNET4, COINS, SUPPORTED_PAIRS, getCoin, isSupportedPair,
} from './networks.js';

export {
  DUST, MIN_RELAY_FEERATE, sha256, hash160, getPublicKey, randomSecret, secretHashOf,
  bytesToHex, hexToBytes, bytesEqual, assertBytes,
} from './crypto.js';

export {
  buildContract, parseContract, verifyContract, verifyFundedOutput,
} from './htlc.js';

export {
  buildRedeemTx, buildRefundTx, buildFundingTx, extractSecret, findSecretInWitness,
} from './tx.js';

export {
  SwapState, canTransition, isTerminal,
  DEFAULT_T1_HOURS, DEFAULT_T2_HOURS, MIN_T_GAP_SECS, MIN_T2_FROM_NOW_SECS,
  MAX_CLTV_TIME, MAX_SWAP_SECS,
  computeTimelocks, validateTimelocks,
  takerContractParams, makerContractParams, verifyMakerContract, verifyTakerContract,
} from './swap.js';

export {
  MsgType, build as buildMessage, validateMessage, parseMessage, serializeMessage, checkAcceptAgainstQuote,
} from './protocol.js';

export const VERSION = '0.1.0';
