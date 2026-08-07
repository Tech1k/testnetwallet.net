// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-core/networks: chain parameters for the two secp256k1 UTXO chains
 * TestnetSwap supports: Bitcoin testnet4 (tBTC) and Litecoin testnet (tLTC).
 *
 * These mirror the values TestnetWallet uses (app.js), so a contract address
 * built here is identical to one the wallet would build. Address/tx building
 * uses `network`; the `api`/`explorer` defaults are conveniences for the maker
 * and CLI (the wallet and the maker both allow overriding the endpoint).
 */
import * as btc from '../vendor/btc-signer.mjs';

// Litecoin testnet params (not shipped by @scure/btc-signer). Same as TestnetWallet.
export const LTC_TESTNET = {
  bech32: 'tltc',
  pubKeyHash: 0x6f,
  scriptHash: 0x3a,
  wif: 0xef,
  bip32: { public: 0x043587cf, private: 0x04358394 },
};

// Bitcoin testnet4 uses the standard testnet params shipped by the library.
export const BTC_TESTNET4 = btc.TEST_NETWORK;

export const COINS = {
  tBTC: {
    ticker: 'tBTC',
    name: 'Bitcoin testnet4',
    network: BTC_TESTNET4,
    api: 'https://mempool.space/testnet4/api',
    explorer: 'https://testnetscan.com/btc-testnet4',
    blockSecs: 600, // ~10 min nominal; testnet is irregular (see timelock notes)
  },
  tLTC: {
    ticker: 'tLTC',
    name: 'Litecoin testnet',
    network: LTC_TESTNET,
    api: 'https://testnetscan.com/ltc-testnet/api',
    explorer: 'https://testnetscan.com/ltc-testnet',
    blockSecs: 150, // ~2.5 min nominal
  },
};

export const SUPPORTED_PAIRS = [
  { from: 'tLTC', to: 'tBTC' },
  { from: 'tBTC', to: 'tLTC' },
];

export function getCoin(ticker) {
  const c = COINS[ticker];
  if (!c) throw new Error(`Unknown coin: ${ticker}`);
  return c;
}

export function isSupportedPair(from, to) {
  return SUPPORTED_PAIRS.some((p) => p.from === from && p.to === to);
}
