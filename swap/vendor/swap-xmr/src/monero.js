// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-xmr/monero: the Monero side of the BTC/LTC <-> XMR swap.
 *
 *  - encodeAddress(): build a STANDARD Monero address string from a public spend
 *    point + public view point (monero-ts has no public-keys->address helper).
 *    The swap's lock address has pubSpend = S_a + S_b and pubView = V_a + V_b,
 *    which both parties compute from shares during setup (via the WASM crypto's
 *    ed_point_add); neither needs the combined PRIVATE spend key to know where
 *    to send the XMR.
 *  - The lock is a normal transfer to that address; the claimer later restores a
 *    wallet from the combined PRIVATE keys (s_a+s_b, v_a+v_b) and sweeps.
 *
 * monero-ts (WASM, Node + browser, remote daemon, no local monerod) handles the
 * wallet ops (lock / view-only detect / restore-and-sweep); this module owns the
 * address math + thin wrappers. Network bytes: mainnet 18, testnet 53, stagenet 24.
 */
import { keccak_256 } from '../vendor/noble-keccak.mjs';

const NET_BYTE = { mainnet: 18, testnet: 53, stagenet: 24 };
// monero-ts MoneroNetworkType: MAINNET 0, TESTNET 1, STAGENET 2
export const MONERO_NETWORK_TYPE = { mainnet: 0, testnet: 1, stagenet: 2 };

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
// chars produced per input block size 0..8 (Monero block-based base58)
const ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11];
const FULL_BLOCK = 8;
const FULL_ENCODED = 11;

const dec = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

function encodeBlock(data) {
  // big-endian integer of up to 8 bytes -> fixed number of base58 chars
  let num = 0n;
  for (const b of data) num = (num << 8n) | BigInt(b);
  const out = new Array(ENCODED_BLOCK_SIZES[data.length]).fill('1');
  let i = out.length - 1;
  while (num > 0n) { out[i--] = B58_ALPHABET[Number(num % 58n)]; num /= 58n; }
  return out.join('');
}

/** Monero block-based base58 encoding of a byte array. */
export function moneroBase58(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += FULL_BLOCK) out += encodeBlock(bytes.subarray(i, i + FULL_BLOCK));
  return out;
}

/**
 * Build a standard Monero address from compressed public spend + view points.
 * @param {object} p { pubSpendHex (32B), pubViewHex (32B), network: 'testnet'|'stagenet'|'mainnet' }
 */
export function encodeAddress({ pubSpendHex, pubViewHex, network = 'testnet' }) {
  const netByte = NET_BYTE[network];
  if (netByte === undefined) throw new Error('unknown network ' + network);
  const spend = dec(pubSpendHex), view = dec(pubViewHex);
  if (spend.length !== 32 || view.length !== 32) throw new Error('public keys must be 32 bytes');
  const data = new Uint8Array(1 + 32 + 32);
  data[0] = netByte; data.set(spend, 1); data.set(view, 33);
  const checksum = keccak_256(data).slice(0, 4);
  const full = new Uint8Array(data.length + 4);
  full.set(data); full.set(checksum, data.length);
  return moneroBase58(full);
}

/**
 * The swap's shared lock address: pubSpend = S_a + S_b, pubView = V_a + V_b.
 * @param {object} x   the WASM crypto module (for ed_point_add)
 */
export function lockAddress(x, { spendShareAHex, spendShareBHex, viewShareAHex, viewShareBHex, network = 'testnet' }) {
  const pubSpendHex = x.ed_point_add(spendShareAHex, spendShareBHex);
  const pubViewHex = x.ed_point_add(viewShareAHex, viewShareBHex);
  return { address: encodeAddress({ pubSpendHex, pubViewHex, network }), pubSpendHex, pubViewHex };
}

/**
 * The combined PRIVATE keys the claimer uses to restore + sweep (s_a+s_b, v_a+v_b).
 * @param {object} x   the WASM crypto module (for ed_scalar_add)
 */
export function combinedPrivateKeys(x, { spendSecretAHex, spendSecretBHex, viewSecretAHex, viewSecretBHex }) {
  return {
    privateSpendKey: x.ed_scalar_add(spendSecretAHex, spendSecretBHex),
    privateViewKey: x.ed_scalar_add(viewSecretAHex, viewSecretBHex),
  };
}

// ---- monero-ts wallet ops (require monero-ts + a remote daemon) ----

/**
 * Restore a wallet from the combined private keys and sweep the locked XMR to
 * `destAddress`. Used by the claimer once it has learned the counterparty's share.
 * @param {object} moneroTs  the imported monero-ts module
 */
export async function restoreAndSweep(moneroTs, {
  network = 'testnet', privateSpendKey, privateViewKey, primaryAddress, restoreHeight, server, destAddress,
}) {
  const wallet = await moneroTs.createWalletFull({
    networkType: MONERO_NETWORK_TYPE[network],
    privateSpendKey, privateViewKey, primaryAddress, restoreHeight, server,
  });
  try {
    await wallet.sync();
    if ((await wallet.getUnlockedBalance()) <= 0n) throw new Error('restoreAndSweep: no unlocked balance (funds NOT swept)');
    const txs = await wallet.sweepUnlocked({ address: destAddress, relay: true });
    const ids = txs.map((t) => t.getHash());
    if (!ids.length) throw new Error('restoreAndSweep produced no transactions');
    return ids;
  } finally { await wallet.close(); }
}

/**
 * Build a view-only wallet (shared private view key) to detect/confirm the locked
 * output at the combined address before acting on it.
 */
export async function viewOnlyBalance(moneroTs, { network = 'testnet', primaryAddress, privateViewKey, restoreHeight, server }) {
  const wallet = await moneroTs.createWalletFull({
    networkType: MONERO_NETWORK_TYPE[network], primaryAddress, privateViewKey, restoreHeight, server,
  });
  await wallet.sync();
  const balance = await wallet.getBalance();
  const unlocked = await wallet.getUnlockedBalance();
  await wallet.close();
  return { balance: balance.toString(), unlocked: unlocked.toString() };
}
