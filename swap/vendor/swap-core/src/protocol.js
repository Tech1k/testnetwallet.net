// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * swap-core/protocol: the line-delimited JSON messages exchanged between a taker
 * session and the maker, over the WSS relay. The relay is a dumb pipe; it never
 * inspects or holds these; it just routes them. swap-core owns the message shapes
 * and validation so both consumers (wallet taker, maker daemon) agree byte-for-byte.
 *
 * Byte-valued fields (pubkeys, secret hash) travel as hex strings. Amounts travel
 * as integer satoshis (`*_sats`) to avoid floating-point drift on the wire.
 *
 * Flow:
 *   taker -> maker : request_quote { from, to, send_sats }
 *   maker -> taker : quote { from, to, send_sats, recv_sats, rate, min_sats, max_sats,
 *                            t1_hours, t2_hours, quote_id, expiry }
 *   taker -> maker : initiate { quote_id, from, to, send_sats,
 *                               secret_hash, taker_recv_pubkey, taker_refund_pubkey }
 *   maker -> taker : accept { quote_id, recv_sats, t1, t2,
 *                             maker_recv_pubkey, maker_refund_pubkey }
 *   taker -> maker : taker_locked { quote_id, contract_addr, fund_txid, vout, t1 }
 *   maker -> taker : maker_locked { quote_id, contract_addr, fund_txid, vout, t2 }
 *   (then taker redeems on-chain revealing S; maker extracts S and redeems)
 *   (any)          : abort { quote_id?, reason }
 */

import { MIN_T_GAP_SECS, MAX_CLTV_TIME, MAX_SWAP_SECS, validateTimelocks } from './swap.js';
import { isSupportedPair } from './networks.js';

const CLTV_THRESHOLD = 500000000;             // >= this = time-based CLTV (BIP65); we require time-based
const MAX_MONEY_SATS = 2_100_000_000_000_000; // 21M coins in sats; generous sanity cap
const DUST = 546;                             // outputs below this are unspendable

export const MsgType = {
  REQUEST_QUOTE: 'request_quote',
  QUOTE: 'quote',
  INITIATE: 'initiate',
  ACCEPT: 'accept',
  TAKER_LOCKED: 'taker_locked',
  MAKER_LOCKED: 'maker_locked',
  ABORT: 'abort',
  ERROR: 'error',
};

const HEX = /^[0-9a-fA-F]+$/;
const isHex = (s, bytes) => typeof s === 'string' && HEX.test(s) && s.length === bytes * 2;
const isPubkey = (s) => isHex(s, 33);
const isHash = (s) => isHex(s, 32);
const isTicker = (s) => s === 'tBTC' || s === 'tLTC';
const isPosInt = (n) => Number.isInteger(n) && n > 0;
// amounts: positive, safe-integer (no precision loss), within a sane money cap
const isAmount = (n) => Number.isSafeInteger(n) && n > 0 && n <= MAX_MONEY_SATS;
const isTxid = (s) => typeof s === 'string' && /^[0-9a-fA-F]{64}$/.test(s);

// ---- builders (do not normalize bytes; callers pass hex strings) ----

export const build = {
  requestQuote: ({ from, to, sendSats }) => ({ type: MsgType.REQUEST_QUOTE, from, to, send_sats: sendSats }),
  quote: ({ from, to, sendSats, recvSats, rate, minSats, maxSats, t1Hours, t2Hours, quoteId, expiry }) => ({
    type: MsgType.QUOTE, from, to, send_sats: sendSats, recv_sats: recvSats, rate,
    min_sats: minSats, max_sats: maxSats, t1_hours: t1Hours, t2_hours: t2Hours, quote_id: quoteId, expiry,
  }),
  initiate: ({ quoteId, from, to, sendSats, secretHash, takerRecvPubkey, takerRefundPubkey }) => ({
    type: MsgType.INITIATE, quote_id: quoteId, from, to, send_sats: sendSats,
    secret_hash: secretHash, taker_recv_pubkey: takerRecvPubkey, taker_refund_pubkey: takerRefundPubkey,
  }),
  accept: ({ quoteId, from, to, sendSats, recvSats, t1, t2, makerRecvPubkey, makerRefundPubkey }) => ({
    type: MsgType.ACCEPT, quote_id: quoteId, from, to, send_sats: sendSats, recv_sats: recvSats, t1, t2,
    maker_recv_pubkey: makerRecvPubkey, maker_refund_pubkey: makerRefundPubkey,
  }),
  takerLocked: ({ quoteId, contractAddr, fundTxid, vout, t1 }) => ({
    type: MsgType.TAKER_LOCKED, quote_id: quoteId, contract_addr: contractAddr, fund_txid: fundTxid, vout, t1,
  }),
  makerLocked: ({ quoteId, contractAddr, fundTxid, vout, t2 }) => ({
    type: MsgType.MAKER_LOCKED, quote_id: quoteId, contract_addr: contractAddr, fund_txid: fundTxid, vout, t2,
  }),
  abort: ({ quoteId, reason }) => ({ type: MsgType.ABORT, quote_id: quoteId, reason: String(reason || 'aborted') }),
  error: ({ quoteId, reason }) => ({ type: MsgType.ERROR, quote_id: quoteId, reason: String(reason || 'error') }),
};

// ---- validation ----

/** Validate a parsed message object. Returns {ok:true} or {ok:false, reason}. */
export function validateMessage(m) {
  if (!m || typeof m !== 'object' || typeof m.type !== 'string') return bad('missing type');
  switch (m.type) {
    case MsgType.REQUEST_QUOTE:
      if (!isTicker(m.from) || !isTicker(m.to) || m.from === m.to || !isSupportedPair(m.from, m.to)) return bad('bad pair');
      if (!isAmount(m.send_sats)) return bad('send_sats must be a sane positive integer (sats)');
      return ok();
    case MsgType.QUOTE:
      if (!isTicker(m.from) || !isTicker(m.to) || m.from === m.to || !isSupportedPair(m.from, m.to)) return bad('bad pair');
      if (!isAmount(m.send_sats) || !isAmount(m.recv_sats)) return bad('amounts must be sane positive integers (sats)');
      if (m.recv_sats < DUST) return bad('recv_sats below dust');
      if (!(typeof m.rate === 'number' && Number.isFinite(m.rate) && m.rate > 0)) return bad('rate must be a positive finite number');
      if (m.min_sats != null && !isAmount(m.min_sats)) return bad('min_sats invalid');
      if (m.max_sats != null && !isAmount(m.max_sats)) return bad('max_sats invalid');
      if (!(Number.isFinite(m.t1_hours) && Number.isFinite(m.t2_hours) && m.t1_hours > 0 && m.t2_hours > 0)) return bad('t1_hours/t2_hours must be positive');
      if (!(m.t2_hours < m.t1_hours)) return bad('t2_hours must be < t1_hours');
      if (m.t1_hours * 3600 > MAX_SWAP_SECS) return bad(`t1_hours exceeds the ${Math.round(MAX_SWAP_SECS / 3600)}h maximum`);
      if (typeof m.quote_id !== 'string' || !m.quote_id) return bad('quote_id required');
      return ok();
    case MsgType.INITIATE:
      if (typeof m.quote_id !== 'string' || !m.quote_id) return bad('quote_id required');
      if (!isTicker(m.from) || !isTicker(m.to) || m.from === m.to || !isSupportedPair(m.from, m.to)) return bad('bad pair');
      if (!isAmount(m.send_sats)) return bad('send_sats must be a sane positive integer (sats)');
      if (!isHash(m.secret_hash)) return bad('secret_hash must be 32-byte hex');
      if (!isPubkey(m.taker_recv_pubkey)) return bad('taker_recv_pubkey must be 33-byte hex');
      if (!isPubkey(m.taker_refund_pubkey)) return bad('taker_refund_pubkey must be 33-byte hex');
      return ok();
    case MsgType.ACCEPT:
      if (typeof m.quote_id !== 'string' || !m.quote_id) return bad('quote_id required');
      if (!isTicker(m.from) || !isTicker(m.to) || m.from === m.to || !isSupportedPair(m.from, m.to)) return bad('bad pair');
      if (!isAmount(m.send_sats)) return bad('send_sats must be a sane positive integer (sats)');
      if (!isAmount(m.recv_sats)) return bad('recv_sats must be a sane positive integer (sats)');
      if (m.recv_sats < DUST) return bad('recv_sats below dust');
      if (!isPosInt(m.t1) || !isPosInt(m.t2)) return bad('t1/t2 must be positive integers');
      // Require time-based CLTV (the project default) and the safety gap. This is
      // a stateless floor; the consumer MUST still run validateTimelocks with the
      // current time (T2 recency) and verify the on-chain locktime before funding.
      if (m.t1 < CLTV_THRESHOLD || m.t2 < CLTV_THRESHOLD) return bad('t1/t2 must be time-based CLTV (unix seconds)');
      // Fail-closed upper bound: reject an out-of-range locktime that would build a
      // 6-byte (BIP65-invalid) CLTV operand and strand the funding party's coins.
      if (m.t1 > MAX_CLTV_TIME || m.t2 > MAX_CLTV_TIME) return bad('t1/t2 exceed the max CLTV timestamp');
      if (!(m.t2 < m.t1)) return bad('t2 must be < t1');
      if (m.t1 - m.t2 < MIN_T_GAP_SECS) return bad(`t1 must exceed t2 by at least ${MIN_T_GAP_SECS}s`);
      if (!isPubkey(m.maker_recv_pubkey)) return bad('maker_recv_pubkey must be 33-byte hex');
      if (!isPubkey(m.maker_refund_pubkey)) return bad('maker_refund_pubkey must be 33-byte hex');
      return ok();
    case MsgType.TAKER_LOCKED:
    case MsgType.MAKER_LOCKED: {
      const t = m.type === MsgType.TAKER_LOCKED ? 't1' : 't2';
      if (typeof m.quote_id !== 'string' || !m.quote_id) return bad('quote_id required');
      if (typeof m.contract_addr !== 'string' || !m.contract_addr) return bad('contract_addr required');
      if (!isTxid(m.fund_txid)) return bad('fund_txid must be a 64-char hex');
      if (!Number.isInteger(m.vout) || m.vout < 0) return bad('vout must be a non-negative integer');
      if (!isPosInt(m[t])) return bad(`${t} must be a positive integer`);
      return ok();
    }
    case MsgType.ABORT:
    case MsgType.ERROR:
      return ok();
    default:
      return bad(`unknown type: ${m.type}`);
  }
}

const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

export function parseMessage(line) {
  let m;
  try { m = JSON.parse(line); } catch { return { ok: false, reason: 'invalid JSON' }; }
  if (!m || typeof m !== 'object') return { ok: false, reason: 'not an object' };
  // Reject prototype-pollution keys so downstream spread/merge of a received
  // message can't be abused; the relay and counterparty are untrusted.
  for (const k of DANGEROUS_KEYS) if (Object.prototype.hasOwnProperty.call(m, k)) return { ok: false, reason: `forbidden key: ${k}` };
  const v = validateMessage(m);
  if (!v.ok) return v;
  return { ok: true, msg: m };
}

/**
 * Cross-message integrity check the taker MUST run on the maker's ACCEPT against
 * the QUOTE it accepted (validateMessage is stateless and cannot do this). Binds
 * quote_id and recv_sats, and re-checks the timelock safety with the current time.
 * NOTE: this does not replace the on-chain checks; the taker must still verify
 * the maker's funded output (amount + scriptPubKey) before revealing the secret.
 */
export function checkAcceptAgainstQuote(quote, accept, nowSec) {
  if (!quote || !accept) return bad('missing quote or accept');
  if (accept.quote_id !== quote.quote_id) return bad('quote_id mismatch');
  if (accept.from !== quote.from || accept.to !== quote.to) return bad('pair mismatch (accept vs quote)');
  if (accept.send_sats !== quote.send_sats)
    return bad(`send_sats mismatch (quoted ${quote.send_sats}, accepted ${accept.send_sats})`);
  if (accept.recv_sats !== quote.recv_sats)
    return bad(`recv_sats mismatch (quoted ${quote.recv_sats}, accepted ${accept.recv_sats})`);
  const tl = validateTimelocks({ t1: accept.t1, t2: accept.t2, nowSec });
  if (!tl.ok) return bad(`unsafe timelocks: ${tl.reason}`);
  // L2: bind the accepted absolute timelocks to the QUOTED durations; the maker must not
  // silently compress the refund window the taker agreed to (allow 20% slack for clock skew).
  if (quote.t1_hours != null && (accept.t1 - nowSec) < quote.t1_hours * 3600 * 0.8)
    return bad(`t1 shorter than quoted (~${quote.t1_hours}h, got ${((accept.t1 - nowSec) / 3600).toFixed(1)}h)`);
  if (quote.t2_hours != null && (accept.t2 - nowSec) < quote.t2_hours * 3600 * 0.8)
    return bad(`t2 shorter than quoted (~${quote.t2_hours}h, got ${((accept.t2 - nowSec) / 3600).toFixed(1)}h)`);
  // Also cap the UPPER side: a maker must not inflate t1 into a far-future locktime that
  // strands the taker's refund. Allow up to 2x the quoted duration for clock skew / rounding.
  // (validateTimelocks above already enforces the absolute MAX_SWAP_SECS / MAX_CLTV_TIME bounds.)
  if (quote.t1_hours != null && (accept.t1 - nowSec) > quote.t1_hours * 3600 * 2)
    return bad(`t1 longer than quoted (~${quote.t1_hours}h, got ${((accept.t1 - nowSec) / 3600).toFixed(1)}h)`);
  if (quote.t2_hours != null && (accept.t2 - nowSec) > quote.t2_hours * 3600 * 2)
    return bad(`t2 longer than quoted (~${quote.t2_hours}h, got ${((accept.t2 - nowSec) / 3600).toFixed(1)}h)`);
  return ok();
}

export function serializeMessage(m) {
  const v = validateMessage(m);
  if (!v.ok) throw new Error(`refusing to serialize invalid message: ${v.reason}`);
  return JSON.stringify(m);
}

function ok() { return { ok: true }; }
function bad(reason) { return { ok: false, reason }; }
