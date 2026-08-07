// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Minimal `Buffer` global shim for the browser. The swap-xmr toolkit uses
 * `Buffer.from(...)` in a few hex<->bytes helpers (call-time only). Node already
 * has Buffer; browsers don't. Importing this installs the global if missing.
 * Matches Node Buffer semantics for the toolkit's usage (hex parse, toString hex,
 * reverse, Uint8Array.from, concat); throws on malformed input rather than the
 * silent coercions Node does, so divergence is loud.
 */
class HexBytes extends Uint8Array {
  toString(enc) {
    if (enc === 'hex') {
      let s = '';
      for (let i = 0; i < this.length; i++) s += this[i].toString(16).padStart(2, '0');
      return s;
    }
    if (!enc || enc === 'utf8' || enc === 'utf-8') return new TextDecoder().decode(this);
    throw new Error('Buffer shim: unsupported encoding ' + enc);
  }
}

function bfrom(a, enc) {
  if (typeof a === 'string') {
    if (enc === 'hex') {
      if (a.length % 2 !== 0) throw new Error('Buffer shim: odd-length hex');
      if (!/^[0-9a-fA-F]*$/.test(a)) throw new Error('Buffer shim: invalid hex'); // catches a bad SECOND nibble too (parseInt would not)
      const out = new HexBytes(a.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(a.substr(i * 2, 2), 16);
      return out;
    }
    return new HexBytes(new TextEncoder().encode(a)); // default utf8
  }
  if (a instanceof ArrayBuffer) return new HexBytes(a);
  return HexBytes.from(a); // Uint8Array / array-like -> copy
}

if (typeof globalThis.Buffer === 'undefined') {
  globalThis.Buffer = {
    from: bfrom,
    alloc: (n) => new HexBytes(n),
    isBuffer: (x) => x instanceof Uint8Array,
    concat: (list) => {
      let len = 0; for (const u of list) len += u.length;
      const out = new HexBytes(len); let off = 0;
      for (const u of list) { out.set(u, off); off += u.length; }
      return out;
    },
  };
}
