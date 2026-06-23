// MWEB Phase 1 self-test runner (external so it works under the production CSP, which blocks inline scripts).
import * as mweb from './mweb.mjs';
const out = document.getElementById('out');
const hex = b => Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');
const line = (s, cls) => { const d=document.createElement('div'); if(cls)d.className=cls; d.textContent=s; out.appendChild(d); };
out.textContent='';
try {
  const t0 = performance.now();
  const r = mweb.selfTest();
  const dt = (performance.now()-t0).toFixed(0);
  if (r.ok) line('✓ ALL PASS  ('+dt+' ms)', 'ok');
  else { line('✗ FAIL  ('+dt+' ms)', 'bad'); r.fails.forEach(f => line('   • '+f, 'bad')); }
  // sample address from the BIP39 test seed, for eyeballing / cross-checking against Electrum-LTC
  const keys = mweb.masterKeysFromMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about','');
  const a0 = mweb.stealthAddress(keys, 0);
  line('');
  line('sample "abandon…about" seed, MWEB index 0:', 'dim');
  line('  scan  A₀ = '+hex(a0.Abytes), 'addr');
  line('  spend B₀ = '+hex(a0.Bbytes), 'addr');
  line('');
  line('NOTE: bit-exactness vs Litecoin consensus (compactSize framing, big-endian ints,', 'dim');
  line('the J generator) is only proven by a real testnet receive - generate a tmweb', 'dim');
  line('address, faucet it, and scan the raw block. Round-trip pass ≠ consensus match.', 'dim');
} catch(e){ line('✗ EXCEPTION: '+(e.message||e), 'bad'); line(String(e.stack||''), 'bad'); }
