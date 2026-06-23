// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Monero engine (Phase 3): a lazy wrapper around the bundled monero-ts (vendor/monero-engine.bundle.js).
 * Self-custodial, direct-to-node - scanning AND signing run locally in WebAssembly (a web worker); the
 * node only serves blocks and relays. The ~6 MB bundle is fetched only when a Monero balance/send is
 * first requested, so BTC/LTC users never download it.
 *
 * Build the bundle once with tools/monero-bundle (npm install && npm run build). Until it exists,
 * load() rejects with a clear message and nothing else in the wallet is affected.
 */
let _ts = null, _loading = null;

export function isLoaded(){ return !!_ts; }

/* Lazy-load the UMD bundle (global `moneroTs`) and point it at the vendored worker. */
export function load(){
  if(_ts) return Promise.resolve(_ts);
  if(_loading) return _loading;
  _loading = new Promise((resolve, reject) => {
    if(self.moneroTs) return finish(self.moneroTs, resolve, reject);
    const s = document.createElement('script');
    s.src = 'vendor/monero-engine.bundle.js';
    s.async = true;
    s.onload = () => self.moneroTs
      ? finish(self.moneroTs, resolve, reject)
      : reject(new Error('monero-engine.bundle.js loaded but global moneroTs is missing'));
    s.onerror = () => reject(new Error('Monero engine not built yet - run tools/monero-bundle (npm install && npm run build).'));
    document.head.appendChild(s);
  });
  return _loading;
}
function finish(m, resolve, reject){
  try { m.LibraryUtils.setWorkerDistPath('vendor/monero.worker.js'); _ts = m; resolve(m); }
  catch(e){ reject(e); }
}

const netType = (m, network) => network === 'testnet' ? m.MoneroNetworkType.TESTNET : m.MoneroNetworkType.STAGENET;

/* Current chain height of the node. Uses the plain /get_height endpoint (fast, no engine load, no connect quirks);
 * falls back to monero-ts. Returns 0 on failure so the caller can apply its own floor. */
export async function getDaemonHeight(nodeUrl){
  const base = String(nodeUrl).replace(/\/+$/, '');
  try {
    const r = await fetch(base + '/get_height', { method: 'GET' });
    if(r.ok){ const j = await r.json(); if(j && j.height) return Number(j.height); }
  } catch(_){}
  try { const m = await load(); const d = await m.connectToDaemonRpc(nodeUrl); return Number(await d.getHeight()); }
  catch(_){ return 0; }
}

/* Lightweight node status via the plain /get_info endpoint (no engine load): is the node reachable, what
 * height is it at, is the node itself synced, and which network is it. Returns
 * { ok, height, targetHeight, synchronized, nettype, status } - ok:false (height 0) when it can't be reached.
 * Both /get_info and /get_height are permitted on a restricted-RPC node, so no privileged access is needed. */
export async function getDaemonInfo(nodeUrl){
  const base = String(nodeUrl).replace(/\/+$/, '');
  try {
    const r = await fetch(base + '/get_info', { method: 'GET' });
    if(r.ok){ const j = await r.json();
      if(j && j.height != null) return { ok:true, height:Number(j.height), targetHeight:Number(j.target_height || 0),
        synchronized: j.synchronized !== false, nettype: j.nettype || '', status: j.status || '' }; }
  } catch(_){}
  try {   // /get_info blocked or down: fall back to /get_height for at least the tip (no engine load)
    const r = await fetch(base + '/get_height', { method: 'GET' });
    if(r.ok){ const j = await r.json(); if(j && j.height) return { ok:true, height:Number(j.height), targetHeight:0, synchronized:true, nettype:'', status:'' }; }
  } catch(_){}
  return { ok:false, height:0, targetHeight:0, synchronized:false, nettype:'', status:'' };
}

/* Open a (view+spend) wallet directly against the node. Returns a monero-ts wallet handle on which the
 * caller drives wallet.getBalance() [atomic units, 1e12 = 1 XMR], wallet.getTxs(),
 * wallet.createTxs({...}) and wallet.relayTx(tx). */
export async function openFromKeys({ network, nodeUrl, primaryAddress, privateViewKey, privateSpendKey, restoreHeight }){
  const m = await load();
  return m.createWalletFull({
    networkType: netType(m, network),
    server: { uri: nodeUrl },
    primaryAddress, privateViewKey, privateSpendKey,
    restoreHeight: restoreHeight ?? 0,
    password: '',                       // empty password; lets getData()/openSaved() round-trip the cache
  });
}

/* Reopen a previously-synced wallet from its saved keys+cache so sync only scans NEW blocks. */
export async function openSaved({ network, nodeUrl, keysData, cacheData }){
  const m = await load();
  return m.openWalletFull({ networkType: netType(m, network), server: { uri: nodeUrl }, keysData, cacheData, password: '' });
}
/* Wallet keys+cache for persistence. Returns [keysData, cacheData] (Uint8Arrays). */
export async function getData(wallet){ return wallet.getData(); }

/* Build a transfer (relay=false). destinations: [{ address, amount(bigint piconero) }]; priority: 0..3 (or undefined). */
export async function createTx(wallet, { accountIndex = 0, destinations, priority }){
  const config = { accountIndex, destinations, relay: false };
  if(priority != null) config.priority = priority;
  return wallet.createTx(config);
}
export async function relay(wallet, tx){ return wallet.relayTx(tx); }

/* Sweep ALL unlocked funds in an account to one address (send-max). Returns the built (unrelayed) txs;
 * a sweep can split into several txs, so the caller sums amounts/fees and relays them all. */
export async function sweep(wallet, address, { accountIndex = 0, priority } = {}){
  const config = { accountIndex, address, relay: false };
  if(priority != null) config.priority = priority;
  const txs = await wallet.sweepUnlocked(config);
  return Array.isArray(txs) ? txs : (txs ? [txs] : []);
}

/* Coin control: list outputs (plain views), and freeze/thaw by key-image hex. */
export async function getOutputs(wallet){
  const outs = await wallet.getOutputs();
  return (outs || []).map(o => {
    const g = (n, d) => { try { const f = o['get'+n]; const v = f ? f.call(o) : undefined; return v==null?d:v; } catch(_){ return d; } };
    const ki = g('KeyImage', null), kiHex = ki && ki.getHex ? ki.getHex() : (ki && ki.hex) || '';
    const amt = g('Amount', 0n);
    return {
      amount: (typeof amt === 'bigint') ? amt : BigInt(amt || 0),
      keyImage: kiHex,
      accountIndex: Number(g('AccountIndex', 0) || 0),
      subaddressIndex: Number(g('SubaddressIndex', 0) || 0),
      spent: !!g('IsSpent', false),
      frozen: !!g('IsFrozen', false),
      locked: !!g('IsLocked', false),
    };
  });
}
export async function freezeOutput(wallet, keyImageHex){ return wallet.freezeOutput(keyImageHex); }
export async function thawOutput(wallet, keyImageHex){ return wallet.thawOutput(keyImageHex); }

/* Accounts: list (with per-account balances), create, and label. */
export async function getAccounts(wallet){
  const accts = await wallet.getAccounts();
  return (accts || []).map(a => {
    const g = (n, d) => { try { const f = a['get'+n]; const v = f ? f.call(a) : undefined; return v==null?d:v; } catch(_){ return d; } };
    const big = v => (typeof v==='bigint') ? v : (v!=null ? BigInt(v) : 0n);
    return { index: Number(g('Index', 0) || 0), label: g('Label', '') || '', balance: big(g('Balance', 0n)), unlocked: big(g('UnlockedBalance', 0n)) };
  });
}
export async function createAccount(wallet, label){ const a = await wallet.createAccount(label || undefined); return a && a.getIndex ? a.getIndex() : null; }
/* Relay one tx or an array of txs; returns the array of tx hashes. */
export async function relayAll(wallet, txs){
  const list = Array.isArray(txs) ? txs : [txs];
  const hashes = [];
  for(const tx of list) hashes.push(await wallet.relayTx(tx));
  return hashes;
}

/* Sign a message with the wallet's spend key (default) or view key. Returns the signature string. */
export async function signMessage(wallet, message, withViewKey){
  const m = await load();
  const type = withViewKey ? m.MoneroMessageSignatureType.SIGN_WITH_VIEW_KEY : m.MoneroMessageSignatureType.SIGN_WITH_SPEND_KEY;
  return wallet.signMessage(message, type, 0, 0);
}
/* Verify a Monero signed message against an address. Returns { good, viewKey } (viewKey = signed with the view key). */
export async function verifyMessage(wallet, message, address, signature){
  const m = await load();
  const res = await wallet.verifyMessage(message, address, signature);
  const good = !!(res && res.getIsGood && res.getIsGood());
  let viewKey = null;
  try { viewKey = res.getSignatureType && res.getSignatureType() === m.MoneroMessageSignatureType.SIGN_WITH_VIEW_KEY; } catch(_){}
  return { good, viewKey };
}

const bigOf = v => (typeof v === 'bigint') ? v : (v != null ? BigInt(v) : 0n);

/* Payment proof (tx proof): prove this wallet sent a tx paying `address`. Returns the proof signature. */
export async function getTxProof(wallet, txHash, address, message){ return wallet.getTxProof(txHash, address, message || ''); }
/* Check a payment proof. Returns { good, inPool, confirmations, received(bigint piconero) }. */
export async function checkTxProof(wallet, txHash, address, message, signature){
  const res = await wallet.checkTxProof(txHash, address, message || '', signature);
  return {
    good: !!(res && res.getIsGood && res.getIsGood()),
    inPool: !!(res && res.getInTxPool && res.getInTxPool()),
    confirmations: Number((res && res.getNumConfirmations && res.getNumConfirmations()) || 0),
    received: bigOf(res && res.getReceivedAmount && res.getReceivedAmount()),
  };
}

/* Spend proof: prove this wallet authored a tx, WITHOUT revealing the recipient. */
export async function getSpendProof(wallet, txHash, message){ return wallet.getSpendProof(txHash, message || ''); }
export async function checkSpendProof(wallet, txHash, message, signature){ return !!(await wallet.checkSpendProof(txHash, message || '', signature)); }

/* Reserve proof: prove control of the wallet's unlocked balance, WITHOUT revealing addresses. */
export async function getReserveProof(wallet, message){ return wallet.getReserveProofWallet(message || ''); }
/* Check a reserve proof against the prover's address. Returns { good, total, spent } (bigint piconero). */
export async function checkReserveProof(wallet, address, message, signature){
  const res = await wallet.checkReserveProof(address, message || '', signature);
  return {
    good: !!(res && res.getIsGood && res.getIsGood()),
    total: bigOf(res && res.getTotalAmount && res.getTotalAmount()),
    spent: bigOf(res && res.getUnconfirmedSpentAmount && res.getUnconfirmedSpentAmount()),
  };
}

/* Tx key: export a tx's private key; verify a payment to `address` with it. */
export async function getTxKey(wallet, txHash){ return wallet.getTxKey(txHash); }
export async function checkTxKey(wallet, txHash, txKey, address){
  const res = await wallet.checkTxKey(txHash, txKey, address);
  return {
    good: !!(res && res.getIsGood && res.getIsGood()),
    inPool: !!(res && res.getInTxPool && res.getInTxPool()),
    confirmations: Number((res && res.getNumConfirmations && res.getNumConfirmations()) || 0),
    received: bigOf(res && res.getReceivedAmount && res.getReceivedAmount()),
  };
}

/* Integrated address: combine a standard address with a payment ID (args optional → wallet primary + random id). */
export async function makeIntegratedAddress(wallet, standardAddress, paymentId){
  const ia = await wallet.getIntegratedAddress(standardAddress || undefined, paymentId || undefined);
  return { integrated: ia && ia.getIntegratedAddress ? ia.getIntegratedAddress() : String(ia),
           standard: ia && ia.getStandardAddress ? ia.getStandardAddress() : '',
           paymentId: ia && ia.getPaymentId ? ia.getPaymentId() : '' };
}
export async function decodeIntegratedAddress(wallet, integratedAddress){
  const ia = await wallet.decodeIntegratedAddress(integratedAddress);
  return { standard: ia && ia.getStandardAddress ? ia.getStandardAddress() : '',
           paymentId: ia && ia.getPaymentId ? ia.getPaymentId() : '',
           integrated: ia && ia.getIntegratedAddress ? ia.getIntegratedAddress() : integratedAddress };
}

/* Scan the chain. Pass startHeight to force the sync to begin there (avoids walking hashes from genesis).
 * onProgress(percentDone 0..1, height, endHeight, startHeight) fires during the scanning phase. */
export async function sync(wallet, onProgress, startHeight){
  const m = await load();
  const listener = new (class extends m.MoneroWalletListener {
    async onSyncProgress(height, startHeight2, endHeight, percentDone, message){ try { onProgress && onProgress(percentDone, height, endHeight, startHeight2); } catch(_){} }
  })();
  if(startHeight != null) await wallet.sync(listener, startHeight);
  else await wallet.sync(listener);
  return wallet;
}
