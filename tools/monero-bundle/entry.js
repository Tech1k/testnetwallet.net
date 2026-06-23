// Bundle entry: re-export the whole monero-ts API as the UMD library "moneroTs".
// webpack turns this (plus monero-ts and the browser polyfills) into vendor/monero-engine.bundle.js,
// which the no-build wallet lazy-loads. The web worker (monero.worker.js) is copied alongside it.
export * from "monero-ts";
