// One-time browser bundle of monero-ts for the no-build TestnetWallet.
// Closely mirrors the official sample: https://github.com/woodser/xmr-sample-webpack
// Output: ../../vendor/monero-engine.bundle.js  (UMD, global `moneroTs`)
//         ../../vendor/monero.worker.js          (the wallet web worker, copied from monero-ts/dist)
const path = require("path");
const webpack = require("webpack");
const CopyPlugin = require("copy-webpack-plugin");

const VENDOR = path.resolve(__dirname, "..", "..", "vendor");
const MONERO_DIST = path.dirname(require.resolve("monero-ts/package.json")) + "/dist";

module.exports = {
  mode: "production",
  entry: "./entry.js",
  output: {
    path: VENDOR,
    filename: "monero-engine.bundle.js",
    library: { name: "moneroTs", type: "umd" },
    globalObject: "self",          // so the same bundle works on the main thread and in a worker
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: path.join(__dirname, "node_modules"),
        type: "javascript/auto",
        use: [{ loader: "babel-loader", options: { presets: ["@babel/preset-env"], cacheDirectory: false } }],
      },
    ],
  },
  devtool: false,
  externals: ["worker_threads", "ws", "perf_hooks", "child_process"],   // node-only; not used in the browser path
  plugins: [
    // newer memfs imports node:buffer / node:events / node:path / node:stream - strip the scheme so the polyfills below resolve
    new webpack.NormalModuleReplacementPlugin(/^node:/, (resource) => { resource.request = resource.request.replace(/^node:/, ""); }),
    new webpack.ProvidePlugin({ process: "process/browser", Buffer: ["buffer", "Buffer"] }),
    new CopyPlugin({ patterns: [
      { from: path.join(MONERO_DIST, "monero.worker.js"), to: path.join(VENDOR, "monero.worker.js") },
      // also copy the worker's third-party license notices (upstream ships them; the bare placeholder isn't enough), prepending the monero-ts notice
      { from: path.join(MONERO_DIST, "monero.worker.js.LICENSE.txt"), to: path.join(VENDOR, "monero.worker.js.LICENSE.txt"),
        transform(content){ return "/*! monero-ts (https://github.com/woodser/monero-ts) - MIT, (c) woodser. WASM bindings to monero-project/monero. Third-party notices follow. */\n\n" + content.toString(); } },
    ] }),
  ],
  resolve: {
    alias: { fs: "memfs" },
    extensions: [".js", ".json"],
    fallback: {                    // browser polyfills for node built-ins monero-ts references
      assert: require.resolve("assert"),
      buffer: require.resolve("buffer"),
      crypto: require.resolve("crypto-browserify"),
      events: require.resolve("events"),
      http: require.resolve("stream-http"),
      https: require.resolve("https-browserify"),
      os: require.resolve("os-browserify/browser"),
      path: require.resolve("path-browserify"),
      process: require.resolve("process/browser"),
      querystring: require.resolve("querystring-es3"),
      stream: require.resolve("stream-browserify"),
      string_decoder: require.resolve("string_decoder"),
      url: require.resolve("url"),
      util: require.resolve("util"),
      vm: require.resolve("vm-browserify"),
      zlib: require.resolve("browserify-zlib"),
      constants: false, net: false, tls: false, dns: false,   // node-only; the browser uses fetch/XHR
    },
  },
};
