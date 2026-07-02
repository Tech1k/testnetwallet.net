<?php
/*
 * mweb.php - single-file MWEB helper for TestnetWallet. Drag-and-drop into a web dir
 * served by Apache/nginx + PHP, on the same host as your litecoind. It is the ONLY
 * thing the wallet talks to for MWEB; litecoind's RPC stays bound to localhost.
 *
 * It does three things, all over litecoind's localhost JSON-RPC (no -rest needed):
 *   GET  ?tip                  -> { height, hash, chain, mwebActive }
 *   GET  ?from=H&to=H2         -> { from, to, blocks:[{height, outputs[], inputs[]}] }
 *                                 (only blocks that have MWEB activity; the browser scans them)
 *   POST {method, params}      -> forwards ONLY sendrawtransaction / testmempoolaccept
 *
 * Privacy + custody: it serves MWEB outputs by HEIGHT RANGE - the browser scans them
 * locally with the view key, so this script never learns which outputs are yours and
 * never sees your keys. Writes are limited to the two broadcast methods; everything else
 * is rejected, so you are not exposing litecoind's full RPC.
 */

// ---- config: edit these, or set via environment ----
$RPC_URL   = getenv('LTC_RPC_URL')  ?: 'http://127.0.0.1:19332';   // testnet RPC port
$RPC_USER  = getenv('LTC_RPC_USER') ?: 'litecoinrpc';
$RPC_PASS  = getenv('LTC_RPC_PASS') ?: '';
$MAX_RANGE = 1000;                                                 // max heights per scan request (bounds runtime)
$MAX_BODY  = 1048576;                                              // 1 MB cap on POST body (a real MWEB tx is a few KB); reject larger
$ALLOW     = ['sendrawtransaction' => true, 'testmempoolaccept' => true];
// CORS: '*' lets any site use this self-hosted testnet helper (the methods are allow-listed above, so the blast
// radius is just broadcasting testnet txs / reading public block ranges on your node). To pin it to your wallet
// origin instead, set LTC_ALLOW_ORIGIN=https://testnetwallet.net (or your host). No real funds are ever at stake.
$ALLOW_ORIGIN = getenv('LTC_ALLOW_ORIGIN') ?: '*';

header('Access-Control-Allow-Origin: ' . $ALLOW_ORIGIN);
if ($ALLOW_ORIGIN !== '*') header('Vary: Origin');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > $MAX_BODY) { http_response_code(413); echo json_encode(['error' => ['message' => 'request too large']]); exit; }

// One keep-alive curl handle reused across calls (a range scan makes many localhost RPC calls).
function rpc($method, $params = []) {
    static $ch = null;
    global $RPC_URL, $RPC_USER, $RPC_PASS;
    if ($ch === null) {
        $ch = curl_init($RPC_URL);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Content-Type: text/plain'],
            CURLOPT_USERPWD        => $RPC_USER . ':' . $RPC_PASS,
            CURLOPT_TIMEOUT        => 30,
        ]);
    }
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['jsonrpc' => '1.0', 'id' => 'mweb', 'method' => $method, 'params' => $params]));
    $out = curl_exec($ch);
    if ($out === false) return ['error' => ['message' => 'rpc connect: ' . curl_error($ch)]];
    $j = json_decode($out, true);
    return is_array($j) ? $j : ['error' => ['message' => 'rpc non-json: ' . substr($out, 0, 200)]];
}
function fail($code, $msg) { http_response_code($code); echo json_encode(['error' => ['message' => $msg]]); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['tip'])) {
        $r = rpc('getblockchaininfo');
        if (!empty($r['error'])) fail(502, $r['error']['message']);
        $c = $r['result'];
        echo json_encode([
            'height'     => $c['blocks'],
            'hash'       => $c['bestblockhash'],
            'chain'      => $c['chain'],
            'mwebActive' => !empty($c['softforks']['mweb']['active']),
        ]);
        exit;
    }
    if (isset($_GET['from']) && isset($_GET['to'])) {
        $from = max(0, (int)$_GET['from']);
        $to   = (int)$_GET['to'];
        if ($to < $from) fail(400, 'to < from');
        if ($to - $from + 1 > $MAX_RANGE) $to = $from + $MAX_RANGE - 1;   // clamp; the client paginates
        $blocks = [];
        for ($h = $from; $h <= $to; $h++) {
            $rh = rpc('getblockhash', [$h]);
            if (!empty($rh['error'])) break;                              // past tip, etc.
            $rb = rpc('getblock', [$rh['result'], 2]);
            if (!empty($rb['error'])) break;
            $mw = isset($rb['result']['mweb']) ? $rb['result']['mweb'] : null;
            if ($mw && (!empty($mw['outputs']) || !empty($mw['inputs']))) {
                $blocks[] = [
                    'height'  => $h,
                    'outputs' => isset($mw['outputs']) ? $mw['outputs'] : [],
                    'inputs'  => isset($mw['inputs'])  ? $mw['inputs']  : [],
                ];
            }
        }
        echo json_encode(['from' => $from, 'to' => $to, 'blocks' => $blocks]);
        exit;
    }
    fail(400, 'unknown GET (use ?tip or ?from=&to=)');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = file_get_contents('php://input', false, null, 0, $MAX_BODY + 1);   // capped read (guards an absent/spoofed Content-Length)
    if (strlen($raw) > $MAX_BODY) fail(413, 'request too large');
    $body = json_decode($raw, true);
    if (!is_array($body)) fail(400, 'bad json');
    $m      = isset($body['method']) ? $body['method'] : (isset($body['hex']) ? 'sendrawtransaction' : null);
    $params = isset($body['params']) ? $body['params'] : (isset($body['hex']) ? [$body['hex']] : []);
    if (!isset($ALLOW[$m])) fail(403, 'method not allowed: ' . $m);
    // sanity-check the raw-tx hex (forwarded verbatim to litecoind): must be bounded hex
    $hexes = ($m === 'testmempoolaccept') ? (isset($params[0]) && is_array($params[0]) ? $params[0] : []) : [isset($params[0]) ? $params[0] : null];
    foreach ($hexes as $h) { if (!is_string($h) || $h === '' || strlen($h) > 200000 || !ctype_xdigit($h)) fail(400, 'invalid tx hex'); }
    echo json_encode(rpc($m, $params));   // { result, error } passthrough
    exit;
}

fail(405, 'method not allowed');
