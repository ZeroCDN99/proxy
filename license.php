<?php
// ── Доверенный прокси-зеркало (s1250022.ha006.t.mydomain.zone) ──────────────
//  Ссылки клиентам выдаются на зеркало, потому что домен zerosan.alwaysdata.net
//  заблокирован в Туркменистане. Зеркало повторяет запрос сюда и передаёт
//  реальный IP клиента в X-Fwd-Ip, подписав его общим секретом X-Fwd-Secret.
//  Ниже подменяем REMOTE_ADDR на этот IP — иначе весь трафик через зеркало
//  выглядел бы как один клиент (важно для WEAK-HWID: md5(UA + REMOTE_ADDR)).
//  Доверяем ТОЛЬКО если запрос действительно пришёл с IP зеркала И секрет верен.
//  Блок самодостаточный: удаляется целиком без последствий для остальной логики.
(function () {
    // Исходящие адреса зеркала (не совпадают с его входящим 176.32.38.47).
    $trusted_proxies = ['212.60.5.182', '2a00:b700:3::30'];
    $shared_secret   = '968f6dacaf5292b98bef45591d73e0402a13cb8884c8bb7a';
    $sent_secret = (string)($_SERVER['HTTP_X_FWD_SECRET'] ?? '');
    // Секрет не должен попасть в логи/выдачу заголовков приложения ни при каких условиях.
    unset($_SERVER['HTTP_X_FWD_SECRET']);
    $peer = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    if (!in_array($peer, $trusted_proxies, true)) {
        // Запрос пришёл не от зеркала — X-Fwd-* мог подделать кто угодно, чистим.
        unset($_SERVER['HTTP_X_FWD_IP'], $_SERVER['HTTP_X_FWD_PROTO'], $_SERVER['HTTP_X_FWD_HOST']);
        return;
    }
    if ($sent_secret === '' || !hash_equals($shared_secret, $sent_secret)) {
        unset($_SERVER['HTTP_X_FWD_IP'], $_SERVER['HTTP_X_FWD_PROTO'], $_SERVER['HTTP_X_FWD_HOST']);
        return;
    }
    $real_ip = trim((string)($_SERVER['HTTP_X_FWD_IP'] ?? ''));
    if ($real_ip === '' || !filter_var($real_ip, FILTER_VALIDATE_IP)) {
        return;
    }
    $_SERVER['_PROXY_ADDR']  = $peer;      // кто переслал (для диагностики)
    $_SERVER['REMOTE_ADDR']  = $real_ip;   // ← ради этой строки всё и делается
    $_SERVER['HTTP_X_REAL_IP'] = $real_ip;
})();
// license.php - V8.22 FULL (MTU 1350 for TM)
// Автор: ZeroBlade
require_once __DIR__ . '/db.php';
if (is_file(__DIR__ . '/happ_branding_module.php')) {
    require_once __DIR__ . '/happ_branding_module.php';
}

$api_secret = "my_super_secret_pass_123";
// ── Load global Vanya config (managed by bot) ──
$_vanya_cfg = (function() {
    $f = __DIR__ . '/vanya_config.json';
    if (!file_exists($f)) return null;
    $j = @json_decode(file_get_contents($f), true);
    return is_array($j) ? $j : null;
})();
$vanya_key = $_vanya_cfg['token'] ?? "b53492e4-ae62-49c7-90da-075783ece24e";

// ── Читаем конфиг доменов (управляется ботом через happ_domain_module.php) ─
function hd_load_for_uid(int $uid): array {
    $f = __DIR__ . '/happ_domains.json';
    $defaults = [
        'provider_id'                        => '',
        'fallback_domains'                   => [],
        'new_domain'                         => '',
        'subscriptions_sort_type'            => '',
        'subscriptions_auto_update_open_enable' => false,
        'subscriptions_ping_onopen_enabled'  => false,
        'hide_settings'                      => false
    ];
    if ($uid <= 0 || !file_exists($f)) return $defaults;
    $j = @json_decode(file_get_contents($f), true);
    if (!is_array($j)) return $defaults;
    $row = $j[(string)$uid] ?? [];
    return array_merge($defaults, is_array($row) ? $row : []);
}
// ──────────────────────────────────────────────────────────────────────────
$vanya_cache_file = __DIR__ . '/vanya_cache.txt';
$free_pool_file   = __DIR__ . '/free_configs.txt';
$whitelist_file   = __DIR__ . '/marzban_whitelist.json';

$_vanyaDefaultLocations = [
    'baku', 'frankfurt', 'oregon', 'tashkent', 'moscow', 'london', 'amsterdam',
    'almaty', 'marseille', 'helsinki', 'stockholm', 'zurich', 'minsk', 'yerevan',
    'riga', 'izmir', 'tallin', 'palermo', 'athens', 'dubai', 'tbilisi'
];
$vanyaLocations = !empty($_vanya_cfg['locations']) ? $_vanya_cfg['locations'] : $_vanyaDefaultLocations;


error_reporting(0);
date_default_timezone_set('Asia/Ashgabat');

// ── Vanya helpers ──────────────────────────────────────────────────────────
function vanya_disabled_for_dealer($dealer_id) {
    $f = __DIR__ . '/dealers.json';
    if (!file_exists($f)) return false;
    $j = json_decode(file_get_contents($f), true);
    if (!is_array($j) || !isset($j['dealers'])) return false;
    $id = (string)(int)$dealer_id;
    if (!isset($j['dealers'][$id])) return false;
    return ($j['dealers'][$id]['vanya_enabled'] ?? true) === false;
}

function load_owner_vanya($owner_id) {
    $f = __DIR__ . '/owner_vanya_' . (int)$owner_id . '.json';
    if (!file_exists($f)) return null;
    $j = @json_decode(file_get_contents($f), true);
    return is_array($j) ? $j : null;
}

function get_flag_emoji_lic($code) {
    if (empty($code) || strlen($code) !== 2) return "🌍";
    $code = strtoupper($code);
    return mb_chr(127397 + ord($code[0])) . mb_chr(127397 + ord($code[1]));
}

function build_location_flag_map() {
    static $map = null;
    if ($map !== null) return $map;
    $map = [];
    $f = __DIR__ . '/vanya_locations.json';
    if (file_exists($f)) {
        $data = @json_decode(file_get_contents($f), true);
        if (is_array($data)) {
            foreach ($data as $item) {
                if (!empty($item['value']) && !empty($item['code'])) {
                    $map[strtolower($item['value'])] = get_flag_emoji_lic($item['code']);
                }
            }
        }
    }
    return $map;
}

// Convert Sing-box VLESS outbound → vless:// URI (Happ / Xray Reality)
function singbox_vless_to_uri(array $ob, string $name): ?string {
    if (strtolower((string)($ob['type'] ?? '')) !== 'vless') return null;
    $server = trim((string)($ob['server'] ?? ''));
    $port   = (int)($ob['server_port'] ?? 0);
    $uuid   = trim((string)($ob['uuid'] ?? ''));
    if ($server === '' || $port <= 0 || $uuid === '') return null;

    $flow = trim((string)($ob['flow'] ?? ''));
    $tls  = (array)($ob['tls'] ?? []);
    $reality = (array)($tls['reality'] ?? []);
    $has_reality = !empty($reality['enabled']) || !empty($reality['public_key']);
    $has_tls     = !empty($tls['enabled']) || $has_reality;

    // Happ docs: encryption, headerType, type, security, sni, fp, pbk, sid, flow, xtls
    $parts = [];
    $parts[] = 'encryption=none';
    $parts[] = 'headerType=none';

    $transport = (array)($ob['transport'] ?? []);
    $net = strtolower((string)($transport['type'] ?? 'tcp'));
    if ($net === '' || $net === 'raw') $net = 'tcp';
    if ($net === 'h2') $net = 'http';
    $parts[] = 'type=' . rawurlencode($net);

    if ($has_reality) {
        $parts[] = 'security=reality';
    } elseif ($has_tls) {
        $parts[] = 'security=tls';
    }

    $sni = trim((string)($tls['server_name'] ?? $tls['sni'] ?? ''));
    if ($sni !== '') $parts[] = 'sni=' . rawurlencode($sni);

    $utls = (array)($tls['utls'] ?? []);
    $fp = trim((string)($utls['fingerprint'] ?? $tls['fingerprint'] ?? ''));
    if ($fp !== '') $parts[] = 'fp=' . rawurlencode($fp);

    if ($has_reality) {
        $pbk = trim((string)($reality['public_key'] ?? ''));
        $sid = trim((string)($reality['short_id'] ?? ''));
        if ($pbk !== '') $parts[] = 'pbk=' . rawurlencode($pbk);
        if ($sid !== '') $parts[] = 'sid=' . rawurlencode($sid);
        $spx = trim((string)($reality['short_id'] === 'unused' ? '' : ($reality['spider_x'] ?? $reality['spiderX'] ?? '')));
        if ($spx !== '') $parts[] = 'spx=' . rawurlencode($spx);
    }

    if ($flow !== '') {
        $parts[] = 'flow=' . rawurlencode($flow);
        // Happ example includes xtls=2 together with vision flow
        $parts[] = 'xtls=2';
        $parts[] = 'packetEncoding=xudp';
    }

    if (!empty($transport['path'])) $parts[] = 'path=' . rawurlencode((string)$transport['path']);
    if (!empty($transport['headers']['Host'])) $parts[] = 'host=' . rawurlencode((string)$transport['headers']['Host']);
    elseif (!empty($transport['host'])) {
        $host = is_array($transport['host']) ? (string)($transport['host'][0] ?? '') : (string)$transport['host'];
        if ($host !== '') $parts[] = 'host=' . rawurlencode($host);
    }
    if ($net === 'grpc' && !empty($transport['service_name'])) {
        $parts[] = 'serviceName=' . rawurlencode((string)$transport['service_name']);
    }

    $qs = implode('&', $parts);
    return "vless://{$uuid}@{$server}:{$port}?{$qs}#" . rawurlencode($name);
}

// Extract JSON object that contains "outbounds" from free-form text (YAML wrapper etc.)
function vanya_extract_config_json(string $raw): ?array {
    $raw = trim($raw);
    if ($raw === '') return null;

    $j = @json_decode($raw, true);
    if (is_array($j)) return $j;

    // YAML: config: | \n { ... }
    if (preg_match('/config\s*:\s*\|?\s*(\{.*)/s', $raw, $m)) {
        $candidate = trim($m[1]);
        $j = @json_decode($candidate, true);
        if (is_array($j)) return $j;
    }

    $start = strpos($raw, '{');
    $end   = strrpos($raw, '}');
    if ($start !== false && $end !== false && $end > $start) {
        $j = @json_decode(substr($raw, $start, $end - $start + 1), true);
        if (is_array($j)) return $j;
    }
    return null;
}

function vanya_http_get(string $url): string {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 25,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Linux; Android 16; SM-S928B Build/BP4A.251205.006; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/150.0.7871.184 Mobile Safari/537.36',
        CURLOPT_HTTPHEADER => [
            'Accept: application/json, text/plain, */*',
            'Accept-Language: ru-RU,ru;q=0.9,en;q=0.8',
            'X-Requested-With: com.vanyavpn.android.client',
        ],
    ]);
    $res = curl_exec($ch);
    curl_close($ch);
    return is_string($res) ? $res : '';
}

function vanya_line_flag(string $ln): string {
    $flag = "\u{1F30D}";
    $ln = trim($ln);
    if ($ln === '') return $flag;
    if ($ln[0] === '{') {
        $j = @json_decode($ln, true);
        $remarks = (string)($j['remarks'] ?? '');
        if (preg_match('/([\x{1F1E6}-\x{1F1FF}]{2})/u', $remarks, $m)) return $m[1];
        return $flag;
    }
    $pos = strpos($ln, '#');
    if ($pos !== false) {
        $frag = rawurldecode(substr($ln, $pos + 1));
        if (preg_match('/^([\x{1F1E6}-\x{1F1FF}]{2})/u', $frag, $m)) return $m[1];
        if (preg_match('/([\x{1F1E6}-\x{1F1FF}]{2})/u', $frag, $m)) return $m[1];
    }
    return $flag;
}

function vanya_encode_happ_json(array $payload): string {
    return json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function vanya_ob_is_entry(array $ob): bool {
    $tag = strtolower((string)($ob['tag'] ?? ''));
    return strpos($tag, 'personal') !== false || strpos($tag, 'entry') !== false;
}

function vanya_include_exit($ov): bool {
    if (is_array($ov) && array_key_exists('include_exit', $ov)) {
        return !empty($ov['include_exit']);
    }
    return false;
}

function vanya_filter_cache_line(string $ln, bool $include_exit): array {
    $ln = trim($ln);
    if ($ln === '') return [];
    if ($include_exit) return [$ln];
    if ($ln[0] !== '{') {
        return (stripos(rawurldecode($ln), 'entry') !== false) ? [$ln] : [];
    }
    $j = @json_decode($ln, true);
    if (!is_array($j)) return [];
    $remarks = (string)($j['remarks'] ?? '');
    if (stripos($remarks, 'entry') !== false) return [$ln];
    $obs = $j['outbounds'] ?? [];
    if (!is_array($obs) || $obs === []) return [];
    $first = $obs[0] ?? [];
    if (is_array($first) && isset($first['protocol'])) {
        return [];
    }
    if (is_array($first) && isset($first['type'])) {
        $has_entry = false;
        $kept = [];
        foreach ($obs as $ob) {
            if (!is_array($ob)) continue;
            $type = strtolower((string)($ob['type'] ?? ''));
            if (in_array($type, ['urltest', 'selector', 'direct', 'block', 'dns'], true)) continue;
            if (vanya_ob_is_entry($ob)) {
                $has_entry = true;
                $kept[] = $ob;
            }
        }
        if (!$has_entry || !$kept) return [];
        $j['outbounds'] = $kept;
        if (stripos((string)($j['remarks'] ?? ''), 'entry') === false) {
            $j['remarks'] = trim((string)($j['remarks'] ?? 'Server')) . ' · entry';
        }
        return [json_encode($j, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)];
    }
    return [];
}

function vanya_xray_name(string $base, string $tag): string {
    $tag_l = strtolower(trim($tag));
    if ($tag_l === '' || $tag_l === 'proxy' || $tag_l === 'node-vless' || $tag_l === 'vless' || $tag_l === 'auto') {
        return $base;
    }
    if (strpos($tag_l, 'personal') !== false || strpos($tag_l, 'entry') !== false) {
        return $base . ' · entry';
    }
    if (stripos($base, $tag) !== false) return $base;
    return $base . ' · ' . $tag;
}

function vanya_outbound_to_happ_line(array $ob, string $name): ?string {
    $x = singbox_outbound_to_xray($ob);
    if (!$x) return null;
    $x['tag'] = 'proxy';
    if (function_exists('happ_xray_server')) {
        $payload = happ_xray_server($name, $x);
    } else {
        $payload = [
            'remarks' => $name,
            'outbounds' => [
                $x,
                ['protocol' => 'freedom', 'tag' => 'direct'],
                ['protocol' => 'blackhole', 'tag' => 'block'],
            ],
        ];
    }
    return vanya_encode_happ_json($payload);
}

// Build Happ Xray JSON line(s) from a Vanya API body.
// Returns ['line'=>json, 'lines'=>[json...], 'kind'=>string, 'nodes'=>int] or null.
function vanya_happ_json_entry($res, string $loc, array $flag_map_loc, bool $include_exit = false): ?array {
    $fl = $flag_map_loc[strtolower($loc)] ?? "🌍";
    $tag_default = ucfirst($loc);
    $raw = is_array($res) ? json_encode($res, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : (string)$res;
    $data = is_array($res) ? $res : @json_decode($raw, true);

    if (is_string($raw) && preg_match('/^\s*location:\s*(.+)$/m', $raw, $lm)) {
        $loc_name = trim($lm[1], " \t\"'");
        if (preg_match('/([\x{1F1E6}-\x{1F1FF}]{2})/u', $loc_name, $fm)) {
            $fl = $fm[1];
        }
        $stripped = trim(preg_replace('/[\x{1F1E6}-\x{1F1FF}]{2}/u', '', $loc_name));
        if ($stripped !== '') $tag_default = $stripped;
    }

    // ── 1) Classic Shadowsocks JSON ──────────────────────────────
    if (is_array($data) && isset($data['server']) && (isset($data['method']) || isset($data['password']))) {
        $tag = (string)($data['tag'] ?? $data['location'] ?? $tag_default);
        $tag = trim(preg_replace('/^[\x{1F1E6}-\x{1F1FF}]{2}\s*/u', '', $tag));
        $name = "$fl $tag";
        $ob = [
            'type' => 'shadowsocks',
            'tag' => 'proxy',
            'server' => (string)($data['server'] ?? ''),
            'server_port' => (int)($data['server_port'] ?? $data['port'] ?? 0),
            'method' => (string)($data['method'] ?? 'chacha20-ietf-poly1305'),
            'password' => (string)($data['password'] ?? ''),
        ];
        $line = vanya_outbound_to_happ_line($ob, $name);
        if ($line === null) return null;
        return ['line' => $line, 'lines' => [$line], 'kind' => 'ss-xray', 'nodes' => 1];
    }

    // ── 2) Sing-box YAML/JSON with VLESS / SS / Trojan ───────────
    $cfg = null;
    if (is_array($data)) {
        if (!empty($data['location'])) {
            $loc_name = trim((string)$data['location']);
            if (preg_match('/([\x{1F1E6}-\x{1F1FF}]{2})/u', $loc_name, $fm)) $fl = $fm[1];
            $tag_default = trim(preg_replace('/[\x{1F1E6}-\x{1F1FF}]{2}/u', '', $loc_name)) ?: $tag_default;
        }
        if (isset($data['config'])) {
            if (is_string($data['config'])) $cfg = vanya_extract_config_json($data['config']);
            elseif (is_array($data['config'])) $cfg = $data['config'];
        }
        if ($cfg === null && !empty($data['outbounds']) && is_array($data['outbounds'])) $cfg = $data;
    }
    if ($cfg === null) $cfg = vanya_extract_config_json($raw);
    if (!is_array($cfg) || empty($cfg['outbounds']) || !is_array($cfg['outbounds'])) {
        return null;
    }

    $name_base = "$fl $tag_default";
    $has_entry_ob = false;
    foreach ($cfg['outbounds'] as $ob) {
        if (is_array($ob) && vanya_ob_is_entry($ob)) { $has_entry_ob = true; break; }
    }
    $lines = [];
    foreach ($cfg['outbounds'] as $ob) {
        if (!is_array($ob)) continue;
        $type = strtolower((string)($ob['type'] ?? ''));
        if (!in_array($type, ['vless', 'shadowsocks', 'trojan', 'hysteria2', 'hy2'], true)) continue;
        if (!$include_exit && $has_entry_ob && !vanya_ob_is_entry($ob)) continue;
        $name = vanya_xray_name($name_base, (string)($ob['tag'] ?? ''));
        $line = vanya_outbound_to_happ_line($ob, $name);
        if ($line === null) continue;
        $lines[] = $line;
    }
    if (empty($lines)) return null;
    return [
        'line' => $lines[0],
        'lines' => $lines,
        'kind' => 'singbox-xray',
        'nodes' => count($lines),
    ];
}

function vanya_fetch_keys($token, $locations, $cache_file = null, $include_exit = false) {
    $collected = []; $log = [];
    if ($cache_file) file_put_contents($cache_file, "");
    $flag_map_loc = build_location_flag_map();
    $token_enc = rawurlencode((string)$token);

    foreach ($locations as $loc) {
        $loc_q = rawurlencode((string)$loc);
        $qs = "token={$token_enc}&location={$loc_q}&lang=ru-RU&referrer=utm_source%3Dgoogle-play%26utm_medium%3Dorganic";

        // Same mirror the official app uses, then vanya.click, then legacy two-step
        $res = vanya_http_get("https://34.66.234.226/app/v1/user/location/change/and/get?{$qs}");
        if ($res === '' || stripos($res, 'Unauthorized') !== false || stripos($res, 'Payment Required') !== false) {
            $res = vanya_http_get("https://vanya.click/app/v1/user/location/change/and/get?{$qs}");
        }
        if ($res === '' || stripos($res, 'Unauthorized') !== false || stripos($res, 'Payment Required') !== false) {
            vanya_http_get("https://vanya.click/app/v1/user/location/change?token={$token_enc}&location={$loc_q}");
            $res = vanya_http_get("https://vanya.click/vanya/" . $token_enc);
        }

        $entry = vanya_happ_json_entry($res, (string)$loc, $flag_map_loc, (bool)$include_exit);
        if ($entry === null) {
            $preview = substr(preg_replace('/\s+/', ' ', (string)$res), 0, 80);
            $log[] = "❌ $loc" . ($preview !== '' ? " [$preview]" : '');
            continue;
        }
        $entry_lines = $entry['lines'] ?? [ $entry['line'] ];
        foreach ($entry_lines as $ln) {
            $ln = trim((string)$ln);
            if ($ln === '') continue;
            $collected[] = $ln;
            if ($cache_file) file_put_contents($cache_file, $ln . "\n", FILE_APPEND);
        }
        $log[] = "✅ $loc (" . $entry['kind'] . ", " . (int)$entry['nodes'] . "n)";
    }
    return ['keys' => $collected, 'log' => $log];
}

/** Vanya node-personal IP is shared across countries and rotates. Patch cache without a full 100+ refetch. */
function vanya_majority_vless_ip(string $cache_file): ?string {
    if (!is_file($cache_file)) return null;
    $counts = [];
    foreach (explode("\n", (string)@file_get_contents($cache_file)) as $ln) {
        $ln = trim($ln);
        if ($ln === '' || $ln[0] !== '{') continue;
        $j = json_decode($ln, true);
        if (!is_array($j)) continue;
        foreach (($j['outbounds'] ?? []) as $ob) {
            if (!is_array($ob) || strtolower((string)($ob['protocol'] ?? '')) !== 'vless') continue;
            $addr = (string)($ob['settings']['vnext'][0]['address'] ?? '');
            if ($addr !== '') $counts[$addr] = ($counts[$addr] ?? 0) + 1;
        }
    }
    if (!$counts) return null;
    arsort($counts);
    return (string)array_key_first($counts);
}

function vanya_personal_ip_from_api_body($res): ?string {
    $raw = is_array($res) ? json_encode($res, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : (string)$res;
    $cfg = null;
    $data = is_array($res) ? $res : json_decode($raw, true);
    if (is_array($data) && isset($data['config'])) {
        $cfg = is_string($data['config']) ? vanya_extract_config_json($data['config']) : $data['config'];
    }
    if ($cfg === null) $cfg = vanya_extract_config_json($raw);
    if (!is_array($cfg) || empty($cfg['outbounds']) || !is_array($cfg['outbounds'])) return null;
    $fallback = null;
    foreach ($cfg['outbounds'] as $ob) {
        if (!is_array($ob)) continue;
        $type = strtolower((string)($ob['type'] ?? ''));
        if ($type !== 'vless') continue;
        $srv = trim((string)($ob['server'] ?? ''));
        if ($srv === '') continue;
        if (vanya_ob_is_entry($ob)) return $srv;
        if ($fallback === null) $fallback = $srv;
    }
    return $fallback;
}

function vanya_rewrite_cache_ip(string $cache_file, string $old_ip, string $new_ip): int {
    if ($old_ip === '' || $new_ip === '' || $old_ip === $new_ip) return 0;
    $raw = (string)@file_get_contents($cache_file);
    if ($raw === '' || strpos($raw, $old_ip) === false) return 0;
    $n = 0;
    $out = [];
    foreach (explode("\n", $raw) as $ln) {
        $trim = rtrim($ln, "\r");
        if (trim($trim) === '' || $trim[0] !== '{') { $out[] = $ln; continue; }
        $j = json_decode($trim, true);
        if (!is_array($j)) { $out[] = $ln; continue; }
        $changed = false;
        foreach ($j['outbounds'] ?? [] as $i => $ob) {
            if (!is_array($ob) || strtolower((string)($ob['protocol'] ?? '')) !== 'vless') continue;
            if (($ob['settings']['vnext'][0]['address'] ?? '') === $old_ip) {
                $j['outbounds'][$i]['settings']['vnext'][0]['address'] = $new_ip;
                $changed = true;
                $n++;
            }
        }
        $out[] = $changed ? json_encode($j, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : $trim;
    }
    if ($n > 0) {
        file_put_contents($cache_file, implode("\n", $out));
    }
    return $n;
}

function vanya_sync_owner_cache(array $ov): void {
    $token = trim((string)($ov['token'] ?? ''));
    $cache_file = __DIR__ . '/' . basename((string)($ov['cache_file'] ?? ''));
    if ($token === '' || $cache_file === __DIR__ . '/' || !is_file($cache_file) || filesize($cache_file) < 20) return;
    $age = time() - (int)@filemtime($cache_file);
    if ($age < 90) return;
    $lockf = $cache_file . '.iplock';
    $lk = @fopen($lockf, 'c');
    if (!$lk) return;
    if (!flock($lk, LOCK_EX | LOCK_NB)) { fclose($lk); return; }
    clearstatcache(true, $cache_file);
    if (time() - (int)@filemtime($cache_file) < 90) { flock($lk, LOCK_UN); fclose($lk); return; }
    $locs = $ov['locations'] ?? [];
    $loc = is_array($locs) && $locs ? (string)$locs[0] : 'madrid';
    $qs = 'token=' . rawurlencode($token) . '&location=' . rawurlencode($loc) . '&lang=ru-RU&referrer=utm_source%3Dgoogle-play%26utm_medium%3Dorganic';
    $res = vanya_http_get("https://34.66.234.226/app/v1/user/location/change/and/get?{$qs}");
    if ($res === '' || stripos($res, 'Unauthorized') !== false) {
        $res = vanya_http_get("https://vanya.click/app/v1/user/location/change/and/get?{$qs}");
    }
    $new_ip = vanya_personal_ip_from_api_body($res);
    $old_ip = vanya_majority_vless_ip($cache_file);
    if ($new_ip && $old_ip && $new_ip !== $old_ip) {
        vanya_rewrite_cache_ip($cache_file, $old_ip, $new_ip);
    }
    @touch($cache_file);
    flock($lk, LOCK_UN);
    fclose($lk);
}

// SEC: timing-safe secret validation helper
function sec_check_secret(string $provided, string $expected): bool {
    if ($provided === '') return false;
    return hash_equals($expected, $provided);
}

// SEC: strip null bytes from all GET input on entry
foreach ($_GET as $k => $v) {
    $_GET[$k] = is_string($v) ? str_replace("\0", '', $v) : $v;
}

// ---------------- MARZBAN PARSE HELPERS ----------------
function unwrap_proxy_url($url) {
    $url = trim((string)$url);
    if ($url === '') return '';
    if (strpos($url, '?') !== false) {
        $p = @parse_url($url);
        if (is_array($p) && isset($p['query'])) {
            parse_str($p['query'], $q);
            if (isset($q['url'])) {
                $inner = urldecode((string)$q['url']);
                if (stripos($inner, 'http://') === 0 || stripos($inner, 'https://') === 0) return $inner;
            }
        }
        if (preg_match('/[?&]url=([^&]+)/i', $url, $m)) {
            $inner = urldecode($m[1]);
            if (stripos($inner, 'http://') === 0 || stripos($inner, 'https://') === 0) return $inner;
        }
    }
    return $url;
}

function parse_userinfo_header($header) {
    $upload = 0; $download = 0; $total = 0; $expire = 0;
    if (preg_match('/subscription-userinfo:\s*(.*)/i', $header, $matches)) {
        $stats_str = trim($matches[1]);
        preg_match('/upload=(\d+)/', $stats_str, $u_m); $upload = (int)($u_m[1] ?? 0);
        preg_match('/download=(\d+)/', $stats_str, $d_m); $download = (int)($d_m[1] ?? 0);
        preg_match('/total=(\d+)/', $stats_str, $t_m); $total = (int)($t_m[1] ?? 0);
        preg_match('/expire=(\d+)/', $stats_str, $e_m); $expire = (int)($e_m[1] ?? 0);
        return ['ok'=>true, 'u'=>$upload, 'd'=>$download, 't'=>$total, 'e'=>$expire, 'raw'=>$stats_str];
    }
    return ['ok'=>false];
}

function parse_expire_from_html($body) {
    if (preg_match('/Expiration\s*Date\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})\s*([0-9]{2}:[0-9]{2}:[0-9]{2})/i', (string)$body, $m)) {
        $ts = strtotime($m[1] . ' ' . $m[2]);
        if ($ts !== false) return (int)$ts;
    }
    return 0;
}

// ---------------- WHITELIST HELPERS (STRICT) ----------------
function wl_init_if_needed() {
    global $whitelist_file;
    if (!file_exists($whitelist_file)) {
        $init = ['mode' => 'STRICT', 'domains' => [], 'ips' => []];
        file_put_contents($whitelist_file, json_encode($init, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
}
function wl_load() {
    global $whitelist_file;
    wl_init_if_needed();
    $j = json_decode(file_get_contents($whitelist_file), true);
    if (!is_array($j)) $j = [];
    if (!isset($j['mode'])) $j['mode'] = 'STRICT';
    if (!isset($j['domains']) || !is_array($j['domains'])) $j['domains'] = [];
    if (!isset($j['ips']) || !is_array($j['ips'])) $j['ips'] = [];
    $j['domains'] = array_values(array_unique(array_filter(array_map(function($d){ return rtrim(strtolower(trim((string)$d)), '.'); }, $j['domains']))));
    $j['ips'] = array_values(array_unique(array_filter(array_map(function($ip){ return trim((string)$ip); }, $j['ips']))));
    return $j;
}
function is_private_or_reserved_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return true;
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
}
function host_matches_domain($host, $allowedDomain) {
    $host = strtolower(rtrim($host, '.'));
    $allowedDomain = strtolower(rtrim($allowedDomain, '.'));
    if ($host === $allowedDomain) return true;
    return (substr($host, -strlen('.'.$allowedDomain)) === '.'.$allowedDomain);
}
function resolve_host_ips($host) {
    $ips = [];
    $res = @gethostbynamel($host);
    if (is_array($res)) $ips = array_merge($ips, $res);
    return array_values(array_unique(array_filter($ips)));
}
function marzban_url_allowed_strict($url, &$reason = '') {
    $wl = wl_load();
    $url = trim((string)$url);
    if ($url === '') { $reason = 'EMPTY_URL'; return false; }
    $p = @parse_url($url);
    if (!is_array($p)) { $reason = 'BAD_URL'; return false; }
    $scheme = strtolower($p['scheme'] ?? '');
    if (!in_array($scheme, ['http','https'], true)) { $reason = 'BAD_SCHEME'; return false; }
    $host = rtrim(strtolower(trim($p['host'] ?? '')), '.');
    if ($host === '' || $host === 'localhost') { $reason = 'BAD_HOST'; return false; }
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (is_private_or_reserved_ip($host)) { $reason = 'PRIVATE_IP_DENIED'; return false; }
        if (in_array($host, $wl['ips'], true)) return true;
        $reason = 'IP_NOT_WHITELISTED'; return false;
    }
    foreach ($wl['domains'] as $d) {
        if ($d && host_matches_domain($host, $d)) {
            foreach (resolve_host_ips($host) as $ip) { if (is_private_or_reserved_ip($ip)) { $reason = 'DOMAIN_RESOLVES_PRIVATE_IP'; return false; } }
            return true;
        }
    }
    foreach (resolve_host_ips($host) as $ip) {
        if (is_private_or_reserved_ip($ip)) continue;
        if (in_array($ip, $wl['ips'], true)) return true;
    }
    $reason = 'HOST_NOT_WHITELISTED'; return false;
}

// =========================================================================
// API ДЛЯ БОТА (Работает через MySQL)
// =========================================================================
if (isset($_GET['action']) && sec_check_secret(($_GET['secret'] ?? ''), $api_secret)) {
    $act = $_GET['action'];
    $t = $_GET['token'] ?? '';

    // --- ВСТАВИТЬ НАЧАЛО БЛОКА ДЯДИ ВАНИ ---


    // --- force_update_owner: обновить персональный кэш владельца ---
    if ($act === 'force_update_owner') {
        $owner_id = (int)($_GET['owner_id'] ?? 0);
        if ($owner_id <= 0) die("Error: invalid owner_id");
        $ov = load_owner_vanya($owner_id);
        if (!$ov || empty($ov['token'])) die("Error: owner vanya not configured");
        $ov_token = (string)$ov['token'];
        $ov_locations = !empty($ov['locations']) ? $ov['locations'] : $GLOBALS['vanyaLocations'];
        $ov_cache_file = __DIR__ . '/' . basename((string)($ov['cache_file'] ?? "owner_vanya_cache_{$owner_id}.txt"));
        ini_set('max_execution_time', 0); @set_time_limit(0); @ignore_user_abort(true);
        $fetch_res = vanya_fetch_keys($ov_token, $ov_locations, $ov_cache_file, vanya_include_exit($ov));
        $collected = $fetch_res['keys'];
        $log_str = implode(", ", $fetch_res['log']);
        echo "OK:" . count($collected) . ":" . $log_str;
        exit;
    }

    // --- owner-specific vanya list/remove ---
    if ($act === 'vanya_list_owner' || $act === 'vanya_remove_owner') {
        $owner_id = (int)($_GET['owner_id'] ?? 0);
        if ($owner_id <= 0) die(json_encode(['ok'=>false,'error'=>'invalid owner_id']));
        $ov = load_owner_vanya($owner_id);
        $cache_file = __DIR__ . '/' . basename((string)($ov['cache_file'] ?? "owner_vanya_cache_{$owner_id}.txt"));
        if ($act === 'vanya_list_owner') {
            $countries = [];
            if (file_exists($cache_file)) {
                $lines = array_filter(array_map('trim', explode("\n", file_get_contents($cache_file))));
                foreach ($lines as $ln) {
                    $flag = vanya_line_flag($ln);
                    if (!isset($countries[$flag])) $countries[$flag] = 0;
                    $countries[$flag]++;
                }
            }
            $out = [];
            foreach ($countries as $k => $c) $out[] = ['key' => $k, 'count' => $c];
            usort($out, function($a,$b){ return $b['count'] <=> $a['count']; });
            header('Content-Type: application/json; charset=utf-8');
            die(json_encode(['ok'=>true, 'countries'=>$out], JSON_UNESCAPED_UNICODE));
        }
        if ($act === 'vanya_remove_owner') {
            $country = (string)($_GET['country'] ?? '');
            if (!$country) die("Error");
            if (!file_exists($cache_file)) die("OK");
            $lines = array_filter(array_map('trim', explode("\n", file_get_contents($cache_file))));
            $kept = [];
            foreach ($lines as $ln) {
                $flag = vanya_line_flag($ln);
                if ($flag !== $country) $kept[] = $ln;
            }
            file_put_contents($cache_file, implode("\n", $kept));
            die("OK");
        }
    }

    if ($act === 'create') {
        $url = (string)($_GET['url'] ?? '');
        $reason = '';
        if (!marzban_url_allowed_strict($url, $reason)) {
            die("Error: MARZBAN_NOT_ALLOWED ($reason)");
        }

        $token = bin2hex(random_bytes(8));
        DB::create_client($token, [
            'name' => $_GET['name'] ?? 'Client',
            'url'  => $url,
            'hwid_limit' => 1,
            'created' => date('Y-m-d H:i'),
            'status' => 'active',
            'note' => '',
            'owner_id' => (int)($_GET['owner_id'] ?? 0),
            'created_by_id' => (int)($_GET['created_by_id'] ?? 0),
            'created_by_username' => (string)($_GET['created_by_username'] ?? ''),
            'created_by_role' => ($_GET['created_by_role'] ?? 'owner') === 'dealer' ? 'dealer' : 'owner'
        ]);
        die("OK:$token");
    }

    if ($act === 'list') {
        header('Content-Type: application/json; charset=utf-8');
        die(json_encode(DB::get_all_clients(), JSON_UNESCAPED_UNICODE));
    }

    // global vanya_list removed

    if ($t) {
        $client = DB::get_client($t);
        if (!$client) {
            header('Content-Type: application/json; charset=utf-8');
            die(json_encode(['ok'=>false, 'error'=>'NOT_FOUND']));
        }

        if ($act === 'refresh') {
            $raw_url = (string)($client['url'] ?? '');
            if (!$raw_url) die(json_encode(['ok'=>false,'error'=>'NO_URL'], JSON_UNESCAPED_UNICODE));

            $url = unwrap_proxy_url($raw_url);
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>true,
                CURLOPT_TIMEOUT=>25, CURLOPT_CONNECTTIMEOUT=>12,
                CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_HEADER=>true,
                CURLOPT_USERAGENT=>'Mozilla/5.0 (HappManager/refresh)'
            ]);
            $resp = curl_exec($ch);
            $h_size = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err  = (string)curl_error($ch);
            curl_close($ch);

            $out = ['ok'=>false, 'code'=>$code, 'used_url'=>$url];

            if ($resp === false) {
                $out['error'] = 'CURL_ERROR'; $out['curl_error'] = $err;
                die(json_encode($out, JSON_UNESCAPED_UNICODE));
            }

            $header = substr($resp, 0, $h_size);
            $body   = substr($resp, $h_size);

            $p = parse_userinfo_header($header);
            if (!empty($p['ok'])) {
                DB::update_client_stats($t, $p['u'], $p['d'], $p['t'], $p['e']);
                $out = ['ok'=>true, 'code'=>$code, 'stats'=>['u'=>$p['u'],'d'=>$p['d'],'t'=>$p['t'],'e'=>$p['e']]];
                die(json_encode($out, JSON_UNESCAPED_UNICODE));
            }

            $expire = parse_expire_from_html($body);
            if ($expire > 0) {
                DB::update_client($t, ['stats_e' => $expire]);
                $out = ['ok'=>true, 'code'=>$code, 'stats'=>['u'=>$client['stats']['u'],'d'=>$client['stats']['d'],'t'=>$client['stats']['t'],'e'=>$expire], 'source'=>'HTML'];
                die(json_encode($out, JSON_UNESCAPED_UNICODE));
            }

            $out['error'] = ($code >= 500 || $code === 0) ? 'MARZBAN_OFFLINE' : 'NO_STATS';
            die(json_encode($out, JSON_UNESCAPED_UNICODE));
        }

        if ($act === 'delete') { DB::delete_client($t); die("OK"); }
        if ($act === 'reset')  { DB::reset_devices($t); die("OK"); }
        if ($act === 'toggle') { 
            DB::update_client($t, ['status' => ($client['status'] === 'active' ? 'paused' : 'active')]); 
            die("OK"); 
        }
        if ($act === 'set_limit') { DB::update_client($t, ['hwid_limit' => (int)($_GET['limit'] ?? 1)]); die("OK"); }
        if ($act === 'note') { DB::update_client($t, ['note' => (string)($_GET['text'] ?? '')]); die("OK"); }
        if ($act === 'rename') { DB::update_client($t, ['name' => (string)($_GET['name'] ?? $client['name'])]); die("OK"); }
        if ($act === 'remove_device') { DB::remove_device($t, (string)($_GET['hwid'] ?? '')); die("OK"); }
    }

    // bulk_replace_domain — не требует $t, вызывается без токена клиента
    if ($act === 'bulk_replace_domain') {
        $old_host = strtolower(trim((string)($_GET['old_host'] ?? '')));
        $new_host = strtolower(trim((string)($_GET['new_host'] ?? '')));
        if (!$old_host || !$new_host) die("Error: missing params");
        if ($old_host === $new_host) die("OK:0");

        $all = DB::get_all_clients();
        $count = 0;
        foreach ($all as $cli_token => $client) {
            $url = (string)($client['url'] ?? '');
            if (!$url) continue;

            // Разворачиваем proxy-ссылку если нужно
            $real_url = unwrap_proxy_url($url);
            $parsed   = parse_url($real_url);
            $host     = strtolower($parsed['host'] ?? '');

            if ($host !== $old_host) continue;

            // Заменяем хост в реальном URL
            $new_real = preg_replace(
                '/^(https?:\/\/)' . preg_quote($old_host, '/') . '(:\d+)?(\/|$)/i',
                '$1' . $new_host . '$2$3',
                $real_url
            );
            if ($new_real === $real_url) continue; // ничего не поменялось

            // Если исходный URL был завёрнутым — подставляем обратно
            if ($url !== $real_url) {
                // пробуем URL-encoded вариант
                $new_url_wrapped = str_replace(urlencode($real_url), urlencode($new_real), $url);
                if ($new_url_wrapped === $url) {
                    // не совпало — пробуем без кодирования
                    $new_url_wrapped = str_replace($real_url, $new_real, $url);
                }
                $final_url = $new_url_wrapped;
            } else {
                $final_url = $new_real;
            }

            DB::update_client($cli_token, ['url' => $final_url]);
            $count++;
        }
        die("OK:$count");
    }
}


// =========================================================================
// ПРОВЕРКА КЛИЕНТА (Подключение VPN)
// =========================================================================
function cache_dir_ensure() {
    $dir = __DIR__ . '/cache';
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    return $dir;
}
function client_cache_file($token, $format = '') {
    $suffix = $format !== '' ? '_' . md5((string)$format) : '';
    return cache_dir_ensure() . '/client_' . sha1((string)$token) . $suffix . '.json';
}
function client_cache_read($token, $url, $ttl = 45, $format = '') {
    $f = client_cache_file($token, $format);
    if (!file_exists($f)) return null;
    $j = json_decode(@file_get_contents($f), true);
    if (!is_array($j)) return null;
    if (($j['token'] ?? '') !== (string)$token) return null;
    if (($j['url'] ?? '') !== (string)$url) return null;
    if ((time() - (int)($j['ts'] ?? 0)) > (int)$ttl) return null;
    if (!isset($j['body']) || !is_string($j['body'])) return null;
    if (!isset($j['headers']) || !is_array($j['headers'])) $j['headers'] = [];
    return $j;
}
function client_cache_write($token, $url, array $headers, $body, $format = '') {
    $f = client_cache_file($token, $format);
    $payload = [
        'ts' => time(),
        'token' => (string)$token,
        'url' => (string)$url,
        'headers' => array_values($headers),
        'body' => (string)$body,
    ];
    @file_put_contents($f, json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function send_cached_client_response(array $cache) {
    foreach (($cache['headers'] ?? []) as $h) {
        if (is_string($h) && $h !== '') header($h);
    }
    echo $cache['body'] ?? '';
    exit;
}
function v2box_remarks_file($token) {
    return cache_dir_ensure() . '/v2box_last_' . sha1((string)$token) . '.json';
}
function v2box_save_last_uris($token, array $uris) {
    $names = [];
    foreach ($uris as $u) {
        $r = v2box_uri_remark($u);
        if ($r !== '' && $r !== 'server') $names[] = $r;
    }
    @file_put_contents(v2box_remarks_file($token), json_encode(array_values(array_unique($names)), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function v2box_last_uris($token): array {
    $f = v2box_remarks_file($token);
    if (!is_file($f)) return [];
    $j = json_decode((string)@file_get_contents($f), true);
    return is_array($j) ? $j : [];
}
function v2box_uri_remark($uri): string {
    $uri = (string)$uri;
    if (preg_match('/#(.+)$/', $uri, $m)) {
        $r = trim(rawurldecode(str_replace('+', '%20', $m[1])));
        if ($r !== '') return $r;
    }
    return 'server';
}
function v2box_dead_uri($remark, $i = 0): string {
    $port = 1 + ($i % 9);
    return 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpkZWFk@127.0.0.1:' . $port . '#' . rawurlencode((string)$remark);
}
function v2box_client_title($fallback = 'Subscription'): string {
    $n = trim((string)($GLOBALS['sub_client_name'] ?? ''));
    return $n !== '' ? $n : (string)$fallback;
}

function v2box_block_response($title, $msg, array $remarks = []) {
    $token = (string)($_GET['token'] ?? '');
    $profile = v2box_client_title($title);
    $uris = [];
    $seen = [];
    if (!$remarks) {
        $remarks = v2box_last_uris($token);
    }
    foreach ($remarks as $i => $old) {
        $r = is_string($old) ? trim($old) : '';
        if ($r === '' || isset($seen[$r])) continue;
        $seen[$r] = true;
        $uris[] = v2box_dead_uri($r, $i);
    }
    if (!$uris) {
        $uris[] = v2box_dead_uri($title, 0);
    }
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Profile-Title: ' . $profile);
    header('announce: base64:' . base64_encode((string)$msg));
    header('Subscription-Userinfo: upload=0; download=0; total=1; expire=0');
    header('profile-update-interval: 1');
    echo base64_encode(implode("\n", $uris) . "\n");
    exit;
}

function die_denied($msg) {
    if (function_exists('sub_is_vpn_app') && !sub_is_vpn_app()) {
        camouflage_restaurant();
    }
    $title = 'STOP ' . $msg;
    if (function_exists('sub_is_v2box') && sub_is_v2box()) {
        v2box_block_response($title, $msg);
    }
    $headers = [
        'Content-Type: application/json; charset=utf-8',
        'Subscription-Userinfo: upload=0; download=0; total=0; expire=0',
        'Profile-Title: ' . $title,
    ];
    foreach ($headers as $h) header($h);
    echo json_encode([[
        'remarks' => $title,
        'outbounds' => [
            ['protocol' => 'freedom', 'tag' => 'direct'],
            ['protocol' => 'blackhole', 'tag' => 'block'],
        ],
    ]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function sub_is_v2box(): bool {
    $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    return strpos($ua, 'v2box') !== false;
}

function sub_is_happ(): bool {
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (preg_match('/\bHapp\//i', $ua)) return true;
    if (!empty($_SERVER['HTTP_X_HWID']) && preg_match('/happ/i', $ua)) return true;
    return false;
}

function sub_is_vpn_app(): bool {
    return sub_is_happ() || sub_is_v2box();
}

function camouflage_restaurant(): void {
    $page = __DIR__ . '/index.html';
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: public, max-age=300');
    header('X-Robots-Tag: noindex, nofollow');
    http_response_code(200);
    if (is_file($page)) {
        readfile($page);
    } else {
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ZeroSan — Japanese Restaurant, Ashgabat</title></head><body><h1>ZeroSan</h1><p>Japanese restaurant · Berkarar, Ashgabat</p></body></html>';
    }
    exit;
}

function sub_collect_request_headers(): array {
    $out = [];
    foreach ([
        function_exists('getallheaders') ? getallheaders() : null,
        function_exists('apache_request_headers') ? apache_request_headers() : null,
    ] as $h) {
        if (!is_array($h)) continue;
        foreach ($h as $k => $v) {
            $out[strtolower((string)$k)] = is_string($v) ? $v : (string)$v;
        }
    }
    foreach ($_SERVER as $k => $v) {
        if (!is_string($k) || strpos($k, 'HTTP_') !== 0) continue;
        $name = strtolower(str_replace('_', '-', substr($k, 5)));
        if (!isset($out[$name])) $out[$name] = (string)$v;
    }
    return $out;
}

function sub_request_hwid(): string {
    $hdrs = sub_collect_request_headers();
    $cands = [];
    foreach (['x-hwid', 'hwid', 'x-device-id', 'x-device-hwid', 'x-client-hwid', 'device-id', 'x-hardware-id'] as $k) {
        if (!empty($hdrs[$k])) $cands[] = (string)$hdrs[$k];
    }
    foreach ($hdrs as $k => $v) {
        if ($v === '') continue;
        if (preg_match('/hwid/', (string)$k)) $cands[] = (string)$v;
    }
    foreach (['hwid', 'x-hwid', 'HWID'] as $q) {
        if (!empty($_GET[$q])) $cands[] = (string)$_GET[$q];
    }
    $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    if (preg_match('/(?:^|[;\s])(?:hwid|x-hwid)[\/:=]([A-Za-z0-9._:-]{4,})/i', $ua, $m)) {
        $cands[] = $m[1];
    }
    foreach ($cands as $h) {
        $h = trim($h);
        if ($h === '' || preg_match('/^(null|undefined|none|nil|-)$/i', $h)) continue;
        if (strlen($h) < 4) continue;
        return $h;
    }
    return '';
}

function v2box_log_request($token, $raw_hwid): void {
    $hdrs = sub_collect_request_headers();
    $keep = [];
    foreach ($hdrs as $k => $v) {
        if (preg_match('/hwid|device|user-agent|ver-os|model|os/i', (string)$k)) {
            $keep[$k] = $v;
        }
    }
    $row = json_encode([
        'ts' => date('c'),
        'token' => substr((string)$token, 0, 12),
        'hwid' => (string)$raw_hwid,
        'ua' => (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
        'hdr' => $keep,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    @file_put_contents(cache_dir_ensure() . '/v2box_last.json', $row);
}

function v2box_hwid_required_response(): void {
    v2box_block_response(
        v2box_client_title(),
        "В V2Box: Subscription Settings → включите Send HWID. Без этого ключи не выдаются. Обновите подписку после включения."
    );
}

function configs_to_share_uris(array $raw_configs): array {
    $uris = [];
    $seen = [];
    foreach ($raw_configs as $cfg) {
        $cfg = trim((string)$cfg);
        if ($cfg === '' || (isset($cfg[0]) && $cfg[0] === '#')) continue;
        if (preg_match('/^[a-zA-Z0-9+\-.]+:\/\//', $cfg)) {
            if (!isset($seen[$cfg])) {
                $seen[$cfg] = true;
                $uris[] = $cfg;
            }
            continue;
        }
        if (!isset($cfg[0]) || ($cfg[0] !== '{' && $cfg[0] !== '[')) continue;
        if (!function_exists('config_line_to_xray_servers') || !function_exists('json_outbound_to_uri')) continue;
        foreach (config_line_to_xray_servers($cfg) as $server) {
            if (!is_array($server)) continue;
            $name = (string)($server['remarks'] ?? 'Server');
            foreach ((array)($server['outbounds'] ?? []) as $ob) {
                if (!is_array($ob)) continue;
                $tag = strtolower((string)($ob['tag'] ?? ''));
                $proto = strtolower((string)($ob['protocol'] ?? ''));
                if (in_array($tag, ['direct', 'block', 'dns-out'], true)) continue;
                if (in_array($proto, ['freedom', 'blackhole', 'dns'], true)) continue;
                $u = json_outbound_to_uri($ob, $name);
                if (is_string($u) && $u !== '' && !isset($seen[$u])) {
                    $seen[$u] = true;
                    $uris[] = $u;
                }
            }
        }
    }
    return $uris;
}

$token = $_GET['token'] ?? '';
if (!$token) die_denied("ACCOUNT DELETED");

$user = DB::get_client($token);
if (!$user) die_denied("ACCOUNT DELETED");
$GLOBALS['sub_client_name'] = (string)($user['name'] ?? '');
if (($user['status'] ?? '') === 'paused') die_denied("PAUSED");

$reason = '';
if (!marzban_url_allowed_strict((string)($user['url'] ?? ''), $reason)) {
    die_denied("PANEL NOT ALLOWED");
}

$is_v2box = sub_is_v2box();
$is_happ = sub_is_happ();
if (!$is_v2box && !$is_happ) {
    camouflage_restaurant();
}
$raw_hwid = sub_request_hwid();
if ($is_v2box) {
    v2box_log_request($token, $raw_hwid);
}
$skip_device = ($is_v2box && $raw_hwid === '');
$hwid = $raw_hwid !== '' ? $raw_hwid : ("WEAK-" . md5(($_SERVER['HTTP_USER_AGENT'] ?? '') . ($_SERVER['REMOTE_ADDR'] ?? '')));
$limit = (int)($user['hwid_limit'] ?? 1);
$found = false;

if (!isset($user['devices']) || !is_array($user['devices'])) $user['devices'] = [];
if (!$skip_device) {
foreach ($user['devices'] as $dev) {
    if (($dev['id'] ?? '') === $hwid) {
        DB::update_device_seen($token, $hwid, date('d.m.Y H:i'));
        $found = true;
        break;
    }
}

if (!$found && $raw_hwid !== '') {
    foreach ($user['devices'] as $dev) {
        $id = (string)($dev['id'] ?? '');
        if (strpos($id, 'WEAK-') === 0 && method_exists('DB', 'remove_device')) {
            DB::remove_device($token, $id);
            $user['devices'] = array_values(array_filter($user['devices'], static function ($d) use ($id) {
                return ($d['id'] ?? '') !== $id;
            }));
        }
    }
}

if (!$found) {
    if (count($user['devices']) < $limit) {
        DB::add_device($token, [
            'id' => $hwid,
            'model' => $_SERVER['HTTP_X_DEVICE_MODEL'] ?? 'Unknown',
            'os' => $_SERVER['HTTP_X_VER_OS'] ?? '',
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'date' => date('d.m.Y H:i'),
            'last_seen' => date('d.m.Y H:i')
        ]);
    } else {
        die_denied("DEVICE LIMIT REACHED ($limit)");
    }
}
}

$client_url = (string)$user['url'];
// Platform-specific JSON cache (android=tun xray0, ios/desktop=socks only)
if (!function_exists('happ_detect_client_platform')) {
    function happ_detect_client_platform(): string {
        $ua = strtolower((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $device_os = strtolower((string)($_SERVER['HTTP_X_DEVICE_OS'] ?? ''));
        $ver_os = strtolower((string)($_SERVER['HTTP_X_VER_OS'] ?? ''));
        $model = strtolower((string)($_SERVER['HTTP_X_DEVICE_MODEL'] ?? ''));
        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $k => $v) {
                $lk = strtolower((string)$k);
                $vv = strtolower((string)$v);
                if ($lk === 'x-device-os' && $device_os === '') $device_os = $vv;
                if ($lk === 'x-ver-os' && $ver_os === '') $ver_os = $vv;
                if ($lk === 'x-device-model' && $model === '') $model = $vv;
            }
        }
        $blob = $ua . ' ' . $device_os . ' ' . $ver_os . ' ' . $model;

        $q = strtolower((string)($_GET['platform'] ?? ''));
        if ($q === 'ios' || $q === 'iphone' || $q === 'ipados') return 'ios';
        if ($q === 'android') return 'android';
        if (in_array($q, ['windows', 'macos', 'linux', 'desktop'], true)) return 'desktop';

        if (preg_match('/iphone|ipad|ipod|\bios\b|ipados|cfnetwork|tvos/', $blob)) return 'ios';
        if (preg_match('/android/', $blob)) return 'android';
        if (preg_match('/windows|win64|win32|macos|mac os|macintosh|linux|ubuntu|debian|fedora/', $blob)) return 'desktop';
        // Happ Android UA is often just "Happ/x.y.z" without OS in the string.
        // Only treat as desktop when X-Device-Os / model actually says Windows/macOS/Linux.
        return 'android';
    }
}
$GLOBALS['HAPP_CLIENT_PLATFORM'] = happ_detect_client_platform();
$hb_uid = (int)($user['created_by_id'] ?? 0);
if ($hb_uid <= 0) $hb_uid = (int)($user['owner_id'] ?? 0);
$hb_brand = function_exists('hb_load_for') ? hb_load_for($hb_uid) : ['announce'=>'','support_url'=>'','web_url'=>'','server_description'=>''];
$_hd = hd_load_for_uid($hb_uid);
$vanya_cache_mtime = '0';
if ($hb_uid > 0) {
    $ov_sync = load_owner_vanya($hb_uid);
    if (is_array($ov_sync) && ($ov_sync['enabled'] ?? false) === true) {
        $ov_cf = __DIR__ . '/' . basename((string)($ov_sync['cache_file'] ?? "owner_vanya_cache_{$hb_uid}.txt"));
        if (is_file($ov_cf)) $vanya_cache_mtime = (string)@filemtime($ov_cf);
    }
}
if (!empty($is_v2box)) {
    $req_format = 'v2box-b64-v1-' . substr(md5(json_encode($hb_brand)), 0, 8);
} else {
    $req_format = 'happ-b64-' . $GLOBALS['HAPP_CLIENT_PLATFORM'] . '-v39-' . substr(md5(json_encode($hb_brand) . $vanya_cache_mtime), 0, 8);
}
$cache = client_cache_read($token, $client_url, 45, $req_format);
if ($cache && !($is_v2box && $raw_hwid === '')) send_cached_client_response($cache);

// ── Запрашиваем Marzban ──
$marzban_online = false;
$configs = [];
$upload = 0; $download = 0; $total = 0; $expire = 0;

$ch = curl_init($client_url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_CONNECTTIMEOUT => 4,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_HEADER => true,
]);
$resp = curl_exec($ch);
$h_size = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($code == 200 && is_string($resp) && $resp !== '') {
    $marzban_online = true;
    $header = substr($resp, 0, $h_size);
    $body   = substr($resp, $h_size);

    if (preg_match('/subscription-userinfo:\s*(.*)/i', $header, $matches)) {
        $stats_str = trim($matches[1]);
        preg_match('/upload=(\d+)/', $stats_str, $u_m); $upload = (int)($u_m[1] ?? 0);
        preg_match('/download=(\d+)/', $stats_str, $d_m); $download = (int)($d_m[1] ?? 0);
        preg_match('/total=(\d+)/', $stats_str, $t_m); $total = (int)($t_m[1] ?? 0);
        preg_match('/expire=(\d+)/', $stats_str, $e_m); $expire = (int)($e_m[1] ?? 0);
        DB::update_client_stats($token, $upload, $download, $total, $expire);
    }

    if ($expire > 0 && $expire < time()) die_denied("EXPIRED");

    $configs = happ_decode_subscription_body((string)$body);
} else {
    // Marzban оффлайн — берём последние известные статы из БД
    $upload  = (int)($user['stats']['u'] ?? 0);
    $download = (int)($user['stats']['d'] ?? 0);
    $total   = (int)($user['stats']['t'] ?? 0);
    $expire  = (int)($user['stats']['e'] ?? 0);

    // Если подписка истекла по последним данным — блокируем
    if ($expire > 0 && $expire < time()) die_denied("EXPIRED");
}

// ── Дядя Ваня + импортные конфиги (всегда, независимо от Marzban) ──
$creator_id  = (int)($user['created_by_id'] ?? 0);
$client_role = (string)($user['created_by_role'] ?? '');

if ($creator_id > 0) {
    $is_vanya_enabled = true;
    if ($client_role === 'dealer' && vanya_disabled_for_dealer($creator_id)) {
        $is_vanya_enabled = false;
    }

    if ($is_vanya_enabled) {
        $ov = load_owner_vanya($creator_id);
        if ($ov && ($ov['enabled'] ?? false) === true) {
            $ov_cache_path = __DIR__ . '/' . basename((string)($ov['cache_file'] ?? "owner_vanya_cache_{$creator_id}.txt"));
            if (file_exists($ov_cache_path) && filesize($ov_cache_path) > 0) {
                $include_exit = vanya_include_exit($ov);
                foreach (explode("\n", (string)file_get_contents($ov_cache_path)) as $ln) {
                    foreach (vanya_filter_cache_line($ln, $include_exit) as $keep) {
                        $configs[] = $keep;
                    }
                }
            }
        }
    }
}

if (file_exists($free_pool_file)) {
    $configs = array_merge($configs, array_filter(explode("\n", file_get_contents($free_pool_file))));
}

if ($creator_id > 0) {
    $owner_cfg = __DIR__ . "/owner_configs_{$creator_id}.txt";
    if (file_exists($owner_cfg)) {
        $configs = array_merge($configs, array_filter(array_map('trim', explode("\n", file_get_contents($owner_cfg)))));
    }
}

// ── Helpers to process JSON configs and URIs for Happ ──
function json_outbound_to_uri(array $outbound, string $default_name = 'Server'): ?string {
    $proto = strtolower((string)($outbound['protocol'] ?? ''));
    $tag = (string)($outbound['tag'] ?? $outbound['name'] ?? $default_name);
    $settings = (array)($outbound['settings'] ?? []);
    $stream = (array)($outbound['streamSettings'] ?? []);

    if ($proto === 'shadowsocks') {
        $servers = $settings['servers'] ?? [];
        if (!empty($servers[0])) {
            $s = $servers[0];
            $addr = $s['address'] ?? '';
            $port = (int)($s['port'] ?? 0);
            $method = $s['method'] ?? '';
            $password = $s['password'] ?? '';
            if ($addr && $port && $method && $password) {
                $userinfo = base64_encode($method . ':' . $password);
                return "ss://{$userinfo}@{$addr}:{$port}#" . rawurlencode($tag);
            }
        }
    } elseif ($proto === 'vless') {
        $vnext = $settings['vnext'] ?? [];
        if (!empty($vnext[0])) {
            $v = $vnext[0];
            $addr = $v['address'] ?? '';
            $port = (int)($v['port'] ?? 0);
            $users = $v['users'] ?? [];
            $uuid = $users[0]['id'] ?? '';
            $flow = $users[0]['flow'] ?? '';
            $net = $stream['network'] ?? 'tcp';
            $sec = $stream['security'] ?? 'none';
            if ($addr && $port && $uuid) {
                $params = [];
                if ($flow) $params['flow'] = $flow;
                if ($net !== 'tcp') $params['type'] = $net;
                if ($sec !== 'none') $params['security'] = $sec;
                if ($sec === 'reality') {
                    $rs = (array)($stream['realitySettings'] ?? []);
                    if (!empty($rs['serverName'])) $params['sni'] = $rs['serverName'];
                    if (!empty($rs['publicKey'])) $params['pbk'] = $rs['publicKey'];
                    if (!empty($rs['shortId'])) $params['sid'] = $rs['shortId'];
                    if (!empty($rs['spiderX'])) $params['spx'] = $rs['spiderX'];
                    if (!empty($rs['fingerprint'])) $params['fp'] = $rs['fingerprint'];
                } elseif ($sec === 'tls') {
                    $ts = (array)($stream['tlsSettings'] ?? []);
                    if (!empty($ts['serverName'])) $params['sni'] = $ts['serverName'];
                }
                $q = http_build_query($params);
                $qs = $q ? "?$q" : '';
                return "vless://{$uuid}@{$addr}:{$port}{$qs}#" . rawurlencode($tag);
            }
        }
    } elseif ($proto === 'trojan') {
        $servers = $settings['servers'] ?? [];
        if (!empty($servers[0])) {
            $s = $servers[0];
            $addr = $s['address'] ?? '';
            $port = (int)($s['port'] ?? 0);
            $pass = $s['password'] ?? '';
            if ($addr && $port && $pass) {
                return "trojan://{$pass}@{$addr}:{$port}?security=tls#" . rawurlencode($tag);
            }
        }
    } elseif ($proto === 'vmess') {
        $vnext = $settings['vnext'] ?? [];
        if (!empty($vnext[0])) {
            $v = $vnext[0];
            $addr = $v['address'] ?? '';
            $port = (int)($v['port'] ?? 0);
            $users = $v['users'] ?? [];
            $uuid = $users[0]['id'] ?? '';
            if ($addr && $port && $uuid) {
                $vmess_json = [
                    'v' => '2',
                    'ps' => $tag,
                    'add' => $addr,
                    'port' => (string)$port,
                    'id' => $uuid,
                    'aid' => '0',
                    'scy' => 'auto',
                    'net' => $stream['network'] ?? 'tcp',
                    'type' => 'none',
                    'tls' => ($stream['security'] ?? '') === 'tls' ? 'tls' : ''
                ];
                return 'vmess://' . base64_encode(json_encode($vmess_json, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
        }
    }
    return null;
}

function happ_uri_fragment_name(string $uri): string {
    $pos = strpos($uri, '#');
    if ($pos === false) return '';
    $name = rawurldecode(substr($uri, $pos + 1));
    // Happ: #title?serverDescription=...
    if (strpos($name, '?') !== false) $name = explode('?', $name, 2)[0];
    return trim($name);
}

/** v2rayN-style share-link split. PHP parse_url breaks passwords with : @ / + */
function happ_split_share_uri(string $uri): ?array {
    $uri = trim($uri);
    if (!preg_match('~^([a-z0-9+.-]+)://(.+)$~i', $uri, $m)) return null;
    $scheme = strtolower($m[1]);
    $rest = $m[2];
    $name = '';
    $hash = strrpos($rest, '#');
    if ($hash !== false) {
        $name = happ_uri_fragment_name('x://h#' . substr($rest, $hash + 1));
        $rest = substr($rest, 0, $hash);
    }
    $query_raw = '';
    $qpos = strpos($rest, '?');
    if ($qpos !== false) {
        $query_raw = substr($rest, $qpos + 1);
        $rest = substr($rest, 0, $qpos);
    }
    $userinfo = '';
    $hostport = $rest;
    $at = strrpos($rest, '@');
    if ($at !== false) {
        $userinfo = substr($rest, 0, $at);
        $hostport = substr($rest, $at + 1);
    }
    $host = '';
    $port = 0;
    $hostport = trim($hostport);
    if ($hostport !== '' && $hostport[0] === '[') {
        $rb = strpos($hostport, ']');
        if ($rb === false) return null;
        $host = substr($hostport, 1, $rb - 1);
        if (isset($hostport[$rb + 1]) && $hostport[$rb + 1] === ':') {
            $port = (int)substr($hostport, $rb + 2);
        }
    } else {
        $colon = strrpos($hostport, ':');
        if ($colon !== false && ctype_digit((string)substr($hostport, $colon + 1))) {
            $host = substr($hostport, 0, $colon);
            $port = (int)substr($hostport, $colon + 1);
        } else {
            $host = $hostport;
        }
    }
    $host = trim($host);
    if ($host !== '' && $host[0] === '[' && substr($host, -1) === ']') {
        $host = substr($host, 1, -1);
    }
    return [
        'scheme' => $scheme,
        'userinfo' => rawurldecode(str_replace('+', '%2B', $userinfo)),
        'host' => $host,
        'port' => $port,
        'query' => happ_parse_query_string($query_raw),
        'name' => $name,
    ];
}

function happ_parse_query_string(string $q): array {
    $q = trim($q);
    if ($q === '') return [];
    $hash = strpos($q, '#');
    if ($hash !== false) $q = substr($q, 0, $hash);
    $out = [];
    foreach (explode('&', $q) as $pair) {
        if ($pair === '') continue;
        $parts = explode('=', $pair, 2);
        $k = urldecode(str_replace('+', ' ', $parts[0]));
        $v = isset($parts[1]) ? urldecode($parts[1]) : '';
        if ($k === '') continue;
        $out[$k] = $v;
    }
    return $out;
}

function happ_parse_query(string $uri): array {
    $qpos = strpos($uri, '?');
    if ($qpos === false) return [];
    return happ_parse_query_string(substr($uri, $qpos + 1));
}

function happ_query_is_true($v): bool {
    $v = strtolower(trim((string)$v));
    return in_array($v, ['1', 'true', 'yes', 'on'], true);
}

function happ_query_get(array $q, array $keys): string {
    foreach ($keys as $k) {
        if (isset($q[$k]) && (string)$q[$k] !== '') return (string)$q[$k];
    }
    foreach ($q as $qk => $qv) {
        foreach ($keys as $k) {
            if (strcasecmp((string)$qk, (string)$k) === 0 && (string)$qv !== '') {
                return (string)$qv;
            }
        }
    }
    return '';
}

function happ_normalize_sha256_pin(string $pin): string {
    $pin = trim($pin);
    $pin = preg_replace('/^(sha-?256:)/i', '', $pin) ?? $pin;
    $pin = str_replace([':', ' ', '-', '_'], '', $pin);
    $pin = strtoupper($pin);
    return preg_match('/^[A-F0-9]{64}$/', $pin) ? $pin : '';
}

function happ_as_object($v) {
    if ($v instanceof \stdClass) return $v;
    if (!is_array($v) || $v === []) return new \stdClass();
    return $v;
}

function happ_decode_subscription_body(string $body): array {
    $body = trim(preg_replace('/^\xEF\xBB\xBF/', '', $body));
    if ($body === '') return [];

    $split_lines = static function (string $text): array {
        $parts = preg_split('/\r\n|\r|\n/', $text);
        if (!is_array($parts)) return [];
        $out = [];
        foreach ($parts as $ln) {
            $ln = trim((string)$ln);
            if ($ln === '' || $ln[0] === '#') continue;
            $out[] = $ln;
        }
        return $out;
    };

    if ($body[0] === '[' || $body[0] === '{') {
        return [$body];
    }
    if (preg_match('/^(vless|vmess|trojan|trojan-go|ss|ssconf|hy2|hysteria2|tuic|socks5?|http):\/\//im', $body)) {
        return $split_lines($body);
    }

    $b64 = preg_replace('/\s+/', '', $body);
    $pad = strlen($b64) % 4;
    if ($pad) $b64 .= str_repeat('=', 4 - $pad);
    $dec = base64_decode($b64, false);
    if (!is_string($dec) || $dec === '') return [];
    $dec = trim($dec);
    if ($dec === '') return [];
    if ($dec[0] === '[' || $dec[0] === '{') return [$dec];
    return $split_lines($dec);
}

function happ_pin_from_query(array $q): string {
    $raw = happ_query_get($q, [
        'pinSHA256',
        'pinSha256',
        'pinsha256',
        'pinnedPeerCertSha256',
        'pinnedpeercertsha256',
        'pin',
        'pcs',
        'certSha',
    ]);
    return $raw !== '' ? happ_normalize_sha256_pin($raw) : '';
}

/** Minimal Happ/Xray server config: remarks + outbounds (Xray protocol style) */
function happ_default_mux(): array {
    return [
        'enabled' => false,
        'concurrency' => -1,
        'xudpConcurrency' => 8,
        'xudpProxyUDP443' => '',
    ];
}

function happ_ensure_proxy_outbound(array $ob): array {
    if (empty($ob['tag'])) $ob['tag'] = 'proxy';
    if (!isset($ob['mux']) || !is_array($ob['mux'])) {
        $ob['mux'] = happ_default_mux();
    }
    // streamSettings defaults
    if (!isset($ob['streamSettings']) || !is_array($ob['streamSettings'])) {
        $ob['streamSettings'] = ['network' => 'tcp', 'security' => ''];
    }
    $ss = &$ob['streamSettings'];
    if (!isset($ss['network']) || $ss['network'] === '') $ss['network'] = 'tcp';
    if (!isset($ss['security']) || $ss['security'] === '') $ss['security'] = 'none';
    foreach (['xhttpSettings','wsSettings','grpcSettings','httpSettings','tcpSettings','kcpSettings','httpupgradeSettings','tlsSettings','realitySettings','hysteriaSettings','quicSettings','grpcSettings'] as $objKey) {
        if (!array_key_exists($objKey, $ss)) continue;
        if (is_array($ss[$objKey]) && $ss[$objKey] === []) $ss[$objKey] = new \stdClass();
    }
    // tcp header none — Happ uses this for plain tcp. Working Vision/Reality JSON has NO tcpSettings.
    $net = strtolower((string)$ss['network']);
    $sec = strtolower((string)($ss['security'] ?? ''));
    if ($sec === 'reality') {
        unset($ss['tcpSettings']);
    } elseif ($net === 'tcp' && empty($ss['tcpSettings'])) {
        $ss['tcpSettings'] = ['header' => ['type' => 'none']];
    }
    // SS-specific server fields
    if (strtolower((string)($ob['protocol'] ?? '')) === 'shadowsocks') {
        if (isset($ob['settings']['servers']) && is_array($ob['settings']['servers'])) {
            foreach ($ob['settings']['servers'] as $i => $srv) {
                if (!is_array($srv)) continue;
                if (!array_key_exists('ota', $srv)) $ob['settings']['servers'][$i]['ota'] = false;
                if (!isset($srv['level'])) $ob['settings']['servers'][$i]['level'] = 8;
            }
        }
    }
    // VLESS — Happ export / working Vanya shape: vnext + users.security=auto.
    // Do NOT flatten to address/port/id: Happ 26.6 still feeds Xray via vnext.
    if (strtolower((string)($ob['protocol'] ?? '')) === 'vless') {
        $st = isset($ob['settings']) && is_array($ob['settings']) ? $ob['settings'] : [];
        if (!isset($st['vnext']) && isset($st['address']) && isset($st['id'])) {
            $st = [
                'vnext' => [[
                    'address' => (string)$st['address'],
                    'port' => (int)($st['port'] ?? 443),
                    'users' => [[
                        'id' => (string)$st['id'],
                        'encryption' => (string)(($st['encryption'] ?? '') ?: 'none'),
                        'flow' => (string)($st['flow'] ?? ''),
                        'level' => (int)($st['level'] ?? 8),
                        'security' => 'auto',
                    ]],
                ]],
            ];
        }
        $vision = false;
        if (isset($st['vnext']) && is_array($st['vnext'])) {
            foreach ($st['vnext'] as $vi => $vn) {
                if (empty($vn['users']) || !is_array($vn['users'])) continue;
                foreach ($vn['users'] as $ui => $u) {
                    if (!is_array($u)) continue;
                    if (!array_key_exists('flow', $u)) $st['vnext'][$vi]['users'][$ui]['flow'] = '';
                    if (!isset($u['encryption']) || $u['encryption'] === '') {
                        $st['vnext'][$vi]['users'][$ui]['encryption'] = 'none';
                    }
                    if (!isset($u['level'])) $st['vnext'][$vi]['users'][$ui]['level'] = 8;
                    if (!isset($u['security'])) $st['vnext'][$vi]['users'][$ui]['security'] = 'auto';
                    if (stripos((string)($st['vnext'][$vi]['users'][$ui]['flow'] ?? ''), 'vision') !== false) {
                        $vision = true;
                    }
                }
            }
        }
        unset($st['address'], $st['port'], $st['id'], $st['encryption'], $st['flow']);
        if ($vision) $st['packetEncoding'] = 'xudp';
        else unset($st['packetEncoding']);
        $ob['settings'] = $st;
        $ob['mux'] = happ_default_mux();
        if ($vision) $ob['mux']['xudpProxyUDP443'] = 'reject';
        if (isset($ob['streamSettings']['realitySettings']) && is_array($ob['streamSettings']['realitySettings'])) {
            $rs = &$ob['streamSettings']['realitySettings'];
            unset($rs['show']);
            $pk = trim((string)($rs['password'] ?? $rs['publicKey'] ?? ''));
            if ($pk !== '') {
                // Xray 26: field renamed publicKey → password (required). Keep both.
                $rs['password'] = $pk;
                $rs['publicKey'] = $pk;
            }
            if (empty($rs['fingerprint'])) $rs['fingerprint'] = 'chrome';
            if (!array_key_exists('shortId', $rs)) $rs['shortId'] = '';
            unset($rs);
        }
    }
    return $ob;
}

/**
 * Happ JSON 1:1 with what the Android app itself exports.
 *
 * Android: socks 10808 + tun tag "tun" / interface name "xray0".
 * iOS: socks only (Network Extension injects the tunnel).
 * Desktop: socks 10808 + http 10809, no tun (Wintun is owned by the app).
 */
function happ_xray_wrap_full(string $remarks, array $outbounds): array {
    $remarks = trim($remarks) !== '' ? $remarks : 'Server';
    $platform = (string)($GLOBALS['HAPP_CLIENT_PLATFORM'] ?? 'android');
    $is_android = ($platform === 'android');
    $is_desktop = ($platform === 'desktop' || $platform === 'windows' || $platform === 'macos' || $platform === 'linux');

    $clean = [];
    foreach ($outbounds as $ob) {
        if (!is_array($ob)) continue;
        $proto = strtolower((string)($ob['protocol'] ?? ''));
        if (in_array($proto, ['freedom', 'blackhole', 'dns'], true)) {
            $clean[] = $ob;
            continue;
        }
        $clean[] = happ_ensure_proxy_outbound($ob);
    }
    $tags = [];
    foreach ($clean as $ob) $tags[(string)($ob['tag'] ?? '')] = true;
    if (empty($tags['direct'])) $clean[] = ['protocol' => 'freedom', 'tag' => 'direct'];
    if (empty($tags['block'])) $clean[] = ['protocol' => 'blackhole', 'tag' => 'block'];

    usort($clean, static function ($a, $b) {
        $rank = static function ($ob) {
            $t = (string)($ob['tag'] ?? '');
            if ($t === 'proxy') return 0;
            if ($t === 'personal') return 1;
            if ($t === 'direct') return 8;
            if ($t === 'block') return 9;
            return 2;
        };
        return $rank($a) <=> $rank($b);
    });

    // socks FIRST (required — Happ feeds TUN/NE packets into this inbound)
    $inbounds = [
        [
            'listen' => '127.0.0.1',
            'port' => 10808,
            'protocol' => 'socks',
            'settings' => [
                'auth' => 'noauth',
                'udp' => true,
                'userLevel' => 8,
            ],
            'sniffing' => [
                'destOverride' => ['http', 'tls', 'quic'],
                'enabled' => true,
            ],
            'tag' => 'socks',
        ],
    ];

    if ($is_desktop) {
        $inbounds[] = [
            'listen' => '127.0.0.1',
            'port' => 10809,
            'protocol' => 'http',
            'settings' => [
                'allowTransparent' => false,
                'userLevel' => 8,
            ],
            'sniffing' => [
                'destOverride' => ['http', 'tls', 'quic'],
                'enabled' => true,
            ],
            'tag' => 'http',
        ];
    }

    // Exact inbound Happ Android exports (tag=tun, name=xray0). iOS/desktop omit it.
    if ($is_android) {
        $inbounds[] = [
            'port' => 0,
            'protocol' => 'tun',
            'settings' => [
                'MTU' => 1500,
                'name' => 'xray0',
                'userLevel' => 8,
            ],
            'sniffing' => [
                'destOverride' => ['http', 'tls', 'quic'],
                'enabled' => true,
            ],
            'tag' => 'tun',
        ];
    }

    return [
        'remarks' => $remarks,
        'dns' => [
            'hosts' => [
                'domain:googleapis.cn' => 'googleapis.com',
            ],
            'queryStrategy' => 'UseIPv4',
            'servers' => [
                '1.1.1.1',
                [
                    'address' => '1.1.1.1',
                    'domains' => [],
                    'port' => 53,
                ],
                [
                    'address' => '8.8.8.8',
                    'domains' => [],
                    'port' => 53,
                ],
            ],
        ],
        'inbounds' => $inbounds,
        'outbounds' => array_values($clean),
        'policy' => [
            'levels' => [
                '8' => [
                    'connIdle' => 300,
                    'downlinkOnly' => 1,
                    'handshake' => 4,
                    'uplinkOnly' => 1,
                ],
            ],
            'system' => [
                'statsOutboundUplink' => true,
                'statsOutboundDownlink' => true,
            ],
        ],
        'routing' => [
            'domainStrategy' => 'IPIfNonMatch',
            'rules' => [
                [
                    'ip' => ['1.1.1.1'],
                    'outboundTag' => 'proxy',
                    'port' => '53',
                ],
                [
                    'ip' => ['8.8.8.8'],
                    'outboundTag' => 'direct',
                    'port' => '53',
                ],
                [
                    'ip' => [
                        '10.0.0.0/8',
                        '172.16.0.0/12',
                        '192.168.0.0/16',
                        '169.254.0.0/16',
                        '224.0.0.0/4',
                        '255.255.255.255',
                        '119.235.112.0/19',
                        '217.174.224.0/20',
                        '93.171.220.0/21',
                        '177.93.143.0/24',
                        '95.85.96.0/19',
                        '216.250.0.0/16',
                    ],
                    'outboundTag' => 'direct',
                ],
            ],
        ],
        'stats' => new \stdClass(),
    ];
}

function happ_xray_server(string $remarks, array $proxy_outbound): array {
    $remarks = trim($remarks) !== '' ? $remarks : 'Server';
    if (empty($proxy_outbound['tag'])) $proxy_outbound['tag'] = 'proxy';
    return happ_xray_wrap_full($remarks, [
        $proxy_outbound,
        ['protocol' => 'freedom', 'tag' => 'direct'],
        ['protocol' => 'blackhole', 'tag' => 'block'],
    ]);
}

function happ_decode_json_param($val) {
    if ($val === null || $val === '') return null;
    if (is_array($val)) return $val;
    if (!is_string($val)) return null;
    $raw = $val;
    // try raw, urldecode, rawurldecode
    foreach ([$raw, urldecode($raw), rawurldecode($raw)] as $candidate) {
        $j = json_decode($candidate, true);
        if (is_array($j)) return $j;
    }
    return null;
}

function happ_is_range_or_int(string $s): bool {
    $s = trim($s);
    if ($s === '') return false;
    if (preg_match('/^\d+$/', $s)) return true;
    if (preg_match('/^\d+\s*-\s*\d+$/', $s)) return true;
    return false;
}

function happ_normalize_fragment_settings(array $settings): array {
    // Ensure packets / length / delay are in the correct semantic slots.
    // Happ expects: packets=tlshello|range, length=int|range, delay=range
    $p = isset($settings['packets']) ? (string)$settings['packets'] : '';
    $l = isset($settings['length']) ? (string)$settings['length'] : '';
    $d = isset($settings['delay']) ? (string)$settings['delay'] : '';

    $is_packets_word = static function (string $s): bool {
        $s = strtolower(trim($s));
        return $s === 'tlshello' || $s === '1-3' || $s === '1-2' || $s === '1-4'
            || $s === '1-5' || preg_match('/^(tlshello|\d+\s*-\s*\d+)$/', $s);
    };

    // Detect rotated assignment: packets got a pure length, delay got tlshello
    if ($p !== '' && $d !== '' && !happ_is_range_or_int($d) && happ_is_range_or_int($p)) {
        // likely length,delay,packets was mapped as packets,length,delay
        // e.g. packets=2, length=0-1, delay=tlshello  → swap to correct
        if (strtolower($d) === 'tlshello' || !happ_is_range_or_int($d)) {
            $settings = [
                'packets' => $d,
                'length' => $p,
                'delay' => $l !== '' ? $l : '0-1',
            ];
            return $settings;
        }
    }

    // delay must be int/range; if not, try to recover
    if ($d !== '' && !happ_is_range_or_int($d) && strtolower($d) !== '') {
        if (strtolower($d) === 'tlshello' || !happ_is_range_or_int($d)) {
            // delay holds packets word
            $settings['packets'] = $d;
            if (happ_is_range_or_int($p)) {
                $settings['length'] = $p;
            }
            $settings['delay'] = happ_is_range_or_int($l) ? $l : '0-1';
            if (!isset($settings['length']) || !happ_is_range_or_int((string)$settings['length'])) {
                $settings['length'] = '2';
            }
        }
    }

    // Defaults
    if (empty($settings['packets'])) $settings['packets'] = 'tlshello';
    if (empty($settings['length'])) $settings['length'] = '2';
    if (empty($settings['delay']) || !happ_is_range_or_int((string)$settings['delay'])) {
        $settings['delay'] = '0-1';
    }
    // length must be int/range
    if (!happ_is_range_or_int((string)$settings['length'])) {
        $settings['length'] = '2';
    }

    return [
        'packets' => (string)$settings['packets'],
        'length' => (string)$settings['length'],
        'delay' => (string)$settings['delay'],
    ];
}

function happ_finalmask_from_query(array $q) {
    // Happ/v2ray: fm={...} or finalmask={...}
    foreach (['fm', 'finalmask', 'finalMask'] as $k) {
        if (!isset($q[$k]) || $q[$k] === '') continue;
        $decoded = happ_decode_json_param($q[$k]);
        if ($decoded === null) {
            if (trim((string)$q[$k]) === '{}' || trim(urldecode((string)$q[$k])) === '{}') {
                return new \stdClass();
            }
            continue;
        }
        if (empty($decoded)) return new \stdClass();
        // Normalize fragment settings inside fm JSON if present
        if (isset($decoded['tcp']) && is_array($decoded['tcp'])) {
            foreach ($decoded['tcp'] as $i => $item) {
                if (!is_array($item)) continue;
                if (strtolower((string)($item['type'] ?? '')) === 'fragment' && isset($item['settings']) && is_array($item['settings'])) {
                    $decoded['tcp'][$i]['settings'] = happ_normalize_fragment_settings($item['settings']);
                }
            }
        }
        return $decoded;
    }
    // fragment=… → Happ finalmask tcp fragment
    // Supported forms:
    //   tlshello,2,0-1          (packets,length,delay) — Happ/v2rayN classic
    //   2,0-1,tlshello          (length,delay,packets) — some panels
    //   1-3,100-200,10-20       (packets,length,delay) numeric ranges
    if (!empty($q['fragment']) && is_string($q['fragment'])) {
        $parts = array_values(array_filter(array_map('trim', explode(',', $q['fragment'])), static function ($x) {
            return $x !== '';
        }));
        $packets = 'tlshello';
        $length = '2';
        $delay = '0-1';
        if (count($parts) >= 3) {
            $a = $parts[0]; $b = $parts[1]; $c = $parts[2];
            // If last token is packets keyword (tlshello) → length,delay,packets
            if (!happ_is_range_or_int($c) && happ_is_range_or_int($a)) {
                $length = $a; $delay = $b; $packets = $c;
            } else {
                // packets,length,delay
                $packets = $a; $length = $b; $delay = $c;
            }
        } elseif (count($parts) === 2) {
            if (happ_is_range_or_int($parts[0])) {
                $length = $parts[0]; $delay = $parts[1];
            } else {
                $packets = $parts[0]; $length = $parts[1];
            }
        } elseif (count($parts) === 1) {
            if (!happ_is_range_or_int($parts[0])) $packets = $parts[0];
            else $length = $parts[0];
        }
        $settings = happ_normalize_fragment_settings([
            'packets' => $packets,
            'length' => $length,
            'delay' => $delay,
        ]);
        return [
            'tcp' => [[
                'type' => 'fragment',
                'settings' => $settings,
            ]],
        ];
    }
    return null;
}

function xray_stream_from_query(array $q): array {
    $net = strtolower((string)($q['type'] ?? $q['network'] ?? 'tcp'));
    if ($net === '' || $net === 'raw' || $net === 'original' || $net === 'none') $net = 'tcp';
    if ($net === 'h2') $net = 'http';
    if ($net === 'h2+ws' || $net === 'ws+h2') $net = 'ws';
    if ($net === 'splithttp') $net = 'xhttp';
    $security = strtolower((string)($q['security'] ?? $q['s'] ?? ''));
    if ($security === 'xtls') $security = 'tls';
    if ($security === 'none') $security = '';

    $stream = [
        'network' => $net,
        'security' => $security,
    ];

    // finalmask (fragment / kcp mask / etc.) — Happ-specific
    $fm = happ_finalmask_from_query($q);
    if ($fm !== null) {
        $stream['finalmask'] = $fm;
    } elseif ($net === 'xhttp' && $security === 'tls') {
        $stream['finalmask'] = [
            'tcp' => [[
                'type' => 'fragment',
                'settings' => [
                    'delay' => '0-1',
                    'length' => '2',
                    'packets' => 'tlshello',
                ],
            ]],
        ];
    }

    $sni = trim(happ_query_get($q, ['sni', 'peer', 'serverName', 'server_name']));
    $host_hdr = trim(happ_query_get($q, ['host', 'Host']));
    if ($sni === '' && $host_hdr !== '' && filter_var($host_hdr, FILTER_VALIDATE_IP) === false) {
        $sni = $host_hdr;
    }

    // TLS / REALITY
    if ($security === 'tls' || $security === 'reality') {
        $fp = trim(happ_query_get($q, ['fp', 'fingerprint']));
        $alpn = trim(happ_query_get($q, ['alpn']));
        $insecure = happ_query_is_true($q['allowInsecure'] ?? $q['insecure'] ?? $q['allow_insecure'] ?? '');
        if ($security === 'reality') {
            $rs = [];
            if ($sni !== '') $rs['serverName'] = $sni;
            if ($fp === '') $fp = 'chrome';
            $rs['fingerprint'] = $fp;
            $pbk = trim((string)($q['pbk'] ?? ''));
            if ($pbk !== '') {
                $rs['publicKey'] = $pbk;
                $rs['password'] = $pbk;
            }
            if (isset($q['sid'])) $rs['shortId'] = (string)$q['sid'];
            else $rs['shortId'] = '';
            $spx = happ_query_get($q, ['spx', 'spiderX', 'spiderx']);
            $rs['spiderX'] = $spx !== '' ? $spx : '/';
            if (!empty($q['pqv'])) $rs['mldsa65Verify'] = (string)$q['pqv'];
            $stream['realitySettings'] = $rs;
        } else {
            $ts = [
                'show' => false,
            ];
            if ($sni !== '') $ts['serverName'] = $sni;
            if ($fp !== '') $ts['fingerprint'] = $fp;
            if ($alpn !== '') {
                $ts['alpn'] = array_values(array_filter(array_map('trim', preg_split('/[;,]/', $alpn) ?: [])));
            }
            if ($insecure) $ts['allowInsecure'] = true;
            $pin = happ_pin_from_query($q);
            if ($pin !== '') $ts['pinnedPeerCertSha256'] = $pin;
            $ech = happ_query_get($q, ['ech']);
            if ($ech !== '') $ts['echConfigList'] = $ech;
            $vcn = happ_query_get($q, ['vcn', 'verifyPeerCertByName']);
            if ($vcn !== '') $ts['verifyPeerCertByName'] = $vcn;
            $stream['tlsSettings'] = $ts;
        }
    }

    $path = (string)($q['path'] ?? '');
    $headerType = strtolower(trim((string)($q['headerType'] ?? $q['header'] ?? '')));

    // Transport settings
    if ($net === 'ws') {
        $ws = [];
        $ws['path'] = $path !== '' ? $path : '/';
        if ($host_hdr !== '') {
            $ws['host'] = $host_hdr;
            $ws['headers'] = ['Host' => $host_hdr];
        }
        if (!empty($q['ed'])) {
            $ws['maxEarlyData'] = (int)$q['ed'];
            $ws['earlyDataHeaderName'] = 'Sec-WebSocket-Protocol';
        }
        $stream['wsSettings'] = $ws;
    } elseif ($net === 'grpc') {
        $gs = [];
        $svc = happ_query_get($q, ['serviceName', 'servicename', 'service_name']);
        if ($svc === '') $svc = $path;
        if ($svc !== '') $gs['serviceName'] = $svc;
        $mode = strtolower((string)($q['mode'] ?? ''));
        if ($mode === 'multi' || $mode === 'gun') $gs['multiMode'] = ($mode === 'multi');
        $auth = happ_query_get($q, ['authority', 'authority']);
        if ($auth !== '') $gs['authority'] = $auth;
        $stream['grpcSettings'] = $gs;
    } elseif ($net === 'http' || $net === 'h2') {
        $hs = [];
        if ($path !== '') $hs['path'] = [$path];
        if ($host_hdr !== '') $hs['host'] = [$host_hdr];
        $stream['httpSettings'] = $hs;
    } elseif ($net === 'kcp' || $net === 'mkcp') {
        $stream['network'] = 'kcp';
        $ks = [
            'mtu' => 1350, // keep TM-safe MTU
            'tti' => (int)($q['tti'] ?? 20),
            'uplinkCapacity' => (int)($q['uplinkCapacity'] ?? $q['uplink'] ?? 12),
            'downlinkCapacity' => (int)($q['downlinkCapacity'] ?? $q['downlink'] ?? 100),
            'congestion' => !empty($q['congestion']),
            'readBufferSize' => (int)($q['readBufferSize'] ?? 2),
            'writeBufferSize' => (int)($q['writeBufferSize'] ?? 2),
        ];
        if (!empty($q['headerType']) && $q['headerType'] !== 'none') {
            $ks['header'] = ['type' => (string)$q['headerType']];
        } else {
            $ks['header'] = ['type' => 'none'];
        }
        if (!empty($q['seed'])) $ks['seed'] = (string)$q['seed'];
        $stream['kcpSettings'] = $ks;
    } elseif ($net === 'tcp') {
        if ($headerType !== '' && $headerType !== 'none') {
            $hdr = ['type' => $headerType];
            if ($headerType === 'http') {
                $req_path = $path !== '' ? $path : '/';
                $req_host = $host_hdr !== '' ? $host_hdr : $sni;
                $hdr['request'] = [
                    'version' => '1.1',
                    'method' => 'GET',
                    'path' => [$req_path],
                    'headers' => [
                        'Host' => $req_host !== '' ? [$req_host] : [''],
                        'User-Agent' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
                        'Accept-Encoding' => ['gzip, deflate'],
                        'Connection' => ['keep-alive'],
                        'Pragma' => ['no-cache'],
                    ],
                ];
            }
            $stream['tcpSettings'] = ['header' => $hdr];
        }
    } elseif ($net === 'xhttp') {
        $stream['network'] = 'xhttp';
        $xs = [];
        if (!empty($q['path'])) $xs['path'] = (string)$q['path'];
        if (!empty($q['host'])) $xs['host'] = (string)$q['host'];
        if (!empty($q['mode'])) $xs['mode'] = (string)$q['mode'];

        // Nested extra JSON (Happ / v2rayN)
        $extra = null;
        if (!empty($q['extra'])) {
            $extra = happ_decode_json_param($q['extra']);
        }
        if (!is_array($extra)) $extra = [];

        // Flat query params → xhttpSettings + extra
        $flat_map = [
            'scMaxConcurrentPosts' => 'scMaxConcurrentPosts',
            'scMaxEachPostBytes' => 'scMaxEachPostBytes',
            'scMinPostsIntervalMs' => 'scMinPostsIntervalMs',
            'xPaddingBytes' => 'xPaddingBytes',
            'scStreamUpServerSecs' => 'scStreamUpServerSecs',
            'noGRPCHeader' => 'noGRPCHeader',
            'noSSEHeader' => 'noSSEHeader',
            'xmux' => 'xmux',
        ];
        foreach ($flat_map as $qk => $xk) {
            if (!isset($q[$qk]) || $q[$qk] === '') continue;
            $val = $q[$qk];
            // numeric-looking keep as int when pure digits
            if (is_string($val) && ctype_digit($val)) {
                $xs[$xk] = (int)$val;
            } else {
                $xs[$xk] = is_numeric($val) && strpos((string)$val, '-') === false && strpos((string)$val, ',') === false
                    ? (0 + $val)
                    : $val;
            }
        }

        // Merge explicit extra over flats into extra object (Happ style)
        foreach (['scMaxEachPostBytes', 'xPaddingBytes', 'scMaxConcurrentPosts', 'scMinPostsIntervalMs'] as $ek) {
            if (isset($xs[$ek]) && !isset($extra[$ek])) {
                // Happ keeps some both top-level and inside extra
                $extra[$ek] = is_int($xs[$ek]) ? (string)$xs[$ek] : $xs[$ek];
            }
        }
        if (!empty($extra)) {
            $xs['extra'] = $extra;
        }

        // Happ-compatible defaults when URI has mode but omits xhttp tuning fields
        if (!empty($xs['mode'])) {
            if (!isset($xs['scMaxConcurrentPosts'])) $xs['scMaxConcurrentPosts'] = 10;
            if (!isset($xs['scMaxEachPostBytes'])) $xs['scMaxEachPostBytes'] = 1000000;
            if (!isset($xs['scMinPostsIntervalMs'])) $xs['scMinPostsIntervalMs'] = '30';
            if (!isset($xs['extra']) || !is_array($xs['extra'])) $xs['extra'] = [];
            if (!isset($xs['extra']['scMaxEachPostBytes'])) $xs['extra']['scMaxEachPostBytes'] = (string)$xs['scMaxEachPostBytes'];
            if (!isset($xs['extra']['xPaddingBytes'])) $xs['extra']['xPaddingBytes'] = '100-1000';
        }

        if ($xs === []) $xs['mode'] = 'auto';
        $stream['xhttpSettings'] = happ_as_object($xs);
    } elseif ($net === 'httpupgrade') {
        $stream['network'] = 'httpupgrade';
        $hu = [];
        if (!empty($q['path'])) $hu['path'] = (string)$q['path'];
        if (!empty($q['host'])) $hu['host'] = (string)$q['host'];
        $stream['httpupgradeSettings'] = happ_as_object($hu);
    } elseif ($net === 'quic') {
        $stream['network'] = 'quic';
        $qs = [
            'security' => strtolower(happ_query_get($q, ['quicSecurity', 'quicsecurity']) ?: 'none'),
            'key' => happ_query_get($q, ['key', 'quicKey']),
            'header' => ['type' => ($headerType !== '' ? $headerType : 'none')],
        ];
        $stream['quicSettings'] = $qs;
    }

    return $stream;
}

function vless_uri_to_xray(string $uri, string $name): ?array {
    $p = happ_split_share_uri($uri);
    if (!$p) return null;
    $uuid = (string)($p['userinfo'] ?? '');
    $host = (string)($p['host'] ?? '');
    $port = (int)($p['port'] ?? 0);
    if ($port <= 0) $port = 443;
    if ($uuid === '' || $host === '') return null;
    $q = $p['query'];
    if ($name === '') $name = (string)($p['name'] ?? '');
    $flow = trim((string)($q['flow'] ?? ''));
    $enc = trim((string)($q['encryption'] ?? 'none'));
    if ($enc === '') $enc = 'none';

    $settings = [
        'vnext' => [[
            'address' => $host,
            'port' => $port,
            'users' => [[
                'id' => $uuid,
                'encryption' => $enc,
                'flow' => $flow,
                'level' => 8,
                'security' => 'auto',
            ]],
        ]],
    ];

    $ob = [
        'protocol' => 'vless',
        'tag' => 'proxy',
        'settings' => $settings,
        'streamSettings' => xray_stream_from_query($q),
        'mux' => happ_default_mux(),
    ];
    return happ_xray_server($name !== '' ? $name : $host, $ob);
}

function trojan_uri_to_xray(string $uri, string $name): ?array {
    $p = happ_split_share_uri($uri);
    if (!$p) return null;
    $password = (string)($p['userinfo'] ?? '');
    $host = (string)($p['host'] ?? '');
    $port = (int)($p['port'] ?? 0);
    if ($port <= 0) $port = 443;
    if ($password === '' || $host === '') return null;
    $q = $p['query'];
    if ($name === '') $name = (string)($p['name'] ?? '');

    $sec = strtolower(trim((string)($q['security'] ?? $q['s'] ?? '')));
    if ($sec === '' || $sec === 'none' || $sec === 'xtls') $q['security'] = 'tls';

    $server = [
        'address' => $host,
        'port' => $port,
        'password' => $password,
        'level' => 8,
    ];
    $flow = trim((string)($q['flow'] ?? ''));
    if ($flow !== '') $server['flow'] = $flow;

    $ob = [
        'protocol' => 'trojan',
        'tag' => 'proxy',
        'settings' => [
            'servers' => [$server],
        ],
        'streamSettings' => xray_stream_from_query($q),
        'mux' => happ_default_mux(),
    ];
    return happ_xray_server($name !== '' ? $name : $host, $ob);
}

function happ_ss_b64_decode(string $s): string {
    $s = strtr(trim($s), '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad) $s .= str_repeat('=', 4 - $pad);
    $d = base64_decode($s, false);
    return is_string($d) ? $d : '';
}

function happ_ss_split_method_pass(string $userinfo): array {
    $userinfo = trim($userinfo);
    if ($userinfo === '') return ['', ''];
    $plain = $userinfo;
    if (strpos($userinfo, ':') === false) {
        $dec = happ_ss_b64_decode($userinfo);
        if ($dec !== '' && strpos($dec, ':') !== false) $plain = $dec;
    } else {
        $plain = rawurldecode($userinfo);
    }
    $colon = strpos($plain, ':');
    if ($colon === false) return ['', ''];
    return [substr($plain, 0, $colon), substr($plain, $colon + 1)];
}

function happ_ss_split_hostport(string $hostport): array {
    $hostport = trim($hostport);
    $host = '';
    $port = 0;
    if ($hostport !== '' && $hostport[0] === '[') {
        $rb = strpos($hostport, ']');
        if ($rb === false) return ['', 0];
        $host = substr($hostport, 1, $rb - 1);
        if (isset($hostport[$rb + 1]) && $hostport[$rb + 1] === ':') {
            $port = (int)substr($hostport, $rb + 2);
        }
    } else {
        $colon = strrpos($hostport, ':');
        if ($colon !== false && ctype_digit((string)substr($hostport, $colon + 1))) {
            $host = substr($hostport, 0, $colon);
            $port = (int)substr($hostport, $colon + 1);
        } else {
            $host = $hostport;
        }
    }
    return [$host, $port];
}

function happ_ss_apply_plugin(array $q): array {
    $plugin = (string)($q['plugin'] ?? '');
    if ($plugin === '') return $q;
    $parts = preg_split('/[;]/', $plugin) ?: [];
    $name = strtolower(trim((string)array_shift($parts)));
    $opts = [];
    foreach ($parts as $p) {
        $p = trim($p);
        if ($p === '') continue;
        if (strpos($p, '=') !== false) {
            [$k, $v] = explode('=', $p, 2);
            $opts[strtolower(trim($k))] = trim($v);
        } else {
            $opts[strtolower($p)] = '1';
        }
    }
    if (strpos($name, 'v2ray') !== false || strpos($name, 'xray') !== false) {
        $mode = strtolower((string)($opts['mode'] ?? $opts['transport'] ?? 'websocket'));
        if ($mode === 'websocket' || $mode === 'ws') $q['type'] = 'ws';
        elseif ($mode === 'quic') $q['type'] = 'quic';
        elseif ($mode === 'grpc') $q['type'] = 'grpc';
        if (!empty($opts['tls']) || isset($opts['tls'])) $q['security'] = 'tls';
        if (!empty($opts['host']) && empty($q['host'])) $q['host'] = $opts['host'];
        if (!empty($opts['path']) && empty($q['path'])) $q['path'] = $opts['path'];
        if (!empty($opts['sni']) && empty($q['sni'])) $q['sni'] = $opts['sni'];
    } elseif (strpos($name, 'obfs') !== false) {
        $obfs = strtolower((string)($opts['obfs'] ?? $opts['mode'] ?? 'http'));
        if ($obfs === 'http' || $obfs === 'tls') {
            $q['type'] = 'tcp';
            $q['headerType'] = 'http';
            if (!empty($opts['obfs-host']) && empty($q['host'])) $q['host'] = $opts['obfs-host'];
            if (!empty($opts['obfs-uri']) && empty($q['path'])) $q['path'] = $opts['obfs-uri'];
        }
    }
    return $q;
}

function ss_uri_to_xray(string $uri, string $name): ?array {
    $raw = trim($uri);
    if (stripos($raw, 'ss://') === 0) $raw = substr($raw, 5);
    elseif (stripos($raw, 'shadowsocks://') === 0) $raw = substr($raw, 14);
    $hash = strpos($raw, '#');
    if ($hash !== false) {
        if ($name === '') $name = happ_uri_fragment_name('ss://x#' . substr($raw, $hash + 1));
        $raw = substr($raw, 0, $hash);
    }
    $q = [];
    $qpos = strpos($raw, '?');
    if ($qpos !== false) {
        $q = happ_parse_query_string(substr($raw, $qpos + 1));
        $raw = substr($raw, 0, $qpos);
    }

    $method = '';
    $password = '';
    $host = '';
    $port = 0;

    $at = strrpos($raw, '@');
    if ($at !== false) {
        $userinfo = substr($raw, 0, $at);
        [$host, $port] = happ_ss_split_hostport(substr($raw, $at + 1));
        [$method, $password] = happ_ss_split_method_pass($userinfo);
    } else {
        $decoded = happ_ss_b64_decode($raw);
        $at2 = strrpos($decoded, '@');
        if ($at2 !== false) {
            [$method, $password] = happ_ss_split_method_pass(substr($decoded, 0, $at2));
            [$host, $port] = happ_ss_split_hostport(substr($decoded, $at2 + 1));
        }
    }
    if ($host === '' || $port <= 0 || $method === '' || $password === '') return null;
    $q = happ_ss_apply_plugin($q);

    $has_stream = !empty($q['type']) || !empty($q['security']) || !empty($q['plugin']);
    $ob = [
        'protocol' => 'shadowsocks',
        'tag' => 'proxy',
        'settings' => [
            'servers' => [[
                'address' => $host,
                'port' => $port,
                'method' => $method,
                'password' => $password,
                'level' => 8,
                'ota' => false,
            ]],
        ],
        'streamSettings' => $has_stream ? xray_stream_from_query($q) : ['network' => 'tcp', 'security' => 'none'],
        'mux' => happ_default_mux(),
    ];
    return happ_xray_server($name !== '' ? $name : $host, $ob);
}

function vmess_uri_to_xray(string $uri, string $name): ?array {
    $raw = trim($uri);
    if (stripos($raw, 'vmess://') === 0) $raw = substr($raw, 8);
    $hash = strpos($raw, '#');
    if ($hash !== false) {
        if ($name === '') $name = happ_uri_fragment_name('vmess://x#' . substr($raw, $hash + 1));
        $raw = substr($raw, 0, $hash);
    }
    $j = json_decode(happ_ss_b64_decode($raw), true);
    if (!is_array($j)) {
        // rare: vmess://uuid@host:port?... (v2rayNG URL form)
        $p = happ_split_share_uri('vmess://' . $raw);
        if (!$p || $p['userinfo'] === '' || $p['host'] === '') return null;
        $q = $p['query'];
        $host = $p['host'];
        $port = $p['port'] > 0 ? $p['port'] : 443;
        $uuid = $p['userinfo'];
        if ($name === '') $name = $p['name'];
        $scy = happ_query_get($q, ['scy', 'security', 'encryption']) ?: 'auto';
        $aid = (int)($q['aid'] ?? $q['alterId'] ?? 0);
    } else {
        $host = (string)($j['add'] ?? $j['address'] ?? '');
        $port = (int)($j['port'] ?? 0);
        $uuid = (string)($j['id'] ?? '');
        if ($name === '' && !empty($j['ps'])) $name = (string)$j['ps'];
        $net = strtolower((string)($j['net'] ?? $j['network'] ?? 'tcp'));
        $tls = strtolower((string)($j['tls'] ?? $j['security'] ?? ''));
        $header = strtolower((string)($j['type'] ?? ''));
        $q = [
            'type' => $net,
            'security' => ($tls === 'tls' || $tls === 'reality') ? $tls : '',
            'sni' => (string)($j['sni'] ?? ''),
            'fp' => (string)($j['fp'] ?? $j['fingerprint'] ?? ''),
            'path' => (string)($j['path'] ?? ''),
            'host' => (string)($j['host'] ?? ''),
            'headerType' => $header,
            'serviceName' => (string)($j['serviceName'] ?? $j['path'] ?? ''),
            'alpn' => (string)($j['alpn'] ?? ''),
            'allowInsecure' => (string)($j['insecure'] ?? $j['allowInsecure'] ?? ''),
            'pbk' => (string)($j['pbk'] ?? ''),
            'sid' => (string)($j['sid'] ?? ''),
            'spx' => (string)($j['spx'] ?? ''),
        ];
        if ($net === 'kcp' || $net === 'mkcp') {
            $q['seed'] = (string)($j['path'] ?? $j['seed'] ?? '');
        }
        if ($net === 'quic') {
            $q['quicSecurity'] = (string)($j['host'] ?? 'none');
            $q['key'] = (string)($j['path'] ?? '');
        }
        $scy = (string)($j['scy'] ?? $j['security'] ?? 'auto');
        if ($scy === '' || $scy === 'tls' || $scy === 'reality' || $scy === 'none') $scy = 'auto';
        $aid = (int)($j['aid'] ?? 0);
    }
    if ($host === '' || $port <= 0 || $uuid === '') return null;

    $ob = [
        'protocol' => 'vmess',
        'tag' => 'proxy',
        'settings' => [
            'vnext' => [[
                'address' => $host,
                'port' => $port,
                'users' => [[
                    'id' => $uuid,
                    'alterId' => $aid,
                    'security' => $scy !== '' ? $scy : 'auto',
                    'level' => 8,
                ]],
            ]],
        ],
        'streamSettings' => xray_stream_from_query($q),
        'mux' => happ_default_mux(),
    ];
    return happ_xray_server($name !== '' ? $name : $host, $ob);
}

function hy2_uri_to_xray(string $uri, string $name): ?array {
    // Happ uses protocol "hysteria" + version 2 (not "hysteria2")
    $p = happ_split_share_uri($uri);
    if (!$p) return null;
    $password = (string)($p['userinfo'] ?? '');
    $host = (string)($p['host'] ?? '');
    $port = (int)($p['port'] ?? 0);
    if ($port <= 0) $port = 443;
    if ($password === '' || $host === '') return null;
    $q = $p['query'];
    if ($name === '') $name = (string)($p['name'] ?? '');
    $sni = trim(happ_query_get($q, ['sni', 'peer']));
    $insecure = happ_query_is_true(happ_query_get($q, ['allowInsecure', 'insecure', 'allow_insecure']));
    $alpn = trim(happ_query_get($q, ['alpn']));
    $fp = trim(happ_query_get($q, ['fp', 'fingerprint']));
    $tlsSettings = [
        'show' => false,
        'alpn' => $alpn !== '' ? array_values(array_filter(array_map('trim', preg_split('/[;,]/', $alpn) ?: []))) : ['h3'],
    ];
    if ($sni !== '') $tlsSettings['serverName'] = $sni;
    if ($fp !== '') $tlsSettings['fingerprint'] = $fp;
    if ($insecure) $tlsSettings['allowInsecure'] = true;
    $pin = happ_pin_from_query($q);
    if ($pin !== '') $tlsSettings['pinnedPeerCertSha256'] = $pin;

    $fm = happ_finalmask_from_query($q);
    $finalmask = ($fm === null) ? new \stdClass() : (empty($fm) ? new \stdClass() : $fm);

    $hy = [
        'auth' => $password,
        'version' => 2,
    ];
    $obfs = happ_query_get($q, ['obfs']);
    $obfsPass = happ_query_get($q, ['obfs-password', 'obfsPassword', 'obfs_password']);
    if ($obfs !== '') $hy['obfs'] = $obfs;
    if ($obfsPass !== '') $hy['obfsPassword'] = $obfsPass;
    $up = happ_query_get($q, ['up', 'upmbps']);
    $down = happ_query_get($q, ['down', 'downmbps']);
    if ($up !== '') $hy['up'] = $up;
    if ($down !== '') $hy['down'] = $down;

    $ob = [
        'protocol' => 'hysteria',
        'tag' => 'proxy',
        'settings' => [
            'address' => $host,
            'port' => $port,
            'version' => 2,
        ],
        'streamSettings' => [
            'network' => 'hysteria',
            'security' => 'tls',
            'finalmask' => $finalmask,
            'hysteriaSettings' => $hy,
            'tlsSettings' => $tlsSettings,
        ],
        'mux' => [
            'enabled' => false,
            'concurrency' => -1,
            'xudpConcurrency' => 8,
            'xudpProxyUDP443' => '',
        ],
    ];
    return happ_xray_server($name !== '' ? $name : $host, $ob);
}

function socks_http_uri_to_xray(string $uri, string $name, string $proto): ?array {
    $p = happ_split_share_uri($uri);
    if (!$p) return null;
    $host = (string)($p['host'] ?? '');
    $port = (int)($p['port'] ?? 0);
    if ($port <= 0) $port = ($proto === 'http') ? 80 : 1080;
    if ($host === '') return null;
    if ($name === '') $name = (string)($p['name'] ?? $host);
    $userinfo = (string)($p['userinfo'] ?? '');
    $user = '';
    $pass = '';
    if ($userinfo !== '') {
        $colon = strpos($userinfo, ':');
        if ($colon === false) $user = $userinfo;
        else {
            $user = substr($userinfo, 0, $colon);
            $pass = substr($userinfo, $colon + 1);
        }
    }
    $server = [
        'address' => $host,
        'port' => $port,
    ];
    if ($user !== '' || $pass !== '') {
        $server['users'] = [[
            'user' => $user,
            'pass' => $pass,
            'level' => 8,
        ]];
    }
    $ob = [
        'protocol' => $proto,
        'tag' => 'proxy',
        'settings' => ['servers' => [$server]],
        'streamSettings' => ['network' => 'tcp', 'security' => 'none'],
        'mux' => happ_default_mux(),
    ];
    return happ_xray_server($name, $ob);
}

function uri_to_happ_json(string $uri): ?array {
    $uri = trim($uri);
    if (!preg_match('/^([a-z0-9+.-]+):\\/\\//i', $uri, $m)) return null;
    $scheme = strtolower($m[1]);
    $name = happ_uri_fragment_name($uri);
    if ($scheme === 'vless') return vless_uri_to_xray($uri, $name);
    if ($scheme === 'trojan' || $scheme === 'trojan-go') return trojan_uri_to_xray($uri, $name);
    if ($scheme === 'ss' || $scheme === 'shadowsocks') return ss_uri_to_xray($uri, $name);
    if ($scheme === 'vmess') return vmess_uri_to_xray($uri, $name);
    if ($scheme === 'hy2' || $scheme === 'hysteria2') return hy2_uri_to_xray($uri, $name);
    if ($scheme === 'socks' || $scheme === 'socks5' || $scheme === 'socks4') return socks_http_uri_to_xray($uri, $name, 'socks');
    if ($scheme === 'http' || $scheme === 'https') return socks_http_uri_to_xray($uri, $name, 'http');
    return null;
}

/** Convert sing-box outbound (type/server) → Xray outbound (protocol/settings) */
function singbox_outbound_to_xray(array $ob): ?array {
    $type = strtolower((string)($ob['type'] ?? ''));
    if ($type === '' || in_array($type, ['urltest', 'selector', 'direct', 'block', 'dns', 'freedom', 'blackhole'], true)) {
        return null;
    }
    $server = (string)($ob['server'] ?? '');
    $port = (int)($ob['server_port'] ?? $ob['port'] ?? 0);
    $tag = (string)($ob['tag'] ?? 'proxy');
    if ($tag === '') $tag = 'proxy';

    if ($type === 'vless') {
        $uuid = (string)($ob['uuid'] ?? '');
        if ($server === '' || $port <= 0 || $uuid === '') return null;
        $tls = (array)($ob['tls'] ?? []);
        $reality = (array)($tls['reality'] ?? []);
        $utls = (array)($tls['utls'] ?? []);
        $has_reality = !empty($reality['enabled']) || !empty($reality['public_key']);
        $has_tls = !empty($tls['enabled']) || $has_reality;
        $q = [
            'type' => (string)(($ob['transport']['type'] ?? 'tcp') ?: 'tcp'),
            'security' => $has_reality ? 'reality' : ($has_tls ? 'tls' : ''),
            'sni' => (string)($tls['server_name'] ?? $tls['sni'] ?? ''),
            'fp' => (string)($utls['fingerprint'] ?? $tls['fingerprint'] ?? ''),
            'pbk' => (string)($reality['public_key'] ?? ''),
            'sid' => (string)($reality['short_id'] ?? ''),
            'spx' => (string)($reality['spider_x'] ?? $reality['spiderX'] ?? '/'),
            'flow' => (string)($ob['flow'] ?? ''),
            'path' => (string)($ob['transport']['path'] ?? ''),
            'host' => (string)($ob['transport']['headers']['Host'] ?? $ob['transport']['host'] ?? ''),
            'serviceName' => (string)($ob['transport']['service_name'] ?? ''),
        ];
        return [
            'protocol' => 'vless',
            'tag' => $tag,
            'settings' => [
                'vnext' => [[
                    'address' => $server,
                    'port' => $port,
                    'users' => [[
                        'id' => $uuid,
                        'encryption' => 'none',
                        'flow' => (string)($ob['flow'] ?? ''),
                        'level' => 8,
                        'security' => 'auto',
                    ]],
                ]],
            ],
            'streamSettings' => xray_stream_from_query($q),
            'mux' => happ_default_mux(),
        ];
    }

    if ($type === 'shadowsocks') {
        $method = (string)($ob['method'] ?? '');
        $password = (string)($ob['password'] ?? '');
        if ($server === '' || $port <= 0 || $method === '' || $password === '') return null;
        return [
            'protocol' => 'shadowsocks',
            'tag' => $tag,
            'settings' => [
                'servers' => [[
                    'address' => $server,
                    'port' => $port,
                    'method' => $method,
                    'password' => $password,
                    'level' => 8,
                ]],
            ],
            'streamSettings' => ['network' => 'tcp', 'security' => ''],
        ];
    }

    if ($type === 'trojan') {
        $password = (string)($ob['password'] ?? '');
        if ($server === '' || $port <= 0 || $password === '') return null;
        $tls = (array)($ob['tls'] ?? []);
        $q = [
            'type' => (string)(($ob['transport']['type'] ?? 'tcp') ?: 'tcp'),
            'security' => 'tls',
            'sni' => (string)($tls['server_name'] ?? ''),
            'fp' => (string)(($ob['tls']['utls']['fingerprint'] ?? '') ?: ''),
            'path' => (string)($ob['transport']['path'] ?? ''),
            'host' => (string)($ob['transport']['headers']['Host'] ?? ''),
        ];
        return [
            'protocol' => 'trojan',
            'tag' => $tag,
            'settings' => [
                'servers' => [[
                    'address' => $server,
                    'port' => $port,
                    'password' => $password,
                    'level' => 8,
                ]],
            ],
            'streamSettings' => xray_stream_from_query($q),
        ];
    }

    return null;
}

/** Expand one cached line (URI or JSON) into list of Xray Happ servers */
function xray_attach_dialer(array $outbound, string $dialer_tag = 'personal'): array {
    if (!isset($outbound['streamSettings']) || !is_array($outbound['streamSettings'])) {
        $outbound['streamSettings'] = ['network' => 'tcp', 'security' => ''];
    }
    if (!isset($outbound['streamSettings']['sockopt']) || !is_array($outbound['streamSettings']['sockopt'])) {
        $outbound['streamSettings']['sockopt'] = [];
    }
    $outbound['streamSettings']['sockopt']['dialerProxy'] = $dialer_tag;
    return $outbound;
}

function happ_xray_cascade_server(string $remarks, array $exit_outbound, array $personal_outbound): array {
    $remarks = trim($remarks) !== '' ? $remarks : 'Server';
    $personal_outbound['tag'] = 'personal';
    $exit_outbound['tag'] = 'proxy';
    $exit_outbound = xray_attach_dialer($exit_outbound, 'personal');
    return happ_xray_wrap_full($remarks, [
        $exit_outbound,
        $personal_outbound,
        ['protocol' => 'freedom', 'tag' => 'direct'],
        ['protocol' => 'blackhole', 'tag' => 'block'],
    ]);
}

function config_line_to_xray_servers(string $cfg): array {
    $cfg = trim($cfg);
    if ($cfg === '' || $cfg[0] === '#') return [];

    // Proxy URI
    if (preg_match('/^[a-zA-Z0-9\+\-\.]+:\/\//', $cfg)) {
        $one = uri_to_happ_json($cfg);
        return $one ? [$one] : [];
    }

    if ($cfg[0] !== '{' && $cfg[0] !== '[') return [];

    $j = @json_decode($cfg, true);
    if (!is_array($j)) return [];

    // Array of servers
    if (isset($j[0]) && is_array($j[0]) && $cfg[0] === '[') {
        $out = [];
        foreach ($j as $item) {
            if (!is_array($item)) continue;
            $out = array_merge($out, config_line_to_xray_servers(json_encode($item, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)));
        }
        return $out;
    }

    // Already Xray (protocol-based)
    if (!empty($j['outbounds']) && is_array($j['outbounds'])) {
        $first = $j['outbounds'][0] ?? null;
        if (is_array($first) && isset($first['protocol'])) {
            $remarks = (string)($j['remarks'] ?? $j['meta']['serverDescription'] ?? 'Server');
            $has_proxy = false;
            $outbounds = [];
            foreach ($j['outbounds'] as $ob) {
                if (!is_array($ob)) continue;
                $proto = strtolower((string)($ob['protocol'] ?? ''));
                if (in_array($proto, ['freedom', 'blackhole', 'dns'], true)) continue;
                $outbounds[] = $ob;
                $has_proxy = true;
            }
            if (!$has_proxy) return [];
            $outbounds[] = ['protocol' => 'freedom', 'tag' => 'direct'];
            $outbounds[] = ['protocol' => 'blackhole', 'tag' => 'block'];
            return [happ_xray_wrap_full($remarks, $outbounds)];
        }

        // Sing-box type-based
        if (is_array($first) && isset($first['type'])) {
            $remarks_base = (string)($j['remarks'] ?? $j['meta']['serverDescription'] ?? 'Server');
            $personal_sb = null;
            $exits_sb = [];
            foreach ($j['outbounds'] as $ob) {
                if (!is_array($ob)) continue;
                $type = strtolower((string)($ob['type'] ?? ''));
                if (in_array($type, ['urltest', 'selector', 'direct', 'block', 'dns'], true)) continue;
                $tag = strtolower((string)($ob['tag'] ?? ''));
                if (strpos($tag, 'personal') !== false) {
                    $personal_sb = $ob;
                } else {
                    $exits_sb[] = $ob;
                }
            }

            // Cascade only when sing-box actually chains via detour.
            // Vanya urltest (personal + country as alternatives) must stay FLAT:
            // dialerProxy + xtls-rprx-vision breaks Reality handshake.
            $needs_cascade = false;
            $ptag = strtolower((string)($personal_sb['tag'] ?? ''));
            foreach ($exits_sb as $ex) {
                $detour = strtolower((string)($ex['detour'] ?? $ex['dialer'] ?? ''));
                if ($detour !== '' && ($detour === $ptag || strpos($detour, 'personal') !== false)) {
                    $needs_cascade = true;
                    break;
                }
            }
            if ($personal_sb !== null && !empty($exits_sb) && $needs_cascade) {
                $px = singbox_outbound_to_xray($personal_sb);
                if (!$px) {
                    // fall through to flat conversion
                } else {
                    $servers = [];
                    foreach ($exits_sb as $ex) {
                        $exx = singbox_outbound_to_xray($ex);
                        if (!$exx) continue;
                        $tag = (string)($ex['tag'] ?? '');
                        $name = $remarks_base;
                        if ($tag !== '' && $tag !== 'proxy' && stripos($remarks_base, $tag) === false) {
                            $name = $remarks_base . ' · ' . $tag;
                        }
                        $servers[] = happ_xray_cascade_server($name, $exx, $px);
                    }
                    if ($servers) return $servers;
                }
            }

            // Flat: each outbound as separate server
            $servers = [];
            foreach ($j['outbounds'] as $ob) {
                if (!is_array($ob)) continue;
                $x = singbox_outbound_to_xray($ob);
                if (!$x) continue;
                $tag = (string)($ob['tag'] ?? '');
                $name = vanya_xray_name($remarks_base, $tag);
                $servers[] = happ_xray_server($name, $x);
            }
            return $servers;
        }
    }

    // Single Xray outbound object
    if (isset($j['protocol'])) {
        $name = (string)($j['tag'] ?? $j['remarks'] ?? 'Server');
        return [happ_xray_server($name, $j)];
    }

    // Single sing-box outbound
    if (isset($j['type'])) {
        $x = singbox_outbound_to_xray($j);
        if ($x) return [happ_xray_server((string)($j['tag'] ?? 'Server'), $x)];
    }

    return [];
}

function xray_outbound_to_uri(array $ob, string $name = 'Server'): ?string {
    $proto = strtolower((string)($ob['protocol'] ?? ''));
    $tag = (string)($ob['tag'] ?? $name);
    if ($tag === 'proxy' || $tag === 'personal') $tag = $name;
    $stream = (array)($ob['streamSettings'] ?? []);
    $net = strtolower((string)($stream['network'] ?? 'tcp'));
    $security = strtolower((string)($stream['security'] ?? ''));

    if ($proto === 'shadowsocks') {
        $s = $ob['settings']['servers'][0] ?? null;
        if (!is_array($s)) return null;
        $addr = (string)($s['address'] ?? '');
        $port = (int)($s['port'] ?? 0);
        $method = (string)($s['method'] ?? '');
        $password = (string)($s['password'] ?? '');
        if ($addr === '' || $port <= 0 || $method === '' || $password === '') return null;
        $userinfo = rtrim(strtr(base64_encode($method . ':' . $password), '+/', '-_'), '=');
        return "ss://{$userinfo}@{$addr}:{$port}#" . rawurlencode($tag);
    }

    if ($proto === 'vless') {
        $v = $ob['settings']['vnext'][0] ?? null;
        if (!is_array($v)) return null;
        $addr = (string)($v['address'] ?? '');
        $port = (int)($v['port'] ?? 0);
        $user = $v['users'][0] ?? [];
        $uuid = (string)($user['id'] ?? '');
        $flow = (string)($user['flow'] ?? '');
        $enc = (string)($user['encryption'] ?? 'none');
        if ($addr === '' || $port <= 0 || $uuid === '') return null;
        $params = ['encryption=' . rawurlencode($enc !== '' ? $enc : 'none')];
        if ($flow !== '') $params[] = 'flow=' . rawurlencode($flow);
        if ($net !== '' && $net !== 'tcp') $params[] = 'type=' . rawurlencode($net);
        else $params[] = 'type=tcp';
        if ($security !== '' && $security !== 'none') $params[] = 'security=' . rawurlencode($security);
        else $params[] = 'security=none';
        if ($security === 'reality') {
            $rs = (array)($stream['realitySettings'] ?? []);
            if (!empty($rs['serverName'])) $params[] = 'sni=' . rawurlencode((string)$rs['serverName']);
            if (!empty($rs['fingerprint'])) $params[] = 'fp=' . rawurlencode((string)$rs['fingerprint']);
            if (!empty($rs['publicKey'])) $params[] = 'pbk=' . rawurlencode((string)$rs['publicKey']);
            if (isset($rs['shortId'])) $params[] = 'sid=' . rawurlencode((string)$rs['shortId']);
            if (!empty($rs['spiderX'])) $params[] = 'spx=' . rawurlencode((string)$rs['spiderX']);
        } elseif ($security === 'tls') {
            $ts = (array)($stream['tlsSettings'] ?? []);
            if (!empty($ts['serverName'])) $params[] = 'sni=' . rawurlencode((string)$ts['serverName']);
            if (!empty($ts['fingerprint'])) $params[] = 'fp=' . rawurlencode((string)$ts['fingerprint']);
            if (!empty($ts['alpn']) && is_array($ts['alpn'])) $params[] = 'alpn=' . rawurlencode(implode(',', $ts['alpn']));
            if (!empty($ts['allowInsecure'])) $params[] = 'allowInsecure=1';
            if (!empty($ts['pinnedPeerCertSha256'])) $params[] = 'pinSHA256=' . rawurlencode((string)$ts['pinnedPeerCertSha256']);
        }
        if ($net === 'ws') {
            $ws = (array)($stream['wsSettings'] ?? []);
            if (!empty($ws['path'])) $params[] = 'path=' . rawurlencode((string)$ws['path']);
            if (!empty($ws['headers']['Host'])) $params[] = 'host=' . rawurlencode((string)$ws['headers']['Host']);
        } elseif ($net === 'grpc') {
            $gs = (array)($stream['grpcSettings'] ?? []);
            if (!empty($gs['serviceName'])) $params[] = 'serviceName=' . rawurlencode((string)$gs['serviceName']);
        } elseif ($net === 'xhttp' || $net === 'splithttp') {
            $xs = (array)($stream['xhttpSettings'] ?? []);
            if (!empty($xs['path'])) $params[] = 'path=' . rawurlencode((string)$xs['path']);
            if (!empty($xs['host'])) $params[] = 'host=' . rawurlencode((string)$xs['host']);
            if (!empty($xs['mode'])) $params[] = 'mode=' . rawurlencode((string)$xs['mode']);
            if (!empty($xs['extra']) && is_array($xs['extra'])) {
                $params[] = 'extra=' . rawurlencode(json_encode($xs['extra'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
            foreach (['scMaxConcurrentPosts','scMaxEachPostBytes','scMinPostsIntervalMs'] as $xk) {
                if (isset($xs[$xk]) && $xs[$xk] !== '') $params[] = $xk . '=' . rawurlencode((string)$xs[$xk]);
            }
        } elseif ($net === 'kcp') {
            $ks = (array)($stream['kcpSettings'] ?? []);
            $params[] = 'mtu=1350';
            if (!empty($ks['tti'])) $params[] = 'tti=' . (int)$ks['tti'];
            if (!empty($ks['header']['type'])) $params[] = 'headerType=' . rawurlencode((string)$ks['header']['type']);
        }
        if (!empty($stream['finalmask'])) {
            $fm = $stream['finalmask'];
            if (is_array($fm) || is_object($fm)) {
                $params[] = 'fm=' . rawurlencode(json_encode($fm, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            }
        }
        $params[] = 'headerType=none';
        return 'vless://' . $uuid . '@' . $addr . ':' . $port . '?' . implode('&', $params) . '#' . rawurlencode($tag);
    }

    if ($proto === 'trojan') {
        $s = $ob['settings']['servers'][0] ?? null;
        if (!is_array($s)) return null;
        $addr = (string)($s['address'] ?? '');
        $port = (int)($s['port'] ?? 0);
        $pass = (string)($s['password'] ?? '');
        if ($addr === '' || $port <= 0 || $pass === '') return null;
        $params = [];
        if ($security !== '') $params[] = 'security=' . rawurlencode($security);
        $ts = (array)($stream['tlsSettings'] ?? []);
        if (!empty($ts['serverName'])) $params[] = 'sni=' . rawurlencode((string)$ts['serverName']);
        $qs = $params ? ('?' . implode('&', $params)) : '';
        return 'trojan://' . rawurlencode($pass) . '@' . $addr . ':' . $port . $qs . '#' . rawurlencode($tag);
    }

    if ($proto === 'hysteria' || $proto === 'hysteria2') {
        $auth = '';
        $addr = '';
        $port = 0;
        $sni = '';
        if (isset($ob['settings']['address'])) {
            $addr = (string)$ob['settings']['address'];
            $port = (int)($ob['settings']['port'] ?? 443);
            $auth = (string)($ob['streamSettings']['hysteriaSettings']['auth'] ?? $ob['settings']['password'] ?? '');
        } else {
            $s = $ob['settings']['servers'][0] ?? null;
            if (is_array($s)) {
                $addr = (string)($s['address'] ?? '');
                $port = (int)($s['port'] ?? 443);
                $auth = (string)($s['password'] ?? '');
            }
        }
        $ts = (array)($stream['tlsSettings'] ?? []);
        $sni = (string)($ts['serverName'] ?? '');
        if ($addr === '' || $port <= 0 || $auth === '') return null;
        $params = ['security=tls'];
        if ($sni !== '') $params[] = 'sni=' . rawurlencode($sni);
        if (!empty($ts['pinnedPeerCertSha256'])) $params[] = 'pinSHA256=' . rawurlencode((string)$ts['pinnedPeerCertSha256']);
        $hy = (array)($stream['hysteriaSettings'] ?? []);
        if (!empty($hy['obfs'])) $params[] = 'obfs=' . rawurlencode((string)$hy['obfs']);
        if (!empty($hy['obfsPassword'])) $params[] = 'obfs-password=' . rawurlencode((string)$hy['obfsPassword']);
        if (!empty($stream['finalmask'])) {
            $fm = $stream['finalmask'];
            $params[] = 'fm=' . rawurlencode(json_encode($fm, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        } else {
            $params[] = 'fm=' . rawurlencode('{}');
        }
        return 'hysteria2://' . rawurlencode($auth) . '@' . $addr . ':' . $port . '?' . implode('&', $params) . '#' . rawurlencode($tag);
    }

    if ($proto === 'vmess') {
        $v = $ob['settings']['vnext'][0] ?? null;
        if (!is_array($v)) return null;
        $addr = (string)($v['address'] ?? '');
        $port = (int)($v['port'] ?? 0);
        $user = $v['users'][0] ?? [];
        $uuid = (string)($user['id'] ?? '');
        if ($addr === '' || $port <= 0 || $uuid === '') return null;
        $ts = (array)($stream['tlsSettings'] ?? []);
        $vmess = [
            'v' => '2',
            'ps' => $tag,
            'add' => $addr,
            'port' => (string)$port,
            'id' => $uuid,
            'aid' => (string)(int)($user['alterId'] ?? 0),
            'scy' => (string)($user['security'] ?? 'auto'),
            'net' => $net !== '' ? $net : 'tcp',
            'type' => 'none',
            'tls' => ($security === 'tls') ? 'tls' : '',
            'sni' => (string)($ts['serverName'] ?? ''),
            'fp' => (string)($ts['fingerprint'] ?? ''),
        ];
        return 'vmess://' . base64_encode(json_encode($vmess, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    return null;
}

function process_configs_for_subscription(array $raw_configs): array {
    $servers = [];
    $seen = [];
    foreach ($raw_configs as $cfg) {
        $cfg = trim((string)$cfg);
        if ($cfg === '' || $cfg[0] === '#') continue;

        // Share-link → full Xray JSON (platform TUN applied inside wrap)
        if (preg_match('/^[a-zA-Z0-9\+\-\.]+:\/\//', $cfg)) {
            $one = uri_to_happ_json($cfg);
            if (is_array($one) && !empty($one['outbounds'])) {
                $key = md5(json_encode($one, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                if (!isset($seen[$key])) {
                    $seen[$key] = true;
                    $servers[] = $one;
                }
            }
            continue;
        }

        // Cached JSON (Vanya etc.)
        if ($cfg[0] === '{' || $cfg[0] === '[') {
            foreach (config_line_to_xray_servers($cfg) as $server) {
                if (!is_array($server) || empty($server['outbounds'])) continue;
                // Re-wrap so platform TUN / routing always applied
                $server = happ_xray_wrap_full(
                    (string)($server['remarks'] ?? 'Server'),
                    $server['outbounds']
                );
                $key = md5(json_encode($server, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                if (!isset($seen[$key])) {
                    $seen[$key] = true;
                    $servers[] = $server;
                }
            }
        }
    }
    return array_values($servers);
}

if (!empty($is_v2box)) {
    $v2_uris = configs_to_share_uris($configs);
    if (empty($v2_uris)) {
        die_denied("MARZBAN OFFLINE");
    }
    v2box_save_last_uris($token, $v2_uris);
    if ($raw_hwid === '') {
        $remarks = [];
        foreach ($v2_uris as $u) {
            $remarks[] = v2box_uri_remark($u);
        }
        v2box_block_response(
            v2box_client_title(),
            "В V2Box: Subscription Settings → включите Send HWID. Без этого ключи не выдаются. Затем обновите подписку.",
            $remarks
        );
    }
    $payload = base64_encode(implode("\n", $v2_uris) . "\n");
    $headers_to_send = [];
    $headers_to_send[] = 'Content-Type: text/plain; charset=utf-8';
    $headers_to_send[] = 'Subscription-Userinfo: upload=' . $upload . '; download=' . $download . '; total=' . $total . '; expire=' . $expire;
    $headers_to_send[] = 'Profile-Title: ' . ($user['name'] ?? '');
    $headers_to_send[] = 'profile-update-interval: 1';
    if (function_exists('hb_headers_for')) {
        foreach (hb_headers_for($hb_brand ?? []) as $hh) {
            $headers_to_send[] = $hh;
        }
    }
    foreach ($headers_to_send as $h) header($h);
    echo $payload;
    client_cache_write($token, $client_url, $headers_to_send, $payload, $req_format);
    exit;
}

if (!sub_is_happ()) {
    $share_uris = configs_to_share_uris($configs);
    if (empty($share_uris)) die_denied("MARZBAN OFFLINE");
    
    $headers_to_send = [];
    $headers_to_send[] = 'Content-Type: text/plain; charset=utf-8';
    $headers_to_send[] = 'Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0';
    $headers_to_send[] = 'Pragma: no-cache';
    $headers_to_send[] = 'Expires: 0';
    $headers_to_send[] = 'Subscription-Userinfo: upload=' . $upload . '; download=' . $download . '; total=' . $total . '; expire=' . $expire;
    $headers_to_send[] = 'Profile-Title: ' . ($user['name'] ?? '');
    $headers_to_send[] = 'Profile-Update-Interval: 1';
    
    $brand_desc = trim((string)($hb_brand['server_description'] ?? ''));
    if ($brand_desc !== '') $headers_to_send[] = 'Server-Description: ' . $brand_desc;
    
    $payload = base64_encode(implode("\n", $share_uris) . "\n");
    foreach ($headers_to_send as $h) header($h);
    echo $payload;
    client_cache_write($token, $client_url, $headers_to_send, $payload, $req_format);
    exit;
}

// ── JSON-подписка с платформенным TUN (android=xray0, ios=utun0) для Happ ──
$unique_configs = process_configs_for_subscription($configs);
if (empty($unique_configs)) {
    die_denied("MARZBAN OFFLINE");
}

$headers_to_send = [];
$headers_to_send[] = 'Content-Type: application/json; charset=utf-8';
$headers_to_send[] = 'Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0';
$headers_to_send[] = 'Pragma: no-cache';
$headers_to_send[] = 'Expires: 0';
$headers_to_send[] = 'Subscription-Userinfo: upload=' . $upload . '; download=' . $download . '; total=' . $total . '; expire=' . $expire;
$headers_to_send[] = 'Profile-Title: ' . ($user['name'] ?? '');
$headers_to_send[] = 'Profile-Update-Interval: 1';
$headers_to_send[] = 'Profile-Web-Page-Url: https://' . (string)($_SERVER['HTTP_HOST'] ?? '') . '/';
$headers_to_send[] = 'X-Happ-Platform: ' . (string)($GLOBALS['HAPP_CLIENT_PLATFORM'] ?? 'android');

$hd_pid  = (string)($_hd['provider_id'] ?? '');
$hd_fb   = (array)($_hd['fallback_domains'] ?? []);
$hd_nd   = (string)($_hd['new_domain'] ?? '');
$hd_sort = (string)($_hd['subscriptions_sort_type'] ?? '');
$hd_hide = !empty($_hd['hide_settings']) ? '1' : '0';
$hd_auto_update_open = !empty($_hd['subscriptions_auto_update_open_enable']) ? '1' : '0';
$hd_ping_onopen = !empty($_hd['subscriptions_ping_onopen_enabled']) ? '1' : '0';
$hd_subscription_pin = !empty($_hd['subscription_pin']) ? '1' : '0';

if ($hd_pid !== '') {
    $headers_to_send[] = 'ProviderID: ' . $hd_pid;
    if (!empty($hd_fb)) {
        $fb_domain = $hd_fb[0];
        $fb_url    = "https://{$fb_domain}/license.php?token=" . urlencode($token);
        $headers_to_send[] = 'Fallback-Url: ' . $fb_url;
    }
    if ($hd_nd !== '') {
        $headers_to_send[] = 'New-Domain: ' . $hd_nd;
    }
    $headers_to_send[] = 'Hide-Settings: ' . $hd_hide;
    if ($hd_sort !== '') $headers_to_send[] = 'Subscriptions-Sort-Type: ' . $hd_sort;
    $headers_to_send[] = 'Subscription-Auto-Update-Open-Enable: ' . $hd_auto_update_open;
    $headers_to_send[] = 'Subscription-Ping-Onopen-Enabled: ' . $hd_ping_onopen;
    $headers_to_send[] = 'Subscription-Pin: ' . $hd_subscription_pin;

    // Inject 'meta' dictionary into JSON items for Happ apps reading meta from body
    foreach ($unique_configs as &$cfg_item) {
        if (is_array($cfg_item)) {
            if (!isset($cfg_item['meta']) || !is_array($cfg_item['meta'])) {
                $cfg_item['meta'] = [];
            }
            $cfg_item['meta']['providerid'] = $hd_pid;
            $cfg_item['meta']['ProviderID'] = $hd_pid;
            if ($hd_nd !== '') {
                $cfg_item['meta']['new-domain'] = $hd_nd;
                $cfg_item['meta']['New-Domain'] = $hd_nd;
            }
            if (!empty($hd_fb)) {
                $fb_url_meta = "https://{$hd_fb[0]}/license.php?token=" . urlencode($token);
                $cfg_item['meta']['fallback-url'] = $fb_url_meta;
                $cfg_item['meta']['Fallback-Url'] = $fb_url_meta;
            }
        }
    }
    unset($cfg_item);
}

$brand_desc = trim((string)($hb_brand['server_description'] ?? ''));
if ($brand_desc !== '') {
    foreach ($unique_configs as &$cfg_item) {
        if (is_array($cfg_item)) {
            if (!isset($cfg_item['meta']) || !is_array($cfg_item['meta'])) {
                $cfg_item['meta'] = [];
            }
            $cfg_item['meta']['serverDescription'] = $brand_desc;
        }
    }
    unset($cfg_item);
}

if (function_exists('hb_headers_for')) {
    foreach (hb_headers_for($hb_brand ?? []) as $hh) {
        $headers_to_send[] = $hh;
    }
}
$payload = json_encode($unique_configs, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
if ($payload === false) {
    die_denied("JSON ENCODE ERROR");
}
foreach ($headers_to_send as $h) header($h);
echo $payload;
client_cache_write($token, $client_url, $headers_to_send, $payload, $req_format);
exit;

