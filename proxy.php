<?php
/**
 * Обратный прокси (зеркало) для подписок.
 *
 *     https://s1250022.ha006.t.mydomain.zone/...   →   https://zerosan.alwaysdata.net/...
 *
 * Зачем: домен zerosan.alwaysdata.net заблокирован в Туркменистане (DNS отдаёт
 * 127.0.0.1), поэтому клиентам выдаются ссылки на этот хост. Сам бот, база и
 * license.php остаются на alwaysdata — здесь только пересылка запроса «как есть».
 *
 * Настоящий IP клиента уходит в X-Fwd-Ip и подписывается общим секретом
 * X-Fwd-Secret. license.php на alwaysdata подставляет его в REMOTE_ADDR, но
 * только если запрос пришёл с IP этого прокси И секрет совпал.
 */

declare(strict_types=1);

const ORIGIN_HOST     = 'zerosan.alwaysdata.net';
const ORIGIN_IP       = '185.31.40.28';
const MIRROR_HOST     = 's1250022.ha006.t.mydomain.zone';
const FWD_SECRET      = '968f6dacaf5292b98bef45591d73e0402a13cb8884c8bb7a';
const CONNECT_TIMEOUT = 12;
const TOTAL_TIMEOUT   = 45;
const MAX_BODY_BYTES  = 16777216;

// Наружу через зеркало не отдаём: вебхук Telegram ходит на alwaysdata напрямую,
// а через прокси его можно было бы дёрнуть, спрятав свой IP. db.php — модуль с
// доступом к БД, он и на origin закрыт, но пусть отказ будет здесь и сразу.
const DENY_BASENAMES = ['bot.php', 'db.php'];

// Заголовки клиента, которые не пересылаем: их выставляет curl / транспорт,
// либо это наши собственные служебные (защита от подделки IP клиентом).
const SKIP_REQUEST_HEADERS = [
    'host', 'content-length', 'connection', 'keep-alive', 'accept-encoding',
    'transfer-encoding', 'expect', 'upgrade', 'te', 'trailer',
    'proxy-authorization', 'proxy-authenticate', 'proxy-connection',
    'x-fwd-ip', 'x-fwd-secret', 'x-fwd-proto', 'x-fwd-host',
    'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip',
];

// Заголовки ответа, которые не отдаём клиенту: hop-by-hop и те, что пересчитает
// сам веб-сервер (тело мы уже раскодировали, поэтому content-encoding снимаем).
const SKIP_RESPONSE_HEADERS = [
    'transfer-encoding', 'connection', 'keep-alive', 'content-length',
    'content-encoding', 'trailer', 'upgrade', 'te',
    'proxy-authenticate', 'proxy-authorization', 'alt-svc',
];

// Заголовки, которых в ответе может быть несколько — их не перезатираем.
const REPEATABLE_RESPONSE_HEADERS = ['set-cookie', 'link', 'vary', 'www-authenticate'];

/** Заголовки входящего запроса в виде ['имя-в-нижнем-регистре' => 'значение']. */
function px_request_headers(): array
{
    $out = [];
    if (function_exists('getallheaders')) {
        foreach ((array)getallheaders() as $k => $v) {
            $out[strtolower((string)$k)] = (string)$v;
        }
    }
    // Подстраховка: getallheaders() под некоторыми SAPI отдаёт не всё.
    foreach ($_SERVER as $k => $v) {
        if (!is_string($k) || strncmp($k, 'HTTP_', 5) !== 0) {
            continue;
        }
        $name = strtolower(str_replace('_', '-', substr($k, 5)));
        if (!isset($out[$name])) {
            $out[$name] = (string)$v;
        }
    }
    if (!isset($out['content-type']) && !empty($_SERVER['CONTENT_TYPE'])) {
        $out['content-type'] = (string)$_SERVER['CONTENT_TYPE'];
    }
    return $out;
}

/** IP клиента. Прокси стоит первым, поэтому доверяем только REMOTE_ADDR. */
function px_client_ip(): string
{
    $ip = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

/** Короткий текстовый ответ об ошибке шлюза. */
function px_fail(int $code, string $msg): void
{
    if (!headers_sent()) {
        http_response_code($code);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo $msg, "\n";
    exit;
}

// ── Разбор входящего запроса ────────────────────────────────────────────────
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$uri    = (string)($_SERVER['REQUEST_URI'] ?? '/');
$path   = parse_url($uri, PHP_URL_PATH);
if (!is_string($path) || $path === '') {
    $path = '/';
}
$query = (string)($_SERVER['QUERY_STRING'] ?? '');
if ($query === '') {
    $q = parse_url($uri, PHP_URL_QUERY);
    $query = is_string($q) ? $q : '';
}

// Сам файл прокси наружу не показываем — на него всё переписывается из .htaccess.
$base = strtolower(basename($path));
if ($base === 'proxy.php' && $path !== '/proxy.php') {
    $base = 'proxy.php';
}
if (in_array($base, DENY_BASENAMES, true) || $base === 'proxy.php') {
    px_fail(403, 'Forbidden');
}
if (strpos($path, '..') !== false) {
    px_fail(400, 'Bad request');
}

$client_ip = px_client_ip();
if ($client_ip === '') {
    px_fail(400, 'Bad request');
}

$origin_url = 'https://' . ORIGIN_HOST . $path . ($query !== '' ? '?' . $query : '');

// ── Сборка заголовков для origin ───────────────────────────────────────────
$in   = px_request_headers();
$send = ['Host: ' . ORIGIN_HOST];
foreach ($in as $name => $value) {
    if (in_array($name, SKIP_REQUEST_HEADERS, true)) {
        continue;
    }
    if (strpos($name, "\n") !== false || strpos($value, "\n") !== false) {
        continue;
    }
    $send[] = $name . ': ' . $value;
}
$send[] = 'X-Fwd-Ip: ' . $client_ip;
$send[] = 'X-Fwd-Secret: ' . FWD_SECRET;
$send[] = 'X-Fwd-Proto: ' . (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off' ? 'http' : 'https');
$send[] = 'X-Fwd-Host: ' . MIRROR_HOST;
$send[] = 'X-Forwarded-For: ' . $client_ip;
$send[] = 'X-Real-Ip: ' . $client_ip;

// ── Тело запроса ───────────────────────────────────────────────────────────
$body = '';
if ($method !== 'GET' && $method !== 'HEAD') {
    $body = (string)file_get_contents('php://input');
    if (strlen($body) > MAX_BODY_BYTES) {
        px_fail(413, 'Payload too large');
    }
}

// ── Запрос к origin ────────────────────────────────────────────────────────
/**
 * @param bool $pin_ip Прибивать ORIGIN_IP вместо DNS (обход подмены/сбоя DNS).
 * @return array{0:int,1:array,2:string,3:int,4:string} код, заголовки, тело, errno, ошибка
 */
function px_fetch(string $url, string $method, array $headers, string $body, bool $pin_ip): array
{
    $resp_headers = [];
    $ch = curl_init($url);
    $opts = [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT        => TOTAL_TIMEOUT,
        CURLOPT_ENCODING       => '',            // gzip по дороге, curl распакует сам
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
        // Только IPv4: origin должен видеть один и тот же исходящий IP этого
        // хоста (212.60.5.182), иначе проверка доверенного прокси не пройдёт.
        CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$resp_headers) {
            $len = strlen($line);
            $t = trim($line);
            if (stripos($t, 'HTTP/') === 0) {
                // Новый блок ответа (1xx / redirect-цепочка) — старые заголовки не нужны.
                $resp_headers = [];
            } elseif ($t !== '' && strpos($t, ':') !== false) {
                [$k, $v] = explode(':', $t, 2);
                $resp_headers[] = [strtolower(trim($k)), trim($v)];
            }
            return $len;
        },
    ];
    if ($method === 'HEAD') {
        $opts[CURLOPT_NOBODY] = true;
    } elseif ($body !== '') {
        $opts[CURLOPT_POSTFIELDS] = $body;
    }
    if ($pin_ip) {
        $opts[CURLOPT_RESOLVE] = [ORIGIN_HOST . ':443:' . ORIGIN_IP];
    }
    curl_setopt_array($ch, $opts);
    $out   = curl_exec($ch);
    $errno = curl_errno($ch);
    $err   = curl_error($ch);
    $code  = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$code, $resp_headers, is_string($out) ? $out : '', $errno, $err];
}

[$code, $rh, $out, $errno, $err] = px_fetch($origin_url, $method, $send, $body, true);

// Прибитый IP мог отвалиться (смена IP у alwaysdata, сетевой сбой) — пробуем DNS.
if ($errno !== 0 || $code === 0) {
    [$code, $rh, $out, $errno, $err] = px_fetch($origin_url, $method, $send, $body, false);
}
if ($errno !== 0 || $code === 0) {
    header('Retry-After: 5');
    px_fail(502, 'Upstream unavailable');
}

// ── Отдаём ответ клиенту как есть ──────────────────────────────────────────
http_response_code($code);
$seen = [];
foreach ($rh as [$name, $value]) {
    if (in_array($name, SKIP_RESPONSE_HEADERS, true)) {
        continue;
    }
    // Redirect и cookie должны остаться на зеркале, иначе клиент уйдёт на
    // заблокированный домен.
    if ($name === 'location' || $name === 'set-cookie' || $name === 'refresh') {
        $value = str_ireplace(ORIGIN_HOST, MIRROR_HOST, $value);
    }
    $repeatable = in_array($name, REPEATABLE_RESPONSE_HEADERS, true);
    header($name . ': ' . $value, $repeatable ? false : !isset($seen[$name]));
    $seen[$name] = true;
}
header('X-Mirror: ' . MIRROR_HOST, true);

if ($method !== 'HEAD') {
    echo $out;
}
