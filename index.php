<?php

declare(strict_types=1);

/**
 * HiData PowerDNS Manager
 * Single-file PHP panel for managing PowerDNS zones and RRsets remotely.
 *
 * Requirements:
 * - PHP 8.1+
 * - cURL extension
 * - Writable storage directory for backups and audit logs
 */

$configPath = __DIR__ . '/config.php';
if (!is_file($configPath)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "Missing config.php. Copy config.example.php to config.php and update it.";
    exit;
}

/** @var array<string,mixed> $config */
$config = require $configPath;

if (!is_array($config)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "Invalid config.php format.";
    exit;
}

error_reporting(E_ALL);
ini_set('display_errors', '0');
date_default_timezone_set((string)($config['app']['timezone'] ?? 'UTC'));

$security = $config['security'] ?? [];
$sessionName = (string)($security['session_name'] ?? 'HIDATA_PDNS');
$isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$cookieSecure = $isHttps && (bool)($security['cookie_secure'] ?? true);

session_name($sessionName);
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => $cookieSecure,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

sendSecurityHeaders($config);
bootstrapStorage($config);

if (!isClientIpAllowed($config)) {
    http_response_code(403);
    renderFatalPage('Access denied', 'Your IP address is not allowed to access this panel.');
}

if (($security['require_https'] ?? false) && !$isHttps) {
    http_response_code(403);
    renderFatalPage('HTTPS required', 'This panel is configured to require HTTPS.');
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

handleLogout();

if (isset($_POST['action']) && $_POST['action'] === 'login') {
    handleLogin($config);
}

requireAuth();

$view = $_GET['view'] ?? 'dashboard';
$zoneNameInput = isset($_GET['zone']) ? trim((string)$_GET['zone']) : '';
$zoneName = $zoneNameInput !== '' ? ensureTrailingDot($zoneNameInput) : '';
$recordFilter = trim((string)($_GET['record_filter'] ?? ''));
$zoneSearch = trim((string)($_GET['zone_search'] ?? ''));

if (isset($_POST['action'])) {
    handleMutation($config);
}

if (isset($_GET['download']) && $_GET['download'] === 'zone' && $zoneName !== '') {
    downloadZoneExport($config, $zoneName);
}

$zones = fetchZones($config);
$currentZone = $zoneName !== '' ? findZoneByName($zones, $zoneName) : null;
$rrsets = [];
if ($currentZone !== null) {
    $zoneDetails = fetchZone($config, $currentZone['id']);
    $rrsets = array_values(array_filter($zoneDetails['rrsets'] ?? [], static function ($rrset) use ($recordFilter) {
        if ($recordFilter === '') {
            return true;
        }
        $needle = mb_strtolower($recordFilter);
        $haystacks = [
            (string)($rrset['name'] ?? ''),
            (string)($rrset['type'] ?? ''),
            json_encode($rrset['records'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '',
        ];
        foreach ($haystacks as $haystack) {
            if (mb_stripos($haystack, $needle) !== false) {
                return true;
            }
        }
        return false;
    }));
} else {
    $zoneDetails = null;
}

renderPage([
    'config' => $config,
    'flash' => $flash,
    'zones' => $zones,
    'zoneSearch' => $zoneSearch,
    'currentZone' => $currentZone,
    'zoneDetails' => $zoneDetails,
    'rrsets' => $rrsets,
    'recordFilter' => $recordFilter,
    'view' => $view,
]);
exit;

function sendSecurityHeaders(array $config): void
{
    $security = $config['security'] ?? [];
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    $csp = [
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self' 'unsafe-inline'",
        "font-src 'self' data:",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ];
    header('Content-Security-Policy: ' . implode('; ', $csp));

    if (($security['hsts'] ?? false) && (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function bootstrapStorage(array $config): void
{
    $storage = $config['storage'] ?? [];
    $dirs = [];
    if (!empty($storage['backup_dir'])) {
        $dirs[] = $storage['backup_dir'];
    }
    if (!empty($storage['audit_log'])) {
        $dirs[] = dirname((string)$storage['audit_log']);
    }
    if (!empty($storage['rate_limit_file'])) {
        $dirs[] = dirname((string)$storage['rate_limit_file']);
    }

    foreach ($dirs as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
    }
}

function renderFatalPage(string $title, string $message): never
{
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . h($title) . '</title>';
    echo '<style>body{font-family:Inter,Arial,sans-serif;background:#0b1220;color:#e5eefb;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.box{max-width:680px;background:#111a2e;border:1px solid #22314f;padding:32px;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{margin:0 0 12px;font-size:28px}p{margin:0;color:#a7badc;line-height:1.7}</style></head><body><div class="box"><h1>' . h($title) . '</h1><p>' . h($message) . '</p></div></body></html>';
    exit;
}

function clientIp(): string
{
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $value = trim((string)$_SERVER[$key]);
            if ($key === 'HTTP_X_FORWARDED_FOR') {
                $parts = explode(',', $value);
                $value = trim($parts[0]);
            }
            return $value;
        }
    }
    return 'unknown';
}

function isClientIpAllowed(array $config): bool
{
    $allowed = $config['security']['allowed_ips'] ?? [];
    if (!is_array($allowed) || $allowed === []) {
        return true;
    }
    $ip = clientIp();
    foreach ($allowed as $allowedIp) {
        if (trim((string)$allowedIp) === $ip) {
            return true;
        }
    }
    return false;
}

function handleLogin(array $config): never
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        redirect('index.php');
    }

    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $auth = $config['auth'] ?? [];

    $rate = loadRateLimit($config);
    $ip = clientIp();
    $entry = $rate[$ip] ?? ['fails' => 0, 'lock_until' => 0];
    if (($entry['lock_until'] ?? 0) > time()) {
        $_SESSION['login_error'] = 'Too many failed login attempts. Please wait and try again.';
        redirect('index.php');
    }

    $validUsername = hash_equals((string)($auth['username'] ?? ''), $username);
    $passwordHash = (string)($auth['password_hash'] ?? '');
    $validPassword = $passwordHash !== '' && password_verify($password, $passwordHash);

    if ($validUsername && $validPassword) {
        session_regenerate_id(true);
        $_SESSION['auth'] = [
            'username' => $username,
            'logged_in_at' => time(),
            'last_seen' => time(),
        ];
        $rate[$ip] = ['fails' => 0, 'lock_until' => 0];
        saveRateLimit($config, $rate);
        audit($config, 'login_success', ['user' => $username]);
        $_SESSION['flash'] = ['type' => 'success', 'message' => 'Signed in successfully.'];
        redirect('index.php');
    }

    $fails = (int)($entry['fails'] ?? 0) + 1;
    $lockUntil = $fails >= 5 ? time() + 300 : 0;
    $rate[$ip] = ['fails' => $fails, 'lock_until' => $lockUntil];
    saveRateLimit($config, $rate);
    audit($config, 'login_failed', ['attempt_user' => $username]);
    $_SESSION['login_error'] = $lockUntil > 0
        ? 'Too many failed login attempts. Your IP has been locked for 5 minutes.'
        : 'Invalid username or password.';
    redirect('index.php');
}

function handleLogout(): void
{
    if (isset($_GET['logout']) && $_GET['logout'] === '1') {
        session_unset();
        session_destroy();
        session_start();
        $_SESSION['flash'] = ['type' => 'success', 'message' => 'Signed out successfully.'];
        redirect('index.php');
    }
}

function requireAuth(): void
{
    if (empty($_SESSION['auth']['username'])) {
        renderLoginPage();
    }
    $_SESSION['auth']['last_seen'] = time();
}

function renderLoginPage(): never
{
    $loginError = $_SESSION['login_error'] ?? null;
    unset($_SESSION['login_error']);
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);

    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>HiData PowerDNS Manager</title>';
    echo '<style>' . baseCss() . loginCss() . '</style>';
    echo '</head><body class="login-body">';
    echo '<div class="login-shell">';
    echo '<div class="login-brand">';
    echo '<div class="brand-mark">Hi</div>';
    echo '<div><div class="brand-title">HiData PowerDNS Manager</div><div class="brand-subtitle">Secure remote DNS control panel</div></div>';
    echo '</div>';
    echo '<div class="login-card">';
    echo '<h1>Sign in</h1>';
    echo '<p class="muted">Use the application account configured in <code>config.php</code>.</p>';
    if ($flash) {
        echo renderFlash($flash);
    }
    if ($loginError) {
        echo '<div class="flash flash-danger">' . h((string)$loginError) . '</div>';
    }
    echo '<form method="post" autocomplete="off">';
    echo '<input type="hidden" name="action" value="login">';
    echo '<label>Username</label><input class="input" type="text" name="username" required autofocus>';
    echo '<label>Password</label><input class="input" type="password" name="password" required>';
    echo '<button class="btn btn-primary btn-block" type="submit">Sign in</button>';
    echo '</form>';
    echo '</div></div></body></html>';
    exit;
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['csrf_token'];
}

function verifyCsrfOrFail(): void
{
    $token = (string)($_POST['csrf_token'] ?? '');
    if ($token === '' || !hash_equals((string)($_SESSION['csrf_token'] ?? ''), $token)) {
        http_response_code(419);
        renderFatalPage('Request rejected', 'The request could not be verified. Please reload the page and try again.');
    }
}

function handleMutation(array $config): never
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        redirect('index.php');
    }
    verifyCsrfOrFail();

    if (($config['features']['read_only'] ?? false) === true) {
        $_SESSION['flash'] = ['type' => 'danger', 'message' => 'Read-only mode is enabled. Changes are not allowed.'];
        redirect(backUrl());
    }

    $action = (string)($_POST['action'] ?? '');
    $zoneName = ensureTrailingDot((string)($_POST['zone_name'] ?? ''));
    if ($zoneName === '.') {
        $_SESSION['flash'] = ['type' => 'danger', 'message' => 'Invalid zone name.'];
        redirect('index.php');
    }

    try {
        $zone = fetchZone($config, $zoneName);
        guardWritableZone($config, $zone);

        switch ($action) {
            case 'add_rrset':
            case 'update_rrset':
                $payload = buildRrsetPayloadFromPost($zone['name']);
                backupZoneBeforeWrite($config, $zone['id']);
                pdnsRequest($config, 'PATCH', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']), [
                    'rrsets' => [$payload],
                ]);
                maybeRectify($config, $zone);
                audit($config, $action, ['zone' => $zone['name'], 'rrset' => $payload]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => $action === 'add_rrset' ? 'Record set added successfully.' : 'Record set updated successfully.'];
                break;

            case 'delete_rrset':
                $name = fqdnFromInput((string)($_POST['name'] ?? ''), $zone['name']);
                $type = strtoupper(trim((string)($_POST['type'] ?? '')));
                if ($type === '') {
                    throw new RuntimeException('Record type is required for deletion.');
                }
                backupZoneBeforeWrite($config, $zone['id']);
                pdnsRequest($config, 'PATCH', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']), [
                    'rrsets' => [[
                        'name' => $name,
                        'type' => $type,
                        'changetype' => 'DELETE',
                    ]],
                ]);
                maybeRectify($config, $zone);
                audit($config, 'delete_rrset', ['zone' => $zone['name'], 'name' => $name, 'type' => $type]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'Record set deleted successfully.'];
                break;

            case 'rectify_zone':
                guardRectifyAllowed($zone);
                pdnsRequest($config, 'PUT', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']) . '/rectify', []);
                audit($config, 'rectify_zone', ['zone' => $zone['name']]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'Zone rectified successfully.'];
                break;

            default:
                throw new RuntimeException('Unsupported action.');
        }
    } catch (Throwable $e) {
        $_SESSION['flash'] = ['type' => 'danger', 'message' => $e->getMessage()];
    }

    redirect('index.php?zone=' . urlencode(rtrim($zoneName, '.')));
}

function buildRrsetPayloadFromPost(string $zoneName): array
{
    $name = fqdnFromInput((string)($_POST['name'] ?? '@'), $zoneName);
    $type = strtoupper(trim((string)($_POST['type'] ?? '')));
    $ttl = (int)($_POST['ttl'] ?? 300);
    $rawValues = trim((string)($_POST['content'] ?? ''));
    if ($type === '') {
        throw new RuntimeException('Record type is required.');
    }
    if ($ttl < 1 || $ttl > 2147483647) {
        throw new RuntimeException('TTL must be between 1 and 2147483647.');
    }
    if ($rawValues === '') {
        throw new RuntimeException('Record content is required.');
    }

    $lines = preg_split('/\r\n|\r|\n/', $rawValues) ?: [];
    $records = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $records[] = ['content' => normalizeRecordContent($type, $line), 'disabled' => false];
    }

    if ($records === []) {
        throw new RuntimeException('At least one record value is required.');
    }
    if ($type === 'CNAME' && count($records) !== 1) {
        throw new RuntimeException('CNAME RRsets must contain exactly one record value.');
    }

    return [
        'name' => $name,
        'type' => $type,
        'ttl' => $ttl,
        'changetype' => 'REPLACE',
        'records' => $records,
    ];
}

function normalizeRecordContent(string $type, string $value): string
{
    $type = strtoupper($type);
    $value = trim($value);

    return match ($type) {
        'A' => validateIpv4($value),
        'AAAA' => validateIpv6($value),
        'CNAME', 'NS', 'PTR' => normalizeHostnameTarget($value),
        'MX' => normalizeMx($value),
        'SRV' => normalizeSrv($value),
        'CAA' => normalizeCaa($value),
        'TXT', 'SPF' => normalizeTxtLike($value),
        default => $value,
    };
}

function validateIpv4(string $value): string
{
    if (!filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        throw new RuntimeException('Invalid IPv4 address: ' . $value);
    }
    return $value;
}

function validateIpv6(string $value): string
{
    if (!filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        throw new RuntimeException('Invalid IPv6 address: ' . $value);
    }
    return $value;
}

function normalizeHostnameTarget(string $value): string
{
    $value = rtrim($value);
    if ($value === '.') {
        return $value;
    }
    return ensureTrailingDot($value);
}

function normalizeMx(string $value): string
{
    if (!preg_match('/^(\d{1,5})\s+(.+)$/', $value, $m)) {
        throw new RuntimeException('MX records must use the format: preference hostname');
    }
    $prio = (int)$m[1];
    if ($prio < 0 || $prio > 65535) {
        throw new RuntimeException('MX priority must be between 0 and 65535.');
    }
    return $prio . ' ' . normalizeHostnameTarget(trim($m[2]));
}

function normalizeSrv(string $value): string
{
    if (!preg_match('/^(\d{1,5})\s+(\d{1,5})\s+(\d{1,5})\s+(.+)$/', $value, $m)) {
        throw new RuntimeException('SRV records must use the format: priority weight port target');
    }
    $priority = (int)$m[1];
    $weight = (int)$m[2];
    $port = (int)$m[3];
    foreach ([$priority, $weight, $port] as $part) {
        if ($part < 0 || $part > 65535) {
            throw new RuntimeException('SRV values must be between 0 and 65535.');
        }
    }
    return sprintf('%d %d %d %s', $priority, $weight, $port, normalizeHostnameTarget(trim($m[4])));
}

function normalizeCaa(string $value): string
{
    if (!preg_match('/^(\d{1,3})\s+([A-Za-z0-9-]+)\s+(.+)$/', $value, $m)) {
        throw new RuntimeException('CAA records must use the format: flags tag value');
    }
    $flags = (int)$m[1];
    if ($flags < 0 || $flags > 255) {
        throw new RuntimeException('CAA flags must be between 0 and 255.');
    }
    $tag = $m[2];
    $rest = trim($m[3]);
    if (!str_starts_with($rest, '"')) {
        $rest = '"' . addcslashes(trim($rest, '"'), '"\\') . '"';
    }
    return sprintf('%d %s %s', $flags, $tag, $rest);
}

function normalizeTxtLike(string $value): string
{
    if (str_starts_with($value, '"') && str_ends_with($value, '"')) {
        return $value;
    }
    return '"' . addcslashes(trim($value, '"'), '"\\') . '"';
}

function ensureTrailingDot(string $name): string
{
    $name = trim($name);
    if ($name === '') {
        return '.';
    }
    return rtrim($name, '.') . '.';
}

function fqdnFromInput(string $input, string $zoneName): string
{
    $input = trim($input);
    $zoneName = ensureTrailingDot($zoneName);
    if ($input === '' || $input === '@') {
        return $zoneName;
    }
    if (str_ends_with($input, '.')) {
        return $input;
    }
    return rtrim($input, '.') . '.' . $zoneName;
}

function displayRelativeName(string $fqdn, string $zoneName): string
{
    $fqdn = ensureTrailingDot($fqdn);
    $zoneName = ensureTrailingDot($zoneName);
    if ($fqdn === $zoneName) {
        return '@';
    }
    $suffix = '.' . rtrim($zoneName, '.');
    if (str_ends_with(rtrim($fqdn, '.'), $suffix)) {
        return substr(rtrim($fqdn, '.'), 0, -strlen($suffix));
    }
    return rtrim($fqdn, '.');
}

function fetchZones(array $config): array
{
    $zones = pdnsRequest($config, 'GET', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones');
    if (!is_array($zones)) {
        throw new RuntimeException('Unexpected zones response from PowerDNS API.');
    }
    usort($zones, static function (array $a, array $b) {
        return strnatcasecmp((string)($a['name'] ?? ''), (string)($b['name'] ?? ''));
    });
    return $zones;
}

function fetchZone(array $config, string $zoneIdOrName): array
{
    $zone = pdnsRequest($config, 'GET', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode(ensureTrailingDot($zoneIdOrName)));
    if (!is_array($zone) || empty($zone['name'])) {
        throw new RuntimeException('Zone not found or invalid response received from PowerDNS API.');
    }
    return $zone;
}

function findZoneByName(array $zones, string $zoneName): ?array
{
    $zoneName = ensureTrailingDot($zoneName);
    foreach ($zones as $zone) {
        if (($zone['name'] ?? null) === $zoneName) {
            return $zone;
        }
    }
    return null;
}

function guardWritableZone(array $config, array $zone): void
{
    if (($config['features']['block_secondary_writes'] ?? true) !== true) {
        return;
    }
    $kind = strtoupper((string)($zone['kind'] ?? ''));
    if (in_array($kind, ['SLAVE', 'SECONDARY', 'CONSUMER'], true)) {
        throw new RuntimeException('Writes are blocked for secondary-style zones in this panel.');
    }
}

function guardRectifyAllowed(array $zone): void
{
    $kind = strtoupper((string)($zone['kind'] ?? ''));
    if (in_array($kind, ['SLAVE', 'SECONDARY', 'CONSUMER'], true)) {
        throw new RuntimeException('Rectify is not allowed for this zone kind.');
    }
}

function maybeRectify(array $config, array $zone): void
{
    if (($config['features']['default_auto_rectify'] ?? false) !== true) {
        return;
    }
    guardRectifyAllowed($zone);
    pdnsRequest($config, 'PUT', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']) . '/rectify', []);
}

function backupZoneBeforeWrite(array $config, string $zoneId): void
{
    if (($config['features']['backup_before_write'] ?? true) !== true) {
        return;
    }

    $export = pdnsRequest($config, 'GET', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode($zoneId) . '/export', null, 'text/plain');
    $backupDir = (string)($config['storage']['backup_dir'] ?? '');
    if ($backupDir === '') {
        throw new RuntimeException('Backup directory is not configured.');
    }
    $filename = $backupDir . '/' . preg_replace('/[^A-Za-z0-9._-]+/', '_', rtrim($zoneId, '.')) . '__' . date('Ymd_His') . '.zone';
    if (@file_put_contents($filename, (string)$export, LOCK_EX) === false) {
        throw new RuntimeException('Failed to save the pre-change zone backup.');
    }
}

function downloadZoneExport(array $config, string $zoneName): never
{
    requireAuth();
    $zone = fetchZone($config, $zoneName);
    $export = pdnsRequest($config, 'GET', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']) . '/export', null, 'text/plain');
    header('Content-Type: text/plain; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . preg_replace('/[^A-Za-z0-9._-]+/', '_', rtrim((string)$zone['name'], '.')) . '.zone"');
    echo (string)$export;
    exit;
}

function pdnsRequest(array $config, string $method, string $path, ?array $payload = null, string $accept = 'application/json')
{
    $pdns = $config['pdns'] ?? [];
    $baseUrl = rtrim((string)($pdns['base_url'] ?? ''), '/');
    $apiKey = (string)($pdns['api_key'] ?? '');
    if ($baseUrl === '' || $apiKey === '') {
        throw new RuntimeException('PowerDNS API configuration is incomplete.');
    }

    $ch = curl_init($baseUrl . $path);
    if ($ch === false) {
        throw new RuntimeException('Could not initialize cURL.');
    }

    $headers = [
        'X-API-Key: ' . $apiKey,
        'Accept: ' . $accept,
    ];
    if ($payload !== null) {
        $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
    }

    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_CONNECTTIMEOUT => (int)($pdns['connect_timeout'] ?? 10),
        CURLOPT_TIMEOUT => (int)($pdns['timeout'] ?? 20),
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => (bool)($pdns['verify_tls'] ?? true),
        CURLOPT_SSL_VERIFYHOST => (bool)($pdns['verify_tls'] ?? true) ? 2 : 0,
        CURLOPT_USERAGENT => 'HiData-PDNS-Manager/1.0',
    ]);

    if (!empty($pdns['ca_bundle'])) {
        curl_setopt($ch, CURLOPT_CAINFO, (string)$pdns['ca_bundle']);
    }

    $response = curl_exec($ch);
    if ($response === false) {
        $error = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('PowerDNS API request failed: ' . $error);
    }

    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $headerSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);

    $body = substr($response, $headerSize);
    if ($status < 200 || $status >= 300) {
        $decoded = json_decode($body, true);
        $message = is_array($decoded)
            ? ((string)($decoded['error'] ?? 'API error'))
            : ('API error (HTTP ' . $status . ')');
        if (is_array($decoded) && !empty($decoded['errors']) && is_array($decoded['errors'])) {
            $message .= ' - ' . implode('; ', array_map('strval', $decoded['errors']));
        }
        throw new RuntimeException($message . ' [HTTP ' . $status . ']');
    }

    if ($accept === 'text/plain') {
        return $body;
    }

    if ($body === '' || $body === 'null') {
        return [];
    }

    try {
        return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        throw new RuntimeException('Failed to decode PowerDNS API response: ' . $e->getMessage());
    }
}

function audit(array $config, string $action, array $context = []): void
{
    $file = (string)($config['storage']['audit_log'] ?? '');
    if ($file === '') {
        return;
    }
    $entry = [
        'ts' => gmdate('c'),
        'action' => $action,
        'user' => $_SESSION['auth']['username'] ?? 'unknown',
        'ip' => clientIp(),
        'context' => $context,
    ];
    @file_put_contents($file, json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function loadRateLimit(array $config): array
{
    $file = (string)($config['storage']['rate_limit_file'] ?? '');
    if ($file === '' || !is_file($file)) {
        return [];
    }
    $raw = file_get_contents($file);
    if ($raw === false || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function saveRateLimit(array $config, array $data): void
{
    $file = (string)($config['storage']['rate_limit_file'] ?? '');
    if ($file === '') {
        return;
    }
    @file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function backUrl(): string
{
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($referer !== '') {
        return $referer;
    }
    return 'index.php';
}

function redirect(string $url): never
{
    header('Location: ' . $url);
    exit;
}

function h(?string $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function renderFlash(?array $flash): string
{
    if (!$flash) {
        return '';
    }
    $type = $flash['type'] ?? 'info';
    return '<div class="flash flash-' . h((string)$type) . '">' . h((string)($flash['message'] ?? '')) . '</div>';
}

function maskSecret(string $value): string
{
    if ($value === '') {
        return 'not set';
    }
    if (strlen($value) <= 8) {
        return str_repeat('*', strlen($value));
    }
    return substr($value, 0, 4) . str_repeat('*', max(4, strlen($value) - 8)) . substr($value, -4);
}

function renderPage(array $data): void
{
    $config = $data['config'];
    $zones = $data['zones'];
    $zoneSearch = $data['zoneSearch'];
    $currentZone = $data['currentZone'];
    $zoneDetails = $data['zoneDetails'];
    $rrsets = $data['rrsets'];
    $recordFilter = $data['recordFilter'];

    $filteredZones = array_values(array_filter($zones, static function ($zone) use ($zoneSearch) {
        if ($zoneSearch === '') {
            return true;
        }
        return mb_stripos((string)($zone['name'] ?? ''), $zoneSearch) !== false;
    }));

    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . h((string)($config['app']['name'] ?? 'HiData PowerDNS Manager')) . '</title>';
    echo '<style>' . baseCss() . appCss() . '</style>';
    echo '</head><body>';
    echo '<div class="layout">';
    echo '<aside class="sidebar">';
    echo '<div class="brand">';
    echo '<div class="brand-logo">Hi</div>';
    echo '<div><div class="brand-name">' . h((string)($config['app']['name'] ?? 'HiData PowerDNS Manager')) . '</div>';
    echo '<div class="brand-tag">Professional DNS control panel</div></div>';
    echo '</div>';

    echo '<form class="search-form" method="get">';
    if ($currentZone) {
        echo '<input type="hidden" name="zone" value="' . h(rtrim((string)$currentZone['name'], '.')) . '">';
    }
    echo '<label class="label">Zone search</label>';
    echo '<input class="input" type="text" name="zone_search" value="' . h($zoneSearch) . '" placeholder="Search zones...">';
    echo '</form>';

    echo '<div class="sidebar-section-title">Zones <span class="badge">' . count($filteredZones) . '</span></div>';
    echo '<div class="zone-list">';
    foreach ($filteredZones as $zone) {
        $active = $currentZone && $currentZone['name'] === $zone['name'] ? ' active' : '';
        echo '<a class="zone-item' . $active . '" href="?zone=' . urlencode(rtrim((string)$zone['name'], '.')) . '">';
        echo '<span class="zone-name">' . h(rtrim((string)$zone['name'], '.')) . '</span>';
        echo '<span class="zone-meta">' . h((string)($zone['kind'] ?? 'Unknown')) . '</span>';
        echo '</a>';
    }
    if ($filteredZones === []) {
        echo '<div class="empty small">No zones found.</div>';
    }
    echo '</div>';

    echo '<div class="config-box">';
    echo '<div class="config-row"><span>API endpoint</span><strong>' . h((string)($config['pdns']['base_url'] ?? '')) . '</strong></div>';
    echo '<div class="config-row"><span>Server ID</span><strong>' . h((string)($config['pdns']['server_id'] ?? '')) . '</strong></div>';
    echo '<div class="config-row"><span>API key</span><strong>' . h(maskSecret((string)($config['pdns']['api_key'] ?? ''))) . '</strong></div>';
    echo '<div class="config-row"><span>Mode</span><strong>' . (($config['features']['read_only'] ?? false) ? 'Read-only' : 'Read / Write') . '</strong></div>';
    echo '</div>';

    echo '</aside>';
    echo '<main class="content">';
    echo '<div class="topbar">';
    echo '<div>';
    echo '<div class="eyebrow">HiData brand UI</div>';
    echo '<h1 class="page-title">' . ($currentZone ? h(rtrim((string)$currentZone['name'], '.')) : 'PowerDNS Dashboard') . '</h1>';
    echo '</div>';
    echo '<div class="top-actions">';
    echo '<span class="user-chip">' . h((string)($_SESSION['auth']['username'] ?? 'admin')) . '</span>';
    echo '<a class="btn btn-ghost" href="?logout=1">Sign out</a>';
    echo '</div>';
    echo '</div>';

    echo renderFlash($data['flash'] ?? null);

    if (!$currentZone || !$zoneDetails) {
        echo '<section class="panel hero">';
        echo '<div class="hero-copy">';
        echo '<h2>Professional remote PowerDNS management</h2>';
        echo '<p>Browse zones from the left, inspect RRsets, add or edit records, export zones, and optionally auto-rectify changes with audit logging and pre-change backups.</p>';
        echo '</div>';
        echo '<div class="hero-grid">';
        echo '<div class="stat-card"><span>Zones</span><strong>' . count($zones) . '</strong></div>';
        echo '<div class="stat-card"><span>TLS verification</span><strong>' . (($config['pdns']['verify_tls'] ?? true) ? 'On' : 'Off') . '</strong></div>';
        echo '<div class="stat-card"><span>Backups</span><strong>' . (($config['features']['backup_before_write'] ?? false) ? 'Enabled' : 'Disabled') . '</strong></div>';
        echo '</div>';
        echo '</section>';
        echo '</main></div>';
        echo modalScripts();
        echo '</body></html>';
        return;
    }

    echo '<section class="panel zone-header">';
    echo '<div class="zone-title-wrap">';
    echo '<div class="zone-title">' . h(rtrim((string)$zoneDetails['name'], '.')) . '</div>';
    echo '<div class="zone-subtitle">Serial ' . h((string)($zoneDetails['serial'] ?? '-')) . ' · Edited serial ' . h((string)($zoneDetails['edited_serial'] ?? '-')) . '</div>';
    echo '</div>';
    echo '<div class="zone-badges">';
    echo '<span class="pill">' . h((string)($zoneDetails['kind'] ?? 'Unknown')) . '</span>';
    echo '<span class="pill">DNSSEC ' . (!empty($zoneDetails['dnssec']) ? 'On' : 'Off') . '</span>';
    echo '<span class="pill">API Rectify ' . (!empty($zoneDetails['api_rectify']) ? 'On' : 'Off') . '</span>';
    echo '</div>';
    echo '<div class="zone-actions">';
    echo '<a class="btn btn-primary" href="#" onclick="openModal(\'addModal\');return false;">Add record</a>';
    echo '<a class="btn btn-ghost" href="?download=zone&amp;zone=' . urlencode(rtrim((string)$zoneDetails['name'], '.')) . '">Export zone</a>';
    echo '<form method="post" class="inline-form" onsubmit="return confirm(\'Rectify this zone now?\')">';
    echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
    echo '<input type="hidden" name="action" value="rectify_zone">';
    echo '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
    echo '<button class="btn btn-ghost" type="submit">Rectify</button>';
    echo '</form>';
    echo '</div>';
    echo '</section>';

    echo '<section class="panel">';
    echo '<div class="toolbar">';
    echo '<form method="get" class="toolbar-form">';
    echo '<input type="hidden" name="zone" value="' . h(rtrim((string)$zoneDetails['name'], '.')) . '">';
    echo '<input class="input" type="text" name="record_filter" value="' . h($recordFilter) . '" placeholder="Search records...">';
    echo '<button class="btn btn-ghost" type="submit">Filter</button>';
    echo '</form>';
    echo '<div class="small muted">Showing ' . count($rrsets) . ' RRsets</div>';
    echo '</div>';

    if ($rrsets === []) {
        echo '<div class="empty">No RRsets matched this zone or filter.</div>';
    } else {
        echo '<div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Records</th><th>Actions</th></tr></thead><tbody>';
        foreach ($rrsets as $rrset) {
            $records = $rrset['records'] ?? [];
            $contentLines = [];
            foreach ($records as $r) {
                $contentLines[] = (string)($r['content'] ?? '');
            }
            $jsPayload = htmlspecialchars(json_encode([
                'name' => displayRelativeName((string)($rrset['name'] ?? ''), (string)$zoneDetails['name']),
                'type' => (string)($rrset['type'] ?? ''),
                'ttl' => (int)($rrset['ttl'] ?? 300),
                'content' => implode("\n", $contentLines),
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

            echo '<tr>';
            echo '<td><div class="mono">' . h(displayRelativeName((string)($rrset['name'] ?? ''), (string)$zoneDetails['name'])) . '</div></td>';
            echo '<td><span class="type-chip">' . h((string)($rrset['type'] ?? '')) . '</span></td>';
            echo '<td>' . h((string)($rrset['ttl'] ?? '-')) . '</td>';
            echo '<td><div class="records">';
            foreach ($contentLines as $line) {
                echo '<div class="record-line mono">' . h($line) . '</div>';
            }
            echo '</div></td>';
            echo '<td><div class="action-stack">';
            echo '<a class="btn btn-small btn-ghost" href="#" data-edit=
"' . $jsPayload . '" onclick="fillEditModal(this.dataset.edit);openModal(\'editModal\');return false;">Edit</a>';
            echo '<form method="post" onsubmit="return confirm(\'Delete this entire RRset?\')">';
            echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
            echo '<input type="hidden" name="action" value="delete_rrset">';
            echo '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
            echo '<input type="hidden" name="name" value="' . h(displayRelativeName((string)($rrset['name'] ?? ''), (string)$zoneDetails['name'])) . '">';
            echo '<input type="hidden" name="type" value="' . h((string)($rrset['type'] ?? '')) . '">';
            echo '<button class="btn btn-small btn-danger" type="submit">Delete</button>';
            echo '</form>';
            echo '</div></td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
    }
    echo '</section>';

    echo buildAddModal((string)$zoneDetails['name']);
    echo buildEditModal((string)$zoneDetails['name']);

    echo '</main></div>';
    echo modalScripts();
    echo '</body></html>';
}

function buildAddModal(string $zoneName): string
{
    return '<div class="modal" id="addModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>Add RRset</h3><button class="icon-btn" onclick="closeModal(\'addModal\')">×</button></div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="add_rrset"><input type="hidden" name="zone_name" value="' . h($zoneName) . '"><div class="grid-two"><div><label>Name</label><input class="input" name="name" value="@" placeholder="@ or subdomain" required></div><div><label>Type</label><select class="input" name="type">' . recordTypeOptions() . '</select></div><div><label>TTL</label><input class="input" type="number" name="ttl" value="300" min="1" max="2147483647" required></div><div><label>Notes</label><div class="hint">Use one value per line for multi-value RRsets.</div></div></div><label>Content</label><textarea class="textarea" name="content" rows="8" placeholder="185.112.35.197 or 10 mail.example.com." required></textarea><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'addModal\')">Cancel</button><button class="btn btn-primary" type="submit">Create RRset</button></div></form></div></div>';
}

function buildEditModal(string $zoneName): string
{
    return '<div class="modal" id="editModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>Edit RRset</h3><button class="icon-btn" onclick="closeModal(\'editModal\')">×</button></div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="update_rrset"><input type="hidden" name="zone_name" value="' . h($zoneName) . '"><div class="grid-two"><div><label>Name</label><input class="input" id="edit_name" name="name" required></div><div><label>Type</label><select class="input" id="edit_type" name="type">' . recordTypeOptions() . '</select></div><div><label>TTL</label><input class="input" type="number" id="edit_ttl" name="ttl" min="1" max="2147483647" required></div><div><label>Notes</label><div class="hint">Editing replaces the whole RRset for this name and type.</div></div></div><label>Content</label><textarea class="textarea" id="edit_content" name="content" rows="8" required></textarea><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'editModal\')">Cancel</button><button class="btn btn-primary" type="submit">Save changes</button></div></form></div></div>';
}

function recordTypeOptions(): string
{
    $types = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'PTR', 'SRV', 'CAA', 'SPF'];
    $html = '';
    foreach ($types as $type) {
        $html .= '<option value="' . h($type) . '">' . h($type) . '</option>';
    }
    return $html;
}

function baseCss(): string
{
    return <<<'CSS'
:root{
  --bg:#08111f;
  --bg-soft:#0e1a2f;
  --panel:#0f1c33;
  --panel-2:#122341;
  --line:#223658;
  --text:#ebf3ff;
  --muted:#9fb3d8;
  --primary:#15b8ff;
  --primary-2:#4de4ff;
  --danger:#ff5478;
  --success:#18d39b;
  --warning:#ffb547;
  --shadow:0 18px 55px rgba(0,0,0,.35);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;background:radial-gradient(circle at top right,#16325d 0,#08111f 42%,#06101c 100%);color:var(--text)}
a{color:inherit;text-decoration:none}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.input,.textarea,select{width:100%;background:#091528;border:1px solid var(--line);color:var(--text);border-radius:14px;padding:12px 14px;outline:none;transition:.2s}
.input:focus,.textarea:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(21,184,255,.12)}
.textarea{resize:vertical;min-height:140px}
label{display:block;margin:0 0 8px;font-size:13px;color:#c6d5ef;font-weight:600}
.btn{appearance:none;border:0;border-radius:14px;padding:11px 16px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;transition:.2s}
.btn:hover{transform:translateY(-1px)}
.btn-primary{background:linear-gradient(135deg,var(--primary),var(--primary-2));color:#06223a;box-shadow:0 10px 28px rgba(21,184,255,.24)}
.btn-ghost{background:#0b1628;color:#d9e7ff;border:1px solid var(--line)}
.btn-danger{background:rgba(255,84,120,.12);color:#ffd4dd;border:1px solid rgba(255,84,120,.3)}
.btn-small{padding:8px 12px;border-radius:12px;font-size:13px}
.btn-block{width:100%}
.flash{padding:14px 16px;border-radius:16px;margin:0 0 18px;font-weight:600}
.flash-success{background:rgba(24,211,155,.12);border:1px solid rgba(24,211,155,.3);color:#c9fff0}
.flash-danger{background:rgba(255,84,120,.12);border:1px solid rgba(255,84,120,.3);color:#ffd7df}
.flash-info{background:rgba(21,184,255,.12);border:1px solid rgba(21,184,255,.3);color:#d1f4ff}
.muted{color:var(--muted)}
.small{font-size:13px}
.pill,.badge,.type-chip{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border-radius:999px;border:1px solid var(--line);background:#0a162a;color:#d5e6ff;font-size:12px;font-weight:700}
.empty{padding:26px;border:1px dashed #38537f;border-radius:18px;color:var(--muted);text-align:center;background:rgba(10,22,42,.45)}
CSS;
}

function loginCss(): string
{
    return <<<'CSS'
.login-body{min-height:100vh;display:grid;place-items:center;padding:32px}
.login-shell{width:min(980px,100%);display:grid;grid-template-columns:1.1fr .9fr;gap:26px;align-items:center}
.login-brand{padding:24px}
.brand-mark{width:84px;height:84px;border-radius:26px;background:linear-gradient(135deg,var(--primary),var(--primary-2));color:#07243d;display:grid;place-items:center;font-size:34px;font-weight:900;box-shadow:var(--shadow);margin-bottom:20px}
.brand-title{font-size:42px;font-weight:900;line-height:1.05;margin-bottom:8px}
.brand-subtitle{font-size:18px;color:var(--muted);line-height:1.7;max-width:620px}
.login-card{background:rgba(15,28,51,.88);border:1px solid var(--line);backdrop-filter:blur(14px);padding:30px;border-radius:28px;box-shadow:var(--shadow)}
.login-card h1{margin:0 0 8px;font-size:30px}
.login-card p{margin:0 0 22px}
.login-card form{display:grid;gap:14px}
@media (max-width:860px){.login-shell{grid-template-columns:1fr}.login-brand{padding:0}.brand-title{font-size:32px}}
CSS;
}

function appCss(): string
{
    return <<<'CSS'
.layout{display:grid;grid-template-columns:330px 1fr;min-height:100vh}
.sidebar{border-right:1px solid rgba(72,101,151,.24);background:rgba(7,16,31,.72);backdrop-filter:blur(18px);padding:24px 20px;display:flex;flex-direction:column;gap:18px}
.brand{display:flex;align-items:center;gap:14px;padding:6px 4px 12px}
.brand-logo{width:54px;height:54px;border-radius:18px;background:linear-gradient(135deg,var(--primary),var(--primary-2));display:grid;place-items:center;color:#06223a;font-weight:900;font-size:22px;box-shadow:var(--shadow)}
.brand-name{font-size:18px;font-weight:900}
.brand-tag{font-size:13px;color:var(--muted);margin-top:3px}
.sidebar-section-title{display:flex;justify-content:space-between;align-items:center;font-size:13px;font-weight:800;color:#c8d7ef;text-transform:uppercase;letter-spacing:.08em}
.zone-list{display:flex;flex-direction:column;gap:8px;max-height:48vh;overflow:auto;padding-right:4px}
.zone-item{display:flex;align-items:center;justify-content:space-between;gap:10px;background:#0a1527;border:1px solid transparent;border-radius:16px;padding:12px 14px;transition:.2s}
.zone-item:hover{border-color:#35507e;background:#0d1a31}
.zone-item.active{background:linear-gradient(180deg,rgba(21,184,255,.18),rgba(77,228,255,.08));border-color:rgba(77,228,255,.35)}
.zone-name{font-weight:700;word-break:break-all}
.zone-meta{font-size:12px;color:var(--muted)}
.config-box{margin-top:auto;border:1px solid var(--line);background:#0a162a;border-radius:20px;padding:16px;display:grid;gap:10px}
.config-row{display:grid;gap:4px}
.config-row span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.config-row strong{font-size:13px;word-break:break-all}
.content{padding:28px;display:flex;flex-direction:column;gap:20px}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.eyebrow{text-transform:uppercase;letter-spacing:.12em;color:#78dfff;font-weight:800;font-size:12px;margin-bottom:8px}
.page-title{margin:0;font-size:34px;line-height:1.06}
.top-actions{display:flex;align-items:center;gap:12px}
.user-chip{padding:11px 14px;border-radius:999px;background:#0b1628;border:1px solid var(--line);font-weight:700}
.panel{background:rgba(15,28,51,.82);border:1px solid rgba(72,101,151,.24);border-radius:26px;padding:22px;box-shadow:var(--shadow)}
.hero{display:grid;grid-template-columns:1.15fr .85fr;gap:18px;align-items:center}
.hero h2{margin:0 0 10px;font-size:28px}
.hero p{margin:0;color:var(--muted);line-height:1.8}
.hero-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.stat-card{background:#0b1628;border:1px solid var(--line);border-radius:20px;padding:18px}
.stat-card span{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.stat-card strong{font-size:28px}
.zone-header{display:grid;grid-template-columns:1.2fr auto auto;gap:16px;align-items:center}
.zone-title{font-size:28px;font-weight:900;word-break:break-all}
.zone-subtitle{color:var(--muted);margin-top:6px}
.zone-badges,.zone-actions{display:flex;flex-wrap:wrap;gap:10px;justify-content:flex-end}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.toolbar-form{display:flex;gap:10px;align-items:center;flex:1;max-width:540px}
.inline-form{display:inline}
.table-wrap{overflow:auto;border:1px solid rgba(72,101,151,.22);border-radius:18px}
table{width:100%;border-collapse:collapse;min-width:900px}
thead th{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#9fb3d8;background:#0a1426}
th,td{padding:16px 14px;border-bottom:1px solid rgba(72,101,151,.18);vertical-align:top}
tbody tr:hover{background:rgba(12,25,47,.65)}
.records{display:grid;gap:6px}
.record-line{padding:8px 10px;border:1px solid rgba(72,101,151,.18);border-radius:12px;background:#081426;white-space:pre-wrap;word-break:break-all}
.action-stack{display:flex;flex-direction:column;gap:8px;align-items:flex-start}
.search-form{display:grid;gap:8px}
.label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#b9cbe8}
.modal{position:fixed;inset:0;background:rgba(2,7,15,.68);display:none;align-items:center;justify-content:center;padding:22px;z-index:60}
.modal.open{display:flex}
.modal-card{width:min(760px,100%);background:#0e1b32;border:1px solid var(--line);border-radius:26px;box-shadow:var(--shadow);padding:22px}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.modal-header h3{margin:0;font-size:24px}
.icon-btn{width:42px;height:42px;border-radius:14px;border:1px solid var(--line);background:#0b1628;color:#fff;font-size:24px;cursor:pointer}
.grid-two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.modal-footer{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
.hint{font-size:13px;color:var(--muted);line-height:1.7;padding-top:12px}
@media (max-width:1100px){.layout{grid-template-columns:280px 1fr}.hero,.zone-header{grid-template-columns:1fr}.zone-badges,.zone-actions{justify-content:flex-start}}
@media (max-width:860px){.layout{grid-template-columns:1fr}.sidebar{border-right:0;border-bottom:1px solid rgba(72,101,151,.24)}.content{padding:18px}.topbar,.toolbar{flex-direction:column;align-items:stretch}.grid-two,.hero-grid{grid-template-columns:1fr}}
CSS;
}

function modalScripts(): string
{
    return <<<'HTML'
<script>
function openModal(id){const el=document.getElementById(id);if(el){el.classList.add('open');el.setAttribute('aria-hidden','false');}}
function closeModal(id){const el=document.getElementById(id);if(el){el.classList.remove('open');el.setAttribute('aria-hidden','true');}}
function fillEditModal(raw){
  try{
    const data=JSON.parse(raw);
    document.getElementById('edit_name').value=data.name||'@';
    document.getElementById('edit_type').value=data.type||'A';
    document.getElementById('edit_ttl').value=data.ttl||300;
    document.getElementById('edit_content').value=data.content||'';
  }catch(e){console.error(e);alert('Failed to load RRset into editor.');}
}
window.addEventListener('keydown',function(e){if(e.key==='Escape'){document.querySelectorAll('.modal.open').forEach(el=>closeModal(el.id));}});
document.querySelectorAll('.modal').forEach(el=>el.addEventListener('click',function(e){if(e.target===el){closeModal(el.id);}}));
</script>
HTML;
}
