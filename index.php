<?php

declare(strict_types=1);

/**
 * HiData GeoDNS Manager
 * Single-file PHP panel for managing PowerDNS zones and RRsets on the same host.
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
date_default_timezone_set((string)($config['app']['timezone'] ?? 'Asia/Tehran'));
validateConfigOrFail($config);

$security = $config['security'] ?? [];
$sessionName = (string)($security['session_name'] ?? 'HIDATA_PDNS');
$isHttps = isHttpsRequest($config);
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
enforceSessionTimeout($config);

sendSecurityHeaders($config, $isHttps);
bootstrapStorage($config);
bootstrapGeoRuleStorage($config);

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

if (isset($_POST['action']) && $_POST['action'] === 'logout') {
    handleLogout($config);
}

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
$geoRuleStats = fetchGeoRuleStats($config);
$currentZone = $zoneName !== '' ? findZoneByName($zones, $zoneName) : null;
$geoRules = [];
$geoRuleGroups = [];
$rrsets = [];
if ($currentZone !== null) {
    $zoneDetails = fetchZone($config, $currentZone['id']);
    $geoRules = fetchGeoRulesForZone($config, (string)$currentZone['name']);
    $geoRuleGroups = groupGeoRulesByFqdn($geoRules);
    $rrsets = filterVisibleZoneRrsets($zoneDetails['rrsets'] ?? [], $geoRuleGroups);
    $rrsets = filterZoneRrsetsBySearch($rrsets, $recordFilter);
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
    'geoRules' => $geoRules,
    'geoRuleGroups' => $geoRuleGroups,
    'geoRuleStats' => $geoRuleStats,
    'rrsets' => $rrsets,
    'recordFilter' => $recordFilter,
    'view' => $view,
]);
exit;

function validateConfigOrFail(array $config): void
{
    $errors = [];

    if (trim((string)($config['auth']['username'] ?? '')) === '') {
        $errors[] = 'auth.username is required.';
    }

    $passwordHash = (string)($config['auth']['password_hash'] ?? '');
    if ($passwordHash === '') {
        $errors[] = 'auth.password_hash is required.';
    } elseif ((password_get_info($passwordHash)['algo'] ?? null) === null) {
        $errors[] = 'auth.password_hash must be generated with password_hash().';
    }

    $baseUrl = trim((string)($config['pdns']['base_url'] ?? ''));
    if ($baseUrl === '' || !filter_var($baseUrl, FILTER_VALIDATE_URL)) {
        $errors[] = 'pdns.base_url must be a valid URL.';
    }

    $apiKey = trim((string)($config['pdns']['api_key'] ?? ''));
    if ($apiKey === '' || $apiKey === 'CHANGE_ME') {
        $errors[] = 'pdns.api_key must be configured.';
    }

    if ($baseUrl !== '' && ($config['pdns']['verify_tls'] ?? true) === false) {
        $host = (string)(parse_url($baseUrl, PHP_URL_HOST) ?? '');
        if (!in_array($host, ['127.0.0.1', '::1', 'localhost'], true)) {
            $errors[] = 'pdns.verify_tls may only be disabled for localhost/loopback URLs.';
        }
    }

    foreach (['backup_dir', 'audit_log', 'rate_limit_file'] as $storageKey) {
        if (empty($config['storage'][$storageKey])) {
            $errors[] = 'storage.' . $storageKey . ' is required.';
        }
    }

    $database = $config['database'] ?? [];
    if (trim((string)($database['host'] ?? '')) === '') {
        $errors[] = 'database.host is required.';
    }
    $port = (int)($database['port'] ?? 0);
    if ($port < 1 || $port > 65535) {
        $errors[] = 'database.port must be between 1 and 65535.';
    }
    foreach (['name', 'username', 'password'] as $databaseKey) {
        if (trim((string)($database[$databaseKey] ?? '')) === '') {
            $errors[] = 'database.' . $databaseKey . ' is required.';
        }
    }
    if (($database['password'] ?? null) === 'CHANGE_ME') {
        $errors[] = 'database.password must be configured.';
    }

    $maxAnswersPerPool = (int)($config['geodns']['max_answers_per_pool'] ?? 8);
    if ($maxAnswersPerPool < 1 || $maxAnswersPerPool > 32) {
        $errors[] = 'geodns.max_answers_per_pool must be between 1 and 32.';
    }

    if ($errors !== []) {
        http_response_code(500);
        renderFatalPage('Configuration error', 'The application configuration is incomplete or unsafe for startup.', $errors);
    }
}

function sendSecurityHeaders(array $config, bool $isHttps): void
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

    if (($security['hsts'] ?? false) && $isHttps) {
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
            if (!@mkdir($dir, 0750, true) && !is_dir($dir)) {
                renderFatalPage('Storage error', 'Failed to create a required storage directory.', [$dir]);
            }
        }
        if (!is_writable($dir)) {
            renderFatalPage('Storage error', 'A required storage directory is not writable by PHP.', [$dir]);
        }
    }
}

function bootstrapGeoRuleStorage(array $config): void
{
    try {
        $pdo = geoDb($config);
        $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS hidata_geo_rules (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    zone_name VARCHAR(255) NOT NULL,
    fqdn VARCHAR(255) NOT NULL,
    record_type VARCHAR(10) NOT NULL,
    ttl INT UNSIGNED NOT NULL DEFAULT 60,
    country_codes VARCHAR(128) NOT NULL,
    country_answers_json LONGTEXT NOT NULL,
    default_answers_json LONGTEXT NOT NULL,
    health_check_port SMALLINT UNSIGNED DEFAULT NULL,
    is_enabled TINYINT(1) NOT NULL DEFAULT 1,
    last_sync_error TEXT DEFAULT NULL,
    last_synced_at DATETIME DEFAULT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_hidata_geo_rules_zone_fqdn_type (zone_name, fqdn, record_type),
    KEY idx_hidata_geo_rules_zone_name (zone_name),
    KEY idx_hidata_geo_rules_zone_fqdn (zone_name, fqdn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
SQL);
    } catch (Throwable $e) {
        http_response_code(500);
        renderFatalPage('Database error', 'Failed to initialize the GeoDNS rule database.', [$e->getMessage()]);
    }
}

function geoDb(array $config): PDO
{
    static $connections = [];

    $database = $config['database'] ?? [];
    $host = trim((string)($database['host'] ?? '127.0.0.1'));
    $port = (int)($database['port'] ?? 3306);
    $name = trim((string)($database['name'] ?? ''));
    $username = trim((string)($database['username'] ?? ''));
    $password = (string)($database['password'] ?? '');
    $charset = trim((string)($database['charset'] ?? 'utf8mb4'));
    $key = implode('|', [$host, (string)$port, $name, $username, $charset, md5($password)]);

    if (isset($connections[$key]) && $connections[$key] instanceof PDO) {
        return $connections[$key];
    }

    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $host, $port, $name, $charset);
    $connections[$key] = new PDO($dsn, $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $connections[$key];
}

function renderFatalPage(string $title, string $message, array $details = []): never
{
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . h($title) . '</title>';
    echo '<style>body{font-family:Inter,Arial,sans-serif;background:#0b1220;color:#e5eefb;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.box{max-width:680px;background:#111a2e;border:1px solid #22314f;padding:32px;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{margin:0 0 12px;font-size:28px}p{margin:0;color:#a7badc;line-height:1.7}ul{margin:18px 0 0;padding-left:20px;color:#c8d8f6;line-height:1.7}</style></head><body><div class="box"><h1>' . h($title) . '</h1><p>' . h($message) . '</p>';
    if ($details !== []) {
        echo '<ul>';
        foreach ($details as $detail) {
            echo '<li>' . h((string)$detail) . '</li>';
        }
        echo '</ul>';
    }
    echo '</div></body></html>';
    exit;
}

function requestHeader(string $key): string
{
    return trim((string)($_SERVER[$key] ?? ''));
}

function isHttpsRequest(array $config): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }

    if ((string)($_SERVER['SERVER_PORT'] ?? '') === '443') {
        return true;
    }

    if (!requestIsFromTrustedProxy($config)) {
        return false;
    }

    $forwardedProto = strtolower(requestHeader('HTTP_X_FORWARDED_PROTO'));
    if ($forwardedProto !== '') {
        return trim(explode(',', $forwardedProto)[0]) === 'https';
    }

    return str_contains(strtolower(requestHeader('HTTP_FORWARDED')), 'proto=https');
}

function requestIsFromTrustedProxy(array $config): bool
{
    if (($config['security']['trust_proxy_headers'] ?? false) !== true) {
        return false;
    }

    $remoteAddr = requestHeader('REMOTE_ADDR');
    if ($remoteAddr === '') {
        return false;
    }

    $trustedProxies = $config['security']['trusted_proxies'] ?? [];
    return is_array($trustedProxies) && ipMatchesList($remoteAddr, $trustedProxies);
}

function clientIp(array $config): string
{
    $remoteAddr = requestHeader('REMOTE_ADDR');
    if (!requestIsFromTrustedProxy($config)) {
        return $remoteAddr !== '' ? $remoteAddr : 'unknown';
    }

    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'] as $header) {
        $value = requestHeader($header);
        if ($value === '') {
            continue;
        }
        if ($header === 'HTTP_X_FORWARDED_FOR') {
            $value = trim(explode(',', $value)[0]);
        }
        if (filter_var($value, FILTER_VALIDATE_IP)) {
            return $value;
        }
    }

    return $remoteAddr !== '' ? $remoteAddr : 'unknown';
}

function ipMatchesList(string $ip, array $rules): bool
{
    foreach ($rules as $rule) {
        $rule = trim((string)$rule);
        if ($rule === '') {
            continue;
        }
        if (str_contains($rule, '/')) {
            if (ipInCidr($ip, $rule)) {
                return true;
            }
            continue;
        }
        if ($rule === $ip) {
            return true;
        }
    }
    return false;
}

function ipInCidr(string $ip, string $cidr): bool
{
    [$subnet, $prefix] = array_pad(explode('/', $cidr, 2), 2, null);
    if ($subnet === null || $prefix === null || !ctype_digit($prefix)) {
        return false;
    }

    $ipBin = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
        return false;
    }

    $prefixInt = (int)$prefix;
    if ($prefixInt < 0 || $prefixInt > strlen($ipBin) * 8) {
        return false;
    }
    $fullBytes = intdiv($prefixInt, 8);
    $remainingBits = $prefixInt % 8;

    if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
        return false;
    }

    if ($remainingBits === 0) {
        return true;
    }

    $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
    return (ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask);
}

function isClientIpAllowed(array $config): bool
{
    $allowed = $config['security']['allowed_ips'] ?? [];
    if (!is_array($allowed) || $allowed === []) {
        return true;
    }
    return ipMatchesList(clientIp($config), $allowed);
}

function handleLogin(array $config): never
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        redirect('index.php');
    }

    verifyCsrfOrFail();
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $auth = $config['auth'] ?? [];

    $rate = loadRateLimit($config);
    $ip = clientIp($config);
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

function handleLogout(array $config): never
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        redirect('index.php');
    }
    verifyCsrfOrFail();
    audit($config, 'logout', []);
    resetSession();
    $_SESSION['flash'] = ['type' => 'success', 'message' => 'Signed out successfully.'];
    redirect('index.php');
}

function enforceSessionTimeout(array $config): void
{
    if (empty($_SESSION['auth']['username'])) {
        return;
    }

    $auth = $_SESSION['auth'];
    $now = time();
    $idleTimeout = (int)($config['auth']['session_idle_timeout'] ?? 3600);
    $absoluteTimeout = (int)($config['auth']['session_absolute_timeout'] ?? 43200);

    if (
        ($idleTimeout > 0 && $now - (int)($auth['last_seen'] ?? 0) > $idleTimeout) ||
        ($absoluteTimeout > 0 && $now - (int)($auth['logged_in_at'] ?? 0) > $absoluteTimeout)
    ) {
        resetSession();
        $_SESSION['flash'] = ['type' => 'info', 'message' => 'Your session expired. Please sign in again.'];
        redirect('index.php');
    }
}

function resetSession(): void
{
    session_unset();
    session_destroy();
    session_start();
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
    echo '<title>HiData GeoDNS Manager</title>';
    echo '<style>' . baseCss() . loginCss() . '</style>';
    echo '</head><body class="login-body">';
    echo '<div class="login-shell">';
    echo '<div class="login-brand">';
    echo '<div class="brand-mark">Hi</div>';
    echo '<div><div class="brand-title">HiData GeoDNS Manager</div><div class="brand-subtitle">Secure PowerDNS control panel</div></div>';
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
    echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
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

    $action = (string)($_POST['action'] ?? '');
    if (($config['features']['read_only'] ?? false) === true) {
        $_SESSION['flash'] = ['type' => 'danger', 'message' => 'Read-only mode is enabled. Changes are not allowed.'];
        redirect(mutationRedirectTarget());
    }

    try {
        switch ($action) {
            case 'create_zone':
                guardZoneCreationAllowed($config);
                $createdZone = createZoneFromPost($config);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'Zone created successfully.'];
                redirect(zoneUrl((string)$createdZone['name']));

            case 'delete_zone':
                guardZoneDeletionAllowed($config);
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                backupZoneSnapshot($config, (string)$zone['id'], 'delete');
                pdnsRequest($config, 'DELETE', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']));
                deleteGeoRulesForZone($config, (string)$zone['name']);
                audit($config, 'delete_zone', ['zone' => $zone['name']]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'Zone deleted successfully.'];
                redirect('index.php');

            case 'add_rrset':
            case 'update_rrset':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                $payload = buildRrsetPayloadFromPost($zone['name']);
                guardManualRrsetMutationsAgainstGeoRules($config, (string)$zone['name'], [$payload], $action);
                backupZoneSnapshot($config, (string)$zone['id'], 'change');
                pdnsRequest($config, 'PATCH', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']), [
                    'rrsets' => [$payload],
                ]);
                maybeRectify($config, $zone);
                audit($config, $action, ['zone' => $zone['name'], 'rrset' => $payload]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => $action === 'add_rrset' ? 'Record set added successfully.' : 'Record set updated successfully.'];
                break;

            case 'delete_rrset':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                $name = fqdnFromInput((string)($_POST['name'] ?? ''), $zone['name']);
                $type = strtoupper(trim((string)($_POST['type'] ?? '')));
                if ($type === '') {
                    throw new RuntimeException('Record type is required for deletion.');
                }
                guardManualRrsetMutationsAgainstGeoRules($config, (string)$zone['name'], [[
                    'name' => $name,
                    'type' => $type,
                ]], 'delete_rrset');
                backupZoneSnapshot($config, (string)$zone['id'], 'change');
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

            case 'import_zone_file':
                $importResult = importZoneFileFromPost($config);
                $_SESSION['flash'] = ['type' => 'success', 'message' => summarizeZoneImportResult($importResult)];
                break;

            case 'create_geo_rule':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                $createdRule = createGeoRuleFromPost($config, $zone);
                audit($config, 'create_geo_rule', [
                    'zone' => $zone['name'],
                    'fqdn' => $createdRule['fqdn'],
                    'record_type' => $createdRule['record_type'],
                ]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'GeoDNS rule created and synced successfully.'];
                break;

            case 'update_geo_rule':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                $updatedRule = updateGeoRuleFromPost($config, $zone);
                audit($config, 'update_geo_rule', [
                    'zone' => $zone['name'],
                    'fqdn' => $updatedRule['fqdn'],
                    'record_type' => $updatedRule['record_type'],
                ]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'GeoDNS rule updated and synced successfully.'];
                break;

            case 'delete_geo_rule':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                $deletedRule = deleteGeoRuleFromPost($config, $zone);
                audit($config, 'delete_geo_rule', [
                    'zone' => $zone['name'],
                    'fqdn' => $deletedRule['fqdn'],
                    'record_type' => $deletedRule['record_type'],
                ]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'GeoDNS rule deleted successfully.'];
                break;

            case 'sync_geo_rule':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                $syncedRule = syncGeoRuleFromPost($config, $zone);
                audit($config, 'sync_geo_rule', [
                    'zone' => $zone['name'],
                    'fqdn' => $syncedRule['fqdn'],
                    'record_type' => $syncedRule['record_type'],
                ]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'GeoDNS rule set synced successfully.'];
                break;

            case 'sync_geo_zone':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardWritableZone($config, $zone);
                $syncResult = syncGeoZoneFromPost($config, $zone);
                audit($config, 'sync_geo_zone', [
                    'zone' => $zone['name'],
                    'synced_sets' => $syncResult['synced_sets'],
                ]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => $syncResult['message']];
                break;

            case 'rectify_zone':
                $zoneName = requirePostedZoneName();
                $zone = fetchZone($config, $zoneName);
                guardRectifyAllowed($zone);
                pdnsRequest($config, 'PUT', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']) . '/rectify');
                audit($config, 'rectify_zone', ['zone' => $zone['name']]);
                $_SESSION['flash'] = ['type' => 'success', 'message' => 'Zone rectified successfully.'];
                break;

            default:
                throw new RuntimeException('Unsupported action.');
        }
    } catch (Throwable $e) {
        $_SESSION['flash'] = ['type' => 'danger', 'message' => $e->getMessage()];
    }

    redirect(mutationRedirectTarget());
}

function guardZoneCreationAllowed(array $config): void
{
    if (($config['features']['allow_zone_create'] ?? true) !== true) {
        throw new RuntimeException('Zone creation is disabled in this panel.');
    }
}

function guardZoneDeletionAllowed(array $config): void
{
    if (($config['features']['allow_zone_delete'] ?? true) !== true) {
        throw new RuntimeException('Zone deletion is disabled in this panel.');
    }
}

function requirePostedZoneName(): string
{
    $zoneName = ensureTrailingDot((string)($_POST['zone_name'] ?? ''));
    if ($zoneName === '.') {
        throw new RuntimeException('A valid zone name is required.');
    }
    return $zoneName;
}

function mutationRedirectTarget(): string
{
    $zoneName = trim((string)($_POST['zone_name'] ?? ''));
    if ($zoneName === '') {
        return 'index.php';
    }
    return zoneUrl($zoneName);
}

function zoneUrl(string $zoneName): string
{
    return 'index.php?zone=' . urlencode(rtrim(ensureTrailingDot($zoneName), '.'));
}

function createZoneFromPost(array $config): array
{
    $zoneName = requirePostedZoneName();
    $kind = canonicalZoneKind((string)($_POST['zone_kind'] ?? 'Native'));
    $payload = [
        'name' => $zoneName,
        'kind' => $kind,
    ];

    $account = trim((string)($_POST['account'] ?? ''));
    if ($account !== '') {
        $payload['account'] = $account;
    }

    if (isSecondaryLikeKind($kind)) {
        $masters = parseTextareaLines((string)($_POST['masters'] ?? ''));
        if ($masters === []) {
            throw new RuntimeException('Secondary-style zones require at least one master server.');
        }
        $payload['masters'] = $masters;
    } else {
        $nameservers = array_map('normalizeHostnameTarget', parseTextareaLines((string)($_POST['nameservers'] ?? '')));
        if ($nameservers === []) {
            throw new RuntimeException('Provide at least one authoritative nameserver for the new zone.');
        }
        $payload['nameservers'] = $nameservers;
        $payload['dnssec'] = !empty($_POST['dnssec']);
        $payload['api_rectify'] = !empty($_POST['api_rectify']);
    }

    $zone = pdnsRequest($config, 'POST', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones', $payload);
    if (!is_array($zone) || empty($zone['name'])) {
        throw new RuntimeException('The PowerDNS API did not return a valid zone after creation.');
    }

    audit($config, 'create_zone', ['zone' => $zone['name'], 'kind' => $kind]);
    return $zone;
}

function canonicalZoneKind(string $kind): string
{
    return match (strtoupper(trim($kind))) {
        'NATIVE' => 'Native',
        'MASTER', 'PRIMARY' => 'Master',
        'SLAVE', 'SECONDARY' => 'Slave',
        'PRODUCER' => 'Producer',
        'CONSUMER' => 'Consumer',
        default => throw new RuntimeException('Unsupported zone kind.'),
    };
}

function isSecondaryLikeKind(string $kind): bool
{
    return in_array(strtoupper($kind), ['SLAVE', 'SECONDARY', 'CONSUMER'], true);
}

function parseTextareaLines(string $raw): array
{
    $lines = preg_split('/\r\n|\r|\n/', trim($raw)) ?: [];
    $values = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line !== '') {
            $values[] = $line;
        }
    }
    return $values;
}

function importZoneFileFromPost(array $config): array
{
    $zoneName = requirePostedZoneName();
    $zone = fetchZone($config, $zoneName);
    guardWritableZone($config, $zone);

    $raw = loadZoneImportTextFromRequest();
    $result = parseZoneImportText($raw, (string)$zone['name'], [
        'include_soa' => !empty($_POST['import_soa']),
        'include_ns' => !empty($_POST['import_ns']),
    ]);
    guardManualRrsetMutationsAgainstGeoRules($config, (string)$zone['name'], $result['rrsets'], 'import_zone_file');

    backupZoneSnapshot($config, (string)$zone['id'], 'import');
    pdnsRequest($config, 'PATCH', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']), [
        'rrsets' => $result['rrsets'],
    ]);
    maybeRectify($config, $zone);

    audit($config, 'import_zone_file', [
        'zone' => $zone['name'],
        'rrset_count' => $result['rrset_count'],
        'record_count' => $result['record_count'],
        'skipped_soa' => $result['skipped_soa'],
        'skipped_ns' => $result['skipped_ns'],
        'skipped_unsupported' => $result['skipped_unsupported'],
    ]);

    return $result;
}

function loadZoneImportTextFromRequest(): string
{
    $pasted = trim((string)($_POST['zone_text'] ?? ''));
    if ($pasted !== '') {
        return $pasted;
    }

    $file = $_FILES['zone_file'] ?? null;
    if (!is_array($file)) {
        throw new RuntimeException('Upload a zone text file or paste the zone content.');
    }

    $error = (int)($file['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($error === UPLOAD_ERR_NO_FILE) {
        throw new RuntimeException('Upload a zone text file or paste the zone content.');
    }
    if ($error !== UPLOAD_ERR_OK) {
        throw new RuntimeException(match ($error) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'The uploaded file is too large.',
            UPLOAD_ERR_PARTIAL => 'The uploaded file was only partially received.',
            default => 'The uploaded file could not be processed.',
        });
    }

    $tmpName = (string)($file['tmp_name'] ?? '');
    if ($tmpName === '' || !is_uploaded_file($tmpName)) {
        throw new RuntimeException('The uploaded file is not available anymore. Please try again.');
    }

    $size = (int)($file['size'] ?? 0);
    if ($size > 2 * 1024 * 1024) {
        throw new RuntimeException('The uploaded file is too large. Keep zone imports under 2 MB.');
    }

    $raw = file_get_contents($tmpName);
    if ($raw === false) {
        throw new RuntimeException('Failed to read the uploaded zone file.');
    }

    $raw = trim((string)$raw);
    if ($raw === '') {
        throw new RuntimeException('The uploaded zone file is empty.');
    }

    return $raw;
}

function parseZoneImportText(string $raw, string $zoneName, array $options = []): array
{
    $zoneName = ensureTrailingDot($zoneName);
    $origin = $zoneName;
    $currentOwner = $zoneName;
    $defaultTtl = null;
    $rrsets = [];
    $skippedSoa = 0;
    $skippedNs = 0;
    $unsupportedTypes = [];

    $lines = preg_split('/\r\n|\r|\n/', $raw) ?: [];
    foreach ($lines as $lineNumber => $line) {
        $withoutComment = stripZoneImportComment((string)$line);
        if (trim($withoutComment) === '') {
            continue;
        }

        $tokens = tokenizeZoneImportLine(trim($withoutComment));
        if ($tokens === []) {
            continue;
        }

        if (str_starts_with($tokens[0], '$')) {
            [$origin, $defaultTtl] = applyZoneImportDirective($tokens, $origin, $zoneName, $defaultTtl, $lineNumber + 1);
            continue;
        }

        $hasImplicitOwner = preg_match('/^[ \t]/', $withoutComment) === 1;
        [$record, $currentOwner] = parseZoneImportRecordTokens(
            $tokens,
            $currentOwner,
            $defaultTtl,
            $origin,
            $zoneName,
            $lineNumber + 1,
            $hasImplicitOwner
        );

        $type = $record['type'];
        if ($type === 'SOA' && ($options['include_soa'] ?? false) !== true) {
            $skippedSoa++;
            continue;
        }
        if ($type === 'NS' && ($options['include_ns'] ?? false) !== true) {
            $skippedNs++;
            continue;
        }
        if (!isSupportedImportRecordType($type)) {
            $unsupportedTypes[$type] = ($unsupportedTypes[$type] ?? 0) + 1;
            continue;
        }

        $content = normalizeRecordContent($type, $record['content']);
        $key = $record['name'] . '|' . $type;
        if (!isset($rrsets[$key])) {
            $rrsets[$key] = [
                'name' => $record['name'],
                'type' => $type,
                'ttl' => $record['ttl'],
                'changetype' => 'REPLACE',
                'records' => [],
            ];
        } elseif ((int)$rrsets[$key]['ttl'] !== (int)$record['ttl']) {
            throw new RuntimeException(sprintf(
                'Imported RRset %s %s mixes multiple TTL values. PowerDNS expects one TTL per RRset.',
                rtrim((string)$record['name'], '.'),
                $type
            ));
        }

        $rrsets[$key]['records'][$content] = [
            'content' => $content,
            'disabled' => false,
        ];
    }

    if ($rrsets === []) {
        throw new RuntimeException('No supported RRsets were found in the uploaded zone text.');
    }

    $recordCount = 0;
    foreach ($rrsets as &$rrset) {
        $rrset['records'] = array_values($rrset['records']);
        if (in_array((string)$rrset['type'], ['CNAME', 'SOA'], true) && count($rrset['records']) !== 1) {
            throw new RuntimeException(sprintf(
                '%s %s must contain exactly one record value.',
                rtrim((string)$rrset['name'], '.'),
                (string)$rrset['type']
            ));
        }
        $recordCount += count($rrset['records']);
    }
    unset($rrset);

    ksort($unsupportedTypes, SORT_NATURAL | SORT_FLAG_CASE);

    return [
        'rrsets' => array_values($rrsets),
        'rrset_count' => count($rrsets),
        'record_count' => $recordCount,
        'skipped_soa' => $skippedSoa,
        'skipped_ns' => $skippedNs,
        'skipped_unsupported' => $unsupportedTypes,
    ];
}

function stripZoneImportComment(string $line): string
{
    $result = '';
    $inQuote = false;
    $escape = false;
    $length = strlen($line);

    for ($i = 0; $i < $length; $i++) {
        $char = $line[$i];
        if ($escape) {
            $result .= $char;
            $escape = false;
            continue;
        }
        if ($char === '\\') {
            $result .= $char;
            $escape = true;
            continue;
        }
        if ($char === '"') {
            $result .= $char;
            $inQuote = !$inQuote;
            continue;
        }
        if (!$inQuote && $char === ';') {
            break;
        }
        $result .= $char;
    }

    return rtrim($result);
}

function tokenizeZoneImportLine(string $line): array
{
    $tokens = [];
    $buffer = '';
    $inQuote = false;
    $escape = false;
    $length = strlen($line);

    for ($i = 0; $i < $length; $i++) {
        $char = $line[$i];
        if ($escape) {
            $buffer .= $char;
            $escape = false;
            continue;
        }
        if ($char === '\\') {
            $buffer .= $char;
            $escape = true;
            continue;
        }
        if ($char === '"') {
            $buffer .= $char;
            $inQuote = !$inQuote;
            continue;
        }
        if (!$inQuote && ctype_space($char)) {
            if ($buffer !== '') {
                $tokens[] = $buffer;
                $buffer = '';
            }
            continue;
        }
        if (!$inQuote && ($char === '(' || $char === ')')) {
            if ($buffer !== '') {
                $tokens[] = $buffer;
                $buffer = '';
            }
            continue;
        }
        $buffer .= $char;
    }

    if ($buffer !== '') {
        $tokens[] = $buffer;
    }

    return $tokens;
}

function applyZoneImportDirective(array $tokens, string $origin, string $zoneName, ?int $defaultTtl, int $lineNumber): array
{
    $directive = strtoupper($tokens[0]);

    return match ($directive) {
        '$ORIGIN' => [resolveZoneImportName($tokens[1] ?? '', $origin, $zoneName, $lineNumber), $defaultTtl],
        '$TTL' => [$origin, normalizeZoneImportTtl($tokens[1] ?? '', $lineNumber)],
        default => [$origin, $defaultTtl],
    };
}

function parseZoneImportRecordTokens(
    array $tokens,
    string $currentOwner,
    ?int $defaultTtl,
    string $origin,
    string $zoneName,
    int $lineNumber,
    bool $hasImplicitOwner
): array {
    $index = 0;
    $owner = $currentOwner;

    if (!$hasImplicitOwner) {
        $first = $tokens[0] ?? '';
        if ($first !== '' && !ctype_digit($first) && !isDnsClassToken($first) && !isRecognizedImportRecordType($first)) {
            $owner = resolveZoneImportName($first, $origin, $zoneName, $lineNumber);
            $currentOwner = $owner;
            $index++;
        }
    }

    $ttl = null;
    $class = null;
    while ($index < count($tokens)) {
        $token = $tokens[$index];
        if ($ttl === null && ctype_digit($token)) {
            $ttl = normalizeZoneImportTtl($token, $lineNumber);
            $index++;
            continue;
        }
        if ($class === null && isDnsClassToken($token)) {
            $class = strtoupper($token);
            $index++;
            continue;
        }
        break;
    }

    $type = strtoupper((string)($tokens[$index] ?? ''));
    if ($type === '' || !isRecognizedImportRecordType($type)) {
        throw new RuntimeException('Could not determine the DNS record type on line ' . $lineNumber . '.');
    }
    $index++;

    $content = trim(implode(' ', array_slice($tokens, $index)));
    if ($content === '') {
        throw new RuntimeException('Imported record content is empty on line ' . $lineNumber . '.');
    }
    if ($class !== null && $class !== 'IN') {
        throw new RuntimeException('Only IN-class records are supported for import (line ' . $lineNumber . ').');
    }

    $ttl = $ttl ?? $defaultTtl ?? 3600;
    if ($ttl < 1 || $ttl > 2147483647) {
        throw new RuntimeException('TTL must be between 1 and 2147483647 on line ' . $lineNumber . '.');
    }
    if (!isNameInsideZone($owner, $zoneName)) {
        throw new RuntimeException(sprintf(
            'The imported record %s is outside the selected zone %s (line %d).',
            rtrim($owner, '.'),
            rtrim($zoneName, '.'),
            $lineNumber
        ));
    }

    return [[
        'name' => $owner,
        'type' => $type,
        'ttl' => $ttl,
        'content' => $content,
    ], $currentOwner];
}

function resolveZoneImportName(string $token, string $origin, string $zoneName, int $lineNumber): string
{
    $token = trim($token);
    if ($token === '') {
        throw new RuntimeException('The import file contains an empty owner/origin token on line ' . $lineNumber . '.');
    }

    if ($token === '@') {
        $fqdn = $origin;
    } elseif (str_ends_with($token, '.')) {
        $fqdn = ensureTrailingDot($token);
    } else {
        $fqdn = ensureTrailingDot($token . '.' . rtrim($origin, '.'));
    }

    if (!isNameInsideZone($fqdn, $zoneName)) {
        throw new RuntimeException(sprintf(
            'The import file references %s, which is outside the selected zone %s (line %d).',
            rtrim($fqdn, '.'),
            rtrim($zoneName, '.'),
            $lineNumber
        ));
    }

    return $fqdn;
}

function normalizeZoneImportTtl(string $token, int $lineNumber): int
{
    if (!ctype_digit($token)) {
        throw new RuntimeException('Invalid TTL value on line ' . $lineNumber . '.');
    }
    return (int)$token;
}

function isDnsClassToken(string $token): bool
{
    return in_array(strtoupper(trim($token)), ['IN', 'CH', 'HS'], true);
}

function isRecognizedImportRecordType(string $token): bool
{
    return in_array(strtoupper(trim($token)), [
        'A', 'AAAA', 'CAA', 'CNAME', 'DNSKEY', 'DS', 'HTTPS', 'LOC', 'MX', 'NAPTR',
        'NS', 'PTR', 'RP', 'SOA', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TLSA', 'TXT', 'URI',
    ], true);
}

function isSupportedImportRecordType(string $type): bool
{
    return in_array(strtoupper($type), ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SPF', 'SRV', 'TXT'], true);
}

function isNameInsideZone(string $fqdn, string $zoneName): bool
{
    $fqdn = ensureTrailingDot($fqdn);
    $zoneName = ensureTrailingDot($zoneName);
    return $fqdn === $zoneName || str_ends_with($fqdn, '.' . $zoneName);
}

function summarizeZoneImportResult(array $result): string
{
    $parts = [
        sprintf(
            'Zone import completed: %d RRsets / %d records applied.',
            (int)($result['rrset_count'] ?? 0),
            (int)($result['record_count'] ?? 0)
        ),
    ];

    $skipped = [];
    $skippedSoa = (int)($result['skipped_soa'] ?? 0);
    $skippedNs = (int)($result['skipped_ns'] ?? 0);
    if ($skippedSoa > 0) {
        $skipped[] = $skippedSoa . ' SOA';
    }
    if ($skippedNs > 0) {
        $skipped[] = $skippedNs . ' NS';
    }
    if ($skipped !== []) {
        $parts[] = 'Skipped by default: ' . implode(', ', $skipped) . '.';
    }

    $unsupported = $result['skipped_unsupported'] ?? [];
    if (is_array($unsupported) && $unsupported !== []) {
        $labels = [];
        foreach ($unsupported as $type => $count) {
            $labels[] = $type . ' (' . (int)$count . ')';
        }
        $parts[] = 'Unsupported record types skipped: ' . implode(', ', $labels) . '.';
    }

    return implode(' ', $parts);
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
    if (!in_array($type, manualRecordTypes(), true)) {
        throw new RuntimeException('Unsupported record type for manual editing.');
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

function fetchGeoRuleStats(array $config): array
{
    $row = geoDb($config)->query(
        'SELECT COUNT(*) AS total_rules, COALESCE(SUM(CASE WHEN is_enabled = 1 THEN 1 ELSE 0 END), 0) AS enabled_rules FROM hidata_geo_rules'
    )->fetch();

    return [
        'total_rules' => (int)($row['total_rules'] ?? 0),
        'enabled_rules' => (int)($row['enabled_rules'] ?? 0),
    ];
}

function fetchGeoRulesForZone(array $config, string $zoneName): array
{
    $stmt = geoDb($config)->prepare(
        "SELECT * FROM hidata_geo_rules WHERE zone_name = :zone_name ORDER BY fqdn ASC, FIELD(record_type, 'A', 'AAAA'), id ASC"
    );
    $stmt->execute(['zone_name' => ensureTrailingDot($zoneName)]);
    $rows = $stmt->fetchAll();
    return array_map(static fn(array $row): array => hydrateGeoRuleRow($row), $rows ?: []);
}

function fetchGeoRulesByFqdn(array $config, string $zoneName, string $fqdn, ?int $excludeId = null): array
{
    $pdo = geoDb($config);
    $sql = "SELECT * FROM hidata_geo_rules WHERE zone_name = :zone_name AND fqdn = :fqdn";
    $params = [
        'zone_name' => ensureTrailingDot($zoneName),
        'fqdn' => ensureTrailingDot($fqdn),
    ];
    if ($excludeId !== null) {
        $sql .= ' AND id != :exclude_id';
        $params['exclude_id'] = $excludeId;
    }
    $sql .= " ORDER BY FIELD(record_type, 'A', 'AAAA'), id ASC";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();
    return array_map(static fn(array $row): array => hydrateGeoRuleRow($row), $rows ?: []);
}

function fetchGeoRuleById(array $config, int $ruleId, ?string $zoneName = null): array
{
    if ($ruleId < 1) {
        throw new RuntimeException('A valid GeoDNS rule id is required.');
    }

    $sql = 'SELECT * FROM hidata_geo_rules WHERE id = :id';
    $params = ['id' => $ruleId];
    if ($zoneName !== null) {
        $sql .= ' AND zone_name = :zone_name';
        $params['zone_name'] = ensureTrailingDot($zoneName);
    }

    $stmt = geoDb($config)->prepare($sql);
    $stmt->execute($params);
    $row = $stmt->fetch();
    if (!is_array($row)) {
        throw new RuntimeException('GeoDNS rule not found.');
    }

    return hydrateGeoRuleRow($row);
}

function requirePostedGeoRuleId(): int
{
    $ruleId = (int)($_POST['geo_rule_id'] ?? 0);
    if ($ruleId < 1) {
        throw new RuntimeException('A valid GeoDNS rule id is required.');
    }
    return $ruleId;
}

function hydrateGeoRuleRow(array $row): array
{
    $zoneName = ensureTrailingDot((string)($row['zone_name'] ?? ''));
    $fqdn = ensureTrailingDot((string)($row['fqdn'] ?? ''));

    return [
        'id' => (int)($row['id'] ?? 0),
        'zone_name' => $zoneName,
        'fqdn' => $fqdn,
        'display_name' => displayRelativeName($fqdn, $zoneName),
        'record_type' => strtoupper(trim((string)($row['record_type'] ?? 'A'))),
        'ttl' => (int)($row['ttl'] ?? 60),
        'country_codes' => normalizeCountryCodeList((string)($row['country_codes'] ?? 'IR'), ['IR']),
        'country_answers' => decodeGeoStringList((string)($row['country_answers_json'] ?? '[]')),
        'default_answers' => decodeGeoStringList((string)($row['default_answers_json'] ?? '[]')),
        'health_check_port' => ($row['health_check_port'] ?? null) === null ? null : (int)$row['health_check_port'],
        'is_enabled' => (bool)($row['is_enabled'] ?? false),
        'last_sync_error' => trim((string)($row['last_sync_error'] ?? '')),
        'last_synced_at' => $row['last_synced_at'] !== null ? (string)$row['last_synced_at'] : null,
        'created_at' => (string)($row['created_at'] ?? ''),
        'updated_at' => (string)($row['updated_at'] ?? ''),
    ];
}

function groupGeoRulesByFqdn(array $geoRules): array
{
    $grouped = [];
    foreach ($geoRules as $rule) {
        $grouped[(string)$rule['fqdn']][] = $rule;
    }
    return $grouped;
}

function groupGeoRulesByKey(array $geoRules): array
{
    $grouped = [];
    foreach ($geoRules as $rule) {
        $grouped[(string)$rule['fqdn'] . '|' . strtoupper((string)$rule['record_type'])] = $rule;
    }
    return $grouped;
}

function filterVisibleZoneRrsets(array $rrsets, array $geoRuleGroups): array
{
    return array_values(array_filter($rrsets, static function ($rrset) use ($geoRuleGroups) {
        $name = ensureTrailingDot((string)($rrset['name'] ?? ''));
        $type = strtoupper(trim((string)($rrset['type'] ?? '')));
        return !($type === 'LUA' && isset($geoRuleGroups[$name]));
    }));
}

function filterZoneRrsetsBySearch(array $rrsets, string $recordFilter): array
{
    if ($recordFilter === '') {
        return $rrsets;
    }

    $needle = mb_strtolower($recordFilter);
    return array_values(array_filter($rrsets, static function ($rrset) use ($needle) {
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
}

function createGeoRuleFromPost(array $config, array $zone): array
{
    $payload = buildGeoRulePayloadFromPost($config, $zone);
    backupZoneSnapshot($config, (string)$zone['id'], 'geo-create');
    $rule = saveGeoRulePayload($config, $payload, null);
    syncGeoRuleSet($config, $zone, (string)$rule['fqdn']);
    return fetchGeoRuleById($config, (int)$rule['id'], (string)$zone['name']);
}

function updateGeoRuleFromPost(array $config, array $zone): array
{
    $existingRule = fetchGeoRuleById($config, requirePostedGeoRuleId(), (string)$zone['name']);
    $payload = buildGeoRulePayloadFromPost($config, $zone, $existingRule);
    backupZoneSnapshot($config, (string)$zone['id'], 'geo-update');
    $rule = saveGeoRulePayload($config, $payload, $existingRule);
    syncGeoRuleSet($config, $zone, (string)$rule['fqdn']);
    if ($existingRule['fqdn'] !== $rule['fqdn']) {
        syncGeoRuleSet($config, $zone, (string)$existingRule['fqdn']);
    }
    return fetchGeoRuleById($config, (int)$rule['id'], (string)$zone['name']);
}

function deleteGeoRuleFromPost(array $config, array $zone): array
{
    $rule = fetchGeoRuleById($config, requirePostedGeoRuleId(), (string)$zone['name']);
    backupZoneSnapshot($config, (string)$zone['id'], 'geo-delete');

    $remainingRules = fetchGeoRulesByFqdn($config, (string)$zone['name'], (string)$rule['fqdn'], (int)$rule['id']);
    try {
        applyGeoRuleSetToPowerDns($config, $zone, (string)$rule['fqdn'], $remainingRules);
        markGeoRuleSetSyncSuccess($config, (string)$zone['name'], (string)$rule['fqdn']);
    } catch (Throwable $e) {
        markGeoRuleSetSyncError($config, (string)$zone['name'], (string)$rule['fqdn'], $e->getMessage());
        throw new RuntimeException('Failed to remove the GeoDNS rule from PowerDNS: ' . $e->getMessage());
    }

    deleteGeoRuleById($config, (int)$rule['id']);
    return $rule;
}

function syncGeoRuleFromPost(array $config, array $zone): array
{
    $rule = fetchGeoRuleById($config, requirePostedGeoRuleId(), (string)$zone['name']);
    backupZoneSnapshot($config, (string)$zone['id'], 'geo-sync');
    syncGeoRuleSet($config, $zone, (string)$rule['fqdn']);
    return fetchGeoRuleById($config, (int)$rule['id'], (string)$zone['name']);
}

function syncGeoZoneFromPost(array $config, array $zone): array
{
    $geoRules = fetchGeoRulesForZone($config, (string)$zone['name']);
    $ruleGroups = groupGeoRulesByFqdn($geoRules);
    if ($ruleGroups === []) {
        return [
            'synced_sets' => 0,
            'message' => 'No GeoDNS rules exist for this zone yet.',
        ];
    }

    backupZoneSnapshot($config, (string)$zone['id'], 'geo-sync-zone');

    $syncedSets = 0;
    $errors = [];
    foreach (array_keys($ruleGroups) as $fqdn) {
        try {
            syncGeoRuleSet($config, $zone, (string)$fqdn);
            $syncedSets++;
        } catch (Throwable $e) {
            $errors[] = rtrim((string)$fqdn, '.') . ': ' . $e->getMessage();
        }
    }

    if ($errors !== []) {
        throw new RuntimeException(sprintf(
            'Synced %d GeoDNS rule set(s), but %d failed: %s',
            $syncedSets,
            count($errors),
            implode(' | ', $errors)
        ));
    }

    return [
        'synced_sets' => $syncedSets,
        'message' => sprintf('Synced %d GeoDNS rule set(s) for this zone.', $syncedSets),
    ];
}

function buildGeoRulePayloadFromPost(array $config, array $zone, ?array $existingRule = null): array
{
    $zoneName = ensureTrailingDot((string)($zone['name'] ?? ''));
    $name = trim((string)($_POST['geo_name'] ?? '@'));
    if ($name === '') {
        $name = '@';
    }
    $fqdn = fqdnFromInput($name, $zoneName);
    if (!isNameInsideZone($fqdn, $zoneName)) {
        throw new RuntimeException('GeoDNS rules may only target records inside the selected zone.');
    }

    $recordType = strtoupper(trim((string)($_POST['geo_record_type'] ?? 'A')));
    if (!in_array($recordType, ['A', 'AAAA'], true)) {
        throw new RuntimeException('GeoDNS rules currently support only A and AAAA answers.');
    }

    $ttl = (int)($_POST['geo_ttl'] ?? defaultGeoRuleTtl($config));
    if ($ttl < 1 || $ttl > 2147483647) {
        throw new RuntimeException('GeoDNS TTL must be between 1 and 2147483647.');
    }

    $countryCodes = normalizeCountryCodeList(
        (string)($_POST['geo_country_codes'] ?? ''),
        defaultGeoCountryCodes($config)
    );
    $countryAnswers = normalizeGeoAnswerPool(
        (string)($_POST['geo_country_answers'] ?? ''),
        $recordType,
        $config,
        'country-matched'
    );
    $defaultAnswers = normalizeGeoAnswerPool(
        (string)($_POST['geo_default_answers'] ?? ''),
        $recordType,
        $config,
        'default'
    );

    $healthCheckPortRaw = trim((string)($_POST['geo_health_check_port'] ?? ''));
    $healthCheckPort = null;
    if ($healthCheckPortRaw !== '') {
        if (!ctype_digit($healthCheckPortRaw)) {
            throw new RuntimeException('Health check port must be numeric.');
        }
        $healthCheckPort = (int)$healthCheckPortRaw;
        if ($healthCheckPort < 1 || $healthCheckPort > 65535) {
            throw new RuntimeException('Health check port must be between 1 and 65535.');
        }
    }

    $payload = [
        'zone_name' => $zoneName,
        'fqdn' => $fqdn,
        'record_type' => $recordType,
        'ttl' => $ttl,
        'country_codes' => $countryCodes,
        'country_answers' => $countryAnswers,
        'default_answers' => $defaultAnswers,
        'health_check_port' => $healthCheckPort,
        'is_enabled' => !empty($_POST['geo_enabled']),
    ];

    guardGeoRuleConflicts($config, $zone, $payload, $existingRule);
    return $payload;
}

function defaultGeoCountryCodes(array $config): array
{
    $defaults = $config['geodns']['default_match_countries'] ?? ['IR'];
    if (!is_array($defaults) || $defaults === []) {
        return ['IR'];
    }

    $values = [];
    foreach ($defaults as $value) {
        $value = strtoupper(trim((string)$value));
        if ($value !== '') {
            $values[] = $value;
        }
    }

    return normalizeCountryCodeList(implode(',', $values), ['IR']);
}

function defaultGeoRuleTtl(array $config): int
{
    $ttl = (int)($config['geodns']['default_ttl'] ?? 60);
    return $ttl > 0 ? $ttl : 60;
}

function normalizeCountryCodeList(string $raw, array $fallback): array
{
    $input = trim($raw);
    if ($input === '') {
        $input = implode(',', $fallback);
    }

    $tokens = preg_split('/[\s,]+/', strtoupper($input)) ?: [];
    $codes = [];
    foreach ($tokens as $token) {
        $token = trim($token);
        if ($token === '') {
            continue;
        }
        if (!preg_match('/^[A-Z]{2}$/', $token)) {
            throw new RuntimeException('Country codes must use two-letter ISO values such as IR or DE.');
        }
        if (!in_array($token, $codes, true)) {
            $codes[] = $token;
        }
    }

    if ($codes === []) {
        throw new RuntimeException('At least one country code is required for a GeoDNS rule.');
    }

    return $codes;
}

function normalizeGeoAnswerPool(string $raw, string $recordType, array $config, string $label): array
{
    $values = parseTextareaLines($raw);
    if ($values === []) {
        throw new RuntimeException('Provide at least one ' . $recordType . ' answer for the ' . $label . ' pool.');
    }

    $normalized = [];
    foreach ($values as $value) {
        $normalizedValue = normalizeRecordContent($recordType, $value);
        if (!in_array($normalizedValue, $normalized, true)) {
            $normalized[] = $normalizedValue;
        }
    }

    $maxAnswers = (int)($config['geodns']['max_answers_per_pool'] ?? 8);
    if (count($normalized) > $maxAnswers) {
        throw new RuntimeException(sprintf('Each GeoDNS pool may contain at most %d answers.', $maxAnswers));
    }

    return $normalized;
}

function decodeGeoStringList(string $raw): array
{
    if ($raw === '') {
        return [];
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return [];
    }

    $values = [];
    foreach ($decoded as $value) {
        if (is_scalar($value)) {
            $stringValue = trim((string)$value);
            if ($stringValue !== '' && !in_array($stringValue, $values, true)) {
                $values[] = $stringValue;
            }
        }
    }

    return $values;
}

function encodeGeoStringList(array $values): string
{
    return json_encode(array_values($values), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

function guardGeoRuleConflicts(array $config, array $zone, array $payload, ?array $existingRule = null): void
{
    $zoneName = ensureTrailingDot((string)($zone['name'] ?? ''));
    $fqdn = (string)$payload['fqdn'];
    $recordType = strtoupper((string)$payload['record_type']);
    $rrsetIndex = [];
    foreach (($zone['rrsets'] ?? []) as $rrset) {
        $rrsetIndex[ensureTrailingDot((string)($rrset['name'] ?? '')) . '|' . strtoupper((string)($rrset['type'] ?? ''))] = $rrset;
    }

    if (isset($rrsetIndex[$fqdn . '|CNAME'])) {
        throw new RuntimeException('This hostname already has a CNAME RRset. Remove the CNAME before enabling GeoDNS here.');
    }

    $sameNameRules = fetchGeoRulesByFqdn($config, $zoneName, $fqdn, $existingRule['id'] ?? null);
    $ownsCurrentLuaRrset = $existingRule !== null && ensureTrailingDot((string)$existingRule['fqdn']) === $fqdn;
    if (!$ownsCurrentLuaRrset && $sameNameRules === [] && isset($rrsetIndex[$fqdn . '|LUA'])) {
        throw new RuntimeException('This hostname already has a raw LUA RRset. Remove it before managing it through the GeoDNS panel.');
    }

    if (isset($rrsetIndex[$fqdn . '|' . $recordType])) {
        throw new RuntimeException(sprintf(
            'A regular %s RRset already exists for %s. Remove it before creating a GeoDNS rule for the same answer type.',
            $recordType,
            rtrim($fqdn, '.')
        ));
    }

    foreach ($sameNameRules as $rule) {
        if ((int)$rule['ttl'] !== (int)$payload['ttl']) {
            throw new RuntimeException('GeoDNS rules for the same hostname share one LUA RRset, so their TTL must match.');
        }
    }
}

function guardManualRrsetMutationsAgainstGeoRules(array $config, string $zoneName, array $rrsets, string $context): void
{
    $geoRules = fetchGeoRulesForZone($config, $zoneName);
    if ($geoRules === []) {
        return;
    }

    $rulesByFqdn = groupGeoRulesByFqdn($geoRules);
    $rulesByKey = groupGeoRulesByKey($geoRules);

    foreach ($rrsets as $rrset) {
        $fqdn = ensureTrailingDot((string)($rrset['name'] ?? ''));
        $type = strtoupper(trim((string)($rrset['type'] ?? '')));
        if ($fqdn === '.' || $type === '') {
            continue;
        }

        if ($type === 'CNAME' && isset($rulesByFqdn[$fqdn])) {
            throw new RuntimeException('This hostname is already managed by GeoDNS. Remove the GeoDNS rule before changing it to a CNAME.');
        }

        if ($type === 'LUA' && isset($rulesByFqdn[$fqdn])) {
            throw new RuntimeException('Managed GeoDNS LUA RRsets can only be changed from the GeoDNS Rules section.');
        }

        if (isset($rulesByKey[$fqdn . '|' . $type])) {
            throw new RuntimeException(sprintf(
                'The %s RRset for %s is managed by GeoDNS. Use the GeoDNS Rules section instead of %s.',
                $type,
                rtrim($fqdn, '.'),
                str_replace('_', ' ', $context)
            ));
        }
    }
}

function syncGeoRuleSet(array $config, array $zone, string $fqdn): void
{
    $zoneName = ensureTrailingDot((string)($zone['name'] ?? ''));
    $fqdn = ensureTrailingDot($fqdn);
    $rules = fetchGeoRulesByFqdn($config, $zoneName, $fqdn);

    try {
        applyGeoRuleSetToPowerDns($config, $zone, $fqdn, $rules);
        markGeoRuleSetSyncSuccess($config, $zoneName, $fqdn);
    } catch (Throwable $e) {
        markGeoRuleSetSyncError($config, $zoneName, $fqdn, $e->getMessage());
        throw new RuntimeException('PowerDNS sync failed for ' . rtrim($fqdn, '.') . ': ' . $e->getMessage());
    }
}

function applyGeoRuleSetToPowerDns(array $config, array $zone, string $fqdn, array $rules): void
{
    $enabledRules = array_values(array_filter($rules, static fn(array $rule): bool => (bool)$rule['is_enabled']));
    if ($enabledRules === []) {
        pdnsRequest($config, 'PATCH', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']), [
            'rrsets' => [[
                'name' => ensureTrailingDot($fqdn),
                'type' => 'LUA',
                'changetype' => 'DELETE',
            ]],
        ]);
        maybeRectify($config, $zone);
        return;
    }

    $ttl = (int)$enabledRules[0]['ttl'];
    foreach ($enabledRules as $rule) {
        if ((int)$rule['ttl'] !== $ttl) {
            throw new RuntimeException('GeoDNS rules for the same hostname must use the same TTL.');
        }
    }

    $records = [];
    foreach (sortGeoRulesForSync($enabledRules) as $rule) {
        $records[] = [
            'content' => buildGeoLuaRecordContent($rule),
            'disabled' => false,
        ];
    }

    pdnsRequest($config, 'PATCH', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']), [
        'rrsets' => [[
            'name' => ensureTrailingDot($fqdn),
            'type' => 'LUA',
            'ttl' => $ttl,
            'changetype' => 'REPLACE',
            'records' => $records,
        ]],
    ]);
    maybeRectify($config, $zone);
}

function buildGeoLuaRecordContent(array $rule): string
{
    $countryExpression = geoLuaCountryExpression($rule['country_codes']);
    $countryPool = geoLuaStringArray($rule['country_answers']);
    $defaultPool = geoLuaStringArray($rule['default_answers']);
    $recordType = strtoupper((string)$rule['record_type']);

    if ($rule['health_check_port'] !== null) {
        $port = (int)$rule['health_check_port'];
        $matchedExpression = geoLuaFailoverExpression($port, $countryPool, $defaultPool);
        $defaultExpression = geoLuaFailoverExpression($port, $defaultPool, $countryPool);
    } else {
        $matchedExpression = $countryPool;
        $defaultExpression = $defaultPool;
    }

    $script = sprintf(
        ';if country(%s) then return %s else return %s end',
        $countryExpression,
        $matchedExpression,
        $defaultExpression
    );

    return $recordType . ' "' . str_replace('"', '\"', $script) . '"';
}

function geoLuaCountryExpression(array $countryCodes): string
{
    if (count($countryCodes) === 1) {
        return geoLuaQuote((string)$countryCodes[0]);
    }
    return geoLuaStringArray($countryCodes);
}

function geoLuaFailoverExpression(int $port, string $primaryPool, string $secondaryPool): string
{
    return sprintf(
        "ifportup(%d, {%s, %s}, {selector='all', backupSelector='all'})",
        $port,
        $primaryPool,
        $secondaryPool
    );
}

function geoLuaStringArray(array $values): string
{
    $quoted = array_map(static fn(string $value): string => geoLuaQuote($value), $values);
    return '{' . implode(',', $quoted) . '}';
}

function geoLuaQuote(string $value): string
{
    return "'" . str_replace(['\\', "'"], ['\\\\', "\\'"], $value) . "'";
}

function sortGeoRulesForSync(array $rules): array
{
    usort($rules, static function (array $a, array $b): int {
        $order = ['A' => 0, 'AAAA' => 1];
        $left = $order[strtoupper((string)($a['record_type'] ?? ''))] ?? 99;
        $right = $order[strtoupper((string)($b['record_type'] ?? ''))] ?? 99;
        return $left <=> $right ?: ((int)($a['id'] ?? 0) <=> (int)($b['id'] ?? 0));
    });
    return $rules;
}

function markGeoRuleSetSyncSuccess(array $config, string $zoneName, string $fqdn): void
{
    $stmt = geoDb($config)->prepare(
        'UPDATE hidata_geo_rules SET last_sync_error = NULL, last_synced_at = :last_synced_at WHERE zone_name = :zone_name AND fqdn = :fqdn'
    );
    $stmt->execute([
        'last_synced_at' => date('Y-m-d H:i:s'),
        'zone_name' => ensureTrailingDot($zoneName),
        'fqdn' => ensureTrailingDot($fqdn),
    ]);
}

function markGeoRuleSetSyncError(array $config, string $zoneName, string $fqdn, string $error): void
{
    $stmt = geoDb($config)->prepare(
        'UPDATE hidata_geo_rules SET last_sync_error = :last_sync_error WHERE zone_name = :zone_name AND fqdn = :fqdn'
    );
    $stmt->execute([
        'last_sync_error' => trim($error),
        'zone_name' => ensureTrailingDot($zoneName),
        'fqdn' => ensureTrailingDot($fqdn),
    ]);
}

function saveGeoRulePayload(array $config, array $payload, ?array $existingRule = null): array
{
    $pdo = geoDb($config);
    $now = date('Y-m-d H:i:s');

    try {
        if ($existingRule === null) {
            $stmt = $pdo->prepare(
                'INSERT INTO hidata_geo_rules (
                    zone_name, fqdn, record_type, ttl, country_codes, country_answers_json, default_answers_json,
                    health_check_port, is_enabled, last_sync_error, last_synced_at, created_at, updated_at
                ) VALUES (
                    :zone_name, :fqdn, :record_type, :ttl, :country_codes, :country_answers_json, :default_answers_json,
                    :health_check_port, :is_enabled, NULL, NULL, :created_at, :updated_at
                )'
            );
            $stmt->execute([
                'zone_name' => (string)$payload['zone_name'],
                'fqdn' => (string)$payload['fqdn'],
                'record_type' => (string)$payload['record_type'],
                'ttl' => (int)$payload['ttl'],
                'country_codes' => implode(',', $payload['country_codes']),
                'country_answers_json' => encodeGeoStringList($payload['country_answers']),
                'default_answers_json' => encodeGeoStringList($payload['default_answers']),
                'health_check_port' => $payload['health_check_port'],
                'is_enabled' => $payload['is_enabled'] ? 1 : 0,
                'created_at' => $now,
                'updated_at' => $now,
            ]);

            return fetchGeoRuleById($config, (int)$pdo->lastInsertId(), (string)$payload['zone_name']);
        }

        $stmt = $pdo->prepare(
            'UPDATE hidata_geo_rules SET
                fqdn = :fqdn,
                record_type = :record_type,
                ttl = :ttl,
                country_codes = :country_codes,
                country_answers_json = :country_answers_json,
                default_answers_json = :default_answers_json,
                health_check_port = :health_check_port,
                is_enabled = :is_enabled,
                last_sync_error = NULL,
                updated_at = :updated_at
             WHERE id = :id AND zone_name = :zone_name'
        );
        $stmt->execute([
            'fqdn' => (string)$payload['fqdn'],
            'record_type' => (string)$payload['record_type'],
            'ttl' => (int)$payload['ttl'],
            'country_codes' => implode(',', $payload['country_codes']),
            'country_answers_json' => encodeGeoStringList($payload['country_answers']),
            'default_answers_json' => encodeGeoStringList($payload['default_answers']),
            'health_check_port' => $payload['health_check_port'],
            'is_enabled' => $payload['is_enabled'] ? 1 : 0,
            'updated_at' => $now,
            'id' => (int)$existingRule['id'],
            'zone_name' => (string)$payload['zone_name'],
        ]);

        return fetchGeoRuleById($config, (int)$existingRule['id'], (string)$payload['zone_name']);
    } catch (PDOException $e) {
        if ((int)$e->getCode() === 23000) {
            throw new RuntimeException('A GeoDNS rule for this hostname and answer type already exists.');
        }
        throw $e;
    }
}

function deleteGeoRuleById(array $config, int $ruleId): void
{
    $stmt = geoDb($config)->prepare('DELETE FROM hidata_geo_rules WHERE id = :id');
    $stmt->execute(['id' => $ruleId]);
}

function deleteGeoRulesForZone(array $config, string $zoneName): void
{
    $stmt = geoDb($config)->prepare('DELETE FROM hidata_geo_rules WHERE zone_name = :zone_name');
    $stmt->execute(['zone_name' => ensureTrailingDot($zoneName)]);
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
    if (!empty($zone['api_rectify'])) {
        return;
    }
    guardRectifyAllowed($zone);
    pdnsRequest($config, 'PUT', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode((string)$zone['id']) . '/rectify');
}

function backupZoneSnapshot(array $config, string $zoneId, string $reason = 'change'): void
{
    if (($config['features']['backup_before_write'] ?? true) !== true) {
        return;
    }

    $export = pdnsRequest($config, 'GET', '/servers/' . rawurlencode((string)$config['pdns']['server_id']) . '/zones/' . rawurlencode($zoneId) . '/export', null, 'text/plain');
    $backupDir = (string)($config['storage']['backup_dir'] ?? '');
    if ($backupDir === '') {
        throw new RuntimeException('Backup directory is not configured.');
    }
    $safeZoneId = preg_replace('/[^A-Za-z0-9._-]+/', '_', rtrim($zoneId, '.'));
    $filename = $backupDir . '/' . $safeZoneId . '__' . preg_replace('/[^A-Za-z0-9._-]+/', '_', $reason) . '__' . date('Ymd_His') . '.zone';
    if (@file_put_contents($filename, (string)$export, LOCK_EX) === false) {
        throw new RuntimeException('Failed to save the pre-change zone backup.');
    }

    $maxBackups = (int)($config['features']['max_backups_per_zone'] ?? 0);
    if ($maxBackups > 0) {
        $files = glob($backupDir . '/' . $safeZoneId . '__*.zone') ?: [];
        rsort($files, SORT_STRING);
        foreach (array_slice($files, $maxBackups) as $file) {
            @unlink($file);
        }
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
        'ip' => clientIp($config),
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

function canCreateZones(array $config): bool
{
    return ($config['features']['read_only'] ?? false) !== true
        && ($config['features']['allow_zone_create'] ?? true) === true;
}

function canDeleteZones(array $config): bool
{
    return ($config['features']['read_only'] ?? false) !== true
        && ($config['features']['allow_zone_delete'] ?? true) === true;
}

function canModifyZone(array $config, ?array $zone): bool
{
    if ($zone === null || ($config['features']['read_only'] ?? false) === true) {
        return false;
    }
    try {
        guardWritableZone($config, $zone);
        return true;
    } catch (Throwable) {
        return false;
    }
}

function canRectifyZone(array $config, ?array $zone): bool
{
    if ($zone === null || ($config['features']['read_only'] ?? false) === true) {
        return false;
    }
    try {
        guardRectifyAllowed($zone);
        return true;
    } catch (Throwable) {
        return false;
    }
}

function renderPage(array $data): void
{
    $config = $data['config'];
    $zones = $data['zones'];
    $zoneSearch = $data['zoneSearch'];
    $currentZone = $data['currentZone'];
    $zoneDetails = $data['zoneDetails'];
    $geoRules = $data['geoRules'];
    $geoRuleGroups = $data['geoRuleGroups'];
    $geoRuleStats = $data['geoRuleStats'];
    $rrsets = $data['rrsets'];
    $recordFilter = $data['recordFilter'];

    $filteredZones = array_values(array_filter($zones, static function ($zone) use ($zoneSearch) {
        if ($zoneSearch === '') {
            return true;
        }
        return mb_stripos((string)($zone['name'] ?? ''), $zoneSearch) !== false;
    }));

    $canCreateZones = canCreateZones($config);
    $canDeleteCurrentZone = canDeleteZones($config) && canModifyZone($config, $zoneDetails);
    $canModifyCurrentZone = canModifyZone($config, $zoneDetails);
    $canRectifyCurrentZone = canRectifyZone($config, $zoneDetails);

    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . h((string)($config['app']['name'] ?? 'HiData GeoDNS Manager')) . '</title>';
    echo '<style>' . baseCss() . appCss() . '</style>';
    echo '</head><body>';
    echo '<div class="layout">';
    echo '<aside class="sidebar">';
    echo '<div class="brand">';
    echo '<div class="brand-logo">Hi</div>';
    echo '<div><div class="brand-name">' . h((string)($config['app']['name'] ?? 'HiData GeoDNS Manager')) . '</div>';
    echo '<div class="brand-tag">GeoDNS rule and zone manager</div></div>';
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
    echo '<div class="config-row"><span>Client IP</span><strong>' . h(clientIp($config)) . '</strong></div>';
    echo '<div class="config-row"><span>Mode</span><strong>' . (($config['features']['read_only'] ?? false) ? 'Read-only' : 'Read / Write') . '</strong></div>';
    echo '</div>';

    echo '</aside>';
    echo '<main class="content">';
    echo '<div class="topbar">';
    echo '<div>';
    echo '<div class="eyebrow">HiData GeoDNS</div>';
    echo '<h1 class="page-title">' . ($currentZone ? h(rtrim((string)$currentZone['name'], '.')) : 'PowerDNS Dashboard') . '</h1>';
    echo '</div>';
    echo '<div class="top-actions">';
    if ($canCreateZones) {
        echo '<a class="btn btn-primary" href="#" onclick="openModal(\'zoneCreateModal\');return false;">New zone</a>';
    }
    echo '<span class="user-chip">' . h((string)($_SESSION['auth']['username'] ?? 'admin')) . '</span>';
    echo '<form method="post" class="inline-form">';
    echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
    echo '<input type="hidden" name="action" value="logout">';
    echo '<button class="btn btn-ghost" type="submit">Sign out</button>';
    echo '</form>';
    echo '</div>';
    echo '</div>';

    echo renderFlash($data['flash'] ?? null);

    if (!$currentZone || !$zoneDetails) {
        echo '<section class="panel hero">';
        echo '<div class="hero-copy">';
        echo '<h2>Manage authoritative DNS and IR/default GeoDNS on the same host as PowerDNS</h2>';
        echo '<p>Create zones, manage regular RRsets, and publish country-aware GeoDNS rules that send Iran to one server and the default world path to another.</p>';
        echo '</div>';
        echo '<div class="hero-grid">';
        echo '<div class="stat-card"><span>Zones</span><strong>' . count($zones) . '</strong></div>';
        echo '<div class="stat-card"><span>Geo Rules</span><strong>' . (int)($geoRuleStats['total_rules'] ?? 0) . '</strong></div>';
        echo '<div class="stat-card"><span>Geo Active</span><strong>' . (int)($geoRuleStats['enabled_rules'] ?? 0) . '</strong></div>';
        echo '<div class="stat-card"><span>Backups</span><strong>' . (($config['features']['backup_before_write'] ?? false) ? 'Enabled' : 'Disabled') . '</strong></div>';
        echo '</div>';
        echo '</section>';
        if ($canCreateZones) {
            echo buildCreateZoneModal();
        }
        echo '</main></div>';
        echo modalScripts();
        echo '</body></html>';
        return;
    }

    echo '<section class="panel zone-header">';
    echo '<div class="zone-title-wrap">';
    echo '<div class="zone-title">' . h(rtrim((string)$zoneDetails['name'], '.')) . '</div>';
    echo '<div class="zone-subtitle">Serial ' . h((string)($zoneDetails['serial'] ?? '-')) . ' | Edited serial ' . h((string)($zoneDetails['edited_serial'] ?? '-')) . '</div>';
    echo '</div>';
    echo '<div class="zone-badges">';
    echo '<span class="pill">' . h((string)($zoneDetails['kind'] ?? 'Unknown')) . '</span>';
    echo '<span class="pill">DNSSEC ' . (!empty($zoneDetails['dnssec']) ? 'On' : 'Off') . '</span>';
    echo '<span class="pill">API Rectify ' . (!empty($zoneDetails['api_rectify']) ? 'On' : 'Off') . '</span>';
    echo '</div>';
    echo '<div class="zone-actions">';
    if ($canModifyCurrentZone) {
        echo '<a class="btn btn-primary" href="#" onclick="openModal(\'geoAddModal\');return false;">New Geo rule</a>';
        echo '<form method="post" class="inline-form">';
        echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
        echo '<input type="hidden" name="action" value="sync_geo_zone">';
        echo '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
        echo '<button class="btn btn-ghost" type="submit">Sync GeoDNS</button>';
        echo '</form>';
        echo '<a class="btn btn-ghost" href="#" onclick="openModal(\'addModal\');return false;">Add record</a>';
        echo '<a class="btn btn-ghost" href="#" onclick="openModal(\'importModal\');return false;">Import TXT</a>';
    }
    echo '<a class="btn btn-ghost" href="?download=zone&amp;zone=' . urlencode(rtrim((string)$zoneDetails['name'], '.')) . '">Export zone</a>';
    if ($canRectifyCurrentZone) {
        echo '<form method="post" class="inline-form" onsubmit="return confirm(\'Rectify this zone now?\')">';
        echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
        echo '<input type="hidden" name="action" value="rectify_zone">';
        echo '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
        echo '<button class="btn btn-ghost" type="submit">Rectify</button>';
        echo '</form>';
    }
    if ($canDeleteCurrentZone) {
        echo '<form method="post" class="inline-form" onsubmit="return confirm(\'Delete this zone and all its records?\')">';
        echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
        echo '<input type="hidden" name="action" value="delete_zone">';
        echo '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
        echo '<button class="btn btn-danger" type="submit">Delete zone</button>';
        echo '</form>';
    }
    echo '</div>';
    echo '</section>';

    echo renderGeoRulesSection($config, $zoneDetails, $geoRules, $canModifyCurrentZone);

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
            $rrsetType = strtoupper((string)($rrset['type'] ?? ''));
            if ($canModifyCurrentZone && $rrsetType !== 'LUA') {
                echo '<a class="btn btn-small btn-ghost" href="#" data-edit="' . $jsPayload . '" onclick="fillEditModal(this.dataset.edit);openModal(\'editModal\');return false;">Edit</a>';
                echo '<form method="post" onsubmit="return confirm(\'Delete this entire RRset?\')">';
                echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
                echo '<input type="hidden" name="action" value="delete_rrset">';
                echo '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
                echo '<input type="hidden" name="name" value="' . h(displayRelativeName((string)($rrset['name'] ?? ''), (string)$zoneDetails['name'])) . '">';
                echo '<input type="hidden" name="type" value="' . h((string)($rrset['type'] ?? '')) . '">';
                echo '<button class="btn btn-small btn-danger" type="submit">Delete</button>';
                echo '</form>';
            } elseif ($canModifyCurrentZone && $rrsetType === 'LUA') {
                echo '<span class="small muted">Raw LUA RRsets are delete-only.</span>';
                echo '<form method="post" onsubmit="return confirm(\'Delete this LUA RRset?\')">';
                echo '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
                echo '<input type="hidden" name="action" value="delete_rrset">';
                echo '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
                echo '<input type="hidden" name="name" value="' . h(displayRelativeName((string)($rrset['name'] ?? ''), (string)$zoneDetails['name'])) . '">';
                echo '<input type="hidden" name="type" value="' . h((string)$rrset['type'] ?? '') . '">';
                echo '<button class="btn btn-small btn-danger" type="submit">Delete</button>';
                echo '</form>';
            } else {
                echo '<span class="small muted">Writes disabled for this zone.</span>';
            }
            echo '</div></td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
    }
    echo '</section>';

    if ($canCreateZones) {
        echo buildCreateZoneModal();
    }
    if ($canModifyCurrentZone) {
        echo buildGeoAddModal((string)$zoneDetails['name'], $config);
        echo buildGeoEditModal((string)$zoneDetails['name']);
        echo buildImportModal((string)$zoneDetails['name']);
        echo buildAddModal((string)$zoneDetails['name']);
        echo buildEditModal((string)$zoneDetails['name']);
    }

    echo '</main></div>';
    echo modalScripts();
    echo '</body></html>';
}

function renderGeoRulesSection(array $config, array $zoneDetails, array $geoRules, bool $canModifyCurrentZone): string
{
    $html = '<section class="panel">';
    $html .= '<div class="section-head">';
    $html .= '<div>';
    $html .= '<h2 class="section-title">GeoDNS Rules</h2>';
    $html .= '<p class="section-copy">Geo decisions use the resolver IP or EDNS Client Subnet when available. For a classic IR/default setup, keep one Iran pool and one default pool here.</p>';
    $html .= '</div>';
    $html .= '<div class="rule-summary"><span class="pill">Rules ' . count($geoRules) . '</span></div>';
    $html .= '</div>';

    if ($geoRules === []) {
        $html .= '<div class="empty">No GeoDNS rules exist for this zone yet. Add one for <code>@</code> or <code>www</code> to send <code>IR</code> to the Iran server and the default path to Europe.</div>';
        $html .= '</section>';
        return $html;
    }

    $html .= '<div class="table-wrap"><table class="geo-table"><thead><tr><th>Name</th><th>Type</th><th>Countries</th><th>Match Pool</th><th>Default Pool</th><th>TTL</th><th>Health</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
    foreach ($geoRules as $rule) {
        $editPayload = htmlspecialchars(json_encode([
            'id' => (int)$rule['id'],
            'name' => (string)$rule['display_name'],
            'record_type' => (string)$rule['record_type'],
            'ttl' => (int)$rule['ttl'],
            'country_codes' => implode(',', $rule['country_codes']),
            'country_answers' => implode("\n", $rule['country_answers']),
            'default_answers' => implode("\n", $rule['default_answers']),
            'health_check_port' => $rule['health_check_port'],
            'is_enabled' => (bool)$rule['is_enabled'],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $healthLabel = $rule['health_check_port'] !== null
            ? 'TCP ' . (int)$rule['health_check_port'] . ' failover'
            : 'Off';

        $html .= '<tr>';
        $html .= '<td><div class="mono">' . h((string)$rule['display_name']) . '</div></td>';
        $html .= '<td><span class="type-chip">' . h((string)$rule['record_type']) . '</span></td>';
        $html .= '<td>' . h(implode(', ', $rule['country_codes'])) . '</td>';
        $html .= '<td>' . renderPoolLines($rule['country_answers']) . '</td>';
        $html .= '<td>' . renderPoolLines($rule['default_answers']) . '</td>';
        $html .= '<td>' . h((string)$rule['ttl']) . '</td>';
        $html .= '<td>' . h($healthLabel) . '</td>';
        $html .= '<td>' . renderGeoRuleStatus($rule) . '</td>';
        $html .= '<td><div class="action-stack">';
        if ($canModifyCurrentZone) {
            $html .= '<a class="btn btn-small btn-ghost" href="#" data-geo-edit="' . $editPayload . '" onclick="fillGeoEditModal(this.dataset.geoEdit);openModal(\'geoEditModal\');return false;">Edit</a>';
            $html .= '<form method="post">';
            $html .= '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
            $html .= '<input type="hidden" name="action" value="sync_geo_rule">';
            $html .= '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
            $html .= '<input type="hidden" name="geo_rule_id" value="' . (int)$rule['id'] . '">';
            $html .= '<button class="btn btn-small btn-ghost" type="submit">Sync</button>';
            $html .= '</form>';
            $html .= '<form method="post" onsubmit="return confirm(\'Delete this GeoDNS rule?\')">';
            $html .= '<input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '">';
            $html .= '<input type="hidden" name="action" value="delete_geo_rule">';
            $html .= '<input type="hidden" name="zone_name" value="' . h((string)$zoneDetails['name']) . '">';
            $html .= '<input type="hidden" name="geo_rule_id" value="' . (int)$rule['id'] . '">';
            $html .= '<button class="btn btn-small btn-danger" type="submit">Delete</button>';
            $html .= '</form>';
        } else {
            $html .= '<span class="small muted">Writes disabled for this zone.</span>';
        }
        $html .= '</div></td>';
        $html .= '</tr>';
    }
    $html .= '</tbody></table></div>';
    $html .= '</section>';

    return $html;
}

function renderPoolLines(array $values): string
{
    $html = '<div class="records">';
    foreach ($values as $value) {
        $html .= '<div class="record-line mono">' . h((string)$value) . '</div>';
    }
    $html .= '</div>';
    return $html;
}

function renderGeoRuleStatus(array $rule): string
{
    if ($rule['last_sync_error'] !== '') {
        return '<div class="status-stack"><span class="pill pill-danger">Sync Error</span><span class="small muted">' . h($rule['last_sync_error']) . '</span></div>';
    }

    if (!$rule['is_enabled']) {
        return '<div class="status-stack"><span class="pill pill-muted">Disabled</span><span class="small muted">Stored in DB, not published.</span></div>';
    }

    $suffix = $rule['last_synced_at'] !== null
        ? '<span class="small muted">Last sync ' . h((string)$rule['last_synced_at']) . '</span>'
        : '<span class="small muted">Waiting for first sync.</span>';
    return '<div class="status-stack"><span class="pill pill-success">Active</span>' . $suffix . '</div>';
}

function buildGeoAddModal(string $zoneName, array $config): string
{
    $defaultCountries = implode(',', defaultGeoCountryCodes($config));
    $defaultTtl = defaultGeoRuleTtl($config);

    return '<div class="modal" id="geoAddModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>New GeoDNS rule</h3><button class="icon-btn" type="button" onclick="closeModal(\'geoAddModal\')">&times;</button></div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="create_geo_rule"><input type="hidden" name="zone_name" value="' . h($zoneName) . '"><div class="grid-two"><div><label>Name</label><input class="input" name="geo_name" value="@" placeholder="@ or www" required></div><div><label>Answer type</label><select class="input" name="geo_record_type"><option value="A">A</option><option value="AAAA">AAAA</option></select></div><div><label>TTL</label><input class="input" type="number" name="geo_ttl" value="' . h((string)$defaultTtl) . '" min="1" max="2147483647" required></div><div><label>Countries</label><input class="input mono" name="geo_country_codes" value="' . h($defaultCountries) . '" placeholder="IR or IR,AF" required></div></div><label>Matched pool</label><textarea class="textarea mono" name="geo_country_answers" rows="5" placeholder="185.112.35.197" required></textarea><label>Default pool</label><textarea class="textarea mono" name="geo_default_answers" rows="5" placeholder="203.0.113.20" required></textarea><div class="grid-two"><div><label>Health check port</label><input class="input" type="number" name="geo_health_check_port" min="1" max="65535" placeholder="443"></div><div><label>Behavior</label><div class="hint">If a health port is set, the chosen country pool falls back to the other pool when that TCP port is down.</div></div></div><label class="check-row"><input type="checkbox" name="geo_enabled" value="1" checked> Publish this rule immediately</label><div class="hint">A and AAAA GeoDNS rules at the same hostname share one PowerDNS LUA RRset, so keep their TTL identical.</div><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'geoAddModal\')">Cancel</button><button class="btn btn-primary" type="submit">Create GeoDNS rule</button></div></form></div></div>';
}

function buildGeoEditModal(string $zoneName): string
{
    return '<div class="modal" id="geoEditModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>Edit GeoDNS rule</h3><button class="icon-btn" type="button" onclick="closeModal(\'geoEditModal\')">&times;</button></div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="update_geo_rule"><input type="hidden" name="zone_name" value="' . h($zoneName) . '"><input type="hidden" name="geo_rule_id" id="geo_edit_rule_id"><div class="grid-two"><div><label>Name</label><input class="input" id="geo_edit_name" name="geo_name" required></div><div><label>Answer type</label><select class="input" id="geo_edit_record_type" name="geo_record_type"><option value="A">A</option><option value="AAAA">AAAA</option></select></div><div><label>TTL</label><input class="input" type="number" id="geo_edit_ttl" name="geo_ttl" min="1" max="2147483647" required></div><div><label>Countries</label><input class="input mono" id="geo_edit_country_codes" name="geo_country_codes" required></div></div><label>Matched pool</label><textarea class="textarea mono" id="geo_edit_country_answers" name="geo_country_answers" rows="5" required></textarea><label>Default pool</label><textarea class="textarea mono" id="geo_edit_default_answers" name="geo_default_answers" rows="5" required></textarea><div class="grid-two"><div><label>Health check port</label><input class="input" type="number" id="geo_edit_health_check_port" name="geo_health_check_port" min="1" max="65535"></div><div><label>Behavior</label><div class="hint">Changing the hostname or answer type re-syncs the new LUA RRset and also cleans up the old location when needed.</div></div></div><label class="check-row"><input type="checkbox" id="geo_edit_enabled" name="geo_enabled" value="1"> Publish this rule immediately</label><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'geoEditModal\')">Cancel</button><button class="btn btn-primary" type="submit">Save GeoDNS rule</button></div></form></div></div>';
}

function manualRecordTypes(): array
{
    return ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS', 'PTR', 'SRV', 'CAA', 'SPF'];
}

function buildAddModal(string $zoneName): string
{
    return '<div class="modal" id="addModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>Add RRset</h3><button class="icon-btn" type="button" onclick="closeModal(\'addModal\')">&times;</button></div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="add_rrset"><input type="hidden" name="zone_name" value="' . h($zoneName) . '"><div class="grid-two"><div><label>Name</label><input class="input" name="name" value="@" placeholder="@ or subdomain" required></div><div><label>Type</label><select class="input" name="type">' . recordTypeOptions() . '</select></div><div><label>TTL</label><input class="input" type="number" name="ttl" value="300" min="1" max="2147483647" required></div><div><label>Notes</label><div class="hint">Use one value per line for multi-value RRsets.</div></div></div><label>Content</label><textarea class="textarea" name="content" rows="8" placeholder="185.112.35.197 or 10 mail.example.com." required></textarea><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'addModal\')">Cancel</button><button class="btn btn-primary" type="submit">Create RRset</button></div></form></div></div>';
}

function buildEditModal(string $zoneName): string
{
    return '<div class="modal" id="editModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>Edit RRset</h3><button class="icon-btn" type="button" onclick="closeModal(\'editModal\')">&times;</button></div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="update_rrset"><input type="hidden" name="zone_name" value="' . h($zoneName) . '"><div class="grid-two"><div><label>Name</label><input class="input" id="edit_name" name="name" required></div><div><label>Type</label><select class="input" id="edit_type" name="type">' . recordTypeOptions() . '</select></div><div><label>TTL</label><input class="input" type="number" id="edit_ttl" name="ttl" min="1" max="2147483647" required></div><div><label>Notes</label><div class="hint">Editing replaces the whole RRset for this name and type.</div></div></div><label>Content</label><textarea class="textarea" id="edit_content" name="content" rows="8" required></textarea><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'editModal\')">Cancel</button><button class="btn btn-primary" type="submit">Save changes</button></div></form></div></div>';
}

function buildImportModal(string $zoneName): string
{
    return '<div class="modal" id="importModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>Import zone text</h3><button class="icon-btn" type="button" onclick="closeModal(\'importModal\')">&times;</button></div><form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="import_zone_file"><input type="hidden" name="zone_name" value="' . h($zoneName) . '"><label>Zone file</label><input class="input" type="file" name="zone_file" accept=".txt,.zone,text/plain"><div class="hint">Upload a Cloudflare/BIND-style text export, or paste the same content below.</div><label>Or paste zone text</label><textarea class="textarea" name="zone_text" rows="12" placeholder="hidata.org. 3600 IN A 192.0.2.10"></textarea><div class="grid-two"><div><label>Import options</label><div class="hint"><label class="check-row"><input type="checkbox" name="import_ns" value="1"> Import NS records too</label><label class="check-row"><input type="checkbox" name="import_soa" value="1"> Import SOA record too</label></div></div><div><label>Notes</label><div class="hint">Imported RRsets are upserted with REPLACE, so records in this file overwrite the same name/type in the selected zone. Records not present in the file are kept. SOA and NS are skipped by default because Cloudflare exports often contain authority values that should be changed before production use.</div></div></div><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'importModal\')">Cancel</button><button class="btn btn-primary" type="submit">Import records</button></div></form></div></div>';
}

function buildCreateZoneModal(): string
{
    return '<div class="modal" id="zoneCreateModal" aria-hidden="true"><div class="modal-card"><div class="modal-header"><h3>Create zone</h3><button class="icon-btn" type="button" onclick="closeModal(\'zoneCreateModal\')">&times;</button></div><form method="post"><input type="hidden" name="csrf_token" value="' . h(csrfToken()) . '"><input type="hidden" name="action" value="create_zone"><div class="grid-two"><div><label>Zone name</label><input class="input" name="zone_name" placeholder="example.com" required></div><div><label>Zone kind</label><select class="input" id="zone_kind" name="zone_kind" onchange="toggleZoneKindFields(this.value)">' . zoneKindOptions() . '</select></div><div id="zone_nameservers_field"><label>Nameservers</label><textarea class="textarea" name="nameservers" rows="5" placeholder="ns1.example.com.&#10;ns2.example.com." required></textarea></div><div id="zone_masters_field" style="display:none"><label>Masters</label><textarea class="textarea" name="masters" rows="5" placeholder="192.0.2.10&#10;192.0.2.11"></textarea></div><div><label>Account</label><input class="input" name="account" placeholder="Optional owner/account label"></div><div><label>Zone options</label><div class="hint"><label class="check-row"><input type="checkbox" name="dnssec" checked> Enable DNSSEC support</label><label class="check-row"><input type="checkbox" name="api_rectify" checked> Enable API rectify</label></div></div></div><div class="modal-footer"><button class="btn btn-ghost" type="button" onclick="closeModal(\'zoneCreateModal\')">Cancel</button><button class="btn btn-primary" type="submit">Create zone</button></div></form></div></div>';
}

function zoneKindOptions(): string
{
    $options = ['Native', 'Master', 'Slave', 'Producer', 'Consumer'];
    $html = '';
    foreach ($options as $option) {
        $html .= '<option value="' . h($option) . '">' . h($option) . '</option>';
    }
    return $html;
}

function recordTypeOptions(): string
{
    $types = manualRecordTypes();
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
.check-row{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:600;color:#d7e4fb;margin:0 0 10px}
.check-row input{margin:0}
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
.hero-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.stat-card{background:#0b1628;border:1px solid var(--line);border-radius:20px;padding:18px}
.stat-card span{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.stat-card strong{font-size:28px}
.zone-header{display:grid;grid-template-columns:1.2fr auto auto;gap:16px;align-items:center}
.zone-title{font-size:28px;font-weight:900;word-break:break-all}
.zone-subtitle{color:var(--muted);margin-top:6px}
.zone-badges,.zone-actions{display:flex;flex-wrap:wrap;gap:10px;justify-content:flex-end}
.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:16px}
.section-title{margin:0 0 8px;font-size:24px}
.section-copy{margin:0;color:var(--muted);line-height:1.7;max-width:880px}
.rule-summary{display:flex;align-items:center;gap:10px}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
.toolbar-form{display:flex;gap:10px;align-items:center;flex:1;max-width:540px}
.inline-form{display:inline}
.table-wrap{overflow:auto;border:1px solid rgba(72,101,151,.22);border-radius:18px}
table{width:100%;border-collapse:collapse;min-width:900px}
table.geo-table{min-width:1180px}
thead th{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#9fb3d8;background:#0a1426}
th,td{padding:16px 14px;border-bottom:1px solid rgba(72,101,151,.18);vertical-align:top}
tbody tr:hover{background:rgba(12,25,47,.65)}
.records{display:grid;gap:6px}
.record-line{padding:8px 10px;border:1px solid rgba(72,101,151,.18);border-radius:12px;background:#081426;white-space:pre-wrap;word-break:break-all}
.action-stack{display:flex;flex-direction:column;gap:8px;align-items:flex-start}
.status-stack{display:grid;gap:6px}
.pill-success{background:rgba(24,211,155,.12);border-color:rgba(24,211,155,.3);color:#c9fff0}
.pill-danger{background:rgba(255,84,120,.12);border-color:rgba(255,84,120,.3);color:#ffd7df}
.pill-muted{background:#0b1628;border-color:var(--line);color:#d5e6ff}
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
function toggleZoneKindFields(kind){
  const secondaryKinds=['Slave','Consumer'];
  const isSecondary=secondaryKinds.includes(kind);
  const masters=document.getElementById('zone_masters_field');
  const nameservers=document.getElementById('zone_nameservers_field');
  const mastersInput=masters?masters.querySelector('textarea'):null;
  const nameserversInput=nameservers?nameservers.querySelector('textarea'):null;
  if(masters){masters.style.display=isSecondary?'block':'none';}
  if(nameservers){nameservers.style.display=isSecondary?'none':'block';}
  if(mastersInput){mastersInput.required=isSecondary;}
  if(nameserversInput){nameserversInput.required=!isSecondary;}
}
function fillEditModal(raw){
  try{
    const data=JSON.parse(raw);
    document.getElementById('edit_name').value=data.name||'@';
    document.getElementById('edit_type').value=data.type||'A';
    document.getElementById('edit_ttl').value=data.ttl||300;
    document.getElementById('edit_content').value=data.content||'';
  }catch(e){console.error(e);alert('Failed to load RRset into editor.');}
}
function fillGeoEditModal(raw){
  try{
    const data=JSON.parse(raw);
    document.getElementById('geo_edit_rule_id').value=data.id||'';
    document.getElementById('geo_edit_name').value=data.name||'@';
    document.getElementById('geo_edit_record_type').value=data.record_type||'A';
    document.getElementById('geo_edit_ttl').value=data.ttl||60;
    document.getElementById('geo_edit_country_codes').value=data.country_codes||'IR';
    document.getElementById('geo_edit_country_answers').value=data.country_answers||'';
    document.getElementById('geo_edit_default_answers').value=data.default_answers||'';
    document.getElementById('geo_edit_health_check_port').value=data.health_check_port||'';
    document.getElementById('geo_edit_enabled').checked=!!data.is_enabled;
  }catch(e){console.error(e);alert('Failed to load GeoDNS rule into editor.');}
}
document.addEventListener('DOMContentLoaded',function(){
  const kind=document.getElementById('zone_kind');
  if(kind){toggleZoneKindFields(kind.value);}
});
window.addEventListener('keydown',function(e){if(e.key==='Escape'){document.querySelectorAll('.modal.open').forEach(el=>closeModal(el.id));}});
document.querySelectorAll('.modal').forEach(el=>el.addEventListener('click',function(e){if(e.target===el){closeModal(el.id);}}));
</script>
HTML;
}
