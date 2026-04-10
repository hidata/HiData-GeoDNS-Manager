<?php

declare(strict_types=1);

return [
    'app' => [
        'name' => 'IRG GeoDNS Manager',
        'timezone' => 'Asia/Tehran',
    ],

    'auth' => [
        'username' => 'admin',
        // Generate with: php make-password-hash.php 'YourStrongPassword'
        'password_hash' => '',
        'session_idle_timeout' => 3600,
        'session_absolute_timeout' => 43200,
    ],

    'api' => [
        'enabled' => true,
        // Use this token in: Authorization: Bearer <token>
        // Leave allow_session_auth enabled if you want browser sessions to access /api/v1/* too.
        'token' => 'CHANGE_ME',
        'token_label' => 'api-token',
        'allow_session_auth' => true,
    ],

    'pdns' => [
        // Same-server default used by the installer.
        'base_url' => 'http://127.0.0.1:8081/api/v1',
        'server_id' => 'localhost',
        'api_key' => 'CHANGE_ME',
        'verify_tls' => false,
        'ca_bundle' => null,
        'connect_timeout' => 5,
        'timeout' => 15,
    ],

    'database' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'hidata_geodns',
        'username' => 'hidata_geodns',
        'password' => 'CHANGE_ME',
        'charset' => 'utf8mb4',
    ],

    'geodns' => [
        'default_match_countries' => ['IR'],
        'default_ttl' => 60,
        'max_answers_per_pool' => 8,
    ],

    'features' => [
        'read_only' => false,
        'backup_before_write' => true,
        'block_secondary_writes' => true,
        'default_auto_rectify' => true,
        'allow_zone_create' => true,
        'allow_zone_delete' => true,
        'max_backups_per_zone' => 20,
    ],

    'security' => [
        'session_name' => 'HIDATA_PDNS',
        'require_https' => false,
        'cookie_secure' => false,
        'hsts' => false,
        'trust_proxy_headers' => true,
        'trusted_proxies' => [
            '127.0.0.1',
            '::1',
        ],
        // Leave empty to allow all source IPs reaching this app.
        'allowed_ips' => [
            // '203.0.113.10',
        ],
    ],

    'storage' => [
        'backup_dir' => __DIR__ . '/storage/backups',
        'audit_log' => __DIR__ . '/storage/audit.log',
        'rate_limit_file' => __DIR__ . '/storage/login-rate.json',
    ],
];
