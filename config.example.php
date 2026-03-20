<?php

declare(strict_types=1);

return [
    'app' => [
        'name' => 'HiData PowerDNS Manager',
        'timezone' => 'Europe/Warsaw',
    ],

    'auth' => [
        'username' => 'admin',
        // Generate with: php make-password-hash.php 'YourStrongPassword'
        'password_hash' => '',
    ],

    'pdns' => [
        'base_url' => 'https://pdns.example.com:8081/api/v1',
        'server_id' => 'localhost',
        'api_key' => 'CHANGE_ME',
        'verify_tls' => true,
        'ca_bundle' => null,
        'connect_timeout' => 10,
        'timeout' => 20,
    ],

    'features' => [
        'read_only' => false,
        'backup_before_write' => true,
        'block_secondary_writes' => true,
        'default_auto_rectify' => false,
    ],

    'security' => [
        'session_name' => 'HIDATA_PDNS',
        'require_https' => true,
        'cookie_secure' => true,
        'hsts' => true,
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
