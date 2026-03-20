# HiData PowerDNS Manager

A standalone PHP panel for securely managing PowerDNS zones and RRsets from another host.

## Features

- Beautiful HiData-styled UI
- Local application login separate from the PowerDNS API key
- Zone list and search
- RRset list and filter
- Add, edit, and delete RRsets
- Zone export
- Zone rectify
- Pre-change zone backups using the PowerDNS export endpoint
- Audit logging
- Optional IP allowlist
- TLS verification for the PowerDNS API connection
- Read-only mode option
- Blocks writes to secondary-style zones by default

## Requirements

- PHP 8.1+
- cURL extension enabled
- HTTPS strongly recommended for this app
- Reachability from this host to your PowerDNS API endpoint

## Setup

1. Copy `config.example.php` to `config.php`
2. Generate a password hash:

```bash
php make-password-hash.php 'YourStrongPassword'
```

3. Put the generated hash into `config.php`
4. Set the PowerDNS API URL, server ID, and API key in `config.php`
5. Make sure the `storage` directory is writable by PHP
6. Serve the folder with PHP-FPM/Apache/Nginx or PHP built-in server for testing

## Example dev run

```bash
php -S 127.0.0.1:8088 -t .
```

Then open:

```text
http://127.0.0.1:8088
```

## Recommended deployment hardening

- Put the app behind HTTPS
- Restrict app access by source IP in your reverse proxy or firewall
- Restrict the PowerDNS webserver/API with `webserver-allow-from`
- Keep `verify_tls = true`
- Keep `backup_before_write = true`
- Use `read_only = true` when you only need browsing

## Notes

- This app manages RRsets, not individual record rows. In PowerDNS an RRset is all records sharing the same name and type.
- Editing replaces the whole RRset by design.
- If `default_auto_rectify` is disabled, you can still use the Rectify button manually.
