# HiData GeoDNS Manager

HiData GeoDNS Manager is a single-file PHP control panel for managing a PowerDNS Authoritative server that runs on the same Ubuntu 22.04 host.

## What the project now installs

The `install-hidata-geodns-manager.sh` script is intended for fresh or controlled deployments on Ubuntu 22.04 and provisions:

- MariaDB
- PowerDNS Authoritative with the `gmysql` backend
- PowerDNS GeoIP support with `pdns-backend-geoip`
- A local GeoIP database from the Ubuntu `geoip-database` package by default, or custom files via `PDNS_GEOIP_DATABASE_FILES`
- A local-only PowerDNS HTTP API on `127.0.0.1:8081`
- Nginx
- PHP-FPM
- Release-based deployment under `/opt/hidata-geodns-manager`
- A generated shared `config.php` with secure random secrets when you do not provide them
- Initial panel storage artifacts and end-to-end readiness checks so the browser login is ready when the script finishes

The PHP panel runs on the same server as PowerDNS and talks to the local API instead of a remote endpoint.

## Panel features

- Local application login separate from the PowerDNS API key
- Zone list, search, create, and delete
- RRset list, filter, add, edit, and delete
- GeoDNS rule management for `IR/default` or other country-code matches
- Per-rule country pool, default pool, TTL, enable/disable state, and optional TCP failover port
- Automatic sync of GeoDNS rules into PowerDNS LUA RRsets
- Zone-file import from plain text or Cloudflare/BIND-style exports
- Zone export
- Zone rectify
- Automatic pre-change zone backups
- Audit logging
- Optional application IP allowlist with CIDR support
- Trusted proxy support for `X-Forwarded-*` and HTTPS detection
- Session idle and absolute timeout controls
- Read-only mode
- Secondary-style write protection

## API

The application also exposes a JSON API under `/api/v1`.

Full endpoint documentation, request formats, validation rules, and `curl` examples are available in [API.md](API.md).

## Quick install

Run on Ubuntu 22.04 as `root`:

```bash
sudo bash install-hidata-geodns-manager.sh
```

The installer writes deployment details to:

```text
/root/hidata-geodns-manager-credentials.txt
```

That file includes the generated panel password, PowerDNS API key, and database credentials.
It also tells you the final panel URL so you can sign in immediately after the script completes.

## Common installer options

```bash
sudo \
  APP_SERVER_NAME=dns-admin.example.com \
  APP_ENABLE_HTTPS=1 \
  TLS_CERT_PATH=/etc/ssl/certs/dns-admin.crt \
  TLS_KEY_PATH=/etc/ssl/private/dns-admin.key \
  APP_ALLOWED_IPS=203.0.113.10/32,198.51.100.0/24 \
  APP_TIMEZONE=Asia/Tehran \
  bash install-hidata-geodns-manager.sh
```

Useful environment variables:

- `APP_SERVER_NAME`
- `APP_ENABLE_HTTPS`
- `TLS_CERT_PATH`
- `TLS_KEY_PATH`
- `APP_ALLOWED_IPS`
- `APP_USERNAME`
- `APP_PASSWORD`
- `APP_PASSWORD_HASH`
- `APP_CONFIG_OVERWRITE=1`
- `PDNS_DB_NAME`
- `PDNS_DB_USER`
- `PDNS_DB_PASSWORD`
- `PDNS_API_KEY`
- `PDNS_GEOIP_DATABASE_FILES`
- `PDNS_LOCAL_PORT`

The installer is intentionally single-host:

- `PDNS_DB_HOST` must remain `127.0.0.1`, `::1`, or `localhost`
- `PDNS_API_BIND` must remain `127.0.0.1`, `::1`, or `localhost`

## Manual development setup

Only use this section when you are intentionally running the PHP panel by itself for development. The production installer already generates the config, storage, credentials, and service wiring automatically.

If you only want to run the PHP panel manually:

1. Update `config.php`
2. Make sure the configured MariaDB database exists and is reachable by the credentials in `config.php`
3. Generate a password hash:

```bash
php make-password-hash.php 'YourStrongPassword'
```

4. Ensure `storage/` is writable
5. Start a test server:

```bash
php -S 127.0.0.1:8088 -t .
```

## Notes

- The tracked `config.php` is now a safe placeholder template. The installer generates the real production config in the shared deployment directory.
- `verify_tls = false` is only appropriate for the same-host default API URL (`http://127.0.0.1:8081/api/v1`).
- GeoDNS rules are stored in MariaDB and published as PowerDNS `LUA` RRsets.
- The default installer uses the Ubuntu `geoip-database` package for country lookups. If you need a different GeoIP source, point `PDNS_GEOIP_DATABASE_FILES` at your own `.dat` or `.mmdb` files.
- GeoDNS answers are based on the resolver address unless the recursive resolver sends EDNS Client Subnet (ECS). Accuracy for end users is best with ECS-aware resolvers.
- The panel manages RRsets, not individual record rows.
- Editing replaces the whole RRset by design.
