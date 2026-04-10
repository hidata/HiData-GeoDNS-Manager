# HiData GeoDNS Manager API

This document describes the application API exposed by `index.php` under `/api/v1`.

The API is intentionally aligned with the panel behavior:

- It manages PowerDNS zones and RRsets.
- It protects GeoDNS-managed hostnames from unsafe direct RRset edits.
- It stores GeoDNS rules and country CIDR sets in MariaDB.
- It creates audit entries and pre-change backups using the same internal code paths as the web panel.

## Base URL

Examples below assume the panel is reachable at:

```text
https://dns-admin.example.com/api/v1
```

## Authentication

The API supports two authentication modes:

1. Bearer token
2. Existing panel session cookie, if `api.allow_session_auth = true`

Bearer token example:

```bash
curl -H "Authorization: Bearer YOUR_API_TOKEN" \
  https://dns-admin.example.com/api/v1/me
```

If authentication is missing or invalid, the API returns:

```json
{
  "ok": false,
  "error": {
    "code": "authentication_required",
    "message": "Authentication required. Use an Authorization: Bearer <token> header or an active panel session."
  }
}
```

## Response Format

Successful responses:

```json
{
  "ok": true,
  "data": {}
}
```

Error responses:

```json
{
  "ok": false,
  "error": {
    "code": "validation_error",
    "message": "TTL must be between 1 and 2147483647."
  }
}
```

Typical status codes:

- `200` successful read or update
- `201` resource created
- `400` malformed JSON or request body
- `401` authentication required
- `403` blocked by read-only mode, IP allowlist, HTTPS policy, or secondary-write protection
- `404` resource or endpoint not found
- `405` wrong HTTP method
- `409` conflict, such as duplicate GeoDNS or country-set creation
- `422` validation failure
- `500` unexpected internal or backend error

## Common Rules

- Zone names are normalized to fully-qualified names with a trailing dot in responses.
- In request bodies, a hostname can usually be sent as `@`, `www`, or a full FQDN such as `www.example.com.`.
- RRset endpoints manage whole RRsets by default.
- Record-level endpoints let you add or remove only specific values inside an RRset.
- GeoDNS-managed hostnames cannot be edited through the generic RRset endpoints for the same answer type.
- In read-only mode, all write endpoints are rejected.
- If `features.block_secondary_writes = true`, writes are blocked for secondary-style zones such as `Slave` and `Consumer`.

## Service Discovery

### `GET /api/v1/health`

Lightweight health check. Does not require authentication.

Example response:

```json
{
  "ok": true,
  "data": {
    "status": "ok",
    "app": "IRG GeoDNS Manager",
    "time": "2026-04-10T16:33:00+00:00"
  }
}
```

### `GET /api/v1`

Returns API metadata, the current auth mode in use, and the main endpoint list.

### `GET /api/v1/me`

Returns the authenticated actor:

```json
{
  "ok": true,
  "data": {
    "auth_type": "token",
    "actor": "api-token",
    "session_user": null
  }
}
```

## Zones

### `GET /api/v1/zones`

Returns all zones visible to the panel.

Query parameters:

- `zone_search`: filters by zone name or account

### `POST /api/v1/zones`

Creates a new zone.

Body fields:

- `zone_name` or `name`: apex domain, for example `example.com`
- `zone_kind` or `kind`: `Native`, `Master`, `Slave`, `Producer`, or `Consumer`
- `account`: optional owner label
- `nameservers`: array or newline-separated string for `Native` and `Master`
- `masters`: array or newline-separated string for `Slave` and `Consumer`
- `dnssec`: optional boolean for `Native` and `Master`
- `api_rectify`: optional boolean for `Native` and `Master`

Example:

```bash
curl -X POST https://dns-admin.example.com/api/v1/zones \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com",
    "kind": "Native",
    "account": "customer-42",
    "nameservers": ["ns1.example.com.", "ns2.example.com."],
    "dnssec": true,
    "api_rectify": true
  }'
```

### `GET /api/v1/zones/{zone}`

Returns one zone with:

- normalized zone summary
- RRset and record counts
- visible RRsets
- GeoDNS rules for the zone

Query parameters:

- `record_filter`: text search across RRset name, type, and content

### `PUT /api/v1/zones/{zone}`

Updates zone metadata.

Supported body fields:

- `zone_kind` or `kind`
- `account`
- `masters`
- `dnssec`
- `api_rectify`
- `catalog`
- `nsec3param`
- `soa_edit`
- `soa_edit_api`

Notes:

- `nameservers` are not accepted here. Manage NS changes through the RRset API.
- If the effective zone kind is secondary-style, at least one master must exist.
- This endpoint uses the PowerDNS zone metadata update operation and is intentionally limited to backend-safe fields.

Example:

```bash
curl -X PUT https://dns-admin.example.com/api/v1/zones/example.com \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account": "customer-42-updated",
    "api_rectify": true
  }'
```

### `DELETE /api/v1/zones/{zone}`

Deletes the zone and removes its stored GeoDNS rules.

### `GET /api/v1/zones/{zone}/export`

Returns plain-text zone export content from PowerDNS.

### `POST /api/v1/zones/{zone}/rectify`

Calls the PowerDNS rectify endpoint for the zone.

### `POST /api/v1/zones/{zone}/import`

Imports zone text and upserts RRsets.

Body fields:

- `zone_text`: required plain-text zone content
- `include_soa`: optional boolean, default `false`
- `include_ns`: optional boolean, default `false`

The import parser accepts Cloudflare/BIND-style text and skips unsupported types.

## RRsets

Supported editable RRset types:

```text
A, AAAA, CAA, CNAME, DNSKEY, DS, HTTPS, LOC, MX, NAPTR, NS, PTR, RP, SOA, SPF, SRV, SSHFP, SVCB, TLSA, TXT, URI
```

Content normalization rules include:

- `A`: IPv4 only
- `AAAA`: IPv6 only
- `CNAME`, `NS`, `PTR`: hostname target normalized with trailing dot
- `MX`: `priority hostname`
- `SRV`: `priority weight port target`
- `CAA`: `flags tag value`
- `SOA`: `mname rname serial refresh retry expire minimum`
- `TXT` and `SPF`: quoted automatically if needed

### `GET /api/v1/zones/{zone}/rrsets`

Returns visible RRsets for a zone.

Query parameters:

- `record_filter`: full-text match against name, type, or content
- `type`: exact RRset type filter
- `name`: exact hostname filter, such as `@`, `www`, or `www.example.com.`

### `POST /api/v1/zones/{zone}/rrsets`

Creates a new RRset.

Body fields:

- `name`: host, defaults to `@`
- `type`: required RRset type
- `ttl`: required integer
- `content`: newline-separated values
- `records`: alternative array form, for example `[{"content":"192.0.2.10","disabled":false}]`

Example:

```bash
curl -X POST https://dns-admin.example.com/api/v1/zones/example.com/rrsets \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "www",
    "type": "A",
    "ttl": 300,
    "content": "192.0.2.10\n192.0.2.11"
  }'
```

### `POST /api/v1/zones/{zone}/rrsets/bulk-delete`

Deletes multiple RRsets in one request.

Body fields:

- `targets`: array of `{ "name": "...", "type": "..." }`
- `rrsets`: accepted alias for `targets`

Example:

```json
{
  "targets": [
    { "name": "@", "type": "TXT" },
    { "name": "old", "type": "A" }
  ]
}
```

### `GET /api/v1/zones/{zone}/rrsets/{type}/{name}`

Returns one RRset.

Important:

- The path order is `/{type}/{name}`, not `/{name}/{type}`.
- `name` can be `@`, `www`, or a full FQDN.

### `PUT /api/v1/zones/{zone}/rrsets/{type}/{name}`

Replaces the full RRset content.

Body fields are the same as RRset creation, except `type` and `name` come from the URL.

### `DELETE /api/v1/zones/{zone}/rrsets/{type}/{name}`

Deletes the full RRset.

## Record-Level RRset Operations

These endpoints are useful when you want to add or remove only some values inside an RRset without rebuilding the full set client-side.

### `GET /api/v1/zones/{zone}/rrsets/{type}/{name}/records`

Returns the RRset and its current record values.

### `POST /api/v1/zones/{zone}/rrsets/{type}/{name}/records`

Adds values to an RRset.

Behavior:

- If the RRset does not exist, it is created.
- If the RRset exists, new values are merged and duplicates are ignored.
- If `ttl` is provided, the RRset TTL is updated as part of the merge.
- `CNAME` and `SOA` still obey single-value rules.

Body fields:

- `content`: newline-separated values
- `records`: array form
- `ttl`: optional integer

Example: add one more A record

```bash
curl -X POST https://dns-admin.example.com/api/v1/zones/example.com/rrsets/A/www/records \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "192.0.2.12"
  }'
```

### `DELETE /api/v1/zones/{zone}/rrsets/{type}/{name}/records`

Deletes specific values from an RRset.

Behavior:

- Only matching values are removed.
- If the last remaining value is deleted, the whole RRset is removed.
- If no provided values match, the API returns `404 record_not_found`.

Example: remove one IP from an existing RRset

```bash
curl -X DELETE https://dns-admin.example.com/api/v1/zones/example.com/rrsets/A/www/records \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "records": ["192.0.2.11"]
  }'
```

## GeoDNS

GeoDNS rules are stored in the application database and synchronized into PowerDNS `LUA` RRsets.

Only `A` and `AAAA` GeoDNS answers are supported.

### `POST /api/v1/zones/{zone}/geodns/sync`

Synchronizes every GeoDNS rule set in the zone to PowerDNS.

### `GET /api/v1/zones/{zone}/geodns/rules`

Returns GeoDNS rules for the zone.

### `POST /api/v1/zones/{zone}/geodns/rules`

Creates a GeoDNS rule and synchronizes the relevant hostname.

Accepted body fields:

- `geo_name` or `name`
- `geo_record_type` or `record_type`: `A` or `AAAA`
- `geo_ttl` or `ttl`
- `geo_country_codes` or `country_codes`
- `geo_country_answers` or `country_answers`
- `geo_default_answers` or `default_answers`
- `geo_health_check_port` or `health_check_port`
- `geo_enabled` or `is_enabled`

Field format rules:

- `country_codes`: comma-separated string or array, such as `IR,DE`
- `country_answers` and `default_answers`: newline-separated string or array
- `health_check_port`: optional integer from `1` to `65535`

Example:

```bash
curl -X POST https://dns-admin.example.com/api/v1/zones/example.com/geodns/rules \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "app",
    "record_type": "A",
    "ttl": 60,
    "country_codes": ["IR"],
    "country_answers": ["203.0.113.10", "203.0.113.11"],
    "default_answers": ["198.51.100.20"],
    "health_check_port": 443,
    "is_enabled": true
  }'
```

### `GET /api/v1/zones/{zone}/geodns/rules/{id}`

Returns one GeoDNS rule.

### `PUT /api/v1/zones/{zone}/geodns/rules/{id}`

Updates a GeoDNS rule and re-synchronizes the affected hostname.

### `DELETE /api/v1/zones/{zone}/geodns/rules/{id}`

Deletes a GeoDNS rule and re-renders the remaining rule set for the hostname.

### `POST /api/v1/zones/{zone}/geodns/rules/{id}/sync`

Re-synchronizes one GeoDNS rule set to PowerDNS.

## Country CIDR Sets

Country CIDR sets can be referenced by GeoDNS country matching. If a custom CIDR set exists for a country code, the generated Lua uses those CIDRs before falling back to the backend country database.

### `GET /api/v1/country-ip-sets`

Returns every country CIDR set plus aggregate statistics.

### `POST /api/v1/country-ip-sets`

Creates a country CIDR set and re-synchronizes any GeoDNS rules already using that country code.

Body fields:

- `country_code` or `country_db_code`
- `country_name` or `country_db_name`
- `cidrs` or `country_db_cidrs`

`cidrs` may be:

- newline-separated string
- comma-separated string
- array of CIDR or IP strings

Plain IPs are accepted and converted automatically to host routes such as `/32` or `/128`.

Example:

```bash
curl -X POST https://dns-admin.example.com/api/v1/country-ip-sets \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "country_code": "IR",
    "country_name": "Iran",
    "cidrs": [
      "5.52.0.0/14",
      "37.32.0.0/12",
      "203.0.113.10"
    ]
  }'
```

### `GET /api/v1/country-ip-sets/{country_code}`

Returns one country CIDR set.

### `PUT /api/v1/country-ip-sets/{country_code}`

Updates the CIDR set in place and re-synchronizes any dependent GeoDNS rule sets.

Country codes are immutable. To change the country code itself, delete and recreate the entry.

### `DELETE /api/v1/country-ip-sets/{country_code}`

Deletes the CIDR set if it is not currently referenced by any GeoDNS rule.

## Practical Workflows

### Create a zone, then add records

1. `POST /zones`
2. `POST /zones/{zone}/rrsets`
3. Optional: `POST /zones/{zone}/rectify`

### Add one more IP to an existing A or AAAA RRset

1. `POST /zones/{zone}/rrsets/{type}/{name}/records`

### Remove only one IP without replacing the full RRset

1. `DELETE /zones/{zone}/rrsets/{type}/{name}/records`

### Enable GeoDNS safely for a hostname

1. Remove any regular `A`, `AAAA`, or conflicting `CNAME` RRset for that hostname
2. Create the GeoDNS rule
3. If needed, add or update country CIDR sets

## Notes for Client Implementations

- URL-encode hostnames when they contain special characters.
- Keep in mind that zone and RRset names are normalized to FQDNs in responses.
- If your integration only wants to append or remove IPs, prefer the record-level endpoints instead of rebuilding the full RRset.
- If your integration manages NS values, use the RRset endpoints for the zone apex NS RRset instead of the zone metadata update endpoint.
