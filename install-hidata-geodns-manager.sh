#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_NAME="HiData GeoDNS Manager"
APP_SLUG="hidata-geodns-manager"
REPO_URL_DEFAULT="https://github.com/hidata/HiData-GeoDNS-Manager"
INSTALL_ROOT_DEFAULT="/opt/${APP_SLUG}"
WEB_ROOT_DEFAULT="/var/www/${APP_SLUG}"
WEB_USER_DEFAULT="www-data"
WEB_GROUP_DEFAULT="www-data"
PHP_VERSION_DEFAULT="8.1"
PDNS_SERVICE_DEFAULT="pdns"
PDNS_DB_NAME_DEFAULT="hidata_geodns"
PDNS_DB_USER_DEFAULT="hidata_geodns"
PDNS_DB_HOST_DEFAULT="127.0.0.1"
PDNS_DB_PORT_DEFAULT="3306"
PDNS_API_BIND_DEFAULT="127.0.0.1"
PDNS_API_PORT_DEFAULT="8081"
PDNS_API_ALLOW_FROM_DEFAULT="127.0.0.1,::1"
PDNS_GEOIP_DATABASE_FILES_DEFAULT=""
APP_SERVER_NAME_DEFAULT="_"
APP_HTTP_PORT_DEFAULT="80"
APP_HTTPS_PORT_DEFAULT="443"
APP_ENABLE_HTTPS_DEFAULT="0"
APP_ENABLE_IPV6_DEFAULT="1"
APP_ALLOWED_IPS_DEFAULT=""
APP_TRUSTED_PROXIES_DEFAULT="127.0.0.1,::1"
APP_TIMEZONE_DEFAULT="Asia/Tehran"
APP_USERNAME_DEFAULT="admin"
APP_SESSION_IDLE_TIMEOUT_DEFAULT="3600"
APP_SESSION_ABSOLUTE_TIMEOUT_DEFAULT="43200"
APP_REQUIRE_HTTPS_DEFAULT="auto"
APP_COOKIE_SECURE_DEFAULT="auto"
APP_HSTS_DEFAULT="auto"
APP_CONFIG_OVERWRITE_DEFAULT="0"

REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
REPO_BRANCH="${REPO_BRANCH:-}"
INSTALL_ROOT="${INSTALL_ROOT:-$INSTALL_ROOT_DEFAULT}"
WEB_ROOT="${WEB_ROOT:-$WEB_ROOT_DEFAULT}"
WEB_USER="${WEB_USER:-$WEB_USER_DEFAULT}"
WEB_GROUP="${WEB_GROUP:-$WEB_GROUP_DEFAULT}"
PHP_VERSION="${PHP_VERSION:-$PHP_VERSION_DEFAULT}"
PHP_FPM_SERVICE="${PHP_FPM_SERVICE:-php${PHP_VERSION}-fpm}"
PHP_FPM_SOCKET="${PHP_FPM_SOCKET:-/run/php/php${PHP_VERSION}-fpm.sock}"
PDNS_SERVICE="${PDNS_SERVICE:-$PDNS_SERVICE_DEFAULT}"
PDNS_DB_NAME="${PDNS_DB_NAME:-$PDNS_DB_NAME_DEFAULT}"
PDNS_DB_USER="${PDNS_DB_USER:-$PDNS_DB_USER_DEFAULT}"
PDNS_DB_PASSWORD="${PDNS_DB_PASSWORD:-}"
PDNS_DB_HOST="${PDNS_DB_HOST:-$PDNS_DB_HOST_DEFAULT}"
PDNS_DB_PORT="${PDNS_DB_PORT:-$PDNS_DB_PORT_DEFAULT}"
PDNS_API_BIND="${PDNS_API_BIND:-$PDNS_API_BIND_DEFAULT}"
PDNS_API_PORT="${PDNS_API_PORT:-$PDNS_API_PORT_DEFAULT}"
PDNS_API_ALLOW_FROM="${PDNS_API_ALLOW_FROM:-$PDNS_API_ALLOW_FROM_DEFAULT}"
PDNS_API_KEY="${PDNS_API_KEY:-}"
PDNS_ENABLE_DNSSEC="${PDNS_ENABLE_DNSSEC:-1}"
PDNS_GEOIP_DATABASE_FILES="${PDNS_GEOIP_DATABASE_FILES:-$PDNS_GEOIP_DATABASE_FILES_DEFAULT}"
PDNS_LOCAL_PORT="${PDNS_LOCAL_PORT:-53}"
PDNS_LOCAL_ADDRESS="${PDNS_LOCAL_ADDRESS:-}"
APP_SERVER_NAME="${APP_SERVER_NAME:-$APP_SERVER_NAME_DEFAULT}"
APP_HTTP_PORT="${APP_HTTP_PORT:-$APP_HTTP_PORT_DEFAULT}"
APP_HTTPS_PORT="${APP_HTTPS_PORT:-$APP_HTTPS_PORT_DEFAULT}"
APP_ENABLE_HTTPS="${APP_ENABLE_HTTPS:-$APP_ENABLE_HTTPS_DEFAULT}"
APP_ENABLE_IPV6="${APP_ENABLE_IPV6:-$APP_ENABLE_IPV6_DEFAULT}"
APP_ALLOWED_IPS="${APP_ALLOWED_IPS:-$APP_ALLOWED_IPS_DEFAULT}"
APP_TRUSTED_PROXIES="${APP_TRUSTED_PROXIES:-$APP_TRUSTED_PROXIES_DEFAULT}"
APP_TIMEZONE="${APP_TIMEZONE:-$APP_TIMEZONE_DEFAULT}"
APP_USERNAME="${APP_USERNAME:-$APP_USERNAME_DEFAULT}"
APP_PASSWORD="${APP_PASSWORD:-}"
APP_PASSWORD_HASH="${APP_PASSWORD_HASH:-}"
APP_SESSION_IDLE_TIMEOUT="${APP_SESSION_IDLE_TIMEOUT:-$APP_SESSION_IDLE_TIMEOUT_DEFAULT}"
APP_SESSION_ABSOLUTE_TIMEOUT="${APP_SESSION_ABSOLUTE_TIMEOUT:-$APP_SESSION_ABSOLUTE_TIMEOUT_DEFAULT}"
APP_REQUIRE_HTTPS="${APP_REQUIRE_HTTPS:-$APP_REQUIRE_HTTPS_DEFAULT}"
APP_COOKIE_SECURE="${APP_COOKIE_SECURE:-$APP_COOKIE_SECURE_DEFAULT}"
APP_HSTS="${APP_HSTS:-$APP_HSTS_DEFAULT}"
APP_CONFIG_OVERWRITE="${APP_CONFIG_OVERWRITE:-$APP_CONFIG_OVERWRITE_DEFAULT}"
TLS_CERT_PATH="${TLS_CERT_PATH:-}"
TLS_KEY_PATH="${TLS_KEY_PATH:-}"
TLS_CHAIN_PATH="${TLS_CHAIN_PATH:-}"
ENABLE_DB_FOREIGN_KEYS="${ENABLE_DB_FOREIGN_KEYS:-0}"
DISABLE_SYSTEMD_RESOLVED_STUB="${DISABLE_SYSTEMD_RESOLVED_STUB:-auto}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
FORCE="${FORCE:-0}"
SKIP_APT="${SKIP_APT:-0}"
RUN_COMPOSER="${RUN_COMPOSER:-auto}"
KEEP_RELEASES="${KEEP_RELEASES:-5}"
DRY_RUN="${DRY_RUN:-0}"

SHARED_DIR="${INSTALL_ROOT}/shared"
SHARED_CONFIG_PATH="${SHARED_DIR}/config.php"
SHARED_STORAGE_PATH="${SHARED_DIR}/storage"
PDNS_CONFIG_FILE="${PDNS_CONFIG_FILE:-/etc/powerdns/pdns.d/90-${APP_SLUG}.conf}"
PDNS_GEOIP_ZONES_FILE="${PDNS_GEOIP_ZONES_FILE:-/etc/powerdns/pdns.d/91-${APP_SLUG}-geoip.yaml}"
PHP_FPM_INI_FILE="${PHP_FPM_INI_FILE:-/etc/php/${PHP_VERSION}/fpm/conf.d/99-${APP_SLUG}.ini}"
NGINX_SITE_PATH="${NGINX_SITE_PATH:-/etc/nginx/sites-available/${APP_SLUG}.conf}"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/${APP_SLUG}.conf"
CREDENTIALS_FILE="${CREDENTIALS_FILE:-/root/${APP_SLUG}-credentials.txt}"
LOGROTATE_FILE="${LOGROTATE_FILE:-/etc/logrotate.d/${APP_SLUG}}"
SYSTEMD_RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/90-${APP_SLUG}.conf"

CURRENT_RELEASE=""
NEW_RELEASE=""
TEMP_DIR=""
ROLLBACK_NEEDED=0
SWITCHED_SYMLINK=0
PRESERVE_APP_CONFIG=0
APP_PASSWORD_GENERATED=0
APP_REQUIRE_HTTPS_RESOLVED=""
APP_COOKIE_SECURE_RESOLVED=""
APP_HSTS_RESOLVED=""
PANEL_VERIFY_NOTE="Skipped panel readiness checks."
PDNS_SERVICE_STOPPED_BY_INSTALLER=0

C_RESET='\033[0m'
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BLUE='\033[34m'
C_CYAN='\033[36m'
C_BOLD='\033[1m'

log() { printf "%b[%s]%b %s\n" "$C_BLUE" "INFO" "$C_RESET" "$*"; }
warn() { printf "%b[%s]%b %s\n" "$C_YELLOW" "WARN" "$C_RESET" "$*" >&2; }
err() { printf "%b[%s]%b %s\n" "$C_RED" "ERROR" "$C_RESET" "$*" >&2; }
ok() { printf "%b[%s]%b %s\n" "$C_GREEN" "OK" "$C_RESET" "$*"; }

die() { err "$*"; exit 1; }

usage() {
  cat <<USAGE
${APP_NAME} full-stack installer for Ubuntu 22.04

Environment variables:
  REPO_URL                GitHub repository URL or owner/repo string
                          Default: ${REPO_URL_DEFAULT}
  REPO_BRANCH             Branch or tag to deploy. If empty, auto-detects default branch.
  GITHUB_TOKEN            Optional GitHub token for private repos.
  INSTALL_ROOT            Default: ${INSTALL_ROOT_DEFAULT}
  WEB_ROOT                Default: ${WEB_ROOT_DEFAULT}
  PHP_VERSION             Default: ${PHP_VERSION_DEFAULT}
  APP_SERVER_NAME         Nginx server_name. Default: ${APP_SERVER_NAME_DEFAULT}
  APP_ENABLE_HTTPS        1 to enable HTTPS in nginx. Default: ${APP_ENABLE_HTTPS_DEFAULT}
  TLS_CERT_PATH           Required when APP_ENABLE_HTTPS=1.
  TLS_KEY_PATH            Required when APP_ENABLE_HTTPS=1.
  APP_ALLOWED_IPS         Optional comma-separated allowlist for the panel.
  APP_USERNAME            Default: ${APP_USERNAME_DEFAULT}
  APP_PASSWORD            Auto-generated when omitted.
  APP_PASSWORD_HASH       Pre-generated hash. Overrides APP_PASSWORD.
  APP_TIMEZONE            Default: ${APP_TIMEZONE_DEFAULT}
  APP_CONFIG_OVERWRITE    1 to regenerate shared config.php.
  PDNS_DB_NAME            Default: ${PDNS_DB_NAME_DEFAULT}
  PDNS_DB_USER            Default: ${PDNS_DB_USER_DEFAULT}
  PDNS_DB_PASSWORD        Auto-generated when omitted.
  PDNS_API_KEY            Auto-generated when omitted.
  PDNS_GEOIP_DATABASE_FILES
                          Optional comma-separated GeoIP database paths for PowerDNS.
  PDNS_LOCAL_PORT         Default: 53
  SKIP_APT                Set to 1 to skip apt package installation.
  RUN_COMPOSER            auto|1|0. Default: auto
  KEEP_RELEASES           Number of old releases to keep. Default: 5
  FORCE                   Set to 1 to skip confirmation prompts.
  DRY_RUN                 Set to 1 to print actions without changing anything.

Examples:
  sudo bash install-hidata-geodns-manager.sh
  sudo APP_SERVER_NAME=dns-admin.example.com APP_ENABLE_HTTPS=1 \\
       TLS_CERT_PATH=/etc/ssl/certs/dns-admin.crt \\
       TLS_KEY_PATH=/etc/ssl/private/dns-admin.key \\
       bash install-hidata-geodns-manager.sh
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }

is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_auto_bool() {
  local value="${1:-auto}" fallback="${2:-0}"
  if [[ "${value,,}" == "auto" ]]; then
    printf '%s\n' "$fallback"
  elif is_true "$value"; then
    printf '1\n'
  else
    printf '0\n'
  fi
}

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf "%b[DRY-RUN]%b %s\n" "$C_CYAN" "$C_RESET" "$*"
    return 0
  fi
  "$@"
}

write_file() {
  local path="$1" mode="$2" owner="$3" group="$4"
  local tmp
  tmp=$(mktemp)
  cat >"$tmp"
  if [[ "$DRY_RUN" == "1" ]]; then
    printf "%b[DRY-RUN]%b write %s\n" "$C_CYAN" "$C_RESET" "$path"
    rm -f "$tmp"
    return 0
  fi
  install -D -m "$mode" -o "$owner" -g "$group" "$tmp" "$path"
  rm -f "$tmp"
}

mysql_exec() {
  local sql="$1"
  if [[ "$DRY_RUN" == "1" ]]; then
    printf "%b[DRY-RUN]%b mysql -e %q\n" "$C_CYAN" "$C_RESET" "$sql"
    return 0
  fi
  mysql --protocol=socket -u root -e "$sql"
}

mysql_scalar() {
  local sql="$1"
  mysql --protocol=socket -N -B -u root -e "$sql"
}

split_csv_lines() {
  printf '%s\n' "$1" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d'
}

normalize_csv() {
  local input="$1"
  local items=()
  while IFS= read -r item; do
    items+=("$item")
  done < <(split_csv_lines "$input")
  if ((${#items[@]} == 0)); then
    printf '\n'
    return 0
  fi
  local joined="" item
  for item in "${items[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$item"
  done
  printf '%s\n' "$joined"
}

php_quote() {
  local value="$1"
  value=${value//\\/\\\\}
  value=${value//\'/\\\'}
  printf "'%s'" "$value"
}

php_array_from_csv() {
  local csv="$1" parent_indent="$2" child_indent="$3"
  local had_item=0
  while IFS= read -r _line; do
    had_item=1
    break
  done < <(split_csv_lines "$csv")
  if [[ "$had_item" == "0" ]]; then
    printf '[]'
    return 0
  fi
  printf "[\n"
  while IFS= read -r item; do
    printf "%s%s,\n" "$child_indent" "$(php_quote "$item")"
  done < <(split_csv_lines "$csv")
  printf "%s]" "$parent_indent"
}

generate_hex_secret() {
  local bytes="${1:-24}"
  if have openssl; then
    openssl rand -hex "$bytes"
  else
    tr -dc 'A-Fa-f0-9' </dev/urandom | head -c $((bytes * 2))
  fi
}

hash_password() {
  local password="$1"
  php -r 'echo password_hash($argv[1], PASSWORD_DEFAULT), PHP_EOL;' "$password"
}

cleanup() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    err "Installer aborted with exit code ${exit_code}."
    if [[ "$SWITCHED_SYMLINK" == "1" && "$ROLLBACK_NEEDED" == "1" && -n "$CURRENT_RELEASE" && "$DRY_RUN" != "1" ]]; then
      warn "Attempting rollback to previous release: ${CURRENT_RELEASE}"
      ln -sfn "$CURRENT_RELEASE" "$WEB_ROOT/current" || true
      ln -sfn "$CURRENT_RELEASE" "$INSTALL_ROOT/current" || true
    fi
    if [[ "$PDNS_SERVICE_STOPPED_BY_INSTALLER" == "1" && "$DRY_RUN" != "1" ]]; then
      warn "Attempting to restart ${PDNS_SERVICE} because the installer stopped it earlier."
      if ! systemctl start "$PDNS_SERVICE" >/dev/null 2>&1; then
        warn "Failed to restart ${PDNS_SERVICE} during cleanup. Check: systemctl status ${PDNS_SERVICE} && journalctl -xeu ${PDNS_SERVICE}"
      fi
    fi
  fi
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -rf "$TEMP_DIR" || true
  fi
}
trap cleanup EXIT

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Please run this installer as root."
}

check_os() {
  [[ -r /etc/os-release ]] || die "Cannot detect operating system."
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "This installer is intended for Ubuntu."
  [[ "${VERSION_ID:-}" == "22.04" || "${VERSION_CODENAME:-}" == "jammy" ]] || warn "This script is optimized for Ubuntu 22.04. Current system: ${PRETTY_NAME:-unknown}."
}

confirm() {
  local prompt="$1"
  [[ "$FORCE" == "1" ]] && return 0
  read -r -p "$prompt [y/N]: " answer
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

ensure_identifier() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[A-Za-z0-9_]+$ ]] || die "${name} must contain only letters, numbers, and underscores."
}

is_loopback_host() {
  local value="${1,,}"
  [[ "$value" == "127.0.0.1" || "$value" == "::1" || "$value" == "localhost" ]]
}

validate_inputs() {
  ensure_identifier "PDNS_DB_NAME" "$PDNS_DB_NAME"
  ensure_identifier "PDNS_DB_USER" "$PDNS_DB_USER"
  [[ "$APP_SESSION_IDLE_TIMEOUT" =~ ^[0-9]+$ ]] || die "APP_SESSION_IDLE_TIMEOUT must be numeric."
  [[ "$APP_SESSION_ABSOLUTE_TIMEOUT" =~ ^[0-9]+$ ]] || die "APP_SESSION_ABSOLUTE_TIMEOUT must be numeric."
  [[ "$KEEP_RELEASES" =~ ^[0-9]+$ ]] || die "KEEP_RELEASES must be numeric."
  [[ "$PDNS_DB_PORT" =~ ^[0-9]+$ ]] || die "PDNS_DB_PORT must be numeric."
  [[ "$PDNS_API_PORT" =~ ^[0-9]+$ ]] || die "PDNS_API_PORT must be numeric."
  [[ "$PDNS_LOCAL_PORT" =~ ^[0-9]+$ ]] || die "PDNS_LOCAL_PORT must be numeric."
  [[ "$APP_HTTP_PORT" =~ ^[0-9]+$ ]] || die "APP_HTTP_PORT must be numeric."
  [[ "$APP_HTTPS_PORT" =~ ^[0-9]+$ ]] || die "APP_HTTPS_PORT must be numeric."
  is_loopback_host "$PDNS_DB_HOST" || die "PDNS_DB_HOST must stay on the local host (127.0.0.1, ::1, or localhost) because this installer provisions a local MariaDB instance."
  is_loopback_host "$PDNS_API_BIND" || die "PDNS_API_BIND must stay on loopback (127.0.0.1, ::1, or localhost) so the panel can safely reach the local PowerDNS API."
  if is_true "$APP_ENABLE_HTTPS"; then
    [[ -n "$TLS_CERT_PATH" && -n "$TLS_KEY_PATH" ]] || die "APP_ENABLE_HTTPS=1 requires TLS_CERT_PATH and TLS_KEY_PATH."
    [[ -r "$TLS_CERT_PATH" ]] || die "TLS certificate not readable: ${TLS_CERT_PATH}"
    [[ -r "$TLS_KEY_PATH" ]] || die "TLS key not readable: ${TLS_KEY_PATH}"
    if [[ -n "$TLS_CHAIN_PATH" ]]; then
      [[ -r "$TLS_CHAIN_PATH" ]] || die "TLS chain file not readable: ${TLS_CHAIN_PATH}"
    fi
  fi
}

resolve_runtime_settings() {
  APP_ENABLE_HTTPS=$(resolve_auto_bool "$APP_ENABLE_HTTPS" "0")
  APP_ENABLE_IPV6=$(resolve_auto_bool "$APP_ENABLE_IPV6" "1")
  APP_REQUIRE_HTTPS_RESOLVED=$(resolve_auto_bool "$APP_REQUIRE_HTTPS" "$APP_ENABLE_HTTPS")
  APP_COOKIE_SECURE_RESOLVED=$(resolve_auto_bool "$APP_COOKIE_SECURE" "$APP_ENABLE_HTTPS")
  APP_HSTS_RESOLVED=$(resolve_auto_bool "$APP_HSTS" "$APP_ENABLE_HTTPS")
  APP_ALLOWED_IPS=$(normalize_csv "$APP_ALLOWED_IPS")
  APP_TRUSTED_PROXIES=$(normalize_csv "$APP_TRUSTED_PROXIES")
  PDNS_API_ALLOW_FROM=$(normalize_csv "$PDNS_API_ALLOW_FROM")
}

extract_php_config_value() {
  local file="$1" section="$2" key="$3"
  [[ -f "$file" ]] || return 0
  php -r '
    $config = require $argv[1];
    if (!is_array($config)) {
        exit(1);
    }
    $section = $argv[2];
    $key = $argv[3];
    $value = $config[$section][$key] ?? "";
    if (is_bool($value)) {
        echo $value ? "1" : "0";
    } elseif (is_scalar($value)) {
        echo (string) $value;
    }
  ' "$file" "$section" "$key" 2>/dev/null || true
}

extract_pdns_setting() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 0
  awk -F= -v search="$key" '$1 == search {print substr($0, index($0, "=") + 1)}' "$file" | tail -n1
}

hydrate_existing_configuration() {
  local existing_app_api_key existing_app_hash existing_pdns_api_key existing_pdns_db_password
  local existing_db_name existing_db_user existing_db_password
  existing_app_api_key=$(extract_php_config_value "$SHARED_CONFIG_PATH" "pdns" "api_key")
  existing_app_hash=$(extract_php_config_value "$SHARED_CONFIG_PATH" "auth" "password_hash")
  existing_db_name=$(extract_php_config_value "$SHARED_CONFIG_PATH" "database" "name")
  existing_db_user=$(extract_php_config_value "$SHARED_CONFIG_PATH" "database" "username")
  existing_db_password=$(extract_php_config_value "$SHARED_CONFIG_PATH" "database" "password")
  existing_pdns_api_key=$(extract_pdns_setting "$PDNS_CONFIG_FILE" "api-key")
  existing_pdns_db_password=$(extract_pdns_setting "$PDNS_CONFIG_FILE" "gmysql-password")

  if [[ -f "$SHARED_CONFIG_PATH" && "$APP_CONFIG_OVERWRITE" != "1" ]]; then
    if [[ -n "$existing_db_name" && -n "$existing_db_user" && -n "$existing_db_password" ]]; then
      PRESERVE_APP_CONFIG=1
      log "Preserving existing shared config.php"
    else
      log "Existing shared config.php is missing GeoDNS database settings; regenerating it."
    fi
  fi

  if [[ -z "$PDNS_API_KEY" ]]; then
    PDNS_API_KEY="${existing_app_api_key:-$existing_pdns_api_key}"
  fi
  if [[ -z "$PDNS_DB_PASSWORD" ]]; then
    PDNS_DB_PASSWORD="${existing_pdns_db_password:-}"
  fi
  if [[ -z "$APP_PASSWORD_HASH" ]]; then
    APP_PASSWORD_HASH="${existing_app_hash:-}"
  fi
}

ensure_secrets() {
  if [[ -z "$PDNS_DB_PASSWORD" ]]; then
    PDNS_DB_PASSWORD=$(generate_hex_secret 18)
  fi
  if [[ -z "$PDNS_API_KEY" ]]; then
    PDNS_API_KEY=$(generate_hex_secret 24)
  fi
  if [[ -z "$APP_PASSWORD_HASH" && "$PRESERVE_APP_CONFIG" != "1" ]]; then
    if [[ -z "$APP_PASSWORD" ]]; then
      APP_PASSWORD=$(generate_hex_secret 12)
      APP_PASSWORD_GENERATED=1
    fi
    APP_PASSWORD_HASH=$(hash_password "$APP_PASSWORD")
  fi
}

apt_install() {
  [[ "$SKIP_APT" == "1" ]] && { warn "Skipping apt package installation because SKIP_APT=1"; return 0; }
  export DEBIAN_FRONTEND=noninteractive
  local packages=(
    ca-certificates curl dnsutils git jq mariadb-server nginx openssl
    pdns-server pdns-backend-geoip pdns-backend-mysql geoip-database rsync unzip
    "php${PHP_VERSION}" "php${PHP_VERSION}-cli" "php${PHP_VERSION}-curl"
    "php${PHP_VERSION}-fpm" "php${PHP_VERSION}-intl" "php${PHP_VERSION}-mbstring"
    "php${PHP_VERSION}-mysql" "php${PHP_VERSION}-opcache" "php${PHP_VERSION}-xml"
    "php${PHP_VERSION}-zip"
  )
  if [[ "$RUN_COMPOSER" == "1" || "$RUN_COMPOSER" == "auto" ]]; then
    packages+=(composer)
  fi
  log "Installing required packages..."
  run apt-get update -y
  run apt-get install -y "${packages[@]}"
}

normalize_repo_url() {
  local input="$1"
  if [[ "$input" =~ ^https?:// ]]; then
    printf '%s\n' "$input"
    return 0
  fi
  if [[ "$input" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    printf 'https://github.com/%s\n' "$input"
    return 0
  fi
  die "Unsupported REPO_URL format: ${input}"
}

repo_owner_repo() {
  local url="$1"
  local cleaned
  cleaned="${url%.git}"
  cleaned="${cleaned#https://github.com/}"
  cleaned="${cleaned#http://github.com/}"
  if [[ ! "$cleaned" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    die "Could not parse owner/repo from REPO_URL=${url}"
  fi
  printf '%s\n' "$cleaned"
}

github_header_args() {
  if [[ -n "$GITHUB_TOKEN" ]]; then
    printf '%s\n' -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "X-GitHub-Api-Version: 2022-11-28"
  else
    printf '%s\n' -H "X-GitHub-Api-Version: 2022-11-28"
  fi
}

detect_default_branch() {
  local owner_repo="$1"
  local api="https://api.github.com/repos/${owner_repo}"
  local response
  local headers=()
  mapfile -t headers < <(github_header_args)
  if response=$(curl -fsSL "${headers[@]}" -H "Accept: application/vnd.github+json" "$api" 2>/dev/null); then
    python3 - <<'PY' "$response"
import json, sys
try:
    data = json.loads(sys.argv[1])
    print(data.get('default_branch',''))
except Exception:
    print('')
PY
    return 0
  fi
  printf '\n'
}

clone_repo() {
  local url="$1" branch="$2" dest="$3"
  if [[ -n "$GITHUB_TOKEN" ]]; then
    run git -c "http.extraHeader=Authorization: Bearer ${GITHUB_TOKEN}" clone --depth 1 --branch "$branch" "$url" "$dest"
  else
    run git clone --depth 1 --branch "$branch" "$url" "$dest"
  fi
}

safe_copy_dir() {
  local src="$1" dst="$2"
  run mkdir -p "$dst"
  run rsync -a --delete --exclude='.git' "$src/" "$dst/"
}

ensure_user_group() {
  getent group "$WEB_GROUP" >/dev/null 2>&1 || die "Group ${WEB_GROUP} does not exist."
  id "$WEB_USER" >/dev/null 2>&1 || die "User ${WEB_USER} does not exist."
}

prepare_layout() {
  run mkdir -p "$INSTALL_ROOT/releases" "$SHARED_STORAGE_PATH/backups" "$WEB_ROOT"
  CURRENT_RELEASE=""
  if [[ -L "$INSTALL_ROOT/current" ]]; then
    CURRENT_RELEASE=$(readlink -f "$INSTALL_ROOT/current" || true)
  elif [[ -L "$WEB_ROOT/current" ]]; then
    CURRENT_RELEASE=$(readlink -f "$WEB_ROOT/current" || true)
  fi
}

generate_shared_config() {
  if [[ "$PRESERVE_APP_CONFIG" == "1" ]]; then
    return 0
  fi

  local allowed_ips_php trusted_proxies_php verify_tls
  allowed_ips_php=$(php_array_from_csv "$APP_ALLOWED_IPS" "        " "            ")
  trusted_proxies_php=$(php_array_from_csv "$APP_TRUSTED_PROXIES" "        " "            ")
  verify_tls="false"
  if [[ "$PDNS_API_BIND" != "127.0.0.1" && "$PDNS_API_BIND" != "::1" ]]; then
    verify_tls="true"
  fi

  log "Writing shared application config..."
  write_file "$SHARED_CONFIG_PATH" 0640 root "$WEB_GROUP" <<EOF
<?php

declare(strict_types=1);

return [
    'app' => [
        'name' => 'HiData GeoDNS Manager',
        'timezone' => $(php_quote "$APP_TIMEZONE"),
    ],

    'auth' => [
        'username' => $(php_quote "$APP_USERNAME"),
        'password_hash' => $(php_quote "$APP_PASSWORD_HASH"),
        'session_idle_timeout' => ${APP_SESSION_IDLE_TIMEOUT},
        'session_absolute_timeout' => ${APP_SESSION_ABSOLUTE_TIMEOUT},
    ],

    'pdns' => [
        'base_url' => $(php_quote "$(build_url "http" "$PDNS_API_BIND" "$PDNS_API_PORT" "/api/v1")"),
        'server_id' => 'localhost',
        'api_key' => $(php_quote "$PDNS_API_KEY"),
        'verify_tls' => ${verify_tls},
        'ca_bundle' => null,
        'connect_timeout' => 5,
        'timeout' => 15,
    ],

    'database' => [
        'host' => $(php_quote "$PDNS_DB_HOST"),
        'port' => ${PDNS_DB_PORT},
        'name' => $(php_quote "$PDNS_DB_NAME"),
        'username' => $(php_quote "$PDNS_DB_USER"),
        'password' => $(php_quote "$PDNS_DB_PASSWORD"),
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
        'require_https' => $(if is_true "$APP_REQUIRE_HTTPS_RESOLVED"; then printf 'true'; else printf 'false'; fi),
        'cookie_secure' => $(if is_true "$APP_COOKIE_SECURE_RESOLVED"; then printf 'true'; else printf 'false'; fi),
        'hsts' => $(if is_true "$APP_HSTS_RESOLVED"; then printf 'true'; else printf 'false'; fi),
        'trust_proxy_headers' => true,
        'trusted_proxies' => ${trusted_proxies_php},
        'allowed_ips' => ${allowed_ips_php},
    ],

    'storage' => [
        'backup_dir' => __DIR__ . '/storage/backups',
        'audit_log' => __DIR__ . '/storage/audit.log',
        'rate_limit_file' => __DIR__ . '/storage/login-rate.json',
    ],
];
EOF
}

initialize_shared_storage() {
  log "Initializing shared storage..."
  run mkdir -p "$SHARED_STORAGE_PATH/backups"
  if [[ "$DRY_RUN" == "1" ]]; then
    printf "%b[DRY-RUN]%b initialize %s\n" "$C_CYAN" "$C_RESET" "$SHARED_STORAGE_PATH"
    return 0
  fi

  touch "$SHARED_STORAGE_PATH/audit.log"
  if [[ ! -f "$SHARED_STORAGE_PATH/login-rate.json" || ! -s "$SHARED_STORAGE_PATH/login-rate.json" ]]; then
    printf '{}\n' >"$SHARED_STORAGE_PATH/login-rate.json"
  fi

  chown "$WEB_USER:$WEB_GROUP" "$SHARED_STORAGE_PATH/backups" "$SHARED_STORAGE_PATH/audit.log" "$SHARED_STORAGE_PATH/login-rate.json"
  chmod 0775 "$SHARED_STORAGE_PATH/backups"
  chmod 0660 "$SHARED_STORAGE_PATH/audit.log" "$SHARED_STORAGE_PATH/login-rate.json"
}

format_url_host() {
  local host="$1"
  if [[ "$host" == \[*\] ]]; then
    printf '%s\n' "$host"
  elif [[ "$host" == *:* ]]; then
    printf '[%s]\n' "$host"
  else
    printf '%s\n' "$host"
  fi
}

build_url() {
  local scheme="$1" host="$2" port="$3" path="${4:-/}"
  local formatted_host
  formatted_host=$(format_url_host "$host")
  if { [[ "$scheme" == "http" ]] && [[ "$port" == "80" ]]; } || { [[ "$scheme" == "https" ]] && [[ "$port" == "443" ]]; }; then
    printf '%s://%s%s\n' "$scheme" "$formatted_host" "$path"
  else
    printf '%s://%s:%s%s\n' "$scheme" "$formatted_host" "$port" "$path"
  fi
}

detect_panel_url() {
  local scheme host port
  if is_true "$APP_ENABLE_HTTPS"; then
    scheme="https"
    port="$APP_HTTPS_PORT"
  else
    scheme="http"
    port="$APP_HTTP_PORT"
  fi

  if [[ "$APP_SERVER_NAME" != "_" ]]; then
    host="$APP_SERVER_NAME"
  else
    host=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -z "$host" ]]; then
      host=$(hostname -f 2>/dev/null || hostname)
    fi
  fi
  build_url "$scheme" "$host" "$port" "/"
}

write_credentials_file() {
  local panel_url
  panel_url=$(detect_panel_url)
  log "Writing deployment credentials to ${CREDENTIALS_FILE}"
  {
    printf '%s\n\n' "${APP_NAME} deployment details"
    printf 'Panel URL: %s\n' "$panel_url"
    printf 'Panel username: %s\n' "$APP_USERNAME"
    if [[ -n "$APP_PASSWORD" ]]; then
      printf 'Panel password: %s\n' "$APP_PASSWORD"
    else
      printf 'Panel password: preserved existing hash in shared config.php (plain password unavailable)\n'
    fi
    printf 'PowerDNS API URL: %s\n' "$(build_url "http" "$PDNS_API_BIND" "$PDNS_API_PORT" "/api/v1")"
    printf 'PowerDNS API key: %s\n' "$PDNS_API_KEY"
    printf 'MariaDB database: %s\n' "$PDNS_DB_NAME"
    printf 'MariaDB user: %s\n' "$PDNS_DB_USER"
    printf 'MariaDB password: %s\n' "$PDNS_DB_PASSWORD"
    printf 'Shared config: %s\n' "$SHARED_CONFIG_PATH"
    printf 'Current release: %s\n' "$INSTALL_ROOT/current"
  } | write_file "$CREDENTIALS_FILE" 0600 root root
}

validate_repo_contents() {
  local src="$1"
  [[ -f "$src/index.php" ]] || die "Repository does not contain index.php at its root."
  if [[ ! -f "$src/config.example.php" && ! -f "$src/config.php" ]]; then
    warn "config.example.php/config.php not found. Installer will continue, but you may need to create config manually."
  fi
}

maybe_run_composer() {
  local release_dir="$1"
  if [[ ! -f "$release_dir/composer.json" ]]; then
    log "No composer.json found. Skipping Composer step."
    return 0
  fi
  if [[ "$RUN_COMPOSER" == "0" ]]; then
    warn "composer.json exists, but Composer step skipped because RUN_COMPOSER=0."
    return 0
  fi
  have composer || die "composer.json exists but Composer is not available."
  log "Running Composer install..."
  run composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader -d "$release_dir"
}

detect_schema_file() {
  local candidate
  candidate=$(dpkg -L pdns-backend-mysql | grep -E '/schema\.mysql\.sql(\.gz)?$' | head -n1 || true)
  [[ -n "$candidate" ]] || die "Could not locate the PowerDNS MySQL schema file from pdns-backend-mysql."
  printf '%s\n' "$candidate"
}

configure_database() {
  log "Starting MariaDB..."
  run systemctl enable --now mariadb

  log "Configuring PowerDNS database and user..."
  mysql_exec "CREATE DATABASE IF NOT EXISTS \`${PDNS_DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  mysql_exec "CREATE USER IF NOT EXISTS '${PDNS_DB_USER}'@'127.0.0.1' IDENTIFIED BY '${PDNS_DB_PASSWORD}';"
  mysql_exec "CREATE USER IF NOT EXISTS '${PDNS_DB_USER}'@'localhost' IDENTIFIED BY '${PDNS_DB_PASSWORD}';"
  mysql_exec "ALTER USER '${PDNS_DB_USER}'@'127.0.0.1' IDENTIFIED BY '${PDNS_DB_PASSWORD}';"
  mysql_exec "ALTER USER '${PDNS_DB_USER}'@'localhost' IDENTIFIED BY '${PDNS_DB_PASSWORD}';"
  mysql_exec "GRANT ALL PRIVILEGES ON \`${PDNS_DB_NAME}\`.* TO '${PDNS_DB_USER}'@'127.0.0.1';"
  mysql_exec "GRANT ALL PRIVILEGES ON \`${PDNS_DB_NAME}\`.* TO '${PDNS_DB_USER}'@'localhost';"
  mysql_exec "FLUSH PRIVILEGES;"

  local domains_table_count
  domains_table_count=$(mysql_scalar "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${PDNS_DB_NAME}' AND table_name='domains';")
  if [[ "$domains_table_count" == "0" ]]; then
    local schema_file
    schema_file=$(detect_schema_file)
    log "Importing PowerDNS schema from ${schema_file}"
    if [[ "$DRY_RUN" == "1" ]]; then
      printf "%b[DRY-RUN]%b import schema %s into %s\n" "$C_CYAN" "$C_RESET" "$schema_file" "$PDNS_DB_NAME"
    elif [[ "$schema_file" == *.gz ]]; then
      gzip -dc "$schema_file" | mysql --protocol=socket -u root "$PDNS_DB_NAME"
    else
      mysql --protocol=socket -u root "$PDNS_DB_NAME" < "$schema_file"
    fi
  else
    log "PowerDNS schema already present in ${PDNS_DB_NAME}; leaving tables intact."
  fi

  if is_true "$ENABLE_DB_FOREIGN_KEYS"; then
    local constraint_count
    constraint_count=$(mysql_scalar "SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA='${PDNS_DB_NAME}' AND CONSTRAINT_NAME='records_domain_id_ibfk';")
    if [[ "$constraint_count" == "0" ]]; then
      log "Applying optional foreign keys to the PowerDNS schema..."
      mysql_exec "ALTER TABLE \`${PDNS_DB_NAME}\`.records ADD CONSTRAINT records_domain_id_ibfk FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE;"
      mysql_exec "ALTER TABLE \`${PDNS_DB_NAME}\`.comments ADD CONSTRAINT comments_domain_id_ibfk FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE;"
      mysql_exec "ALTER TABLE \`${PDNS_DB_NAME}\`.domainmetadata ADD CONSTRAINT domainmetadata_domain_id_ibfk FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE;"
      mysql_exec "ALTER TABLE \`${PDNS_DB_NAME}\`.cryptokeys ADD CONSTRAINT cryptokeys_domain_id_ibfk FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE ON UPDATE CASCADE;"
    fi
  fi

  log "Ensuring the GeoDNS application tables exist..."
  mysql_exec "CREATE TABLE IF NOT EXISTS \`${PDNS_DB_NAME}\`.hidata_geo_rules (
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
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"
}

ensure_pdns_include_dir() {
  local main_conf="/etc/powerdns/pdns.conf"
  [[ -f "$main_conf" ]] || die "Missing PowerDNS main config: ${main_conf}"
  if ! grep -Eq '^[[:space:]]*include-dir[[:space:]]*=' "$main_conf"; then
    log "Adding include-dir to ${main_conf}"
    if [[ "$DRY_RUN" == "1" ]]; then
      printf "%b[DRY-RUN]%b append include-dir=/etc/powerdns/pdns.d to %s\n" "$C_CYAN" "$C_RESET" "$main_conf"
    else
      printf '\ninclude-dir=/etc/powerdns/pdns.d\n' >>"$main_conf"
    fi
  fi
}

detect_geoip_database_files() {
  if [[ -n "$PDNS_GEOIP_DATABASE_FILES" ]]; then
    local custom_files=()
    local candidate
    while IFS= read -r candidate; do
      [[ -n "$candidate" ]] || continue
      [[ -r "$candidate" ]] || die "Configured GeoIP database file is not readable: ${candidate}"
      custom_files+=("$candidate")
    done < <(split_csv_lines "$PDNS_GEOIP_DATABASE_FILES")

    ((${#custom_files[@]} > 0)) || die "PDNS_GEOIP_DATABASE_FILES was provided, but no readable files were found in it."

    local custom_joined=""
    for candidate in "${custom_files[@]}"; do
      if [[ -n "$custom_joined" ]]; then
        custom_joined+=","
      fi
      custom_joined+="$candidate"
    done

    printf '%s\n' "$custom_joined"
    return 0
  fi

  local files=()
  local candidate
  for candidate in /usr/share/GeoIP/*.dat /usr/share/GeoIP/*.mmdb; do
    [[ -f "$candidate" ]] || continue
    files+=("$candidate")
  done

  ((${#files[@]} > 0)) || die "Could not locate any GeoIP database files. Install geoip-database or set PDNS_GEOIP_DATABASE_FILES."

  local joined="" file
  for file in "${files[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$file"
  done
  printf '%s\n' "$joined"
}

configure_systemd_resolved_stub() {
  if [[ "$PDNS_LOCAL_PORT" != "53" ]]; then
    return 0
  fi
  case "${DISABLE_SYSTEMD_RESOLVED_STUB,,}" in
    0|false|no)
      return 0
      ;;
  esac
  if ! systemctl list-unit-files | grep -q '^systemd-resolved\.service'; then
    return 0
  fi
  log "Disabling systemd-resolved's stub listener so PowerDNS can bind to port 53..."
  run mkdir -p /etc/systemd/resolved.conf.d
  write_file "$SYSTEMD_RESOLVED_DROPIN" 0644 root root <<EOF
[Resolve]
DNSStubListener=no
EOF
  run systemctl restart systemd-resolved
  if [[ "$DRY_RUN" != "1" ]]; then
    if [[ -L /etc/resolv.conf ]]; then
      local resolved_target
      resolved_target=$(readlink -f /etc/resolv.conf || true)
      if [[ "$resolved_target" == "/run/systemd/resolve/stub-resolv.conf" ]]; then
        ln -sfn /run/systemd/resolve/resolv.conf /etc/resolv.conf
      fi
    elif grep -q '127\.0\.0\.53' /etc/resolv.conf 2>/dev/null && [[ -f /run/systemd/resolve/resolv.conf ]]; then
      cp /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi
  fi
}

stop_pdns_service_if_running() {
  if [[ "$PDNS_LOCAL_PORT" != "53" || "$DRY_RUN" == "1" ]]; then
    return 0
  fi
  if ! systemctl is-active --quiet "$PDNS_SERVICE"; then
    return 0
  fi
  log "Stopping ${PDNS_SERVICE} temporarily so port 53 can be validated..."
  run systemctl stop "$PDNS_SERVICE"
  PDNS_SERVICE_STOPPED_BY_INSTALLER=1
}

link_shared_items() {
  local release_dir="$1"
  run rm -f "$release_dir/config.php"
  run ln -sfn "$SHARED_CONFIG_PATH" "$release_dir/config.php"

  if [[ -e "$release_dir/storage" && ! -L "$release_dir/storage" ]]; then
    run rm -rf "$release_dir/storage"
  fi
  run ln -sfn "$SHARED_STORAGE_PATH" "$release_dir/storage"

  if [[ "$DRY_RUN" != "1" ]]; then
    chown -R root:root "$release_dir"
    find "$release_dir" -type d -exec chmod 755 {} +
    find "$release_dir" -type f -exec chmod 644 {} +
  fi
  run chown -R "$WEB_USER:$WEB_GROUP" "$SHARED_STORAGE_PATH"
  if [[ "$DRY_RUN" != "1" ]]; then
    find "$SHARED_STORAGE_PATH" -type d -exec chmod 775 {} +
    find "$SHARED_STORAGE_PATH" -type f -exec chmod 664 {} + || true
  fi
}

switch_release() {
  local release_dir="$1"
  run ln -sfn "$release_dir" "$INSTALL_ROOT/current"
  run ln -sfn "$release_dir" "$WEB_ROOT/current"
  SWITCHED_SYMLINK=1
  ROLLBACK_NEEDED=1
}

assert_dns_port_available() {
  if [[ "$PDNS_LOCAL_PORT" != "53" || "$DRY_RUN" == "1" ]]; then
    return 0
  fi
  local listeners
  listeners=$(ss -Hlnup "( sport = :53 )" 2>/dev/null || true)
  if [[ -n "$listeners" ]]; then
    warn "The following process(es) are already listening on port 53:"
    printf '%s\n' "$listeners" >&2
    die "Port 53 must be free before PowerDNS can start. Stop the conflicting service(s) or set PDNS_LOCAL_PORT to another port."
  fi
}

configure_pdns() {
  ensure_pdns_include_dir
  run mkdir -p /etc/powerdns/pdns.d
  local geoip_database_files
  geoip_database_files=$(detect_geoip_database_files)
  log "Writing PowerDNS GeoIP zone helper file..."
  write_file "$PDNS_GEOIP_ZONES_FILE" 0644 root root <<EOF
# Managed by ${APP_NAME} installer
domains: []
EOF
  log "Writing PowerDNS configuration..."
  {
    cat <<EOF
# Managed by ${APP_NAME} installer
launch=gmysql,geoip
gmysql-host=${PDNS_DB_HOST}
gmysql-port=${PDNS_DB_PORT}
gmysql-dbname=${PDNS_DB_NAME}
gmysql-user=${PDNS_DB_USER}
gmysql-password=${PDNS_DB_PASSWORD}
gmysql-dnssec=$(if is_true "$PDNS_ENABLE_DNSSEC"; then printf 'yes'; else printf 'no'; fi)
gmysql-innodb-read-committed=yes
enable-lua-records=yes
edns-subnet-processing=yes
geoip-database-files=${geoip_database_files}
geoip-zones-file=${PDNS_GEOIP_ZONES_FILE}
webserver=yes
webserver-address=${PDNS_API_BIND}
webserver-port=${PDNS_API_PORT}
webserver-allow-from=${PDNS_API_ALLOW_FROM}
api=yes
api-key=${PDNS_API_KEY}
version-string=anonymous
EOF
    if [[ -n "$PDNS_LOCAL_ADDRESS" ]]; then
      printf 'local-address=%s\n' "$PDNS_LOCAL_ADDRESS"
    fi
    if [[ "$PDNS_LOCAL_PORT" != "53" ]]; then
      printf 'local-port=%s\n' "$PDNS_LOCAL_PORT"
    fi
  } | write_file "$PDNS_CONFIG_FILE" 0640 root root
}

configure_php_runtime() {
  log "Writing PHP-FPM hardening overrides..."
  write_file "$PHP_FPM_INI_FILE" 0644 root root <<EOF
; Managed by ${APP_NAME} installer
cgi.fix_pathinfo=0
expose_php=0
session.cookie_httponly=1
session.cookie_samesite=Lax
EOF
}

nginx_allowlist_block() {
  if [[ -z "$APP_ALLOWED_IPS" ]]; then
    printf '\n'
    return 0
  fi
  while IFS= read -r cidr; do
    printf '    allow %s;\n' "$cidr"
  done < <(split_csv_lines "$APP_ALLOWED_IPS")
  printf '    deny all;\n'
}

nginx_common_server_block() {
  local tls_enabled="$1"
  cat <<EOF
    server_name ${APP_SERVER_NAME};
    root ${WEB_ROOT}/current;
    index index.php;
    client_max_body_size 16m;

    access_log /var/log/nginx/${APP_SLUG}.access.log;
    error_log /var/log/nginx/${APP_SLUG}.error.log warn;
$(nginx_allowlist_block)
    location = /healthz {
        access_log off;
        add_header Content-Type text/plain always;
        return 200 "ok\n";
    }

    location /storage/ {
        deny all;
    }

    location ~ ^/(config(?:\.example)?\.php|make-password-hash\.php|README\.md)$ {
        deny all;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT \$realpath_root;
EOF
  if [[ "$tls_enabled" == "1" ]]; then
    cat <<'EOF'
        fastcgi_param HTTPS on;
EOF
  fi
  cat <<EOF
        fastcgi_pass unix:${PHP_FPM_SOCKET};
    }
EOF
}

configure_nginx() {
  local http_listen https_listen redirect_port
  http_listen="    listen ${APP_HTTP_PORT};"
  https_listen="    listen ${APP_HTTPS_PORT} ssl http2;"
  redirect_port=""
  if [[ "$APP_HTTPS_PORT" != "443" ]]; then
    redirect_port=":${APP_HTTPS_PORT}"
  fi
  if [[ "$APP_ENABLE_IPV6" == "1" ]]; then
    http_listen+=$'\n'"    listen [::]:${APP_HTTP_PORT};"
    https_listen+=$'\n'"    listen [::]:${APP_HTTPS_PORT} ssl http2;"
  fi

  log "Writing nginx site configuration..."
  if is_true "$APP_ENABLE_HTTPS"; then
    {
      cat <<EOF
# Managed by ${APP_NAME} installer
server {
${http_listen}
    server_name ${APP_SERVER_NAME};
    return 301 https://\$host${redirect_port}\$request_uri;
}

server {
${https_listen}
    ssl_certificate ${TLS_CERT_PATH};
    ssl_certificate_key ${TLS_KEY_PATH};
EOF
      if [[ -n "$TLS_CHAIN_PATH" ]]; then
        printf '    ssl_trusted_certificate %s\n' "$TLS_CHAIN_PATH"
      fi
      cat <<EOF
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
$(nginx_common_server_block "1")
}
EOF
    } | write_file "$NGINX_SITE_PATH" 0644 root root
  else
    {
      cat <<EOF
# Managed by ${APP_NAME} installer
server {
${http_listen}
$(nginx_common_server_block "0")
}
EOF
    } | write_file "$NGINX_SITE_PATH" 0644 root root
  fi
  run ln -sfn "$NGINX_SITE_PATH" "$NGINX_SITE_LINK"
  run rm -f /etc/nginx/sites-enabled/default
}

prune_old_releases() {
  local releases_dir="$INSTALL_ROOT/releases"
  local current_target
  current_target=$(readlink -f "$INSTALL_ROOT/current" || true)
  mapfile -t old_releases < <(find "$releases_dir" -mindepth 1 -maxdepth 1 -type d | sort)
  local count=${#old_releases[@]}
  if (( count <= KEEP_RELEASES )); then
    return 0
  fi
  local remove_count=$((count - KEEP_RELEASES))
  local i
  for ((i=0; i<remove_count; i++)); do
    local candidate="${old_releases[$i]}"
    [[ -n "$current_target" && "$candidate" == "$current_target" ]] && continue
    log "Removing old release: $candidate"
    run rm -rf "$candidate"
  done
}

configure_logrotate() {
  log "Writing logrotate policy for the panel audit log..."
  write_file "$LOGROTATE_FILE" 0644 root root <<EOF
${SHARED_STORAGE_PATH}/audit.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
    copytruncate
    create 0660 ${WEB_USER} ${WEB_GROUP}
}
EOF
}

validate_release_files() {
  [[ -n "$NEW_RELEASE" ]] || die "No new release path was prepared."
  log "Linting PHP application files..."
  run php -l "$NEW_RELEASE/index.php"
  run php -l "$SHARED_CONFIG_PATH"
}

validate_service_configs() {
  log "Validating PowerDNS and nginx configuration..."
  run pdns_server --config=check
  run nginx -t
}

restart_services() {
  log "Enabling and restarting services..."
  run systemctl enable --now "$PHP_FPM_SERVICE"
  run systemctl enable --now "$PDNS_SERVICE"
  run systemctl enable --now nginx
  run systemctl restart "$PHP_FPM_SERVICE"
  run systemctl restart "$PDNS_SERVICE"
  run systemctl restart nginx
}

verify_services() {
  if [[ "$DRY_RUN" == "1" ]]; then
    PANEL_VERIFY_NOTE="Skipped panel readiness checks in dry-run mode."
    return 0
  fi
  log "Verifying service status..."
  systemctl is-active --quiet mariadb || die "MariaDB is not active."
  systemctl is-active --quiet "$PHP_FPM_SERVICE" || die "${PHP_FPM_SERVICE} is not active."
  systemctl is-active --quiet "$PDNS_SERVICE" || die "${PDNS_SERVICE} is not active."
  systemctl is-active --quiet nginx || die "nginx is not active."

  local geodns_table_count
  geodns_table_count=$(mysql_scalar "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${PDNS_DB_NAME}' AND table_name='hidata_geo_rules';")
  [[ "$geodns_table_count" == "1" ]] || die "GeoDNS application table hidata_geo_rules was not created successfully."

  log "Verifying local PowerDNS API..."
  curl -fsS -H "X-API-Key: ${PDNS_API_KEY}" "$(build_url "http" "$PDNS_API_BIND" "$PDNS_API_PORT" "/api/v1/servers/localhost")" >/dev/null \
    || die "Failed to query the local PowerDNS API after deployment."
}

allowlist_allows_local_verification() {
  [[ -z "$APP_ALLOWED_IPS" ]] && return 0
  while IFS= read -r cidr; do
    case "$cidr" in
      127.0.0.1|127.0.0.1/32|127.0.0.0/8|0.0.0.0/0|::1|::1/128|::/0)
        return 0
        ;;
    esac
  done < <(split_csv_lines "$APP_ALLOWED_IPS")
  return 1
}

verify_panel() {
  local scheme port request_host panel_root_url health_url health_body
  local login_page cookie_jar dashboard_page csrf_token
  local -a curl_args

  if [[ "$DRY_RUN" == "1" ]]; then
    PANEL_VERIFY_NOTE="Skipped panel readiness checks in dry-run mode."
    return 0
  fi

  if ! allowlist_allows_local_verification; then
    PANEL_VERIFY_NOTE="Skipped browser-level smoke tests because APP_ALLOWED_IPS does not include loopback."
    warn "$PANEL_VERIFY_NOTE"
    return 0
  fi

  if is_true "$APP_ENABLE_HTTPS"; then
    scheme="https"
    port="$APP_HTTPS_PORT"
  else
    scheme="http"
    port="$APP_HTTP_PORT"
  fi

  request_host="127.0.0.1"
  curl_args=(-fsS --retry 5 --retry-delay 1 --connect-timeout 5)
  if is_true "$APP_ENABLE_HTTPS"; then
    curl_args+=(-k)
  fi
  if [[ "$APP_SERVER_NAME" != "_" ]]; then
    request_host="$APP_SERVER_NAME"
    curl_args+=(--resolve "${APP_SERVER_NAME}:${port}:127.0.0.1")
  fi

  health_url=$(build_url "$scheme" "$request_host" "$port" "/healthz")
  panel_root_url=$(build_url "$scheme" "$request_host" "$port" "/")

  log "Verifying panel health endpoint..."
  health_body=$(curl "${curl_args[@]}" "$health_url") || die "Failed to reach the panel health endpoint at ${health_url}"
  health_body=${health_body//$'\r'/}
  [[ "$health_body" == "ok" || "$health_body" == $'ok\n' ]] || die "Unexpected response from ${health_url}: ${health_body@Q}"

  login_page="${TEMP_DIR}/panel-login.html"
  cookie_jar="${TEMP_DIR}/panel-cookies.txt"
  dashboard_page="${TEMP_DIR}/panel-dashboard.html"
  rm -f "$login_page" "$cookie_jar" "$dashboard_page"

  log "Verifying panel login page..."
  curl "${curl_args[@]}" -c "$cookie_jar" "$panel_root_url" -o "$login_page" \
    || die "Failed to load the panel login page at ${panel_root_url}"
  grep -Fq '<h1>Sign in</h1>' "$login_page" \
    || die "The panel login page did not render as expected."

  if [[ -z "$APP_PASSWORD" ]]; then
    PANEL_VERIFY_NOTE="Verified the panel URL and login page. Login smoke test skipped because the installer does not know the plain panel password."
    warn "$PANEL_VERIFY_NOTE"
    return 0
  fi

  csrf_token=$(python3 - "$login_page" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    html = fh.read()

match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
if not match:
    raise SystemExit(1)

print(match.group(1))
PY
) || die "Failed to extract the panel login CSRF token."

  log "Verifying panel sign-in with the configured application credentials..."
  curl "${curl_args[@]}" -L -b "$cookie_jar" -c "$cookie_jar" \
    --data-urlencode "csrf_token=${csrf_token}" \
    --data-urlencode "action=login" \
    --data-urlencode "username=${APP_USERNAME}" \
    --data-urlencode "password=${APP_PASSWORD}" \
    "$panel_root_url" -o "$dashboard_page" \
    || die "Failed to sign in to the panel with the configured application credentials."

  grep -Fq 'Signed in successfully.' "$dashboard_page" \
    || die "The panel did not confirm a successful login after installation."
  grep -Fq 'Sign out' "$dashboard_page" \
    || die "The authenticated panel view did not render as expected after login."

  PANEL_VERIFY_NOTE="Verified the panel URL, login page, and authenticated dashboard using the configured installer credentials."
}

print_summary() {
  local panel_url
  panel_url=$(detect_panel_url)
  cat <<SUMMARY

${APP_NAME} deployment completed successfully.

Paths:
  Install root     : ${INSTALL_ROOT}
  Current release  : ${INSTALL_ROOT}/current
  Web root         : ${WEB_ROOT}/current
  Shared config    : ${SHARED_CONFIG_PATH}
  Shared storage   : ${SHARED_STORAGE_PATH}
  PowerDNS config  : ${PDNS_CONFIG_FILE}
  GeoIP zones file : ${PDNS_GEOIP_ZONES_FILE}
  Nginx site       : ${NGINX_SITE_PATH}
  Credentials file : ${CREDENTIALS_FILE}

Endpoints:
  Panel            : ${panel_url}
  PowerDNS API     : $(build_url "http" "$PDNS_API_BIND" "$PDNS_API_PORT" "/api/v1")

Notes:
  - The PowerDNS API is bound locally for the PHP panel running on this same server.
  - Use the credentials file above to retrieve the generated panel password and API key.
  - Readiness      : ${PANEL_VERIFY_NOTE}
  - Add your DNS zones in the panel, then point your registrar glue/NS records to this server.
SUMMARY

  if ! is_true "$APP_ENABLE_HTTPS"; then
    warn "The panel is configured without HTTPS. Enable APP_ENABLE_HTTPS=1 with TLS_CERT_PATH/TLS_KEY_PATH or put the site behind a trusted HTTPS reverse proxy."
  fi
  if [[ -z "$APP_ALLOWED_IPS" ]]; then
    warn "APP_ALLOWED_IPS is empty, so the panel is not IP-restricted at the application layer."
  fi
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_root
  check_os

  REPO_URL=$(normalize_repo_url "$REPO_URL")
  local owner_repo
  owner_repo=$(repo_owner_repo "$REPO_URL")

  if [[ -z "$REPO_BRANCH" ]]; then
    REPO_BRANCH=$(detect_default_branch "$owner_repo")
    if [[ -z "$REPO_BRANCH" ]]; then
      warn "Could not auto-detect default branch from GitHub. Falling back to 'main'."
      REPO_BRANCH="main"
    fi
  fi

  resolve_runtime_settings
  validate_inputs

  log "Project        : ${APP_NAME}"
  log "Repository     : ${REPO_URL}"
  log "Branch/Tag     : ${REPO_BRANCH}"
  log "Install root   : ${INSTALL_ROOT}"
  log "Web root       : ${WEB_ROOT}"
  log "PowerDNS DB    : ${PDNS_DB_NAME}"
  log "PowerDNS API   : $(build_url "http" "$PDNS_API_BIND" "$PDNS_API_PORT" "/api/v1")"
  log "PHP-FPM        : ${PHP_FPM_SERVICE}"

  if [[ "$FORCE" != "1" ]]; then
    confirm "Proceed with full-stack deployment?" || die "Cancelled by user."
  fi

  apt_install
  ensure_user_group
  prepare_layout
  hydrate_existing_configuration
  ensure_secrets
  generate_shared_config
  initialize_shared_storage
  configure_systemd_resolved_stub
  stop_pdns_service_if_running
  assert_dns_port_available
  configure_database
  configure_pdns
  configure_php_runtime
  configure_nginx
  configure_logrotate

  TEMP_DIR=$(mktemp -d "/tmp/${APP_SLUG}.XXXXXX")
  local repo_checkout="$TEMP_DIR/repo"
  log "Downloading ${APP_NAME} from GitHub..."
  if ! clone_repo "$REPO_URL" "$REPO_BRANCH" "$repo_checkout"; then
    die "Failed to clone repository. If the repo is private, set GITHUB_TOKEN."
  fi

  validate_repo_contents "$repo_checkout"

  local ts
  ts=$(date +%Y%m%d-%H%M%S)
  NEW_RELEASE="$INSTALL_ROOT/releases/${ts}"
  log "Preparing release directory: ${NEW_RELEASE}"
  safe_copy_dir "$repo_checkout" "$NEW_RELEASE"

  maybe_run_composer "$NEW_RELEASE"
  link_shared_items "$NEW_RELEASE"
  switch_release "$NEW_RELEASE"
  validate_release_files
  validate_service_configs
  restart_services
  verify_services
  verify_panel
  prune_old_releases
  write_credentials_file

  ok "${APP_NAME} has been deployed successfully."
  print_summary
}

main "$@"
