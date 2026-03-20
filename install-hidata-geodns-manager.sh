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
PHP_FPM_SERVICE_DEFAULT="php8.1-fpm"
PHP_VERSION_DEFAULT="8.1"

REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
REPO_BRANCH="${REPO_BRANCH:-}"
INSTALL_ROOT="${INSTALL_ROOT:-$INSTALL_ROOT_DEFAULT}"
WEB_ROOT="${WEB_ROOT:-$WEB_ROOT_DEFAULT}"
WEB_USER="${WEB_USER:-$WEB_USER_DEFAULT}"
WEB_GROUP="${WEB_GROUP:-$WEB_GROUP_DEFAULT}"
PHP_FPM_SERVICE="${PHP_FPM_SERVICE:-$PHP_FPM_SERVICE_DEFAULT}"
PHP_VERSION="${PHP_VERSION:-$PHP_VERSION_DEFAULT}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
FORCE="${FORCE:-0}"
SKIP_APT="${SKIP_APT:-0}"
RUN_COMPOSER="${RUN_COMPOSER:-auto}"
KEEP_RELEASES="${KEEP_RELEASES:-5}"
DRY_RUN="${DRY_RUN:-0}"

CURRENT_RELEASE=""
NEW_RELEASE=""
TEMP_DIR=""
ROLLBACK_NEEDED=0
SWITCHED_SYMLINK=0

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
${APP_NAME} installer for Ubuntu 22.04

Environment variables:
  REPO_URL           GitHub repository URL or owner/repo string
                     Default: ${REPO_URL_DEFAULT}
  REPO_BRANCH        Branch or tag to deploy. If empty, auto-detects default branch.
  GITHUB_TOKEN       Optional GitHub token for private repos.
  INSTALL_ROOT       Default: ${INSTALL_ROOT_DEFAULT}
  WEB_ROOT           Default: ${WEB_ROOT_DEFAULT}
  WEB_USER           Default: ${WEB_USER_DEFAULT}
  WEB_GROUP          Default: ${WEB_GROUP_DEFAULT}
  PHP_VERSION        Default: ${PHP_VERSION_DEFAULT}
  PHP_FPM_SERVICE    Default: ${PHP_FPM_SERVICE_DEFAULT}
  SKIP_APT           Set to 1 to skip apt package installation.
  RUN_COMPOSER       auto|1|0. Default: auto
  KEEP_RELEASES      Number of old releases to keep. Default: 5
  FORCE              Set to 1 to skip confirmation prompts.
  DRY_RUN            Set to 1 to print actions without changing anything.

Examples:
  sudo bash install-hidata-geodns-manager.sh
  sudo REPO_BRANCH=main bash install-hidata-geodns-manager.sh
  sudo GITHUB_TOKEN=ghp_xxx REPO_BRANCH=main bash install-hidata-geodns-manager.sh
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf "%b[DRY-RUN]%b %s\n" "$C_CYAN" "$C_RESET" "$*"
    return 0
  fi
  "$@"
}

cleanup() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    err "Installer aborted with exit code ${exit_code}."
    if [[ "$SWITCHED_SYMLINK" == "1" && "$ROLLBACK_NEEDED" == "1" && -n "$CURRENT_RELEASE" ]]; then
      warn "Attempting rollback to previous release: ${CURRENT_RELEASE}"
      ln -sfn "$CURRENT_RELEASE" "$WEB_ROOT/current" || true
      ln -sfn "$CURRENT_RELEASE" "$INSTALL_ROOT/current" || true
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

apt_install() {
  [[ "$SKIP_APT" == "1" ]] && { warn "Skipping apt package installation because SKIP_APT=1"; return 0; }
  export DEBIAN_FRONTEND=noninteractive
  local packages=(
    ca-certificates curl unzip git rsync jq
    php php-cli php-fpm php-curl php-mbstring php-xml php-zip php-intl
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
  run rsync -a --delete "$src/" "$dst/"
}

ensure_user_group() {
  getent group "$WEB_GROUP" >/dev/null 2>&1 || die "Group ${WEB_GROUP} does not exist."
  id "$WEB_USER" >/dev/null 2>&1 || die "User ${WEB_USER} does not exist."
}

prepare_layout() {
  run mkdir -p "$INSTALL_ROOT/releases" "$INSTALL_ROOT/shared" "$INSTALL_ROOT/shared/storage/backups" "$INSTALL_ROOT/shared/storage/logs" "$WEB_ROOT"
  CURRENT_RELEASE=""
  if [[ -L "$INSTALL_ROOT/current" ]]; then
    CURRENT_RELEASE=$(readlink -f "$INSTALL_ROOT/current" || true)
  elif [[ -L "$WEB_ROOT/current" ]]; then
    CURRENT_RELEASE=$(readlink -f "$WEB_ROOT/current" || true)
  fi
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

link_shared_items() {
  local release_dir="$1"
  local shared="$INSTALL_ROOT/shared"

  if [[ -f "$shared/config.php" ]]; then
    run rm -f "$release_dir/config.php"
    run ln -sfn "$shared/config.php" "$release_dir/config.php"
  else
    if [[ -f "$release_dir/config.example.php" ]]; then
      log "Creating shared config.php from config.example.php"
      run cp -a "$release_dir/config.example.php" "$shared/config.php"
      run chmod 640 "$shared/config.php"
      run chown root:"$WEB_GROUP" "$shared/config.php"
      run rm -f "$release_dir/config.php"
      run ln -sfn "$shared/config.php" "$release_dir/config.php"
    elif [[ -f "$release_dir/config.php" ]]; then
      log "Moving repository config.php into shared config location"
      run mv "$release_dir/config.php" "$shared/config.php"
      run chmod 640 "$shared/config.php"
      run chown root:"$WEB_GROUP" "$shared/config.php"
      run ln -sfn "$shared/config.php" "$release_dir/config.php"
    fi
  fi

  if [[ -e "$release_dir/storage" && ! -L "$release_dir/storage" ]]; then
    run rm -rf "$release_dir/storage"
  fi
  run ln -sfn "$shared/storage" "$release_dir/storage"

  run chown -R "$WEB_USER:$WEB_GROUP" "$shared/storage"
  run find "$shared/storage" -type d -exec chmod 775 {} +
  run find "$shared/storage" -type f -exec chmod 664 {} + || true
}

switch_release() {
  local release_dir="$1"
  run ln -sfn "$release_dir" "$INSTALL_ROOT/current"
  run ln -sfn "$release_dir" "$WEB_ROOT/current"
  SWITCHED_SYMLINK=1
  ROLLBACK_NEEDED=1
}

reload_php_fpm() {
  if systemctl list-unit-files | grep -q "^${PHP_FPM_SERVICE}\.service"; then
    log "Reloading ${PHP_FPM_SERVICE}"
    run systemctl reload "$PHP_FPM_SERVICE"
  else
    warn "${PHP_FPM_SERVICE}.service was not found. Skipping PHP-FPM reload."
  fi
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

print_summary() {
  cat <<SUMMARY

${APP_NAME} deployment completed.

Paths:
  Install root : ${INSTALL_ROOT}
  Current link : ${INSTALL_ROOT}/current
  Web root     : ${WEB_ROOT}/current
  Shared config: ${INSTALL_ROOT}/shared/config.php
  Shared data  : ${INSTALL_ROOT}/shared/storage

Next steps:
  1. Edit ${INSTALL_ROOT}/shared/config.php
  2. Point your web server document root to ${WEB_ROOT}/current
  3. Keep the PowerDNS API bound to localhost when the PHP app runs on the same server
  4. Test the panel and confirm backups are being written to storage/backups
SUMMARY
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_root
  check_os
  ensure_user_group

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

  log "Project        : ${APP_NAME}"
  log "Repository     : ${REPO_URL}"
  log "Branch/Tag     : ${REPO_BRANCH}"
  log "Install root   : ${INSTALL_ROOT}"
  log "Web root       : ${WEB_ROOT}"
  log "Web user/group : ${WEB_USER}:${WEB_GROUP}"
  log "PHP-FPM        : ${PHP_FPM_SERVICE}"

  if [[ "$FORCE" != "1" ]]; then
    confirm "Proceed with deployment?" || die "Cancelled by user."
  fi

  apt_install
  prepare_layout

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
  reload_php_fpm
  prune_old_releases

  ok "${APP_NAME} has been deployed successfully."
  print_summary
}

main "$@"
