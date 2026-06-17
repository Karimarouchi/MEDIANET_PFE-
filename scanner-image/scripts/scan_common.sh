#!/usr/bin/env bash
# =============================================================================
# scan_common.sh — Helpers robustes pour les scripts de scan défensif Vulnix
# À sourcer AVANT les modules run_*_scans.sh
# =============================================================================

# Ne pas activer `set -e`: beaucoup de scanners retournent !=0 quand ils trouvent
# des vulnérabilités. On contrôle les erreurs outil par outil.
set -o pipefail

: "${RESULTS_DIR:=/workspace/results}"
: "${SCAN_TIMEOUT_DEFAULT:=600}"
: "${SCAN_DEBUG:=false}"

mkdir -p "${RESULTS_DIR}" 2>/dev/null || true

log() {
  printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

json_escape() {
  if command -v jq >/dev/null 2>&1; then
    jq -Rn --arg v "$1" '$v'
  else
    printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  fi
}

write_json_warning() {
  local file="$1"
  local msg="$2"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  if command -v jq >/dev/null 2>&1; then
    jq -n --arg warning "$msg" '{warning:$warning}' > "$file" 2>/dev/null || true
  fi
  if [ ! -s "$file" ]; then
    printf '{"warning":%s}\n' "$(json_escape "$msg")" > "$file"
  fi
}

write_json_array_empty() {
  local file="$1"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  printf '[]\n' > "$file"
}

write_json_object_empty() {
  local file="$1"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  printf '{}\n' > "$file"
}

require_tool() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1
}

skip_if_missing() {
  # Retourne 0 si l'outil est absent, 1 s'il est présent.
  local tool="$1"
  local output_file="${2:-}"
  local message="${3:-$tool is not installed; scan skipped}"
  if ! require_tool "$tool"; then
    log "[WARN] ${message}"
    [ -n "$output_file" ] && write_json_warning "$output_file" "$message"
    return 0
  fi
  return 1
}

run_with_timeout() {
  local seconds="${1:-${SCAN_TIMEOUT_DEFAULT}}"
  shift || return 1
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
    local code=$?
    if [ "$code" -eq 124 ]; then
      log "[TIMEOUT] $* killed after ${seconds}s"
    fi
    return "$code"
  fi
  "$@"
}

record_tool() {
  local tool="$1"
  local file="${TOOLS_EXECUTED_FILE:-${RESULTS_DIR}/tools_executed.txt}"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  printf '%s\n' "$tool" >> "$file" 2>/dev/null || true
  sort -u "$file" -o "$file" 2>/dev/null || true
}

record_file_if_exists() {
  local f="$1"
  [ -f "$f" ] || return 0
  local file="${GENERATED_FILES_FILE:-${RESULTS_DIR}/generated_files.txt}"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  printf '%s\n' "$(basename "$f")" >> "$file" 2>/dev/null || true
  sort -u "$file" -o "$file" 2>/dev/null || true
}

validate_json_or_replace() {
  local file="$1"
  local fallback="${2:-[]}"
  if [ ! -s "$file" ]; then
    printf '%s\n' "$fallback" > "$file"
    return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    jq empty "$file" >/dev/null 2>&1 || printf '%s\n' "$fallback" > "$file"
  fi
}

is_valid_http_url() {
  local url="$1"
  case "$url" in
    http://*|https://*) ;;
    *) return 1 ;;
  esac
  # Refuse caractères de contrôle, espaces, backticks et shell metachar dangereux.
  case "$url" in
    *[[:space:]]*|*[\`]*|*[\<\>]*|*[\{\\\}]*|*[\|]*|*[\^]*) return 1 ;;
  esac
  return 0
}

normalize_host_port() {
  # Retourne "host port". Accepte example.com, example.com:8443, https://example.com:8443/path
  local input="$1"
  input="${input#http://}"
  input="${input#https://}"
  input="${input%%/*}"
  local host="${input%%:*}"
  local port="${input##*:}"
  [ "$port" = "$input" ] && port="443"
  printf '%s %s\n' "$host" "$port"
}

is_valid_host_port() {
  local input="$1"
  local hp host port
  hp="$(normalize_host_port "$input")" || return 1
  host="${hp% *}"
  port="${hp#* }"
  [ -n "$host" ] || return 1
  [[ "$host" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

safe_jq_array_from_file() {
  local file="$1"
  if [ -f "$file" ] && command -v jq >/dev/null 2>&1; then
    jq -R . < "$file" | jq -s .
  else
    printf '[]'
  fi
}

severity_rank_jq='def sev_rank:
  if . == "CRITICAL" then 4
  elif . == "HIGH" then 3
  elif . == "MEDIUM" then 2
  elif . == "LOW" then 1
  else 0 end;'
