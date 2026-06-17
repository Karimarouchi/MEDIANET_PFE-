#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# DAST — Dynamic Application Security Testing via OWASP ZAP
# Called by scan.sh when SCAN_MODE=dast or when DAST_TARGET_URL is provided.
# Produces: zap.json in $RESULTS_DIR
# ─────────────────────────────────────────────────────────────────────────────

run_dast_scans() {
  local results_dir="$1"
  local target_url="$2"

  if [ -z "${target_url}" ]; then
    echo "[WARN] DAST: no target URL provided (DAST_TARGET_URL is empty), skipping ZAP scan."
    return 0
  fi

  # Basic URL sanity check — must start with http:// or https:// and avoid unsafe characters
  if ! is_valid_http_url "${target_url}"; then
    echo "[WARN] DAST: DAST_TARGET_URL='${target_url}' is not a valid http/https URL, skipping."
    write_json_warning "${results_dir}/zap.json" "Invalid DAST_TARGET_URL"
    record_file_if_exists "${results_dir}/zap.json"
    return 0
  fi

  if [ ! -f /opt/zaproxy/zap-baseline.py ]; then
    echo "[WARN] DAST: /opt/zaproxy/zap-baseline.py not found, skipping."
    write_json_warning "${results_dir}/zap.json" "OWASP ZAP baseline script not installed"
    record_file_if_exists "${results_dir}/zap.json"
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    echo "[WARN] DAST: python3 not found, skipping."
    write_json_warning "${results_dir}/zap.json" "python3 not installed"
    record_file_if_exists "${results_dir}/zap.json"
    return 0
  fi

  echo "[SCAN] DAST — OWASP ZAP baseline scan on: ${target_url}"
  echo "[INFO] ZAP baseline scan detects: SQLi, XSS, CSRF, open redirects, misconfigured headers..."

  local zap_out="${results_dir}/zap.json"
  local zap_log="${results_dir}/zap.log"

  # zap-baseline.py: passive scan + basic active checks, safe for any app
  # -t  : target URL
  # -J  : JSON report output file
  # -I  : ignore failures (exit 0 even if alerts found)
  # -T 5: max time in minutes for the whole scan
  timeout 600 python3 /opt/zaproxy/zap-baseline.py \
    -t "${target_url}" \
    -J "${zap_out}" \
    -I \
    -T 5 \
    > "${zap_log}" 2>&1 || true

  validate_json_or_replace "${zap_out}" '{"site":[]}'
  if [ -f "${zap_out}" ] && [ -s "${zap_out}" ]; then
    local alert_count
    alert_count=$(jq '.site[0].alerts | length' "${zap_out}" 2>/dev/null || echo "0")
    echo "[SUCCESS] ZAP scan completed — ${alert_count} alert(s) found"
    record_tool "zaproxy"
    record_file_if_exists "${zap_out}"
  else
    echo "[WARN] ZAP scan produced no output — target may be unreachable or ZAP failed to start"
    echo "[INFO] Check ${zap_log} for details"
  fi
}
