#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Nuclei — Fast web vulnerability scanner (complements OWASP ZAP baseline)
# Called by scan.sh when DAST_TARGET_URL is provided.
# Safe mode: only exposure, misconfig, cves, tech tags — no intrusive/dos/fuzz.
# Produces: nuclei.jsonl, nuclei.log in $RESULTS_DIR
# ─────────────────────────────────────────────────────────────────────────────

run_nuclei_scans() {
  local results_dir="$1"
  local target_url="$2"

  if [ -z "${target_url}" ]; then
    log "[WARN] Nuclei: no target URL provided (DAST_TARGET_URL is empty), skipping."
    return 0
  fi

  # Basic URL sanity check — must start with http:// or https://
  if ! is_valid_http_url "${target_url}"; then
    log "[WARN] Nuclei: DAST_TARGET_URL='${target_url}' is not a valid http/https URL, skipping."
    write_json_warning "${results_dir}/nuclei.jsonl" "Invalid DAST_TARGET_URL"
    record_file_if_exists "${results_dir}/nuclei.jsonl"
    return 0
  fi

  if ! command -v nuclei >/dev/null 2>&1; then
    log "[WARN] Nuclei: binary not found, skipping."
    write_json_warning "${results_dir}/nuclei.jsonl" "nuclei not installed"
    record_file_if_exists "${results_dir}/nuclei.jsonl"
    return 0
  fi

  log "[SCAN] Nuclei — scanning: ${target_url}"
  log "[INFO] Detects: CVE web, Swagger/OpenAPI exposé, panels admin, backup files, HTTP misconfig, tech vulnérables, Git exposé"

  local nuclei_out="${results_dir}/nuclei.jsonl"
  local nuclei_log="${results_dir}/nuclei.log"
  local rate_limit="${NUCLEI_RATE_LIMIT:-5}"

  # Safe production flags:
  # -tags exposure,misconfig,cves,tech  → détection passive uniquement
  # -exclude-tags intrusive,dos,fuzz    → jamais d'attaque active
  # -no-interactsh                      → pas de callbacks vers serveurs externes
  # -rate-limit 5                       → max 5 req/s, respectueux de la cible
  timeout 600 nuclei \
    -u "${target_url}" \
    -severity low,medium,high,critical \
    -tags exposure,misconfig,cves,tech \
    -exclude-tags intrusive,dos,fuzz \
    -rate-limit "${rate_limit}" \
    -timeout 10 \
    -retries 1 \
    -jsonl \
    -o "${nuclei_out}" \
    -no-interactsh \
    -silent \
    > "${nuclei_log}" 2>&1 || true

  if [ -f "${nuclei_out}" ] && [ -s "${nuclei_out}" ]; then
    local finding_count
    finding_count=$(wc -l < "${nuclei_out}" 2>/dev/null || echo "0")
    log "[SUCCESS] Nuclei scan completed — ${finding_count} finding(s)"
    record_tool "nuclei"
    record_file_if_exists "${nuclei_out}"
  else
    log "[WARN] Nuclei: no findings or target unreachable — check ${nuclei_log}"
  fi
  record_file_if_exists "${nuclei_log}"
}
