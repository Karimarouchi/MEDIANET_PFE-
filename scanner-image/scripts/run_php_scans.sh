#!/usr/bin/env bash

run_php_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running PHP scans"

  # ── composer audit ────────────────────────────────────────────
  if [ -f "${repo_dir}/composer.lock" ] || [ -f "${repo_dir}/composer.json" ]; then
    log "  composer audit..."
    (
      cd "${repo_dir}" && composer audit --format=json \
        > "${results_dir}/composer-audit.json"
    ) 2> "${results_dir}/composer-audit.log" || true

    extract_cve_summary_composer \
      "${results_dir}/composer-audit.json" \
      "${results_dir}/composer-audit-cve-summary.json"
    record_file_if_exists "${results_dir}/composer-audit-cve-summary.json"
  else
    log "  composer audit skipped (no composer.json / composer.lock)"
    echo '{"warning":"composer.json/composer.lock not found; composer audit skipped"}' \
      > "${results_dir}/composer-audit.json"
  fi

  record_tool "composer-audit"
  record_file_if_exists "${results_dir}/composer-audit.json"
  record_file_if_exists "${results_dir}/composer-audit.log"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVEs from composer audit JSON → composer-audit-cve-summary.json
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_composer() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  local count
  count=$(jq '.advisories | length' "${input_file}" 2>/dev/null || echo "0")

  if [ "${count}" -eq 0 ]; then
    echo '[]' > "${output_file}"
    log "    composer audit: 0 vulnerabilities found"
    return
  fi

  # composer audit format: {"advisories":{"package/name":[{...}]}}
  jq '[
    .advisories | to_entries[] |
    .key as $pkg |
    .value[] |
    {
      cveId:          (.cve // .advisoryId // "UNKNOWN"),
      packageName:    $pkg,
      packageVersion: (.affectedVersions // "unknown"),
      severity:       "UNKNOWN",
      cvssScore:      null,
      fixedVersion:   (.affectedVersions // "no fix available"),
      description:    (.title // ""),
      dataSource:     (.link // ""),
      source:         "composer-audit"
    }
  ]' "${input_file}" > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    composer audit: ${found} vulnerabilities found"
}