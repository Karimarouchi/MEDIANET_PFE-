#!/usr/bin/env bash

run_node_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running Node.js scans"

  # ── npm audit ────────────────────────────────────────────────
  local lock_file
  lock_file=$(find "${repo_dir}" -maxdepth 4 \( -name "package-lock.json" -o -name "npm-shrinkwrap.json" \) | head -1)
  if [ -n "${lock_file}" ]; then
    local lock_dir
    lock_dir="$(dirname "${lock_file}")"
    log "  npm audit (in ${lock_dir})..."
    (
      cd "${lock_dir}" && npm audit --json > "${results_dir}/npm-audit.json"
    ) 2> "${results_dir}/npm-audit.log" || true
    extract_cve_summary_npm "${results_dir}/npm-audit.json" "${results_dir}/npm-audit-cve-summary.json"
    record_file_if_exists "${results_dir}/npm-audit-cve-summary.json"
  else
    log "  npm audit skipped (no package-lock.json)"
    echo '{"warning":"package-lock.json or npm-shrinkwrap.json not found; npm audit skipped"}' \
      > "${results_dir}/npm-audit.json"
  fi

  record_tool "npm-audit"
  record_file_if_exists "${results_dir}/npm-audit.json"
  record_file_if_exists "${results_dir}/npm-audit.log"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVEs from npm audit JSON → npm-audit-cve-summary.json
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_npm() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  # npm audit v7+ format
  local count
  count=$(jq '.vulnerabilities | length' "${input_file}" 2>/dev/null || echo "0")

  if [ "${count}" -eq 0 ]; then
    echo '[]' > "${output_file}"
    log "    npm audit: 0 vulnerabilities found"
    return
  fi

  jq '[
    .vulnerabilities | to_entries[] |
    .key as $pkg |
    .value |
    {
      cveId:          (.via[]? | select(type=="object") | .url // "N/A" | gsub(".*/"; "CVE-") | if startswith("CVE-") then . else "N/A" end) // "N/A",
      packageName:    $pkg,
      packageVersion: (.nodes[0]? // "unknown"),
      severity:       (.severity | ascii_upcase),
      fixedVersion:   (.fixAvailable.version // "no fix available"),
      description:    ((.via[]? | select(type=="object") | .title) // ""),
      dataSource:     ((.via[]? | select(type=="object") | .url) // ""),
      source:         "npm-audit"
    }
  ] | sort_by(.severity) | reverse' "${input_file}" > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    npm audit: ${found} vulnerabilities found"
}