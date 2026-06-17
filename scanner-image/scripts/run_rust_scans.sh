#!/usr/bin/env bash

run_rust_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running Rust scans"

  # ── cargo audit ───────────────────────────────────────────────
  if [ -f "${repo_dir}/Cargo.toml" ]; then
    log "  cargo audit..."
    (
      cd "${repo_dir}" && cargo audit --json \
        > "${results_dir}/cargo-audit.json"
    ) 2> "${results_dir}/cargo-audit.log" || true

    extract_cve_summary_cargo \
      "${results_dir}/cargo-audit.json" \
      "${results_dir}/cargo-audit-cve-summary.json"
    record_file_if_exists "${results_dir}/cargo-audit-cve-summary.json"
  else
    log "  cargo audit skipped (no Cargo.toml)"
    echo '{"warning":"Cargo.toml not found; cargo audit skipped"}' \
      > "${results_dir}/cargo-audit.json"
  fi

  record_tool "cargo-audit"
  record_file_if_exists "${results_dir}/cargo-audit.json"
  record_file_if_exists "${results_dir}/cargo-audit.log"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVEs from cargo audit JSON → cargo-audit-cve-summary.json
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_cargo() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  local count
  count=$(jq '.vulnerabilities.list | length' "${input_file}" 2>/dev/null || echo "0")

  if [ "${count}" -eq 0 ]; then
    echo '[]' > "${output_file}"
    log "    cargo audit: 0 vulnerabilities found"
    return
  fi

  jq '[
    .vulnerabilities.list[] |
    {
      cveId:          (.advisory.id // "UNKNOWN"),
      packageName:    (.package.name // "unknown"),
      packageVersion: (.package.version // "unknown"),
      severity:       (
                        if   (.advisory.cvss != null and (.advisory.cvss | tonumber? // 0) >= 9.0) then "CRITICAL"
                        elif (.advisory.cvss != null and (.advisory.cvss | tonumber? // 0) >= 7.0) then "HIGH"
                        elif (.advisory.cvss != null and (.advisory.cvss | tonumber? // 0) >= 4.0) then "MEDIUM"
                        else "LOW" end
                      ),
      cvssScore:      (.advisory.cvss // null),
      fixedVersion:   (.versions.patched[0] // "no fix available"),
      description:    (.advisory.description // ""),
      dataSource:     (.advisory.url // ""),
      source:         "cargo-audit"
    }
  ]' "${input_file}" > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    cargo audit: ${found} vulnerabilities found"
}