#!/usr/bin/env bash

run_go_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running Go scans"

  # ── govulncheck ───────────────────────────────────────────────
  if [ -f "${repo_dir}/go.mod" ]; then
    log "  govulncheck..."
    (
      cd "${repo_dir}" && govulncheck -json ./... \
        > "${results_dir}/govulncheck.json"
    ) 2> "${results_dir}/govulncheck.log" || true

    extract_cve_summary_govulncheck \
      "${results_dir}/govulncheck.json" \
      "${results_dir}/govulncheck-cve-summary.json"
    record_file_if_exists "${results_dir}/govulncheck-cve-summary.json"
  else
    log "  govulncheck skipped (no go.mod)"
    echo '{"warning":"go.mod not found; govulncheck skipped"}' \
      > "${results_dir}/govulncheck.json"
  fi

  record_tool "govulncheck"
  record_file_if_exists "${results_dir}/govulncheck.json"
  record_file_if_exists "${results_dir}/govulncheck.log"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVEs from govulncheck JSON → govulncheck-cve-summary.json
# govulncheck outputs multiple JSON objects (one per line), not an array
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_govulncheck() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  # govulncheck emits one JSON object per line — collect vuln entries
  jq -s '[
    .[] |
    select(.finding != null) |
    .finding |
    {
      cveId:          (.osv // "UNKNOWN"),
      packageName:    (.trace[0]?.module // "unknown"),
      packageVersion: (.trace[0]?.version // "unknown"),
      severity:       "HIGH",
      cvssScore:      null,
      fixedVersion:   (.fixed_version // "no fix available"),
      description:    "",
      dataSource:     ("https://osv.dev/vulnerability/" + (.osv // "")),
      source:         "govulncheck"
    }
  ] | unique_by(.cveId + "|" + .packageName)' "${input_file}" \
    > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    govulncheck: ${found} vulnerabilities found"
}