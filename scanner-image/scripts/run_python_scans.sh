#!/usr/bin/env bash

run_python_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running Python scans"

  # ── pip-audit ─────────────────────────────────────────────────
  log "  pip-audit..."

  if [ -f "${repo_dir}/requirements.txt" ]; then
    (
      cd "${repo_dir}" && pip-audit \
        --requirement requirements.txt \
        --format json \
        --output "${results_dir}/pip-audit.json"
    ) 2> "${results_dir}/pip-audit.log" || true

  elif [ -f "${repo_dir}/pyproject.toml" ]; then
    (
      cd "${repo_dir}" && pip-audit \
        --format json \
        --output "${results_dir}/pip-audit.json"
    ) 2> "${results_dir}/pip-audit.log" || true

  elif [ -f "${repo_dir}/Pipfile" ]; then
    (
      cd "${repo_dir}" && pip-audit \
        --format json \
        --output "${results_dir}/pip-audit.json"
    ) 2> "${results_dir}/pip-audit.log" || true

  else
    log "  pip-audit skipped (no requirements.txt / pyproject.toml / Pipfile)"
    echo '{"warning":"no Python requirements file found; pip-audit skipped"}' \
      > "${results_dir}/pip-audit.json"
  fi

  record_tool "pip-audit"
  record_file_if_exists "${results_dir}/pip-audit.json"
  record_file_if_exists "${results_dir}/pip-audit.log"

  # Extract CVE summary
  extract_cve_summary_pip "${results_dir}/pip-audit.json" "${results_dir}/pip-audit-cve-summary.json"
  record_file_if_exists "${results_dir}/pip-audit-cve-summary.json"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVEs from pip-audit JSON → pip-audit-cve-summary.json
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_pip() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  # pip-audit returns: {"dependencies":[{"name","version","vulns":[{"id","fix_versions","aliases","description"}]}]}
  local count
  count=$(jq '[.dependencies[]?.vulns[]?] | length' "${input_file}" 2>/dev/null || echo "0")

  if [ "${count}" -eq 0 ]; then
    echo '[]' > "${output_file}"
    log "    pip-audit: 0 vulnerabilities found"
    return
  fi

  jq '[
    .dependencies[] |
    .name as $pkg |
    .version as $ver |
    .vulns[]? |
    {
      cveId:          (
                        (.aliases[]? | select(startswith("CVE-")))
                        // .id
                        // "UNKNOWN"
                      ),
      packageName:    $pkg,
      packageVersion: $ver,
      severity:       "UNKNOWN",
      cvssScore:      null,
      fixedVersion:   (.fix_versions[0] // "no fix available"),
      description:    (.description // ""),
      dataSource:     ("https://osv.dev/vulnerability/" + (.id // "")),
      source:         "pip-audit"
    }
  ] | sort_by(.cveId)' "${input_file}" > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    pip-audit: ${found} vulnerabilities found"
}