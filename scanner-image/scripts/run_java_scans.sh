#!/usr/bin/env bash

run_java_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running Java scans"

  # ── OWASP Dependency-Check ────────────────────────────────────
  if find "${repo_dir}" -maxdepth 4 \( -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" \) | grep -q .; then
    DC_DATA_DIR="/root/.dependency-check/data"
    DC_INIT_DIR="/opt/dc-data-init"

    # On first run the mounted volume is empty. Copy the NVD database pre-built
    # into the image at /opt/dc-data-init so we can run offline immediately.
    if [ ! -d "${DC_DATA_DIR}" ] || [ -z "$(ls -A "${DC_DATA_DIR}" 2>/dev/null)" ]; then
      if [ -d "${DC_INIT_DIR}" ] && [ "$(ls -A "${DC_INIT_DIR}" 2>/dev/null)" ]; then
        log "  dependency-check — first run: copying NVD database from image cache..."
        mkdir -p "${DC_DATA_DIR}"
        cp -r "${DC_INIT_DIR}/." "${DC_DATA_DIR}/"
        log "  dependency-check — NVD database ready (offline mode)"
      else
        log "  dependency-check SKIPPED — NVD database not available (rebuild image to pre-populate)."
        echo '{"warning":"NVD database not initialized. Rebuild the scanner image to fix."}' \
          > "${results_dir}/dependency-check-report.json"
        echo '[]' > "${results_dir}/dependency-check-cve-summary.json"
        record_tool "dependency-check"
        record_file_if_exists "${results_dir}/dependency-check-report.json"
        return
      fi
    fi

    log "  dependency-check (this may take several minutes)..."
    run_with_timeout 600 \
      dependency-check.sh \
        --scan "${repo_dir}" \
        --format JSON \
        --out "${results_dir}" \
        --noupdate \
        --data "${DC_DATA_DIR}" \
      > "${results_dir}/dependency-check.log" 2>&1 || true

    extract_cve_summary_depcheck \
      "${results_dir}/dependency-check-report.json" \
      "${results_dir}/dependency-check-cve-summary.json"
    record_file_if_exists "${results_dir}/dependency-check-cve-summary.json"
  else
    log "  dependency-check skipped (no pom.xml / build.gradle)"
    echo '{"warning":"No pom.xml/build.gradle found; dependency-check skipped"}' \
      > "${results_dir}/dependency-check-report.json"
  fi

  record_tool "dependency-check"
  record_file_if_exists "${results_dir}/dependency-check-report.json"
  record_file_if_exists "${results_dir}/dependency-check.log"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVEs from dependency-check JSON → cve-summary.json
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_depcheck() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  local count
  count=$(jq '[.dependencies[]? | select(.vulnerabilities != null) | .vulnerabilities[]] | length' \
    "${input_file}" 2>/dev/null || echo "0")

  if [ "${count}" -eq 0 ]; then
    echo '[]' > "${output_file}"
    log "    dependency-check: 0 CVEs found"
    return
  fi

  jq '[
    .dependencies[] |
    select(.vulnerabilities != null) |
    .fileName as $pkg |
    .vulnerabilities[] |
    {
      cveId:          (.name // "UNKNOWN"),
      packageName:    $pkg,
      packageVersion: "unknown",
      severity:       (.severity // "UNKNOWN" | ascii_upcase),
      cvssScore:      (.cvssv3.baseScore // .cvssv2.score // null),
      fixedVersion:   "no fix available",
      description:    (.description // ""),
      dataSource:     ("https://nvd.nist.gov/vuln/detail/" + (.name // "")),
      source:         "dependency-check"
    }
  ] | sort_by(
        if   .severity == "CRITICAL" then 0
        elif .severity == "HIGH"     then 1
        elif .severity == "MEDIUM"   then 2
        else 3 end
      )' "${input_file}" > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    dependency-check: ${found} CVEs found"
}