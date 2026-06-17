#!/usr/bin/env bash

run_license_scan() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running license compliance scan"

  # ── Syft SBOM with license info ──────────────────────────────
  # syft is already run in generic scans for CVE, but here we extract licenses
  local sbom_file="${results_dir}/sbom.json"

  if [ ! -f "${sbom_file}" ]; then
    log "  Generating SBOM for license extraction..."
    syft dir:"${repo_dir}" -o json \
      > "${sbom_file}" \
      2> "${results_dir}/syft-license.log" || true
  fi

  if [ ! -f "${sbom_file}" ] || [ ! -s "${sbom_file}" ]; then
    log "  No SBOM available — skipping license scan"
    echo '{"warning":"No SBOM generated"}' > "${results_dir}/license-report.json"
    record_file_if_exists "${results_dir}/license-report.json"
    return 0
  fi

  # ── Extract license data from SBOM ───────────────────────────
  log "  Extracting license information from SBOM..."

  jq '{
    summary: {
      totalPackages:  [.artifacts[]?] | length,
      withLicense:    [.artifacts[]? | select(.licenses != null and (.licenses | length) > 0)] | length,
      noLicense:      [.artifacts[]? | select(.licenses == null or (.licenses | length) == 0)] | length
    },
    riskLicenses: [
      .artifacts[]? |
      select(.licenses != null) |
      .name as $pkg |
      .version as $ver |
      .licenses[]? |
      select(.value != null) |
      .value as $lic |
      select(
        ($lic | test("GPL-3|AGPL|SSPL|EUPL|OSL-3|RPSL|Sleepycat|Watcom"; "i"))
      ) |
      {
        package:      $pkg,
        version:      $ver,
        license:      $lic,
        risk:         "HIGH",
        reason:       "Copyleft / restrictive license — may require source disclosure"
      }
    ],
    copyleftWeakLicenses: [
      .artifacts[]? |
      select(.licenses != null) |
      .name as $pkg |
      .version as $ver |
      .licenses[]? |
      select(.value != null) |
      .value as $lic |
      select(
        ($lic | test("LGPL|MPL|EPL|CPL|CDDL"; "i"))
      ) |
      {
        package:      $pkg,
        version:      $ver,
        license:      $lic,
        risk:         "MEDIUM",
        reason:       "Weak copyleft — modifications to this library may need to be disclosed"
      }
    ],
    unknownLicenses: [
      .artifacts[]? |
      select(.licenses == null or (.licenses | length) == 0) |
      {
        package:  .name,
        version:  .version,
        risk:     "LOW",
        reason:   "No license detected — review manually"
      }
    ] | .[0:50],
    allLicenses: (
      [
        .artifacts[]? |
        select(.licenses != null) |
        .licenses[]? |
        .value // empty
      ] | group_by(.) | map({license: .[0], count: length}) | sort_by(-.count)
    )
  }' "${sbom_file}" > "${results_dir}/license-report.json" 2>/dev/null \
    || echo '{"error":"Failed to parse SBOM for licenses"}' > "${results_dir}/license-report.json"

  # Log summary
  local total risk_count
  total=$(jq '.summary.totalPackages' "${results_dir}/license-report.json" 2>/dev/null || echo "0")
  risk_count=$(jq '.riskLicenses | length' "${results_dir}/license-report.json" 2>/dev/null || echo "0")
  log "    License scan: ${total} packages analyzed, ${risk_count} high-risk licenses found"

  record_tool "license-scan"
  record_file_if_exists "${results_dir}/license-report.json"
}
