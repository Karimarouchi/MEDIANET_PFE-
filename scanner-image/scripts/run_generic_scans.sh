#!/usr/bin/env bash

run_generic_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running generic scans"

  # ── Gitleaks — secret detection ──────────────────────────────
  log "  [1/6] gitleaks — secret scanning..."
  gitleaks detect \
    --source "${repo_dir}" \
    --report-format json \
    --report-path "${results_dir}/gitleaks.json" \
    --no-git \
    > "${results_dir}/gitleaks.log" 2>&1 || true
  record_tool "gitleaks"
  record_file_if_exists "${results_dir}/gitleaks.json"
  record_file_if_exists "${results_dir}/gitleaks.log"

  # ── TruffleHog — entropy-based secret detection ──────────────
  log "  [1b/6] trufflehog — entropy-based secret scanning..."
  if command -v trufflehog >/dev/null 2>&1; then
    trufflehog filesystem "${repo_dir}" \
      --json \
      --no-update \
      --no-verification \
      > "${results_dir}/trufflehog.json" \
      2> "${results_dir}/trufflehog.log" || true
    if [ -s "${results_dir}/trufflehog.json" ]; then
      local trufflehog_count
      trufflehog_count=$(grep -c '"SourceMetadata"' "${results_dir}/trufflehog.json" 2>/dev/null || echo "0")
      log "  [INFO] TruffleHog — ${trufflehog_count} secret(s) found"
      record_tool "trufflehog"
      record_file_if_exists "${results_dir}/trufflehog.json"
    else
      log "  [INFO] TruffleHog — no secrets found"
    fi
    record_file_if_exists "${results_dir}/trufflehog.log"
  else
    log "  [WARN] trufflehog not installed — skipping"
  fi

  # ── Semgrep — static code analysis ──────────────────────────
  log "  [2/6] semgrep — static analysis..."
  semgrep scan \
    --config auto \
    "${repo_dir}" \
    --json \
    --output "${results_dir}/semgrep.json" \
    > "${results_dir}/semgrep.log" 2>&1 || true
  record_tool "semgrep"
  record_file_if_exists "${results_dir}/semgrep.json"
  record_file_if_exists "${results_dir}/semgrep.log"

  # ── Semgrep OWASP Top 10 — targeted security rules ──────────
  log "  [2b/6] semgrep — OWASP Top 10 rules..."
  semgrep scan \
    --config "p/owasp-top-ten" \
    "${repo_dir}" \
    --json \
    --output "${results_dir}/semgrep-owasp.json" \
    > "${results_dir}/semgrep-owasp.log" 2>&1 || true
  record_tool "semgrep-owasp"
  record_file_if_exists "${results_dir}/semgrep-owasp.json"
  record_file_if_exists "${results_dir}/semgrep-owasp.log"

  # ── Syft — SBOM generation ───────────────────────────────────
  log "  [3/6] syft — SBOM generation..."
  SYFT_PACKAGES_JAVA_ARCHIVE_USE_NETWORK=true \
  SYFT_PACKAGES_JAVA_ARCHIVE_MAX_PARENT_RECURSIVE_DEPTH=5 \
    syft dir:"${repo_dir}" -o json \
      > "${results_dir}/sbom.json" \
      2> "${results_dir}/syft.log" || true
  record_tool "syft"
  record_file_if_exists "${results_dir}/sbom.json"
  record_file_if_exists "${results_dir}/syft.log"

  # ── Maven CycloneDX SBOM — proper Java BOM version resolution ─
  # Trivy/Syft cannot resolve Spring Boot BOM-managed versions from pom.xml source.
  # The Maven CycloneDX plugin uses Maven's own resolver, giving full transitive
  # dependency trees with correct versions (e.g. postgresql@42.6.1 from BOM).
  # We use the repo's own Maven wrapper so no additional tools are needed.
  MAVEN_CYCLONEDX_SBOM="${results_dir}/maven-bom.cdx.json"
  POM_FILE=$(find "${repo_dir}" -maxdepth 5 -name "pom.xml" ! -path "*/target/*" | head -1)
  if [ -n "${POM_FILE}" ]; then
    POM_DIR=$(dirname "${POM_FILE}")
    MVNW="${POM_DIR}/mvnw"
    MAVEN_CMD=""
    if [ -f "${MVNW}" ]; then
      chmod +x "${MVNW}" 2>/dev/null || true
      MAVEN_CMD="${MVNW}"
    elif command -v mvn >/dev/null 2>&1; then
      MAVEN_CMD="mvn"
    fi

    if [ -n "${MAVEN_CMD}" ]; then
      log "  [3b] maven-cyclonedx — resolving Java dependencies via Maven BOM..."
      ( cd "${POM_DIR}" && \
        timeout 300 "${MAVEN_CMD}" \
          org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom \
          -DoutputFormat=json \
          -DoutputName=bom \
          -Dmaven.test.skip=true \
          --batch-mode \
          --no-transfer-progress \
          -q \
          > "${results_dir}/maven-cyclonedx.log" 2>&1 \
      ) || true
      if [ -f "${POM_DIR}/target/bom.json" ]; then
        cp "${POM_DIR}/target/bom.json" "${MAVEN_CYCLONEDX_SBOM}"
        MAVEN_PKG_COUNT=$(jq '.components | length' "${MAVEN_CYCLONEDX_SBOM}" 2>/dev/null || echo "0")
        log "  [3b] maven-cyclonedx — SBOM ready: ${MAVEN_PKG_COUNT} packages (BOM-resolved)"
      else
        log "  [3b] maven-cyclonedx — SBOM generation failed (see maven-cyclonedx.log)"
      fi
      record_file_if_exists "${MAVEN_CYCLONEDX_SBOM}"
      record_file_if_exists "${results_dir}/maven-cyclonedx.log"
    else
      log "  [3b] maven-cyclonedx — skipped (no mvnw or mvn found)"
    fi
  else
    log "  [3b] maven-cyclonedx — skipped (no pom.xml found)"
  fi

  # ── Trivy — CVE + secrets + misconfigurations ─────────────────
  log "  [4/6] trivy — CVE + secrets + misconfig scan..."
  trivy fs \
    --format json \
    --scanners vuln,secret,misconfig \
    -o "${results_dir}/trivy.json" \
    "${repo_dir}" \
    > "${results_dir}/trivy.log" 2>&1 || true
  record_tool "trivy"
  record_file_if_exists "${results_dir}/trivy.json"
  record_file_if_exists "${results_dir}/trivy.log"

  # Extract CVE summary from trivy results
  extract_cve_summary_trivy "${results_dir}/trivy.json" "${results_dir}/trivy-cve-summary.json"
  record_file_if_exists "${results_dir}/trivy-cve-summary.json"

  # Determine the best resolved SBOM for Grype + OSV-Scanner.
  # Priority: Maven CycloneDX (best for Java BOM) > Trivy-parsed > empty fallback.
  log "  [4b] resolving best SBOM source for vulnerability scans..."
  TRIVY_SBOM="${results_dir}/trivy-resolved-sbom.json"
  jq '{
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
      .Results[]? |
      .Packages[]? |
      select(.Version != null and .Version != "") |
      {
        "type": "library",
        "name": .Name,
        "version": .Version,
        "purl": (.Identifier.PURL // null)
      }
    ] | unique_by(.name + "|" + .version)
  }' "${results_dir}/trivy.json" > "${TRIVY_SBOM}" 2>/dev/null \
    || echo '{"bomFormat":"CycloneDX","specVersion":"1.4","version":1,"components":[]}' > "${TRIVY_SBOM}"
  TRIVY_PKG_COUNT=$(jq '.components | length' "${TRIVY_SBOM}" 2>/dev/null || echo "0")
  log "  [4b] trivy SBOM: ${TRIVY_PKG_COUNT} packages"
  record_file_if_exists "${TRIVY_SBOM}"

  # Choose the SBOM with the most packages (Maven wins if > Trivy)
  RESOLVED_SBOM="${TRIVY_SBOM}"
  if [ -f "${MAVEN_CYCLONEDX_SBOM}" ] && [ -s "${MAVEN_CYCLONEDX_SBOM}" ]; then
    MAVEN_PKG_COUNT=$(jq '.components | length' "${MAVEN_CYCLONEDX_SBOM}" 2>/dev/null || echo "0")
    if [ "${MAVEN_PKG_COUNT}" -gt "${TRIVY_PKG_COUNT}" ]; then
      RESOLVED_SBOM="${MAVEN_CYCLONEDX_SBOM}"
      log "  [4b] using Maven SBOM: ${MAVEN_PKG_COUNT} packages (more complete than Trivy's ${TRIVY_PKG_COUNT})"
    else
      log "  [4b] using Trivy SBOM: ${TRIVY_PKG_COUNT} packages (Maven had ${MAVEN_PKG_COUNT})"
    fi
  fi

  # ── Grype — CVE scan from resolved packages SBOM ─────────────
  log "  [5/6] grype — CVE vulnerability scan (resolved packages SBOM)..."
  GRYPE_DISTRO_FLAG=""
  if [ -n "${TARGET_OS:-}" ]; then
    GRYPE_DISTRO_FLAG="--distro ${TARGET_OS}"
    log "  [5/6] grype — using distro override: ${TARGET_OS}"
  fi
  GRYPE_INPUT="${RESOLVED_SBOM}"
  if [ ! -s "${GRYPE_INPUT}" ]; then
    GRYPE_INPUT="${results_dir}/sbom.json"
    log "  [5/6] grype — falling back to Syft SBOM"
  fi
  # shellcheck disable=SC2086
  grype sbom:"${GRYPE_INPUT}" ${GRYPE_DISTRO_FLAG} -o json \
    > "${results_dir}/grype.json" \
    2> "${results_dir}/grype.log" || true
  record_tool "grype"
  record_file_if_exists "${results_dir}/grype.json"
  record_file_if_exists "${results_dir}/grype.log"

  # Extract CVE summary from grype results
  extract_cve_summary_grype "${results_dir}/grype.json" "${results_dir}/grype-cve-summary.json"
  record_file_if_exists "${results_dir}/grype-cve-summary.json"

  # ── OSV-Scanner — SBOM scan ───────────────────────────────────
  log "  [6/6] osv-scanner — OSV database scan (CycloneDX SBOM)..."
  # Use '--sbom' flag with a .cdx.json file (OSV-Scanner auto-detects CycloneDX
  # from the extension). The Maven SBOM is named maven-bom.cdx.json which satisfies
  # the spec naming requirement. Fall back to source scan if no SBOM available.
  if [ -s "${RESOLVED_SBOM}" ]; then
    osv-scanner scan source \
      --sbom "${RESOLVED_SBOM}" \
      --format json \
      > "${results_dir}/osv-scanner.json" \
      2> "${results_dir}/osv-scanner.log" || true
  else
    # Fallback: source scan with --no-resolve
    osv-scanner scan source -r "${repo_dir}" \
      --no-resolve \
      --allow-no-lockfiles \
      --format json \
      > "${results_dir}/osv-scanner.json" \
      2> "${results_dir}/osv-scanner.log" || true
  fi
  record_tool "osv-scanner"
  record_file_if_exists "${results_dir}/osv-scanner.json"
  record_file_if_exists "${results_dir}/osv-scanner.log"

  # ── Consolidated CVE list (all tools merged) ─────────────────
  merge_all_cves "${results_dir}"

  # ── Outdated dependency report from SBOM ─────────────────────
  log "  [+] Generating dependency inventory report..."
  generate_dependency_report "${results_dir}"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVE list from grype.json → grype-cve-summary.json
# Format: [{cveId, packageName, packageVersion, severity, fixedVersion, source}]
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_grype() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  # Check if there are any matches at all
  local match_count
  match_count=$(jq '.matches | length' "${input_file}" 2>/dev/null || echo "0")

  if [ "${match_count}" -eq 0 ]; then
    echo '[]' > "${output_file}"
    log "    grype: 0 CVEs found"
    return
  fi

  jq '[
    .matches[] |
    {
      cveId:          (.vulnerability.id // "UNKNOWN"),
      packageName:    (.artifact.name // "unknown"),
      packageVersion: (.artifact.version // "unknown"),
      severity:       (.vulnerability.severity // "UNKNOWN"),
      cvssScore:      (
                        (.vulnerability.cvss[]? | select(.version == "3.1") | .metrics.baseScore)
                        // (.vulnerability.cvss[0]?.metrics.baseScore)
                        // null
                      ),
      fixedVersion:   (
                        [.vulnerability.fix.versions[]?][0]
                        // "no fix available"
                      ),
      description:    (.vulnerability.description // ""),
      dataSource:     (.vulnerability.dataSource // ""),
      source:         "grype"
    }
  ] | sort_by(.severity) | reverse' "${input_file}" > "${output_file}" 2>/dev/null || echo '[]' > "${output_file}"

  local found_count
  found_count=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    grype: ${found_count} CVEs found"
}

# ─────────────────────────────────────────────────────────────────
# Extract CVE list from trivy.json → trivy-cve-summary.json
# ─────────────────────────────────────────────────────────────────
extract_cve_summary_trivy() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  local vuln_count
  vuln_count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "${input_file}" 2>/dev/null || echo "0")

  if [ "${vuln_count}" -eq 0 ]; then
    echo '[]' > "${output_file}"
    log "    trivy: 0 CVEs found"
    return
  fi

  jq '[
    .Results[]? |
    .Target as $target |
    .Vulnerabilities[]? |
    {
      cveId:          (.VulnerabilityID // "UNKNOWN"),
      packageName:    (.PkgName // "unknown"),
      packageVersion: (.InstalledVersion // "unknown"),
      severity:       (.Severity // "UNKNOWN"),
      cvssScore:      (
                        .CVSS?.nvd?.V3Score
                        // .CVSS?.nvd?.V2Score
                        // null
                      ),
      fixedVersion:   (.FixedVersion // "no fix available"),
      description:    (.Description // ""),
      dataSource:     (.PrimaryURL // ""),
      target:         $target,
      source:         "trivy"
    }
  ] | sort_by(.severity) | reverse' "${input_file}" > "${output_file}" 2>/dev/null || echo '[]' > "${output_file}"

  local found_count
  found_count=$(jq 'length' "${output_file}" 2>/dev/null || echo "?")
  log "    trivy: ${found_count} CVEs found"
}

# ─────────────────────────────────────────────────────────────────
# Merge all CVE sources into one unified file: all-cves.json
# This is the file Spring Boot will parse first.
# ─────────────────────────────────────────────────────────────────
merge_all_cves() {
  local results_dir="$1"
  local output_file="${results_dir}/all-cves.json"

  local grype_file="${results_dir}/grype-cve-summary.json"
  local trivy_file="${results_dir}/trivy-cve-summary.json"
  # Idée 1 — OSV-Scanner source included in merge (raw JSON parsed by Spring Boot separately,
  # but we also include normalized CVE-ID entries here for the merged badge count)
  local osv_file="${results_dir}/osv-scanner.json"

  # Start with empty arrays if files don't exist
  local grype_data="[]"
  local trivy_data="[]"
  local osv_data="[]"

  [ -f "${grype_file}" ] && grype_data=$(cat "${grype_file}")
  [ -f "${trivy_file}" ] && trivy_data=$(cat "${trivy_file}")

  # Extract CVE entries from OSV-Scanner raw JSON (normalize to same schema)
  if [ -f "${osv_file}" ] && [ -s "${osv_file}" ]; then
    osv_data=$(jq '[
      .results[]?.packages[]? |
      .package as $pkg |
      .vulnerabilities[]? |
      {
        cveId: (.id // "UNKNOWN"),
        packageName: ($pkg.name // "unknown"),
        packageVersion: ($pkg.version // ""),
        severity: (
          if (.severity[]?.score? // 0 | tonumber) >= 9.0 then "CRITICAL"
          elif (.severity[]?.score? // 0 | tonumber) >= 7.0 then "HIGH"
          elif (.severity[]?.score? // 0 | tonumber) >= 4.0 then "MEDIUM"
          else "LOW"
          end
        ),
        cvssScore: (.severity[]?.score? // null),
        fixedVersion: "",
        description: (.summary // ""),
        dataSource: "osv",
        source: "osv-scanner"
      }
    ] // []' "${osv_file}" 2>/dev/null || echo "[]")
  fi

  # Merge and deduplicate by cveId + packageName — keep all sources
  jq -n \
    --argjson grype "${grype_data}" \
    --argjson trivy "${trivy_data}" \
    --argjson osv   "${osv_data}" \
    '
    ($grype + $trivy + $osv)
    | group_by(.cveId + "|" + .packageName)
    | map(
        {
          cveId:          .[0].cveId,
          packageName:    .[0].packageName,
          packageVersion: .[0].packageVersion,
          severity:       .[0].severity,
          cvssScore:      .[0].cvssScore,
          fixedVersion:   .[0].fixedVersion,
          description:    (map(.description) | map(select(. != "" and . != null)) | first // ""),
          dataSource:     .[0].dataSource,
          source:         (map(.source) | unique | join(",")),
          sources:        (map(.source) | unique),
          confirmedBy:    (map(.source) | unique | length)
        }
      )
    | sort_by(
        if .severity == "CRITICAL" then 0
        elif .severity == "HIGH" then 1
        elif .severity == "MEDIUM" then 2
        elif .severity == "LOW" then 3
        else 4 end
      )
    ' > "${output_file}" 2>/dev/null || echo '[]' > "${output_file}"

  local total
  total=$(jq 'length' "${output_file}" 2>/dev/null || echo "0")
  local critical
  critical=$(jq '[.[] | select(.severity=="CRITICAL")] | length' "${output_file}" 2>/dev/null || echo "0")
  local high
  high=$(jq '[.[] | select(.severity=="HIGH")] | length' "${output_file}" 2>/dev/null || echo "0")

  log "    === CVE TOTAL: ${total} (CRITICAL: ${critical}, HIGH: ${high}) ==="

  record_file_if_exists "${output_file}"
}

# ─────────────────────────────────────────────────────────────────
# Generate dependency inventory from SBOM
# Counts packages by type, lists direct/transitive if available
# ─────────────────────────────────────────────────────────────────
generate_dependency_report() {
  local results_dir="$1"
  local sbom_file="${results_dir}/sbom.json"
  local output_file="${results_dir}/dependency-report.json"

  if [ ! -f "${sbom_file}" ] || [ ! -s "${sbom_file}" ]; then
    echo '{"warning":"No SBOM available"}' > "${output_file}"
    record_file_if_exists "${output_file}"
    return
  fi

  jq '{
    totalPackages: ([.artifacts[]?] | length),
    byType: (
      [.artifacts[]? | .type // "unknown"] |
      group_by(.) | map({type: .[0], count: length}) | sort_by(-.count)
    ),
    byLanguage: (
      [.artifacts[]? | .language // "unknown"] |
      group_by(.) | map({language: .[0], count: length}) | sort_by(-.count)
    ),
    packages: [
      .artifacts[]? |
      {
        name:     .name,
        version:  .version,
        type:     .type,
        language: .language,
        licenses: [.licenses[]?.value? // empty]
      }
    ] | sort_by(.name)
  }' "${sbom_file}" > "${output_file}" 2>/dev/null \
    || echo '{"error":"Failed to generate dependency report"}' > "${output_file}"

  local pkg_count
  pkg_count=$(jq '.totalPackages' "${output_file}" 2>/dev/null || echo "0")
  log "    Dependency report: ${pkg_count} packages cataloged"

  record_file_if_exists "${output_file}"
}