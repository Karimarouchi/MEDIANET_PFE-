#!/usr/bin/env bash
# =============================================================================
# run_compliance_scans.sh — Idée 2 : OpenSCAP CIS/NIST/PCI compliance scan
# =============================================================================
#
# This script runs oscap xccdf eval against the local machine (container)
# using the SCAP Security Guide (SSG) for the detected OS.
#
# Supported COMPLIANCE_PROFILE values:
#   CIS_L1         → CIS Level 1 server benchmark (recommended defaults)
#   CIS_L2         → CIS Level 2 server benchmark (strict)
#   NIST_800-53    → NIST SP 800-53 (low baseline)
#   PCI_DSS        → PCI DSS v3.2 profile
#
# Output files written to RESULTS_DIR:
#   openscap-results.xml   — Full XCCDF result XML (parsed by Spring Boot)
#   openscap-report.html   — Human-readable HTML report
#   compliance_profile.txt — Profile name written for backend metadata read
#
# =============================================================================

# Guard: only source once
[ "${_RUN_COMPLIANCE_SCANS_SH:-}" = "1" ] && return 0
_RUN_COMPLIANCE_SCANS_SH=1

run_compliance_scan() {
  local compliance_profile="${1:-}"
  local results_dir="${2:-${RESULTS_DIR:-/workspace/results}}"

  if [ -z "${compliance_profile}" ]; then
    log "[COMPLIANCE] No COMPLIANCE_PROFILE set — skipping OpenSCAP scan."
    return 0
  fi

  log "[COMPLIANCE] Starting OpenSCAP compliance scan — profile: ${compliance_profile}"

  # ── Detect OpenSCAP availability ──────────────────────────────────────────
  if ! command -v oscap &>/dev/null; then
    log "[COMPLIANCE] WARNING: oscap not installed — skipping compliance scan."
    log "[COMPLIANCE] Install with: apt-get install -y openscap-scanner scap-security-guide"
    echo "${compliance_profile}" > "${results_dir}/compliance_profile.txt"
    echo '[]' > "${results_dir}/openscap-results.xml" 2>/dev/null || true
    return 0
  fi

  # ── Detect SSG XCCDF guide path ───────────────────────────────────────────
  # Standard locations for scap-security-guide on Debian/Ubuntu (Kali base)
  local ssg_base=""
  for candidate in \
    /usr/share/xml/scap/ssg/content \
    /usr/share/scap-security-guide \
    /usr/share/ssg; do
    if [ -d "${candidate}" ]; then
      ssg_base="${candidate}"
      break
    fi
  done

  if [ -z "${ssg_base}" ]; then
    log "[COMPLIANCE] WARNING: SCAP Security Guide not found — skipping compliance scan."
    log "[COMPLIANCE] Install with: apt-get install -y scap-security-guide"
    echo "${compliance_profile}" > "${results_dir}/compliance_profile.txt"
    return 0
  fi

  # ── Select XCCDF guide for Debian/Ubuntu (closest to Kali) ───────────────
  # SSG ships per-distro files; we use Debian as the closest match for Kali Linux
  local xccdf_guide=""
  for candidate in \
    "${ssg_base}/ssg-debian12-xccdf.xml" \
    "${ssg_base}/ssg-debian11-xccdf.xml" \
    "${ssg_base}/ssg-debian10-xccdf.xml" \
    "${ssg_base}/ssg-ubuntu2204-xccdf.xml" \
    "${ssg_base}/ssg-ubuntu2004-xccdf.xml" \
    "${ssg_base}/ssg-ubuntu1804-xccdf.xml"; do
    if [ -f "${candidate}" ]; then
      xccdf_guide="${candidate}"
      break
    fi
  done

  if [ -z "${xccdf_guide}" ]; then
    log "[COMPLIANCE] WARNING: No suitable XCCDF guide found in ${ssg_base} — skipping."
    echo "${compliance_profile}" > "${results_dir}/compliance_profile.txt"
    return 0
  fi

  log "[COMPLIANCE] Using XCCDF guide: ${xccdf_guide}"

  # ── Map profile name → XCCDF profile ID ──────────────────────────────────
  local xccdf_profile_id=""
  case "${compliance_profile}" in
    CIS_L1)
      xccdf_profile_id="xccdf_org.ssgproject.content_profile_cis_server_l1"
      ;;
    CIS_L2)
      xccdf_profile_id="xccdf_org.ssgproject.content_profile_cis"
      ;;
    NIST_800-53)
      xccdf_profile_id="xccdf_org.ssgproject.content_profile_ospp"
      ;;
    PCI_DSS)
      xccdf_profile_id="xccdf_org.ssgproject.content_profile_pci-dss"
      ;;
    *)
      # Treat as a raw XCCDF profile ID (advanced usage)
      xccdf_profile_id="${compliance_profile}"
      ;;
  esac

  log "[COMPLIANCE] Using XCCDF profile ID: ${xccdf_profile_id}"

  # ── Verify profile exists in guide ───────────────────────────────────────
  if ! oscap info "${xccdf_guide}" 2>/dev/null | grep -q "${xccdf_profile_id}"; then
    log "[COMPLIANCE] WARNING: Profile '${xccdf_profile_id}' not found in ${xccdf_guide}"
    log "[COMPLIANCE] Available profiles:"
    oscap info "${xccdf_guide}" 2>/dev/null | grep "Id:" | head -20 | sed 's/^/[COMPLIANCE]   /'
    log "[COMPLIANCE] Skipping compliance scan."
    echo "${compliance_profile}" > "${results_dir}/compliance_profile.txt"
    return 0
  fi

  # ── Run oscap evaluation ──────────────────────────────────────────────────
  local xml_out="${results_dir}/openscap-results.xml"
  local html_out="${results_dir}/openscap-report.html"

  log "[COMPLIANCE] Running oscap xccdf eval — this may take 1-3 minutes..."

  oscap xccdf eval \
    --profile "${xccdf_profile_id}" \
    --results "${xml_out}" \
    --report  "${html_out}" \
    "${xccdf_guide}" \
    >> "${results_dir}/openscap.log" 2>&1 || true
  # oscap exits with non-zero when rules fail — that is expected, use || true

  # ── Save profile metadata for backend ────────────────────────────────────
  echo "${compliance_profile}" > "${results_dir}/compliance_profile.txt"

  # ── Log summary ──────────────────────────────────────────────────────────
  if [ -f "${xml_out}" ] && [ -s "${xml_out}" ]; then
    local pass_count fail_count
    pass_count=$(grep -c '<result>pass</result>' "${xml_out}" 2>/dev/null || echo "0")
    fail_count=$(grep -c '<result>fail</result>' "${xml_out}" 2>/dev/null || echo "0")
    log "[COMPLIANCE] Results: ${pass_count} PASS / ${fail_count} FAIL"
    log "[COMPLIANCE] XML result: ${xml_out}"
    log "[COMPLIANCE] HTML report: ${html_out}"
    record_file_if_exists "${xml_out}"
    record_file_if_exists "${html_out}"
    record_file_if_exists "${results_dir}/compliance_profile.txt"
    record_file_if_exists "${results_dir}/openscap.log"
  else
    log "[COMPLIANCE] WARNING: openscap-results.xml is empty or missing after scan."
  fi

  record_tool "openscap"
  log "[COMPLIANCE] OpenSCAP compliance scan complete."
}
