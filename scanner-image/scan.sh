#!/usr/bin/env bash
set -uo pipefail

# =============================================================================
# Vulnix robust scanner orchestrator
# =============================================================================

RESULTS_DIR="${RESULTS_DIR:-/workspace/results}"
REPO_DIR="${REPO_DIR:-/workspace/repo}"
SCAN_MODE="${SCAN_MODE:-auto}"
REPO_URL="${REPO_URL:-}"
REPO_CLONE_URL="${REPO_CLONE_URL:-${REPO_URL}}"
TARGET_DOMAIN="${TARGET_DOMAIN:-}"
DAST_TARGET_URL="${DAST_TARGET_URL:-}"
BRANCH="${BRANCH:-}"
DOCKER_IMAGE="${DOCKER_IMAGE:-}"
TARGET_OS="${TARGET_OS:-}"
COMPLIANCE_PROFILE="${COMPLIANCE_PROFILE:-}"

mkdir -p "${RESULTS_DIR}" /workspace/logs

TOOLS_EXECUTED_FILE="${RESULTS_DIR}/tools_executed.txt"
ECOSYSTEMS_FILE="${RESULTS_DIR}/ecosystems_detected.txt"
GENERATED_FILES_FILE="${RESULTS_DIR}/generated_files.txt"

: > "${TOOLS_EXECUTED_FILE}"
: > "${ECOSYSTEMS_FILE}"
: > "${GENERATED_FILES_FILE}"

SCAN_START_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCAN_START_EPOCH="$(date +%s)"
STATUS="completed"

# Common helpers first
if [ -f /opt/vulnix/scripts/scan_common.sh ]; then
  # shellcheck source=/dev/null
  source /opt/vulnix/scripts/scan_common.sh
else
  log() { printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
fi

load_module() {
  local module="$1"
  if [ -f "$module" ]; then
    # shellcheck source=/dev/null
    source "$module"
  else
    log "[WARN] Missing module: $module"
    STATUS="partial"
  fi
}

for module in \
  /opt/vulnix/scripts/detect_ecosystems.sh \
  /opt/vulnix/scripts/run_generic_scans.sh \
  /opt/vulnix/scripts/run_ssl_scans.sh \
  /opt/vulnix/scripts/run_node_scans.sh \
  /opt/vulnix/scripts/run_python_scans.sh \
  /opt/vulnix/scripts/run_php_scans.sh \
  /opt/vulnix/scripts/run_go_scans.sh \
  /opt/vulnix/scripts/run_rust_scans.sh \
  /opt/vulnix/scripts/run_java_scans.sh \
  /opt/vulnix/scripts/run_docker_scans.sh \
  /opt/vulnix/scripts/run_iac_scans.sh \
  /opt/vulnix/scripts/run_license_scan.sh \
  /opt/vulnix/scripts/run_dast_scans.sh \
  /opt/vulnix/scripts/run_nuclei_scans.sh \
  /opt/vulnix/scripts/run_docker_image_scans.sh \
  /opt/vulnix/scripts/run_compliance_scans.sh; do
  load_module "$module"
done

clone_repo() {
  if [ -z "${REPO_URL}" ]; then
    log "No REPO_URL provided, skipping repository clone."
    return 0
  fi

  case "${REPO_CLONE_URL}" in
    http://*|https://*|git@*|ssh://*) ;;
    *)
      log "Invalid REPO_CLONE_URL protocol. Allowed: http(s), git@, ssh."
      echo "Invalid REPO_CLONE_URL protocol" > "${RESULTS_DIR}/git_clone.log"
      record_file_if_exists "${RESULTS_DIR}/git_clone.log"
      return 1
      ;;
  esac

  rm -rf "${REPO_DIR}"

  if [ -n "${BRANCH}" ]; then
    log "Cloning repository (branch: ${BRANCH})..."
    git clone --depth 1 --single-branch --branch "${BRANCH}" "${REPO_CLONE_URL}" "${REPO_DIR}" \
      > "${RESULTS_DIR}/git_clone.log" 2>&1 || return 1
  else
    log "Cloning repository..."
    git clone --depth 1 "${REPO_CLONE_URL}" "${REPO_DIR}" \
      > "${RESULTS_DIR}/git_clone.log" 2>&1 || return 1
  fi

  record_file_if_exists "${RESULTS_DIR}/git_clone.log"
  log "Repository cloned successfully."
  return 0
}

force_ecosystem_if_needed() {
  case "${SCAN_MODE}" in
    node|python|php|go|rust|java|docker|iac|dotnet)
      log "Forced ecosystem: ${SCAN_MODE}"
      echo "${SCAN_MODE}" > "${ECOSYSTEMS_FILE}"
      ;;
    ssl-only)
      log "SSL-only mode: skipping repo scans."
      : > "${ECOSYSTEMS_FILE}"
      ;;
    dast)
      log "DAST mode: skipping repo scans, ZAP will scan DAST_TARGET_URL."
      : > "${ECOSYSTEMS_FILE}"
      ;;
    docker-image)
      log "Docker image mode: will scan image CVEs + optional DAST."
      : > "${ECOSYSTEMS_FILE}"
      ;;
    auto|full|quick) ;;
    *)
      log "Unknown SCAN_MODE=${SCAN_MODE}, falling back to auto."
      SCAN_MODE="auto"
      ;;
  esac
}

run_ecosystem_scans() {
  if [ ! -s "${ECOSYSTEMS_FILE}" ]; then
    log "No ecosystems detected — skipping ecosystem-specific scans."
    return 0
  fi

  sort -u "${ECOSYSTEMS_FILE}" -o "${ECOSYSTEMS_FILE}" 2>/dev/null || true

  while IFS= read -r ecosystem; do
    [ -z "${ecosystem}" ] && continue
    log "Running ecosystem scan: ${ecosystem}"
    case "${ecosystem}" in
      node)   run_node_scans   "${REPO_DIR}" "${RESULTS_DIR}" ;;
      python) run_python_scans "${REPO_DIR}" "${RESULTS_DIR}" ;;
      php)    run_php_scans    "${REPO_DIR}" "${RESULTS_DIR}" ;;
      go)     run_go_scans     "${REPO_DIR}" "${RESULTS_DIR}" ;;
      rust)   run_rust_scans   "${REPO_DIR}" "${RESULTS_DIR}" ;;
      java)   run_java_scans   "${REPO_DIR}" "${RESULTS_DIR}" ;;
      docker) run_docker_scans "${REPO_DIR}" "${RESULTS_DIR}" ;;
      iac)    run_iac_scans    "${REPO_DIR}" "${RESULTS_DIR}" ;;
      dotnet) log "dotnet detected, no dedicated dotnet module yet; generic/SBOM scans still apply." ;;
      *)      log "Unknown ecosystem '${ecosystem}', skipped." ;;
    esac
  done < "${ECOSYSTEMS_FILE}"
}

run_quick_scans() {
  log "Quick scan mode: running gitleaks + semgrep + trivy only"

  if skip_if_missing "gitleaks" "${RESULTS_DIR}/gitleaks.json" "gitleaks absent — secret scan ignoré"; then
    record_file_if_exists "${RESULTS_DIR}/gitleaks.json"
  else
    gitleaks detect --source "${REPO_DIR}" --report-format json \
      --report-path "${RESULTS_DIR}/gitleaks.json" --no-git \
      > "${RESULTS_DIR}/gitleaks.log" 2>&1 || true
    validate_json_or_replace "${RESULTS_DIR}/gitleaks.json" '[]'
    record_tool "gitleaks"
    record_file_if_exists "${RESULTS_DIR}/gitleaks.json"
    record_file_if_exists "${RESULTS_DIR}/gitleaks.log"
  fi

  if skip_if_missing "semgrep" "${RESULTS_DIR}/semgrep.json" "semgrep absent — SAST ignoré"; then
    record_file_if_exists "${RESULTS_DIR}/semgrep.json"
  else
    semgrep scan --config auto "${REPO_DIR}" --json \
      --output "${RESULTS_DIR}/semgrep.json" \
      > "${RESULTS_DIR}/semgrep.log" 2>&1 || true
    validate_json_or_replace "${RESULTS_DIR}/semgrep.json" '{"results":[]}'
    record_tool "semgrep"
    record_file_if_exists "${RESULTS_DIR}/semgrep.json"
    record_file_if_exists "${RESULTS_DIR}/semgrep.log"
  fi

  if skip_if_missing "trivy" "${RESULTS_DIR}/trivy.json" "trivy absent — CVE scan ignoré"; then
    record_file_if_exists "${RESULTS_DIR}/trivy.json"
  else
    trivy fs --format json --scanners vuln,secret,misconfig \
      -o "${RESULTS_DIR}/trivy.json" "${REPO_DIR}" \
      > "${RESULTS_DIR}/trivy.log" 2>&1 || true
    validate_json_or_replace "${RESULTS_DIR}/trivy.json" '{"Results":[]}'
    record_tool "trivy"
    record_file_if_exists "${RESULTS_DIR}/trivy.json"
    record_file_if_exists "${RESULTS_DIR}/trivy.log"
  fi
}

validate_domain() {
  if ! is_valid_host_port "$1"; then
    log "WARNING: invalid target domain: $1"
    return 1
  fi
  local hp domain port
  hp="$(normalize_host_port "$1")"
  domain="${hp% *}"
  port="${hp#* }"

  log "Validating domain connectivity: ${domain}:${port}"
  if ! nc -z -w 10 "${domain}" "${port}" 2>/dev/null; then
    log "WARNING: ${domain}:${port} is not reachable. SSL scans may fail or return no results."
  else
    log "Domain ${domain}:${port} is reachable."
  fi
  return 0
}

generate_result_json() {
  local ecosystems_json tools_json files_json scan_end_time duration
  scan_end_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  duration=$(( $(date +%s) - SCAN_START_EPOCH ))

  ecosystems_json="$(safe_jq_array_from_file "${ECOSYSTEMS_FILE}")"
  tools_json="$(safe_jq_array_from_file "${TOOLS_EXECUTED_FILE}")"
  files_json="$(safe_jq_array_from_file "${GENERATED_FILES_FILE}")"

  jq -n \
    --arg repoUrl        "${REPO_URL}" \
    --arg branch         "${BRANCH}" \
    --arg scanMode       "${SCAN_MODE}" \
    --arg targetDomain   "${TARGET_DOMAIN}" \
    --arg dastTargetUrl   "${DAST_TARGET_URL}" \
    --arg dockerImage    "${DOCKER_IMAGE}" \
    --arg targetOs       "${TARGET_OS}" \
    --arg complianceProfile "${COMPLIANCE_PROFILE}" \
    --arg status         "${STATUS}" \
    --arg startedAt      "${SCAN_START_TIME}" \
    --arg finishedAt     "${scan_end_time}" \
    --argjson durationSeconds "${duration}" \
    --argjson ecosystemsDetected "${ecosystems_json}" \
    --argjson toolsExecuted      "${tools_json}" \
    --argjson generatedFiles     "${files_json}" \
    '{
      repoUrl: $repoUrl,
      branch: $branch,
      scanMode: $scanMode,
      targetDomain: $targetDomain,
      dastTargetUrl: $dastTargetUrl,
      dockerImage: $dockerImage,
      targetOs: $targetOs,
      complianceProfile: $complianceProfile,
      status: $status,
      startedAt: $startedAt,
      finishedAt: $finishedAt,
      durationSeconds: $durationSeconds,
      ecosystemsDetected: $ecosystemsDetected,
      toolsExecuted: $toolsExecuted,
      generatedFiles: $generatedFiles
    }' > "${RESULTS_DIR}/result.json" 2>/dev/null || {
      STATUS="partial"
      printf '{"status":"partial","error":"failed to generate result.json"}\n' > "${RESULTS_DIR}/result.json"
    }

  record_file_if_exists "${RESULTS_DIR}/result.json"
  log "result.json generated."
}

main() {
  log "=========================================="
  log "Vulnix scanner started"
  log "SCAN_MODE          = ${SCAN_MODE}"
  log "REPO_URL           = ${REPO_URL:-<none>}"
  log "TARGET_DOMAIN      = ${TARGET_DOMAIN:-<none>}"
  log "DAST_TARGET_URL    = ${DAST_TARGET_URL:-<none>}"
  log "DOCKER_IMAGE       = ${DOCKER_IMAGE:-<none>}"
  log "BRANCH             = ${BRANCH:-<default>}"
  log "TARGET_OS          = ${TARGET_OS:-<none>}"
  log "COMPLIANCE_PROFILE = ${COMPLIANCE_PROFILE:-<none>}"
  log "=========================================="

  export TARGET_OS RESULTS_DIR TOOLS_EXECUTED_FILE GENERATED_FILES_FILE

  local phase_start

  if [ -n "${REPO_URL}" ]; then
    phase_start=$(date +%s)
    clone_repo || STATUS="failed"
    log "  [TIMING] Clone: $(( $(date +%s) - phase_start ))s"
  fi

  force_ecosystem_if_needed

  if [ "${STATUS}" = "completed" ] && [ -d "${REPO_DIR}" ] && [ "${SCAN_MODE}" != "ssl-only" ] && [ "${SCAN_MODE}" != "dast" ] && [ "${SCAN_MODE}" != "docker-image" ]; then
    if [ "${SCAN_MODE}" = "quick" ]; then
      phase_start=$(date +%s)
      run_quick_scans
      log "  [TIMING] Quick scans: $(( $(date +%s) - phase_start ))s"
    else
      if [ "${SCAN_MODE}" = "auto" ] || [ "${SCAN_MODE}" = "full" ]; then
        log "Detecting ecosystems..."
        detect_ecosystems "${REPO_DIR}" "${ECOSYSTEMS_FILE}"
        sort -u "${ECOSYSTEMS_FILE}" -o "${ECOSYSTEMS_FILE}" 2>/dev/null || true
        log "Ecosystems found: $(tr '\n' ' ' < "${ECOSYSTEMS_FILE}" 2>/dev/null || echo 'none')"
      fi

      phase_start=$(date +%s)
      run_generic_scans "${REPO_DIR}" "${RESULTS_DIR}"
      log "  [TIMING] Generic scans: $(( $(date +%s) - phase_start ))s"

      phase_start=$(date +%s)
      run_ecosystem_scans
      log "  [TIMING] Ecosystem scans: $(( $(date +%s) - phase_start ))s"

      phase_start=$(date +%s)
      run_license_scan "${REPO_DIR}" "${RESULTS_DIR}"
      log "  [TIMING] License scan: $(( $(date +%s) - phase_start ))s"
    fi
  fi

  if [ -n "${TARGET_DOMAIN}" ]; then
    if validate_domain "${TARGET_DOMAIN}"; then
      phase_start=$(date +%s)
      run_ssl_scans "${TARGET_DOMAIN}" "${RESULTS_DIR}"
      log "  [TIMING] SSL scans: $(( $(date +%s) - phase_start ))s"
    else
      write_json_warning "${RESULTS_DIR}/ssl-summary.json" "Invalid TARGET_DOMAIN"
      record_file_if_exists "${RESULTS_DIR}/ssl-summary.json"
      STATUS="partial"
    fi
  fi

  if [ -n "${DAST_TARGET_URL}" ] || [ "${SCAN_MODE}" = "dast" ]; then
    phase_start=$(date +%s)
    run_dast_scans "${RESULTS_DIR}" "${DAST_TARGET_URL}"
    log "  [TIMING] DAST scan (ZAP): $(( $(date +%s) - phase_start ))s"

    phase_start=$(date +%s)
    run_nuclei_scans "${RESULTS_DIR}" "${DAST_TARGET_URL}"
    log "  [TIMING] DAST scan (Nuclei): $(( $(date +%s) - phase_start ))s"
  fi

  if [ "${SCAN_MODE}" = "docker-image" ]; then
    phase_start=$(date +%s)
    run_docker_image_scans "${RESULTS_DIR}" "${DOCKER_IMAGE}" "${DAST_TARGET_URL}"
    log "  [TIMING] Docker image scan: $(( $(date +%s) - phase_start ))s"
  fi

  if [ -n "${COMPLIANCE_PROFILE}" ]; then
    phase_start=$(date +%s)
    run_compliance_scan "${COMPLIANCE_PROFILE}" "${RESULTS_DIR}"
    log "  [TIMING] Compliance scan: $(( $(date +%s) - phase_start ))s"
  fi

  generate_result_json

  local total_cves=0 crit_cves=0 high_cves=0 total_duration
  if [ -f "${RESULTS_DIR}/all-cves.json" ] && command -v jq >/dev/null 2>&1; then
    total_cves=$(jq 'length' "${RESULTS_DIR}/all-cves.json" 2>/dev/null || echo "0")
    crit_cves=$(jq '[.[] | select(.severity=="CRITICAL")] | length' "${RESULTS_DIR}/all-cves.json" 2>/dev/null || echo "0")
    high_cves=$(jq '[.[] | select(.severity=="HIGH")] | length' "${RESULTS_DIR}/all-cves.json" 2>/dev/null || echo "0")
  fi

  total_duration=$(( $(date +%s) - SCAN_START_EPOCH ))
  log "=========================================="
  log "Vulnix scanner finished — status=${STATUS}"
  log "Total CVEs: ${total_cves} (CRITICAL: ${crit_cves}, HIGH: ${high_cves})"
  log "Total duration: ${total_duration}s"
  log "=========================================="
  echo "%%SCAN_COMPLETE%%"
}

main "$@"
