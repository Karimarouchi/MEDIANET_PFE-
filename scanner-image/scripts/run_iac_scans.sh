#!/usr/bin/env bash

run_iac_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running Infrastructure-as-Code (IaC) scans"

  local has_iac=false

  # Detect IaC files
  local tf_files k8s_files compose_files cf_files
  tf_files=$(find "${repo_dir}" -maxdepth 4 -name "*.tf" -type f 2>/dev/null | head -1)
  k8s_files=$(find "${repo_dir}" -maxdepth 4 \( -name "*.yaml" -o -name "*.yml" \) -type f \
    -exec grep -l "apiVersion\|kind:\s*Deployment\|kind:\s*Service\|kind:\s*Pod" {} \; 2>/dev/null | head -1)
  compose_files=$(find "${repo_dir}" -maxdepth 3 \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \) -type f 2>/dev/null | head -1)
  cf_files=$(find "${repo_dir}" -maxdepth 4 \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) -type f \
    -exec grep -l "AWSTemplateFormatVersion\|AWS::CloudFormation" {} \; 2>/dev/null | head -1)

  [ -n "${tf_files}" ] || [ -n "${k8s_files}" ] || [ -n "${compose_files}" ] || [ -n "${cf_files}" ] && has_iac=true

  if [ "${has_iac}" = "false" ]; then
    log "  No IaC files detected — skipping IaC scans"
    echo '{"warning":"No IaC files found (Terraform, Kubernetes, Docker Compose, CloudFormation)"}' \
      > "${results_dir}/iac-scan.json"
    record_file_if_exists "${results_dir}/iac-scan.json"
    return 0
  fi

  # ── Checkov — multi-framework IaC scanner ────────────────────
  if command -v checkov &>/dev/null; then
    log "  checkov — IaC security scan..."
    run_with_timeout 600 \
      checkov \
        --directory "${repo_dir}" \
        --output json \
        --quiet \
        --compact \
        --skip-download \
      > "${results_dir}/checkov.json" \
      2> "${results_dir}/checkov.log" || true
    record_tool "checkov"
    record_file_if_exists "${results_dir}/checkov.json"
    record_file_if_exists "${results_dir}/checkov.log"

    # Extract failed checks summary
    extract_iac_summary_checkov "${results_dir}/checkov.json" "${results_dir}/iac-checkov-summary.json"
    record_file_if_exists "${results_dir}/iac-checkov-summary.json"
  else
    log "  checkov not installed — skipping"
  fi

  # ── Trivy misconfig scan (works on Terraform, K8s, Dockerfile, etc.) ─────
  log "  trivy — IaC misconfig scan..."
  trivy fs \
    --format json \
    --scanners misconfig \
    -o "${results_dir}/trivy-iac.json" \
    "${repo_dir}" \
    > "${results_dir}/trivy-iac.log" 2>&1 || true
  record_tool "trivy-iac"
  record_file_if_exists "${results_dir}/trivy-iac.json"
  record_file_if_exists "${results_dir}/trivy-iac.log"

  # Extract trivy misconfig summary
  extract_iac_summary_trivy "${results_dir}/trivy-iac.json" "${results_dir}/iac-trivy-summary.json"
  record_file_if_exists "${results_dir}/iac-trivy-summary.json"

  # ── Merge IaC results ────────────────────────────────────────
  merge_iac_results "${results_dir}"
}

# ─────────────────────────────────────────────────────────────────
# Extract failed checks from checkov → iac-checkov-summary.json
# ─────────────────────────────────────────────────────────────────
extract_iac_summary_checkov() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  # Checkov can output array (multi-framework) or single object
  jq '
    (if type == "array" then . else [.] end) |
    [
      .[] |
      select(.results != null) |
      .results.failed_checks[]? |
      {
        checkId:    (.check_id // "UNKNOWN"),
        checkName:  (.name // "Unknown check"),
        severity:   (.severity // "MEDIUM"),
        file:       (.file_path // "unknown"),
        resource:   (.resource // "unknown"),
        guideline:  (.guideline // ""),
        source:     "checkov"
      }
    ]
  ' "${input_file}" > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "0")
  log "    checkov: ${found} failed checks"
}

# ─────────────────────────────────────────────────────────────────
# Extract misconfigurations from trivy IaC scan
# ─────────────────────────────────────────────────────────────────
extract_iac_summary_trivy() {
  local input_file="$1"
  local output_file="$2"

  if [ ! -f "${input_file}" ]; then
    echo '[]' > "${output_file}"
    return
  fi

  jq '[
    .Results[]? |
    .Target as $target |
    .Misconfigurations[]? |
    {
      checkId:    (.ID // "UNKNOWN"),
      checkName:  (.Title // "Unknown"),
      severity:   (.Severity // "MEDIUM"),
      file:       $target,
      resource:   (.CauseMetadata.Resource // ""),
      message:    (.Message // ""),
      resolution: (.Resolution // ""),
      source:     "trivy-misconfig"
    }
  ]' "${input_file}" > "${output_file}" 2>/dev/null \
    || echo '[]' > "${output_file}"

  local found
  found=$(jq 'length' "${output_file}" 2>/dev/null || echo "0")
  log "    trivy IaC: ${found} misconfigurations"
}

# ─────────────────────────────────────────────────────────────────
# Merge all IaC scan results into iac-summary.json
# ─────────────────────────────────────────────────────────────────
merge_iac_results() {
  local results_dir="$1"
  local output_file="${results_dir}/iac-summary.json"

  local checkov_data="[]"
  local trivy_data="[]"

  [ -f "${results_dir}/iac-checkov-summary.json" ] && checkov_data=$(cat "${results_dir}/iac-checkov-summary.json")
  [ -f "${results_dir}/iac-trivy-summary.json" ] && trivy_data=$(cat "${results_dir}/iac-trivy-summary.json")

  jq -n \
    --argjson checkov "${checkov_data}" \
    --argjson trivy  "${trivy_data}" \
    '($checkov + $trivy) | sort_by(
      if   .severity == "CRITICAL" then 0
      elif .severity == "HIGH"     then 1
      elif .severity == "MEDIUM"   then 2
      else 3 end
    )' > "${output_file}" 2>/dev/null || echo '[]' > "${output_file}"

  local total
  total=$(jq 'length' "${output_file}" 2>/dev/null || echo "0")
  log "    === IaC TOTAL: ${total} misconfigurations ==="

  record_file_if_exists "${output_file}"
}
