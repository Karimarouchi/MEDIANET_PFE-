#!/usr/bin/env bash

run_docker_scans() {
  local repo_dir="$1"
  local results_dir="$2"

  log "Running Docker security scans"

  # Find all Dockerfiles
  local dockerfiles
  dockerfiles=$(find "${repo_dir}" -maxdepth 3 -name "Dockerfile*" -type f 2>/dev/null)

  if [ -z "${dockerfiles}" ]; then
    log "  No Dockerfile found — skipping Docker scans"
    echo '{"warning":"No Dockerfile found"}' > "${results_dir}/docker-scan.json"
    record_file_if_exists "${results_dir}/docker-scan.json"
    return 0
  fi

  local all_issues="[]"
  local file_count=0

  while IFS= read -r dockerfile; do
    [ -z "${dockerfile}" ] && continue
    file_count=$((file_count + 1))
    local rel_path="${dockerfile#${repo_dir}/}"
    log "  Analyzing: ${rel_path}"

    # ── Hadolint — Dockerfile linting ──────────────────────────
    if command -v hadolint &>/dev/null; then
      log "    hadolint..."
      local hadolint_out="${results_dir}/hadolint-${file_count}.json"
      hadolint --format json "${dockerfile}" \
        > "${hadolint_out}" 2>/dev/null || true
      record_file_if_exists "${hadolint_out}"

      # Convert hadolint output to our format
      local issues
      issues=$(jq --arg file "${rel_path}" '[
        .[] |
        {
          rule:     .code,
          severity: (if .level == "error" then "HIGH"
                     elif .level == "warning" then "MEDIUM"
                     elif .level == "info" then "LOW"
                     else "LOW" end),
          message:  .message,
          line:     .line,
          file:     $file,
          source:   "hadolint"
        }
      ]' "${hadolint_out}" 2>/dev/null || echo '[]')

      all_issues=$(echo "${all_issues}" "${issues}" | jq -s 'add')
    fi

    # ── Manual Dockerfile best-practice checks ─────────────────
    local manual_issues="[]"

    # Check: Running as root (no USER instruction)
    if ! grep -q "^USER " "${dockerfile}" 2>/dev/null; then
      manual_issues=$(echo "${manual_issues}" | jq --arg file "${rel_path}" \
        '. + [{
          rule: "DK-001",
          severity: "MEDIUM",
          message: "No USER instruction found — container runs as root by default",
          line: 0,
          file: $file,
          source: "vulnix-docker"
        }]')
    fi

    # Check: Using latest tag
    if grep -qE "^FROM\s+\S+:latest" "${dockerfile}" 2>/dev/null; then
      manual_issues=$(echo "${manual_issues}" | jq --arg file "${rel_path}" \
        '. + [{
          rule: "DK-002",
          severity: "MEDIUM",
          message: "Using :latest tag — pin to a specific version for reproducibility",
          line: 0,
          file: $file,
          source: "vulnix-docker"
        }]')
    fi

    # Check: ADD instead of COPY (potential security risk)
    if grep -qE "^ADD\s+" "${dockerfile}" 2>/dev/null; then
      manual_issues=$(echo "${manual_issues}" | jq --arg file "${rel_path}" \
        '. + [{
          rule: "DK-003",
          severity: "LOW",
          message: "Using ADD instead of COPY — ADD can auto-extract archives and fetch URLs, prefer COPY unless needed",
          line: 0,
          file: $file,
          source: "vulnix-docker"
        }]')
    fi

    # Check: EXPOSE with no specific ports
    if ! grep -q "^EXPOSE " "${dockerfile}" 2>/dev/null; then
      manual_issues=$(echo "${manual_issues}" | jq --arg file "${rel_path}" \
        '. + [{
          rule: "DK-004",
          severity: "LOW",
          message: "No EXPOSE instruction — document which ports the container listens on",
          line: 0,
          file: $file,
          source: "vulnix-docker"
        }]')
    fi

    # Check: Secrets or passwords in ENV
    if grep -qiE "^ENV\s+.*(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)" "${dockerfile}" 2>/dev/null; then
      manual_issues=$(echo "${manual_issues}" | jq --arg file "${rel_path}" \
        '. + [{
          rule: "DK-005",
          severity: "CRITICAL",
          message: "Potential secret/password found in ENV instruction — use Docker secrets or build args instead",
          line: 0,
          file: $file,
          source: "vulnix-docker"
        }]')
    fi

    # Check: HEALTHCHECK missing
    if ! grep -q "^HEALTHCHECK " "${dockerfile}" 2>/dev/null; then
      manual_issues=$(echo "${manual_issues}" | jq --arg file "${rel_path}" \
        '. + [{
          rule: "DK-006",
          severity: "LOW",
          message: "No HEALTHCHECK instruction — add one for production readiness",
          line: 0,
          file: $file,
          source: "vulnix-docker"
        }]')
    fi

    all_issues=$(echo "${all_issues}" "${manual_issues}" | jq -s 'add')

  done <<< "${dockerfiles}"

  # ── Trivy config scan for Docker ─────────────────────────────
  log "  trivy misconfig scan on Dockerfiles..."
  trivy fs \
    --format json \
    --scanners misconfig \
    -o "${results_dir}/trivy-docker-misconfig.json" \
    "${repo_dir}" \
    > "${results_dir}/trivy-docker-misconfig.log" 2>&1 || true
  record_tool "trivy-docker-misconfig"
  record_file_if_exists "${results_dir}/trivy-docker-misconfig.json"

  # Write combined results
  echo "${all_issues}" | jq '.' > "${results_dir}/docker-scan.json" 2>/dev/null \
    || echo '[]' > "${results_dir}/docker-scan.json"

  local total
  total=$(echo "${all_issues}" | jq 'length' 2>/dev/null || echo "0")
  log "    Docker scan: ${total} issues found across ${file_count} Dockerfile(s)"

  record_tool "docker-scan"
  record_file_if_exists "${results_dir}/docker-scan.json"
}
