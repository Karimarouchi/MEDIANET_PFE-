#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Docker Image Scan — CVE analysis of image layers + DAST on running container
# Called by scan.sh when SCAN_MODE=docker-image.
# Produces: trivy.json, grype.json (plus zap.json if DAST_TARGET_URL is set)
# ─────────────────────────────────────────────────────────────────────────────

run_docker_image_scans() {
  local results_dir="$1"
  local docker_image="$2"
  local dast_target_url="$3"

  if [ -z "${docker_image}" ]; then
    echo "[WARN] Docker image scan: DOCKER_IMAGE is empty, nothing to scan."
    return 0
  fi

  echo "[SCAN] Docker image CVE scan started: ${docker_image}"

  # ── Trivy — image layer CVE scan ─────────────────────────────────────────
  echo "[SCAN] Trivy: scanning image layers for known CVEs..."
  local trivy_out="${results_dir}/trivy.json"
  local trivy_log="${results_dir}/trivy.log"

  timeout 600 trivy image \
    --format json \
    --output "${trivy_out}" \
    --timeout 8m \
    --no-progress \
    "${docker_image}" \
    > "${trivy_log}" 2>&1 || true

  if [ -f "${trivy_out}" ] && [ -s "${trivy_out}" ]; then
    local trivy_cves
    trivy_cves=$(jq '[.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID != null)] | length' \
      "${trivy_out}" 2>/dev/null || echo "0")
    echo "[SUCCESS] Trivy scan completed — ${trivy_cves} CVE(s) found in image"
    record_tool "trivy"
    record_file_if_exists "${trivy_out}"
  else
    echo "[WARN] Trivy produced no output — check ${trivy_log}"
  fi

  # ── Grype — image CVE scan (second opinion) ───────────────────────────────
  echo "[SCAN] Grype: scanning image for additional CVEs..."
  local grype_out="${results_dir}/grype.json"
  local grype_log="${results_dir}/grype.log"

  timeout 600 grype "registry:${docker_image}" \
    -o json \
    > "${grype_out}" 2>"${grype_log}" || true

  if [ -f "${grype_out}" ] && [ -s "${grype_out}" ]; then
    local grype_cves
    grype_cves=$(jq '.matches | length' "${grype_out}" 2>/dev/null || echo "0")
    echo "[SUCCESS] Grype scan completed — ${grype_cves} CVE(s) found in image"
    record_tool "grype"
    record_file_if_exists "${grype_out}"
  else
    echo "[WARN] Grype produced no output — check ${grype_log}"
  fi

  # ── Syft SBOM (optional — generates sbom.json if syft is available) ───────
  if command -v syft &>/dev/null; then
    echo "[SCAN] Syft: generating SBOM for ${docker_image}..."
    local sbom_out="${results_dir}/sbom.json"
    timeout 300 syft "${docker_image}" -o spdx-json > "${sbom_out}" 2>/dev/null || true
    record_file_if_exists "${sbom_out}"
  fi

  # ── DAST — ZAP scan on running container ─────────────────────────────────
  if [ -n "${dast_target_url}" ]; then
    echo "[SCAN] Running ZAP DAST against container at: ${dast_target_url}"
    run_dast_scans "${results_dir}" "${dast_target_url}"
  else
    echo "[INFO] No DAST_TARGET_URL provided — skipping ZAP scan"
  fi

  echo "[SUCCESS] Docker image scan completed for: ${docker_image}"
}
