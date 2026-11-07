#!/usr/bin/env bash
# Build-time check: every tool the scan scripts call must be present, otherwise the image is not built.
# A scan that silently skips a missing tool looks "clean" while it scanned nothing.
set -u

missing=0

need() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '  ok       %s\n' "$1"
  else
    printf '  MISSING  %s\n' "$1"
    missing=$((missing + 1))
  fi
}

echo "[selftest] scanner tools"
for t in \
  trivy grype syft osv-scanner gitleaks credsweeper semgrep checkov pip-audit hadolint \
  nuclei zap.sh dependency-check.sh govulncheck cargo-audit \
  sslyze testssl.sh sslscan nmap \
  npm node mvn composer java go cargo php jq curl; do
  need "$t"
done

echo "[selftest] data the tools need offline"
if [ -n "$(ls -A /root/nuclei-templates 2>/dev/null)" ]; then
  echo "  ok       nuclei templates"
else
  echo "  MISSING  nuclei templates (/root/nuclei-templates is empty)"
  missing=$((missing + 1))
fi
if [ -f /opt/zaproxy/zap.sh ] && ls /opt/zaproxy/zap-*.jar >/dev/null 2>&1; then
  echo "  ok       zap (zap.sh and jar)"
else
  echo "  MISSING  zap jar under /opt/zaproxy"
  missing=$((missing + 1))
fi

echo "[selftest] versions"
nuclei -version 2>&1 | head -1 || true
dependency-check.sh --version 2>&1 | tail -1 || true

if [ "${missing}" -gt 0 ]; then
  echo "[selftest] FAILED: ${missing} item(s) missing"
  exit 1
fi
echo "[selftest] all tools present"
