#!/usr/bin/env bash
# CredSweeper (Samsung) — second secret detector next to gitleaks.
# gitleaks misses many hard-coded passwords (low entropy, no known format); CredSweeper finds them but is noisier.
# Medianet merges both reports and its triage model judges the union. Skipped silently when CredSweeper is absent.

run_credsweeper() {
  local repo_dir="$1"
  local results_dir="$2"

  if ! command -v credsweeper >/dev/null 2>&1 && ! python3 -c "import credsweeper" >/dev/null 2>&1; then
    log "[WARN] credsweeper absent — second secret detector ignoré"
    return 0
  fi

  log "  credsweeper — second secret detector..."
  # --no-stdout: findings were also printed to the log (1.2 GB on a repo with committed reports).
  # --size_limit: real secrets live in small files; multi-MB files are data, dumps and old reports (the JSON grew
  # to 1.4 GB and the step took minutes). Not --skip_ignored: a tracked file that is also in .gitignore (a committed
  # application.properties) is exactly the leak to find.
  python3 -m credsweeper \
    --path "${repo_dir}" \
    --save-json "${results_dir}/credsweeper.json" \
    --jobs 4 \
    --no-stdout \
    --size_limit 5MiB \
    > "${results_dir}/credsweeper.log" 2>&1 || true
  validate_json_or_replace "${results_dir}/credsweeper.json" '[]'
  record_tool "credsweeper"
  record_file_if_exists "${results_dir}/credsweeper.json"
  record_file_if_exists "${results_dir}/credsweeper.log"
}
