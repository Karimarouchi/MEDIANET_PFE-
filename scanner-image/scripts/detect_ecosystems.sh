#!/usr/bin/env bash

detect_ecosystems() {
  local repo_dir="$1"
  local output_file="$2"

  : > "${output_file}"

  # Helper: search recursively (max depth 4) for a file pattern
  _find_any() {
    find "${repo_dir}" -maxdepth 4 -name "$1" -type f 2>/dev/null | head -1
  }

  # ── Node.js ──────────────────────────────────────────────────
  if [ -f "${repo_dir}/package.json" ] || \
     [ -f "${repo_dir}/package-lock.json" ] || \
     [ -f "${repo_dir}/yarn.lock" ] || \
     [ -f "${repo_dir}/pnpm-lock.yaml" ] || \
     [ -n "$(_find_any 'package.json')" ]; then
    echo "node" >> "${output_file}"
  fi

  # ── Python ───────────────────────────────────────────────────
  if [ -f "${repo_dir}/requirements.txt" ] || \
     [ -f "${repo_dir}/pyproject.toml" ] || \
     [ -f "${repo_dir}/Pipfile" ] || \
     [ -f "${repo_dir}/Pipfile.lock" ] || \
     [ -f "${repo_dir}/poetry.lock" ] || \
     [ -f "${repo_dir}/setup.py" ] || \
     [ -f "${repo_dir}/setup.cfg" ] || \
     [ -n "$(_find_any 'requirements.txt')" ]; then
    echo "python" >> "${output_file}"
  fi

  # ── PHP ──────────────────────────────────────────────────────
  if [ -f "${repo_dir}/composer.json" ] || \
     [ -f "${repo_dir}/composer.lock" ] || \
     [ -n "$(_find_any 'composer.json')" ]; then
    echo "php" >> "${output_file}"
  fi

  # ── Go ───────────────────────────────────────────────────────
  if [ -f "${repo_dir}/go.mod" ] || \
     [ -f "${repo_dir}/go.sum" ] || \
     [ -n "$(_find_any 'go.mod')" ]; then
    echo "go" >> "${output_file}"
  fi

  # ── Rust ─────────────────────────────────────────────────────
  if [ -f "${repo_dir}/Cargo.toml" ] || \
     [ -f "${repo_dir}/Cargo.lock" ] || \
     [ -n "$(_find_any 'Cargo.toml')" ]; then
    echo "rust" >> "${output_file}"
  fi

  # ── Java / Kotlin ─────────────────────────────────────────────
  if [ -f "${repo_dir}/pom.xml" ] || \
     [ -f "${repo_dir}/build.gradle" ] || \
     [ -f "${repo_dir}/build.gradle.kts" ] || \
     [ -f "${repo_dir}/settings.gradle" ] || \
     [ -f "${repo_dir}/settings.gradle.kts" ] || \
     [ -n "$(_find_any 'pom.xml')" ] || \
     [ -n "$(_find_any 'build.gradle')" ]; then
    echo "java" >> "${output_file}"
  fi

  # ── .NET / C# ────────────────────────────────────────────────
  if [ -n "$(_find_any '*.csproj')" ] || \
     [ -n "$(_find_any '*.sln')" ] || \
     [ -n "$(_find_any '*.fsproj')" ]; then
    echo "dotnet" >> "${output_file}"
  fi

  # ── Docker ───────────────────────────────────────────────────
  if [ -n "$(_find_any 'Dockerfile')" ] || \
     [ -n "$(_find_any 'Dockerfile.*')" ] || \
     [ -n "$(_find_any 'docker-compose*.yml')" ] || \
     [ -n "$(_find_any 'docker-compose*.yaml')" ]; then
    echo "docker" >> "${output_file}"
  fi

  # ── Infrastructure as Code ───────────────────────────────────
  if [ -n "$(_find_any '*.tf')" ] || \
     [ -n "$(_find_any 'Pulumi.yaml')" ] || \
     [ -n "$(find "${repo_dir}" -maxdepth 4 -name "*.yaml" -exec grep -l 'apiVersion' {} \; 2>/dev/null | head -1)" ]; then
    echo "iac" >> "${output_file}"
  fi

  # Remove duplicates and sort
  sort -u -o "${output_file}" "${output_file}"

  # Unset helper
  unset -f _find_any
}