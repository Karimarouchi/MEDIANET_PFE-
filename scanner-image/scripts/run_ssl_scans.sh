#!/usr/bin/env bash

run_ssl_scans() {
  local target_domain="$1"
  local results_dir="$2"

  if ! is_valid_host_port "${target_domain}"; then
    log "WARNING: invalid TARGET_DOMAIN '${target_domain}' — skipping SSL/TLS scans."
    write_json_warning "${results_dir}/ssl-summary.json" "Invalid TARGET_DOMAIN"
    record_file_if_exists "${results_dir}/ssl-summary.json"
    return 0
  fi

  local _hp _domain _port
  _hp="$(normalize_host_port "${target_domain}")"
  _domain="${_hp% *}"
  _port="${_hp#* }"

  log "Running SSL/TLS scans on ${_domain}:${_port}"

  # Always use host:port (never raw https:// URL) — SSLyze rejects URL form.
  local sslyze_target="${_domain}:${_port}"

  # ── SSLyze ───────────────────────────────────────────────────
  if skip_if_missing "sslyze" "${results_dir}/sslyze.json" "sslyze absent — scan SSLyze ignoré"; then
    :
  else
    log "  [1/6] sslyze..."
    run_with_timeout 180 \
      sslyze --json_out "${results_dir}/sslyze.json" "${sslyze_target}" \
      > "${results_dir}/sslyze.log" 2>&1 || true
    validate_json_or_replace "${results_dir}/sslyze.json" '{"server_scan_results":[]}'
  fi
  record_tool "sslyze"
  record_file_if_exists "${results_dir}/sslyze.json"
  record_file_if_exists "${results_dir}/sslyze.log"

  # ── SSLScan ──────────────────────────────────────────────────
  log "  [2/6] sslscan..."
  run_with_timeout 120 \
    sslscan --xml="${results_dir}/sslscan.xml" "${sslyze_target}" \
    > "${results_dir}/sslscan.log" 2>&1 || true
  record_tool "sslscan"
  record_file_if_exists "${results_dir}/sslscan.xml"
  record_file_if_exists "${results_dir}/sslscan.log"

  # ── testssl.sh ───────────────────────────────────────────────
  log "  [3/6] testssl.sh (timeout 600s)..."
  run_with_timeout 600 \
    testssl.sh \
      --jsonfile-pretty "${results_dir}/testssl.json" \
      --logfile "${results_dir}/testssl.log" \
      --quiet \
      "${sslyze_target}" \
    > /dev/null 2>&1 || true
  record_tool "testssl.sh"
  record_file_if_exists "${results_dir}/testssl.json"
  record_file_if_exists "${results_dir}/testssl.log"

  # ── Nmap ssl-enum-ciphers ────────────────────────────────────
  log "  [4/6] nmap ssl-enum-ciphers..."
  run_with_timeout 120 \
    nmap --script ssl-enum-ciphers \
      -p "${_port}" \
      "${_domain}" \
      -oN "${results_dir}/nmap-ssl.txt" \
    > "${results_dir}/nmap-ssl.log" 2>&1 || true
  record_tool "nmap-ssl-enum-ciphers"
  record_file_if_exists "${results_dir}/nmap-ssl.txt"
  record_file_if_exists "${results_dir}/nmap-ssl.log"

  # ── Nmap ssl-heartbleed (explicit CVE-2014-0160 proof) ───────
  log "  [4b/6] nmap ssl-heartbleed..."
  run_with_timeout 90 \
    nmap -Pn -p "${_port}" \
      --script ssl-heartbleed \
      --script-args "tls.servername=${_domain}" \
      "${_domain}" \
      -oN "${results_dir}/nmap-heartbleed.txt" \
      -oX "${results_dir}/nmap-heartbleed.xml" \
    > "${results_dir}/nmap-heartbleed.log" 2>&1 || true
  record_tool "nmap-ssl-heartbleed"
  record_file_if_exists "${results_dir}/nmap-heartbleed.txt"
  record_file_if_exists "${results_dir}/nmap-heartbleed.xml"
  record_file_if_exists "${results_dir}/nmap-heartbleed.log"

  # ── Nikto ────────────────────────────────────────────────────
  log "  [5/6] nikto (timeout 600s)..."
  run_with_timeout 600 \
    nikto \
      -h "${target_domain}" \
      -output "${results_dir}/nikto.txt" \
      -Format txt \
    > "${results_dir}/nikto.log" 2>&1 || true
  record_tool "nikto"
  record_file_if_exists "${results_dir}/nikto.txt"
  record_file_if_exists "${results_dir}/nikto.log"

  # ── WhatWeb ──────────────────────────────────────────────────
  log "  [6/6] whatweb..."
  run_with_timeout 60 \
    whatweb "${target_domain}" \
    > "${results_dir}/whatweb.txt" \
    2> "${results_dir}/whatweb.log" || true
  record_tool "whatweb"
  record_file_if_exists "${results_dir}/whatweb.txt"
  record_file_if_exists "${results_dir}/whatweb.log"

  # ── Extract SSL issues summary ───────────────────────────────
  extract_ssl_summary "${results_dir}" "${target_domain}"
}

# ─────────────────────────────────────────────────────────────────
# Parse sslscan XML + nmap txt + cert checks → ssl-summary.json
# Spring Boot reads this file for the ssl_report table
# ─────────────────────────────────────────────────────────────────
extract_ssl_summary() {
  local results_dir="$1"
  local target_domain="$2"
  local output_file="${results_dir}/ssl-summary.json"

  local domain="${target_domain%%:*}"
  local port="${target_domain##*:}"
  [ "${port}" = "${target_domain}" ] && port="443"

  local tls10="false"
  local tls11="false"
  local tls12="false"
  local tls13="false"
  local sweet32="false"
  local has_3des="false"
  local heartbleed="false"
  local compression="false"
  local poodle="false"
  local beast="false"
  local robot="false"
  local freak="false"
  local logjam="false"
  local rc4="false"
  local drown="false"
  local hsts="false"
  local ocsp_stapling="false"
  local xfo="false"
  local xcto="false"
  local csp="false"
  local ref_policy="false"
  local perm_policy="false"
  local coop="false"
  local corp="false"
  local coep="false"
  local cert_days_left="-1"
  local cert_issuer="unknown"
  local cert_subject="unknown"
  local cert_expired="false"
  local chain_complete="true"
  local cert_sign_alg="unknown"
  local cert_key_size="unknown"
  local cert_not_before="unknown"
  local cert_not_after_str="unknown"
  local cert_serial="unknown"
  local cert_ev="false"
  local cert_wildcard="false"
  local cert_transparency="false"
  local cert_sans_count=0

  # ── Certificate expiration check via openssl ─────────────────
  log "  [+] Checking certificate expiration..."
  local cert_info
  cert_info=$(echo | timeout 10 openssl s_client -servername "${domain}" -connect "${domain}:${port}" 2>/dev/null)

  if [ -n "${cert_info}" ]; then
    local not_after
    not_after=$(echo "${cert_info}" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    if [ -n "${not_after}" ]; then
      local expiry_epoch now_epoch
      expiry_epoch=$(date -d "${not_after}" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "${not_after}" +%s 2>/dev/null || echo "0")
      now_epoch=$(date +%s)
      if [ "${expiry_epoch}" -gt 0 ]; then
        cert_days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        [ "${cert_days_left}" -lt 0 ] && cert_expired="true"
      fi
    fi

    # Issuer
    cert_issuer=$(echo "${cert_info}" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//' | head -1)
    [ -z "${cert_issuer}" ] && cert_issuer="unknown"

    # Subject
    cert_subject=$(echo "${cert_info}" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' | head -1)
    [ -z "${cert_subject}" ] && cert_subject="unknown"

    # Certificate chain completeness
    local chain_depth
    chain_depth=$(echo "${cert_info}" | grep -c "^ [0-9]" 2>/dev/null || echo "0")
    if [ "${chain_depth}" -le 1 ]; then
      local verify_result
      verify_result=$(echo "${cert_info}" | grep "Verify return code" 2>/dev/null || echo "")
      echo "${verify_result}" | grep -q "unable to get local issuer\|unable to verify\|certificate not trusted" && chain_complete="false"
    fi

    # OCSP Stapling
    echo "${cert_info}" | grep -qi "OCSP Response Status: successful" && ocsp_stapling="true"
  fi

  # ── HTTP security headers check via curl ────────────────────
  log "  [+] Checking HTTP security headers..."
  local http_headers_raw
  local hsts_value=""
  local csp_value=""
  local csp_report_only="false"
  http_headers_raw=$(timeout 15 curl -sI -L --max-redirs 2 "https://${domain}:${port}" 2>/dev/null || echo "")
  if [ -n "${http_headers_raw}" ]; then
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*strict-transport-security:" && hsts="true"
    hsts_value=$(echo "${http_headers_raw}" | grep -iE "^[[:space:]]*strict-transport-security:" | head -1 | sed 's/^[^:]*:[ ]*//' | tr -d '\r')
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*x-frame-options:" && xfo="true"
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*x-content-type-options:.*nosniff" && xcto="true"
    # CSP enforcing vs Report-Only (Report-Only does NOT count as protecting)
    while IFS= read -r _hdr_line; do
      [ -z "${_hdr_line}" ] && continue
      _hdr_l=$(echo "${_hdr_line}" | tr -d '\r')
      _hdr_key=$(echo "${_hdr_l}" | cut -d: -f1 | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]//g')
      _hdr_val=$(echo "${_hdr_l}" | sed 's/^[^:]*:[ ]*//')
      if [ "${_hdr_key}" = "content-security-policy-report-only" ]; then
        csp_report_only="true"
        csp_value="${_hdr_val}"
      elif [ "${_hdr_key}" = "content-security-policy" ]; then
        csp="true"
        csp_value="${_hdr_val}"
      fi
    done <<< "$(echo "${http_headers_raw}" | grep -iE '^[[:space:]]*content-security-policy')"
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*referrer-policy:" && ref_policy="true"
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*permissions-policy:|^[[:space:]]*feature-policy:" && perm_policy="true"
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*cross-origin-opener-policy:" && coop="true"
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*cross-origin-resource-policy:" && corp="true"
    echo "${http_headers_raw}" | grep -Eqi "^[[:space:]]*cross-origin-embedder-policy:" && coep="true"
  fi

  # Parse protocols + Heartbleed (POSITIVE evidence only — never default to vulnerable)
  # BUGFIX: old logic was:
  #   grep "not vulnerable to heartbleed" || heartbleed=true
  # which false-positived when ANSI colors split the phrase
  # (e.g. "not vulnerable\e[0m to heartbleed") or wording differed.
  local heartbleed_evidence="non testé"
  if [ -f "${results_dir}/sslscan.log" ] || [ -f "${results_dir}/sslscan.xml" ]; then
    if [ -f "${results_dir}/sslscan.log" ]; then
      # Strip ANSI escape codes before matching
      local sslscan_clean
      sslscan_clean=$(sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "${results_dir}/sslscan.log" 2>/dev/null || cat "${results_dir}/sslscan.log")
      echo "${sslscan_clean}" | grep -q "TLSv1.0   enabled\|TLSv1.0.*enabled" && tls10="true"
      echo "${sslscan_clean}" | grep -q "TLSv1.1   enabled\|TLSv1.1.*enabled" && tls11="true"
      echo "${sslscan_clean}" | grep -q "TLSv1.2.*enabled" && tls12="true"
      echo "${sslscan_clean}" | grep -q "TLSv1.3.*enabled" && tls13="true"
      echo "${sslscan_clean}" | grep -q "3DES\|DES-CBC3" && has_3des="true"
    fi
  fi

  # Heartbleed — require explicit VULNERABLE signal from ≥1 reliable source
  # Sources (in order): sslscan.xml, nmap ssl-heartbleed, testssl, cleaned sslscan.log
  if [ -f "${results_dir}/sslscan.xml" ]; then
    if grep -qE '<heartbleed[^>]*vulnerable="1"' "${results_dir}/sslscan.xml" 2>/dev/null; then
      heartbleed="true"
      heartbleed_evidence="sslscan.xml: vulnerable=\"1\""
    elif grep -qE '<heartbleed' "${results_dir}/sslscan.xml" 2>/dev/null; then
      heartbleed_evidence="sslscan.xml: vulnerable=\"0\" (non vulnérable)"
    fi
  fi

  if [ "${heartbleed}" = "false" ] && [ -f "${results_dir}/nmap-heartbleed.txt" ]; then
    # Nmap only reports vulnerability with an explicit "VULNERABLE" / "State: VULNERABLE" block.
    # Exit code 0 + "443/tcp open" alone must NEVER count as detection.
    if grep -qiE 'State:\s*VULNERABLE|VULNERABLE:' "${results_dir}/nmap-heartbleed.txt" 2>/dev/null \
       && ! grep -qiE 'NOT VULNERABLE|not vulnerable' "${results_dir}/nmap-heartbleed.txt" 2>/dev/null; then
      heartbleed="true"
      heartbleed_evidence="nmap ssl-heartbleed: State VULNERABLE"
    else
      heartbleed_evidence="nmap ssl-heartbleed: pas de bloc VULNERABLE (OK)"
    fi
  elif [ -f "${results_dir}/nmap-heartbleed.xml" ]; then
    if grep -qiE 'script id="ssl-heartbleed"[^>]*>.*VULNERABLE|output="[^"]*VULNERABLE' \
         "${results_dir}/nmap-heartbleed.xml" 2>/dev/null; then
      heartbleed="true"
      heartbleed_evidence="nmap-heartbleed.xml: VULNERABLE"
    fi
  fi

  # Parse nmap enum for SWEET32
  if [ -f "${results_dir}/nmap-ssl.txt" ]; then
    grep -qi "SWEET32\|3DES vulnerable" "${results_dir}/nmap-ssl.txt" 2>/dev/null && sweet32="true"
  fi

  # Parse testssl.json using jq — each field is on its own line so grep won't work across lines
  # Vulnerable severities: LOW, MEDIUM, HIGH, CRITICAL, WARN  (OK and INFO = not vulnerable)
  if [ -f "${results_dir}/testssl.json" ]; then
    _testssl_sev() {
      jq -r --arg id "$1" \
        '[.scanResult[].vulnerabilities[] | select(.id == $id) | .severity] | first // "OK"' \
        "${results_dir}/testssl.json" 2>/dev/null || echo "OK"
    }
    _is_vuln_sev() {
      case "$1" in LOW|MEDIUM|HIGH|CRITICAL|WARN) return 0 ;; *) return 1 ;; esac
    }

    local sev
    # Heartbleed (CVE-2014-0160) — positive severity only
    sev=$(_testssl_sev "heartbleed")
    if _is_vuln_sev "${sev}"; then
      heartbleed="true"
      heartbleed_evidence="testssl.sh: heartbleed severity=${sev}"
    elif [ "${heartbleed}" = "false" ]; then
      case "${sev}" in
        OK|INFO) heartbleed_evidence="testssl.sh: heartbleed=${sev} (non vulnérable)" ;;
      esac
    fi
    # CRIME (TLS compression)
    sev=$(_testssl_sev "CRIME_TLS"); _is_vuln_sev "${sev}" && compression="true"
    # POODLE: SSLv3 CBC padding oracle
    sev=$(_testssl_sev "POODLE_SSL"); _is_vuln_sev "${sev}" && poodle="true"
    # BEAST: TLS 1.0 CBC — testssl reports BEAST and BEAST_CBC_TLS1 separately
    sev=$(_testssl_sev "BEAST"); _is_vuln_sev "${sev}" && beast="true"
    if [ "${beast}" = "false" ]; then
      sev=$(_testssl_sev "BEAST_CBC_TLS1"); _is_vuln_sev "${sev}" && beast="true"
    fi
    # ROBOT: RSA PKCS#1 padding oracle
    sev=$(_testssl_sev "ROBOT"); _is_vuln_sev "${sev}" && robot="true"
    # FREAK: export-grade RSA ciphers
    sev=$(_testssl_sev "FREAK"); _is_vuln_sev "${sev}" && freak="true"
    # LOGJAM: weak DH  — also check LOGJAM-common_primes
    sev=$(_testssl_sev "LOGJAM"); _is_vuln_sev "${sev}" && logjam="true"
    if [ "${logjam}" = "false" ]; then
      sev=$(_testssl_sev "LOGJAM-common_primes"); _is_vuln_sev "${sev}" && logjam="true"
    fi
    # RC4 cipher
    sev=$(_testssl_sev "RC4"); _is_vuln_sev "${sev}" && rc4="true"
    # DROWN: SSLv2 cross-protocol attack
    sev=$(_testssl_sev "DROWN"); _is_vuln_sev "${sev}" && drown="true"

    # ── Certificate details from serverDefaults ──────────────────
    _testssl_cert() {
      jq -r --arg id "$1" \
        '[.scanResult[].serverDefaults[] | select(.id | startswith($id)) | .finding] | first // ""' \
        "${results_dir}/testssl.json" 2>/dev/null || echo ""
    }
    local val
    val=$(_testssl_cert "cert_signatureAlgorithm"); [ -n "${val}" ] && cert_sign_alg="${val}"
    val=$(_testssl_cert "cert_keySize"); [ -n "${val}" ] && cert_key_size=$(echo "${val}" | sed 's/ (exponent[^)]*)//;s/ (curve[^)]*)//')
    val=$(_testssl_cert "cert_notBefore");  [ -n "${val}" ] && cert_not_before="${val}"
    val=$(_testssl_cert "cert_notAfter");   [ -n "${val}" ] && cert_not_after_str="${val}"
    val=$(_testssl_cert "cert_serialNumber"); [ -n "${val}" ] && cert_serial="${val}"
    val=$(_testssl_cert "cert_certificatePolicies_EV"); echo "${val}" | grep -qi "^yes" && cert_ev="true"
    val=$(_testssl_cert "cert_commonName"); echo "${val}" | grep -q "^\*." && cert_wildcard="true"
    val=$(_testssl_cert "certificate_transparency"); echo "${val}" | grep -qi "^yes" && cert_transparency="true"
    val=$(_testssl_cert "cert_subjectAltName")
    if [ -n "${val}" ]; then
      cert_sans_count=$(echo "${val}" | tr ' ' '\n' | grep -c '.' 2>/dev/null || echo 0)
    fi
  fi

  # Fallback: parse sslscan.log for RC4, SSLv3 (POODLE), SSLv2 (DROWN)
  if [ -f "${results_dir}/sslscan.log" ]; then
    grep -qi "RC4\|ARCFOUR"       "${results_dir}/sslscan.log" 2>/dev/null && rc4="true"
    grep -qi "SSLv3.*enabled"     "${results_dir}/sslscan.log" 2>/dev/null && poodle="true"
    grep -qi "SSLv2.*enabled"     "${results_dir}/sslscan.log" 2>/dev/null && drown="true"
  fi

  # Fallback: parse nmap for LOGJAM / FREAK / DH key size
  if [ -f "${results_dir}/nmap-ssl.txt" ]; then
    grep -qi "LOGJAM\|dh_key_size.*[0-9]\{1,3\}[^0-9]"  "${results_dir}/nmap-ssl.txt" 2>/dev/null && logjam="true"
    grep -qi "FREAK\|export.*RSA"                          "${results_dir}/nmap-ssl.txt" 2>/dev/null && freak="true"
    grep -qi "rc4\|arcfour"                                "${results_dir}/nmap-ssl.txt" 2>/dev/null && rc4="true"
  fi

  # ── Determine overall grade ─────────────────────────────────
  # A+ = TLS 1.3 + HSTS + no deprecated protocols + no vulns
  # A  = TLS 1.2+ + HSTS + no deprecated + no vulns
  # B  = deprecated protocols (TLS 1.0/1.1)
  # C  = weak ciphers (3DES, SWEET32, RC4, LOGJAM, FREAK)
  # D  = cert issues (expired, incomplete chain)
  # F  = critical vulnerability (heartbleed, POODLE, ROBOT, DROWN, BEAST)
  local grade="A"

  # Start with best possible
  if [ "${tls13}" = "true" ] && [ "${tls10}" = "false" ] && [ "${tls11}" = "false" ] && \
     [ "${hsts}" = "true" ] && [ "${has_3des}" = "false" ] && [ "${sweet32}" = "false" ] && \
     [ "${heartbleed}" = "false" ] && [ "${cert_expired}" = "false" ] && [ "${chain_complete}" = "true" ] && \
     [ "${poodle}" = "false" ] && [ "${robot}" = "false" ] && [ "${drown}" = "false" ] && \
     [ "${rc4}" = "false" ] && [ "${freak}" = "false" ] && [ "${logjam}" = "false" ]; then
    grade="A+"
  fi

  # Downgrade conditions
  if [ "${hsts}" = "false" ] && [ "${grade}" = "A+" ]; then grade="A"; fi
  if [ "${tls10}" = "true" ] || [ "${tls11}" = "true" ]; then grade="B"; fi
  if [ "${has_3des}" = "true" ] || [ "${sweet32}" = "true" ] || [ "${rc4}" = "true" ] || \
     [ "${logjam}" = "true" ] || [ "${freak}" = "true" ]; then grade="C"; fi
  if [ "${cert_expired}" = "true" ] || [ "${chain_complete}" = "false" ]; then grade="D"; fi
  if [ "${cert_days_left}" -ge 0 ] && [ "${cert_days_left}" -le 30 ] && [ "${grade}" \> "B" ]; then grade="B"; fi
  if [ "${heartbleed}" = "true" ] || [ "${poodle}" = "true" ] || [ "${robot}" = "true" ] || \
     [ "${drown}" = "true" ] || [ "${beast}" = "true" ]; then grade="F"; fi
  if [ "${compression}" = "true" ] && [ "${grade}" \> "C" ]; then grade="C"; fi

  # Write JSON
  jq -n \
    --arg  tls10          "${tls10}" \
    --arg  tls11          "${tls11}" \
    --arg  tls12          "${tls12}" \
    --arg  tls13          "${tls13}" \
    --arg  sweet32        "${sweet32}" \
    --arg  has3des        "${has_3des}" \
    --arg  heartbleed     "${heartbleed}" \
    --arg  heartbleedEv   "${heartbleed_evidence}" \
    --arg  compression    "${compression}" \
    --arg  poodle         "${poodle}" \
    --arg  beast          "${beast}" \
    --arg  robot          "${robot}" \
    --arg  freak          "${freak}" \
    --arg  logjam         "${logjam}" \
    --arg  rc4            "${rc4}" \
    --arg  drown          "${drown}" \
    --arg  hsts           "${hsts}" \
    --arg  hstsValue      "${hsts_value}" \
    --arg  ocspStapling   "${ocsp_stapling}" \
    --arg  xfo            "${xfo}" \
    --arg  xcto           "${xcto}" \
    --arg  csp            "${csp}" \
    --arg  cspReportOnly  "${csp_report_only}" \
    --arg  cspValue       "${csp_value}" \
    --arg  refPolicy      "${ref_policy}" \
    --arg  permPolicy     "${perm_policy}" \
    --arg  coop           "${coop}" \
    --arg  corp           "${corp}" \
    --arg  coep           "${coep}" \
    --arg  certExpired    "${cert_expired}" \
    --argjson certDaysLeft "${cert_days_left}" \
    --arg  certIssuer     "${cert_issuer}" \
    --arg  certSubject    "${cert_subject}" \
    --arg  chainComplete   "${chain_complete}" \
    --arg  certSignAlg     "${cert_sign_alg}" \
    --arg  certKeySize     "${cert_key_size}" \
    --arg  certNotBefore   "${cert_not_before}" \
    --arg  certNotAfterStr "${cert_not_after_str}" \
    --arg  certSerial      "${cert_serial}" \
    --arg  certEv          "${cert_ev}" \
    --arg  certWildcard    "${cert_wildcard}" \
    --arg  certTranspar    "${cert_transparency}" \
    --argjson certSansCount "${cert_sans_count}" \
    --arg  grade           "${grade}" \
    '{
      protocols: {
        tls10:      ($tls10 == "true"),
        tls11:      ($tls11 == "true"),
        tls12:      ($tls12 == "true"),
        tls13:      ($tls13 == "true")
      },
      vulnerabilities: {
        sweet32:      ($sweet32 == "true"),
        has3des:      ($has3des == "true"),
        heartbleed:   ($heartbleed == "true"),
        heartbleedEvidence: $heartbleedEv,
        crime:        ($compression == "true"),
        poodle:       ($poodle == "true"),
        beast:        ($beast == "true"),
        robot:        ($robot == "true"),
        freak:        ($freak == "true"),
        logjam:       ($logjam == "true"),
        rc4:          ($rc4 == "true"),
        drown:        ($drown == "true")
      },
      certificate: {
        expired:       ($certExpired == "true"),
        daysLeft:      $certDaysLeft,
        issuer:        $certIssuer,
        subject:       $certSubject,
        chainComplete: ($chainComplete == "true"),
        signatureAlg:  $certSignAlg,
        keySize:       $certKeySize,
        notBefore:     $certNotBefore,
        notAfterStr:   $certNotAfterStr,
        serialNumber:  $certSerial,
        ev:            ($certEv == "true"),
        wildcard:      ($certWildcard == "true"),
        transparency:  ($certTranspar == "true"),
        sansCount:     $certSansCount
      },
      headers: {
        hsts:              ($hsts == "true"),
        hstsValue:         $hstsValue,
        ocspStapling:      ($ocspStapling == "true"),
        xFrameOptions:     ($xfo == "true"),
        xContentType:      ($xcto == "true"),
        csp:               ($csp == "true"),
        cspReportOnly:     ($cspReportOnly == "true"),
        cspValue:          $cspValue,
        referrerPolicy:            ($refPolicy == "true"),
        permissionsPolicy:         ($permPolicy == "true"),
        crossOriginOpenerPolicy:   ($coop == "true"),
        crossOriginResourcePolicy: ($corp == "true"),
        crossOriginEmbedderPolicy: ($coep == "true")
      },
      grade:   $grade,
      source:  "sslscan+nmap+testssl+openssl"
    }' > "${output_file}" 2>/dev/null

  log "    SSL summary: grade=${grade} | TLS1.0=${tls10} TLS1.1=${tls11} TLS1.3=${tls13} | HSTS=${hsts} CSP=${csp} CSP-RO=${csp_report_only} XFO=${xfo} XCTO=${xcto} RP=${ref_policy} PP=${perm_policy} COOP=${coop} CORP=${corp} COEP=${coep} OCSP=${ocsp_stapling}"
  log "    Vulns: heartbleed=${heartbleed} poodle=${poodle} beast=${beast} robot=${robot} freak=${freak} logjam=${logjam} rc4=${rc4} drown=${drown} crime=${compression}"
  log "    Certificate: expires in ${cert_days_left} days | chain_complete=${chain_complete} | expired=${cert_expired}"
  record_file_if_exists "${output_file}"
}