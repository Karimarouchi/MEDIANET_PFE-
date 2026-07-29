package com.medianet.controller;

import com.medianet.util.JwtUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.ScanRequest;
import com.medianet.dto.ScanResponse;
import com.medianet.dto.SslResultDto;
import com.medianet.entity.ScanResult;
import com.medianet.entity.User;
import com.medianet.repository.ScanResultRepo;
import com.medianet.service.ScanService;
import com.medianet.service.SslLabsService;
import com.medianet.service.CensysSslService;
import com.medianet.service.SslAiService;
import com.medianet.service.UserService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

@RestController
@RequestMapping("/api/ssl")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class SslController {

    private final ScanService scanService;
    private final ScanResultRepo scanResultRepo;
    private final UserService userService;
    private final SslLabsService sslLabsService;
    private final CensysSslService censysSslService;
    private final SslAiService sslAiService;
    private final ObjectMapper mapper = new ObjectMapper(
            com.fasterxml.jackson.core.JsonFactory.builder()
                    .streamReadConstraints(com.fasterxml.jackson.core.StreamReadConstraints.builder()
                            .maxNumberLength(5000).build())
                    .build())
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);

    public SslController(ScanService scanService, ScanResultRepo scanResultRepo,
            UserService userService, SslLabsService sslLabsService,
            CensysSslService censysSslService, SslAiService sslAiService) {
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.userService = userService;
        this.sslLabsService = sslLabsService;
        this.censysSslService = censysSslService;
        this.sslAiService = sslAiService;
    }

    // ── POST /api/ssl/scan → launch ssl-only scan ───────────────────
    @PostMapping("/scan")
    public ResponseEntity<ScanResponse> startSslScan(
            @RequestBody SslScanRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        ScanRequest scanReq = new ScanRequest();
        scanReq.setScanMode("ssl-only");
        scanReq.setTargetDomain(req.getDomain());
        scanReq.setRepoUrl("ssl://" + req.getDomain()); // stable DB identifier
        ScanResponse resp = scanService.startScan(scanReq, currentUser);

        // Fire SSL Labs + Censys analyses in parallel (non-blocking @Async)
        ScanResult scanEntity = scanResultRepo.findById(resp.getScanId()).orElse(null);
        if (scanEntity != null) {
            String dir = scanEntity.getResultsDir();
            sslLabsService.analyzeAsync(req.getDomain(), dir);
            censysSslService.analyzeAsync(req.getDomain(), dir);
        }

        return ResponseEntity.ok(resp);
    }

    // ── GET /api/ssl/scan/{scanId}/logs → SSE log stream ───────────
    @GetMapping(value = "/scan/{scanId}/logs", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamLogs(@PathVariable Long scanId,
            jakarta.servlet.http.HttpServletResponse response) {
        response.setHeader("X-Accel-Buffering", "no");
        response.setHeader("Cache-Control", "no-cache");
        return scanService.createLogEmitter(scanId);
    }

    // ── GET /api/ssl/scan/{scanId}/result → parsed SSL summary ─────
    @GetMapping("/scan/{scanId}/result")
    public ResponseEntity<SslResultDto> getSslResult(@PathVariable Long scanId) {
        ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
        if (scan == null)
            return ResponseEntity.notFound().build();

        SslResultDto dto = SslResultDto.builder()
                .scanStatus(scan.getStatus().name())
                .domain(resolveSslDomain(scan))
                .grade("?")
                .certDaysLeft(-1)
                .chainComplete(true)
                .sourcesTotal(4)
                .build();

        // ── Source 1: Kali Linux (ssl-summary.json) ───────────────────
        boolean isDone = scan.getStatus() == ScanResult.ScanStatus.COMPLETED
                || scan.getStatus() == ScanResult.ScanStatus.FAILED;
        if (isDone) {
            File summaryFile = Path.of(scan.getResultsDir(), "ssl-summary.json").toFile();
            if (summaryFile.exists()) {
                try {
                    JsonNode root = mapper.readTree(summaryFile);

                    dto.setGrade(text(root, "grade", "?"));
                    dto.setSource(text(root, "source", ""));

                    JsonNode proto = root.path("protocols");
                    dto.setTls10(proto.path("tls10").asBoolean(false));
                    dto.setTls11(proto.path("tls11").asBoolean(false));
                    dto.setTls12(proto.path("tls12").asBoolean(true));
                    dto.setTls13(proto.path("tls13").asBoolean(false));

                    JsonNode vuln = root.path("vulnerabilities");
                    boolean heartbleedFlag = vuln.path("heartbleed").asBoolean(false);
                    String heartbleedEv = vuln.path("heartbleedEvidence").asText(null);
                    // Correct known false-positives from legacy parser (ANSI / inverted grep)
                    heartbleedFlag = resolveHeartbleed(scan.getResultsDir(), heartbleedFlag);
                    if (heartbleedEv == null || heartbleedEv.isBlank()) {
                        heartbleedEv = buildHeartbleedEvidence(scan.getResultsDir(), heartbleedFlag);
                    }
                    dto.setHeartbleed(heartbleedFlag);
                    dto.setHeartbleedEvidence(heartbleedEv);
                    dto.setSweet32(vuln.path("sweet32").asBoolean(false));
                    dto.setHas3des(vuln.path("has3des").asBoolean(false));
                    dto.setCrime(vuln.path("crime").asBoolean(false));
                    dto.setPoodle(vuln.path("poodle").asBoolean(false));
                    dto.setBeast(vuln.path("beast").asBoolean(false));
                    dto.setRobot(vuln.path("robot").asBoolean(false));
                    dto.setFreak(vuln.path("freak").asBoolean(false));
                    dto.setLogjam(vuln.path("logjam").asBoolean(false));
                    dto.setRc4(vuln.path("rc4").asBoolean(false));
                    dto.setDrown(vuln.path("drown").asBoolean(false));

                    JsonNode cert = root.path("certificate");
                    dto.setCertExpired(cert.path("expired").asBoolean(false));
                    dto.setCertDaysLeft(cert.path("daysLeft").asInt(-1));
                    dto.setCertIssuer(cert.path("issuer").asText("unknown"));
                    dto.setCertSubject(cert.path("subject").asText("unknown"));
                    dto.setChainComplete(cert.path("chainComplete").asBoolean(true));
                    dto.setCertSignatureAlg(cert.path("signatureAlg").asText("unknown"));
                    dto.setCertKeySize(cert.path("keySize").asText("unknown"));
                    dto.setCertNotBefore(cert.path("notBefore").asText("—"));
                    dto.setCertNotAfterStr(cert.path("notAfterStr").asText("—"));
                    dto.setCertSerialNumber(cert.path("serialNumber").asText("unknown"));
                    dto.setCertEv(cert.path("ev").asBoolean(false));
                    dto.setCertWildcard(cert.path("wildcard").asBoolean(false));
                    dto.setCertTransparency(cert.path("transparency").asBoolean(false));
                    dto.setCertSansCount(cert.path("sansCount").asInt(0));

                    JsonNode headers = root.path("headers");
                    dto.setHsts(headers.path("hsts").asBoolean(false));
                    dto.setHstsValue(headers.path("hstsValue").asText(null));
                    dto.setOcspStapling(headers.path("ocspStapling").asBoolean(false));
                    dto.setXFrameOptions(headers.path("xFrameOptions").asBoolean(false));
                    dto.setXContentTypeOptions(headers.path("xContentType").asBoolean(false));
                    dto.setContentSecurityPolicy(headers.path("csp").asBoolean(false));
                    dto.setCspReportOnly(headers.path("cspReportOnly").asBoolean(false));
                    dto.setCspValue(headers.path("cspValue").asText(null));
                    dto.setReferrerPolicy(headers.path("referrerPolicy").asBoolean(false));
                    dto.setPermissionsPolicy(headers.path("permissionsPolicy").asBoolean(false));

                } catch (Exception e) {
                    // ssl-summary.json malformed — return partial DTO with status
                }
            }
        }

        // Live refresh of security headers (so nginx fixes appear without full Kali re-scan)
        refreshLiveSecurityHeaders(dto);

        // ── Source 2: SSL Labs (ssl-labs-result.json) ──────────────────
        File labsFile = Path.of(scan.getResultsDir(), "ssl-labs-result.json").toFile();
        if (labsFile.exists()) {
            try {
                JsonNode labs = mapper.readTree(labsFile);
                String labsStatus = labs.path("status").asText("PENDING");
                dto.setSsllabsStatus(labsStatus);
                if ("READY".equals(labsStatus)) {
                    dto.setSsllabsGrade(labs.path("grade").asText("?"));
                    dto.setSsllabsIpAddress(labs.path("ipAddress").asText(""));
                    dto.setSsllabsHasWarnings(labs.path("hasWarnings").asBoolean(false));
                    dto.setSsllabsForwardSecrecy(labs.path("forwardSecrecy").asBoolean(false));
                    dto.setSsllabsDrown(labs.path("drownVulnerable").asBoolean(false));
                } else {
                    dto.setSsllabsGrade("?");
                }
            } catch (Exception e) {
                dto.setSsllabsStatus("ERROR");
                dto.setSsllabsGrade("?");
            }
        } else {
            dto.setSsllabsStatus("DISABLED");
            dto.setSsllabsGrade("?");
        }

        // ── Source 3: Censys (censys-result.json) ────────────────────
        File censysFile = Path.of(scan.getResultsDir(), "censys-result.json").toFile();
        if (censysFile.exists()) {
            try {
                JsonNode cns = mapper.readTree(censysFile);
                String cnsStatus = cns.path("status").asText("PENDING");
                dto.setCensysStatus(cnsStatus);
                if ("READY".equals(cnsStatus)) {
                    dto.setCensysGrade(cns.path("grade").asText("?"));
                    dto.setCensysIpAddress(cns.path("ipAddress").asText(""));
                    dto.setCensysDaysLeft(cns.path("daysLeft").asInt(-1));
                    dto.setCensysExpired(cns.path("expired").asBoolean(false));
                    dto.setCensysCertValid(cns.path("certValid").asBoolean(false));
                    dto.setCensysIssuer(cns.path("issuer").asText(""));
                    dto.setCensysKeySize(cns.path("keySize").asText(""));
                    dto.setCensysValidationLevel(cns.path("validationLevel").asText("DV"));
                    dto.setCensysCtPresent(cns.path("ctPresent").asBoolean(false));
                    dto.setCensysSansCount(cns.path("sansCount").asInt(0));
                    dto.setCensysOpenPorts(cns.path("openPorts").asText(""));
                } else {
                    dto.setCensysGrade("?");
                }
            } catch (Exception e) {
                dto.setCensysStatus("ERROR");
                dto.setCensysGrade("?");
            }
        } else {
            dto.setCensysStatus("PENDING");
            dto.setCensysGrade("?");
        }

        // ── Source 4: SSLyze (sslyze.json produced by Kali scanner, step 1/6) ──
        // Parse as soon as the file exists — SSLyze writes its own complete JSON
        // independently of the other tools. No need to wait for the full scan to
        // finish.
        // Guard: if the file is still being written (timeout-killed sslyze), parsing
        // will throw JsonParseException → treat as PENDING while scan is running.
        File sslyzeFile = Path.of(scan.getResultsDir(), "sslyze.json").toFile();
        if (sslyzeFile.exists() && sslyzeFile.length() > 10) {
            try {
                JsonNode sz = mapper.readTree(sslyzeFile);
                JsonNode servers = sz.path("server_scan_results");
                if (servers.isArray() && servers.size() > 0) {
                    JsonNode szScan = servers.get(0);
                    String szScanStatus = szScan.path("scan_status").asText("ERROR");
                    if ("COMPLETED".equals(szScanStatus)) {
                        dto.setSslyzeStatus("READY");
                        JsonNode sr = szScan.path("scan_result");
                        String szIp = szScan.path("server_location").path("ip_address").asText("");
                        dto.setSslyzeIpAddress(szIp);

                        // Protocols
                        boolean ssl20 = sz_hasAccepted(sr, "ssl_2_0_cipher_suites");
                        boolean ssl30 = sz_hasAccepted(sr, "ssl_3_0_cipher_suites");
                        boolean tls10 = sz_hasAccepted(sr, "tls_1_0_cipher_suites");
                        boolean tls11 = sz_hasAccepted(sr, "tls_1_1_cipher_suites");
                        boolean tls12 = sz_hasAccepted(sr, "tls_1_2_cipher_suites");
                        boolean tls13 = sz_hasAccepted(sr, "tls_1_3_cipher_suites");
                        dto.setSslyzeSupportsSSL20(ssl20);
                        dto.setSslyzeSupportsSSL30(ssl30);
                        dto.setSslyzeSupportsTLS10(tls10);
                        dto.setSslyzeSupportsTLS11(tls11);
                        dto.setSslyzeSupportsTLS12(tls12);
                        dto.setSslyzeSupportsTLS13(tls13);
                        int cipherCount = sz_cipherCount(sr, "tls_1_2_cipher_suites")
                                + sz_cipherCount(sr, "tls_1_3_cipher_suites");
                        dto.setSslyzeCipherCount(cipherCount);

                        // Vulnerabilities
                        boolean hb = sr.path("heartbleed").path("result").path("is_vulnerable_to_heartbleed")
                                .asBoolean(false);
                        boolean ccs = sr.path("openssl_ccs_injection").path("result")
                                .path("is_vulnerable_to_ccs_injection").asBoolean(false);
                        boolean comp = sr.path("tls_compression").path("result").path("supports_compression")
                                .asBoolean(false);
                        boolean renego = sr.path("session_renegotiation").path("result")
                                .path("is_vulnerable_to_client_renegotiation_dos").asBoolean(false);
                        String robotRaw = sr.path("robot").path("result").path("robot_result").asText("UNKNOWN");
                        boolean robot = robotRaw.startsWith("VULNERABLE");
                        dto.setSslyzeHeartbleed(hb);
                        dto.setSslyzeRobot(robot);
                        dto.setSslyzeCcsInjection(ccs);
                        dto.setSslyzeCompression(comp);
                        dto.setSslyzeInsecureRenegotiation(renego);

                        // Certificate
                        JsonNode certDeploy = sr.path("certificate_info").path("result")
                                .path("certificate_deployments");
                        if (certDeploy.isArray() && certDeploy.size() > 0) {
                            JsonNode dep = certDeploy.get(0);
                            JsonNode chain = dep.path("received_certificate_chain");
                            if (chain.isArray() && chain.size() > 0) {
                                JsonNode leaf = chain.get(0);
                                dto.setSslyzeCertSubject(leaf.path("subject").path("rfc4514_string").asText(""));
                                dto.setSslyzeCertIssuer(leaf.path("issuer").path("rfc4514_string").asText(""));
                                dto.setSslyzeKeySize(leaf.path("public_key").path("key_size").asInt(0));
                                String notAfter = leaf.path("not_valid_after").asText("");
                                if (!notAfter.isBlank()) {
                                    try {
                                        int days = (int) java.time.Instant.now().until(
                                                java.time.Instant.parse(notAfter), java.time.temporal.ChronoUnit.DAYS);
                                        dto.setSslyzeDaysLeft(days);
                                    } catch (Exception ignored) {
                                    }
                                }
                            }
                            boolean chainTrusted = !dep.path("verified_certificate_chain").isNull()
                                    && !dep.path("verified_certificate_chain").isMissingNode()
                                    && dep.path("verified_certificate_chain").isArray()
                                    && dep.path("verified_certificate_chain").size() > 0;
                            dto.setSslyzeChainTrusted(chainTrusted);
                            boolean ocsp = !dep.path("ocsp_response").isNull()
                                    && !dep.path("ocsp_response").isMissingNode();
                            dto.setSslyzeOcspStapling(ocsp);
                        }

                        // SSLyze grade
                        String szGrade;
                        if (hb || robot || ccs || !dto.isSslyzeChainTrusted()) {
                            szGrade = "F";
                        } else if (ssl20 || ssl30) {
                            szGrade = "D";
                        } else if (tls10 || dto.getSslyzeKeySize() > 0 && dto.getSslyzeKeySize() < 2048) {
                            szGrade = "C";
                        } else if (tls11 || !tls13) {
                            szGrade = "B";
                        } else if (dto.isSslyzeOcspStapling()) {
                            szGrade = "A+";
                        } else {
                            szGrade = "A";
                        }
                        dto.setSslyzeGrade(szGrade);
                    } else {
                        dto.setSslyzeStatus("ERROR");
                        dto.setSslyzeGrade("?");
                    }
                } else {
                    dto.setSslyzeStatus("ERROR");
                    dto.setSslyzeGrade("?");
                }
            } catch (Exception e) {
                // Parse failed: file may be partially written (sslyze killed by timeout)
                // or contain unexpected structure. If scan still running → retry later.
                try {
                    java.nio.file.Files.writeString(Path.of(scan.getResultsDir(), "sslyze-error.txt"),
                            e.getClass().getName() + ": " + e.getMessage());
                } catch (Exception ignored) {
                }
                if (!isDone) {
                    dto.setSslyzeStatus("PENDING");
                    dto.setSslyzeGrade("?");
                } else {
                    dto.setSslyzeStatus("ERROR");
                    dto.setSslyzeGrade("?");
                }
            }
        } else if (isDone) {
            // Scan finished but sslyze.json missing → SSLyze failed
            dto.setSslyzeStatus("ERROR");
            dto.setSslyzeGrade("?");
        } else {
            // Scan still running and file not yet created → waiting
            dto.setSslyzeStatus("PENDING");
            dto.setSslyzeGrade("?");
        }

        // ── Combined grade: weighted fusion of ready sources ────────
        // Weights: Kali=20, SSL Labs=30, Censys=30, SSLyze=20
        int ready = 0;
        double weightedSum = 0;
        double totalWeight = 0;
        boolean anyF = false;

        if (!"?".equals(dto.getGrade()) && isDone) {
            int s = gradeScore(dto.getGrade());
            if (s >= 0) {
                weightedSum += s * 20.0;
                totalWeight += 20;
                ready++;
                if (s == 0)
                    anyF = true;
            }
        }
        if ("READY".equals(dto.getSsllabsStatus()) && !"?".equals(dto.getSsllabsGrade())) {
            int s = gradeScore(dto.getSsllabsGrade());
            if (s >= 0) {
                weightedSum += s * 30.0;
                totalWeight += 30;
                ready++;
                if (s == 0)
                    anyF = true;
            }
        }
        if ("READY".equals(dto.getCensysStatus()) && !"?".equals(dto.getCensysGrade())) {
            int s = gradeScore(dto.getCensysGrade());
            if (s >= 0) {
                weightedSum += s * 30.0;
                totalWeight += 30;
                ready++;
                if (s == 0)
                    anyF = true;
            }
        }
        if ("READY".equals(dto.getSslyzeStatus()) && !"?".equals(dto.getSslyzeGrade())) {
            int s = gradeScore(dto.getSslyzeGrade());
            if (s >= 0) {
                weightedSum += s * 20.0;
                totalWeight += 20;
                ready++;
                if (s == 0)
                    anyF = true;
            }
        }

        dto.setSourcesReady(ready);
        dto.setCombinedGrade(anyF ? "F" : (totalWeight > 0 ? scoreToGrade(weightedSum / totalWeight) : "?"));

        return ResponseEntity.ok(dto);
    }

    private String resolveSslDomain(ScanResult scan) {
        if (scan.getRepository() != null) {
            String td = scan.getRepository().getTargetDomain();
            if (td != null && !td.isBlank()) return td.trim();
            String url = scan.getRepository().getRepoUrl();
            if (url != null) {
                String d = url.trim();
                if (d.startsWith("ssl://")) d = d.substring(6);
                if (d.startsWith("https://")) d = d.substring(8);
                if (d.startsWith("http://")) d = d.substring(7);
                if (d.contains("/")) d = d.substring(0, d.indexOf('/'));
                if (!d.isBlank()) return d;
            }
        }
        return "";
    }

    /**
     * Re-check HSTS / CSP / security headers live against the domain.
     * Avoids stale Kali snapshots after the user fixes nginx.
     */
    private void refreshLiveSecurityHeaders(SslResultDto dto) {
        String domain = dto.getDomain();
        if (domain == null || domain.isBlank() || "?".equals(domain)) return;
        domain = domain.trim();
        if (domain.startsWith("https://")) domain = domain.substring(8);
        if (domain.startsWith("http://")) domain = domain.substring(7);
        if (domain.contains("/")) domain = domain.substring(0, domain.indexOf('/'));
        // targetDomain may be "host:443"
        if (domain.contains(":") && domain.lastIndexOf(':') > domain.lastIndexOf(']')) {
            domain = domain.substring(0, domain.lastIndexOf(':'));
        }
        if (domain.isBlank()) return;

        String url = "https://" + domain + "/";
        try {
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                    .followRedirects(java.net.http.HttpClient.Redirect.NORMAL)
                    .connectTimeout(java.time.Duration.ofSeconds(10))
                    .build();

            java.net.http.HttpHeaders hdrs = fetchHeaders(client, url, true);
            // Always prefer GET if critical headers missing (some stacks omit them on HEAD)
            if (!hasAnySecurityHeader(hdrs)
                    || firstHeader(hdrs, "x-frame-options") == null
                    || firstHeader(hdrs, "x-content-type-options") == null) {
                java.net.http.HttpHeaders getHdrs = fetchHeaders(client, url, false);
                if (hasAnySecurityHeader(getHdrs)) {
                    hdrs = getHdrs;
                }
            }
            if (hdrs == null) {
                dto.setHeadersLiveChecked(false);
                return;
            }

            String hsts = firstHeader(hdrs, "strict-transport-security");
            if (hsts != null && !hsts.isBlank()) {
                dto.setHsts(true);
                dto.setHstsValue(hsts.trim());
            }

            String csp = firstHeader(hdrs, "content-security-policy");
            String cspRo = firstHeader(hdrs, "content-security-policy-report-only");
            if (csp != null && !csp.isBlank()) {
                dto.setContentSecurityPolicy(true);
                dto.setCspReportOnly(false);
                dto.setCspValue(csp.trim());
            } else if (cspRo != null && !cspRo.isBlank()) {
                dto.setContentSecurityPolicy(false);
                dto.setCspReportOnly(true);
                dto.setCspValue(cspRo.trim());
            }

            String xfo = firstHeader(hdrs, "x-frame-options");
            if (xfo != null && !xfo.isBlank()) {
                dto.setXFrameOptions(true);
            }
            String xcto = firstHeader(hdrs, "x-content-type-options");
            if (xcto != null && xcto.toLowerCase(java.util.Locale.ROOT).contains("nosniff")) {
                dto.setXContentTypeOptions(true);
            }
            if (firstHeader(hdrs, "referrer-policy") != null) dto.setReferrerPolicy(true);
            if (firstHeader(hdrs, "permissions-policy") != null
                    || firstHeader(hdrs, "feature-policy") != null) {
                dto.setPermissionsPolicy(true);
            }

            dto.setHeadersLiveChecked(true);
        } catch (Exception e) {
            dto.setHeadersLiveChecked(false);
        }
    }

    private static java.net.http.HttpHeaders fetchHeaders(
            java.net.http.HttpClient client, String url, boolean head) throws Exception {
        java.net.http.HttpRequest.Builder b = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .timeout(java.time.Duration.ofSeconds(15));
        if (head) {
            b.method("HEAD", java.net.http.HttpRequest.BodyPublishers.noBody());
        } else {
            b.GET();
        }
        return client.send(b.build(), java.net.http.HttpResponse.BodyHandlers.discarding()).headers();
    }

    private static boolean hasAnySecurityHeader(java.net.http.HttpHeaders hdrs) {
        if (hdrs == null || hdrs.map().isEmpty()) return false;
        return firstHeader(hdrs, "strict-transport-security") != null
                || firstHeader(hdrs, "content-security-policy") != null
                || firstHeader(hdrs, "content-security-policy-report-only") != null
                || firstHeader(hdrs, "x-frame-options") != null
                || firstHeader(hdrs, "x-content-type-options") != null;
    }

    private static String firstHeader(java.net.http.HttpHeaders headers, String name) {
        return headers.firstValue(name).orElse(null);
    }

    // ── Heartbleed false-positive correction (legacy Kali parser) ─────
    /**
     * Legacy sslscan.log parsing used: grep "not vulnerable to heartbleed" || true
     * which flipped to VULNERABLE when ANSI codes split the phrase.
     * Re-check artifact files and only keep heartbleed=true with positive proof.
     */
    private boolean resolveHeartbleed(String resultsDir, boolean summaryFlag) {
        if (resultsDir == null || resultsDir.isBlank()) return false;

        File xml = Path.of(resultsDir, "sslscan.xml").toFile();
        if (xml.exists()) {
            String content = readQuiet(xml);
            if (content != null) {
                if (content.matches("(?s).*<heartbleed[^>]*vulnerable=\"1\".*")) return true;
                if (content.contains("<heartbleed")) return false;
            }
        }

        File nmapTxt = Path.of(resultsDir, "nmap-heartbleed.txt").toFile();
        if (nmapTxt.exists()) {
            String content = readQuiet(nmapTxt);
            if (content != null) {
                String lower = content.toLowerCase();
                if (lower.contains("state: vulnerable") || lower.contains("vulnerable:")) {
                    if (!lower.contains("not vulnerable")) return true;
                }
                return false;
            }
        }

        File nmapXml = Path.of(resultsDir, "nmap-heartbleed.xml").toFile();
        if (nmapXml.exists()) {
            String content = readQuiet(nmapXml);
            if (content != null && content.toUpperCase().contains("VULNERABLE")
                    && !content.toLowerCase().contains("not vulnerable")) {
                return true;
            }
        }

        File sslscanLog = Path.of(resultsDir, "sslscan.log").toFile();
        if (sslscanLog.exists()) {
            String content = stripAnsi(readQuiet(sslscanLog));
            if (content != null) {
                String lower = content.toLowerCase();
                if (lower.contains("not vulnerable") && lower.contains("heartbleed")) return false;
                if (lower.contains("vulnerable to heartbleed") && !lower.contains("not vulnerable")) return true;
            }
        }

        File testssl = Path.of(resultsDir, "testssl.json").toFile();
        if (testssl.exists()) {
            try {
                JsonNode root = mapper.readTree(testssl);
                for (JsonNode scanRes : root.path("scanResult")) {
                    for (JsonNode v : scanRes.path("vulnerabilities")) {
                        if (!"heartbleed".equalsIgnoreCase(v.path("id").asText())) continue;
                        String sev = v.path("severity").asText("OK").toUpperCase();
                        return sev.equals("LOW") || sev.equals("MEDIUM") || sev.equals("HIGH")
                                || sev.equals("CRITICAL") || sev.equals("WARN");
                    }
                }
            } catch (Exception ignored) {
            }
        }

        // No positive proof found → never trust legacy true flag alone
        return false;
    }

    private String buildHeartbleedEvidence(String resultsDir, boolean vulnerable) {
        if (resultsDir == null) return vulnerable ? "détecté (sans détail)" : "non vulnérable";
        File xml = Path.of(resultsDir, "sslscan.xml").toFile();
        if (xml.exists()) {
            String c = readQuiet(xml);
            if (c != null && c.contains("<heartbleed")) {
                return vulnerable
                        ? "sslscan.xml: vulnerable=\"1\""
                        : "sslscan.xml: vulnerable=\"0\" — non vulnérable";
            }
        }
        File nmapTxt = Path.of(resultsDir, "nmap-heartbleed.txt").toFile();
        if (nmapTxt.exists()) {
            return vulnerable
                    ? "nmap ssl-heartbleed: State VULNERABLE"
                    : "nmap ssl-heartbleed: pas de bloc VULNERABLE (OK)";
        }
        File log = Path.of(resultsDir, "sslscan.log").toFile();
        if (log.exists()) {
            String c = stripAnsi(readQuiet(log));
            if (c != null && c.toLowerCase().contains("heartbleed")) {
                return vulnerable ? "sslscan.log: heartbleed vulnerable" : "sslscan.log: not vulnerable to heartbleed";
            }
        }
        return vulnerable ? "preuve positive" : "aucune preuve VULNERABLE";
    }

    private static String stripAnsi(String s) {
        if (s == null) return null;
        return s.replaceAll("\u001B\\[[0-9;]*[a-zA-Z]", "");
    }

    private static String readQuiet(File f) {
        try {
            return Files.readString(f.toPath(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            try {
                return Files.readString(f.toPath(), StandardCharsets.ISO_8859_1);
            } catch (Exception e2) {
                return null;
            }
        }
    }

    // ── SSLyze helpers ────────────────────────────────────────────────
    private boolean sz_hasAccepted(JsonNode sr, String key) {
        JsonNode res = sr.path(key).path("result");
        if (res.isMissingNode() || res.isNull())
            return false;
        JsonNode suites = res.path("accepted_cipher_suites");
        return suites.isArray() && suites.size() > 0;
    }

    private int sz_cipherCount(JsonNode sr, String key) {
        JsonNode res = sr.path(key).path("result");
        if (res.isMissingNode() || res.isNull())
            return 0;
        JsonNode suites = res.path("accepted_cipher_suites");
        return suites.isArray() ? suites.size() : 0;
    }

    // ── Grade scoring helpers ─────────────────────────────────────────
    private int gradeScore(String grade) {
        return switch (grade != null ? grade : "?") {
            case "A+" -> 100;
            case "A" -> 90;
            case "B" -> 75;
            case "C" -> 60;
            case "D" -> 45;
            case "F" -> 0;
            default -> -1;
        };
    }

    private String scoreToGrade(double score) {
        if (score >= 97)
            return "A+";
        if (score >= 85)
            return "A";
        if (score >= 70)
            return "B";
        if (score >= 55)
            return "C";
        if (score >= 40)
            return "D";
        return "F";
    }

    // ── POST /api/ssl/ai-analysis → Gemini SSL assessment ─────────────
    @PostMapping("/ai-analysis")
    public ResponseEntity<java.util.Map<String, Object>> sslAiAnalysis(
            @RequestBody java.util.Map<String, Object> context) {
        return ResponseEntity.ok(sslAiService.analyze(context));
    }

    // ── Inner request DTO ─────────────────────────────────────────────
    public static class SslScanRequest {
        private String domain;

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }
    }

    // ── Helper ────────────────────────────────────────────────────────
    private String text(JsonNode node, String field, String def) {
        JsonNode n = node.get(field);
        return (n == null || n.isNull()) ? def : n.asText(def);
    }
}
