package com.medianet.controller;

import com.medianet.util.JwtUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.CertChainEntryDto;
import com.medianet.dto.CertNameDto;
import com.medianet.dto.CertSanEntryDto;
import com.medianet.dto.CertTrustStoreDto;
import com.medianet.dto.CertificateDetailDto;
import com.medianet.dto.ScanRequest;
import com.medianet.dto.ScanResponse;
import com.medianet.dto.SslResultDto;
import com.medianet.dto.TlsCipherSuiteDto;
import com.medianet.dto.TlsProtocolDetailDto;
import com.medianet.entity.ScanResult;
import com.medianet.entity.User;
import com.medianet.repository.ScanResultRepo;
import com.medianet.service.ScanService;
import com.medianet.service.SslLabsService;
import com.medianet.service.CensysSslService;
import com.medianet.service.SslAiService;
import com.medianet.service.SslResultStoreService;
import com.medianet.service.UserService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@RestController
@RequestMapping("/api/ssl")
public class SslController {

    private final ScanService scanService;
    private final ScanResultRepo scanResultRepo;
    private final UserService userService;
    private final SslLabsService sslLabsService;
    private final CensysSslService censysSslService;
    private final SslAiService sslAiService;
    private final SslResultStoreService sslResultStoreService;
    private final ObjectMapper mapper = new ObjectMapper(
            com.fasterxml.jackson.core.JsonFactory.builder()
                    .streamReadConstraints(com.fasterxml.jackson.core.StreamReadConstraints.builder()
                            .maxNumberLength(5000).build())
                    .build())
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);

    public SslController(ScanService scanService, ScanResultRepo scanResultRepo,
            UserService userService, SslLabsService sslLabsService,
            CensysSslService censysSslService, SslAiService sslAiService,
            SslResultStoreService sslResultStoreService) {
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.userService = userService;
        this.sslLabsService = sslLabsService;
        this.censysSslService = censysSslService;
        this.sslAiService = sslAiService;
        this.sslResultStoreService = sslResultStoreService;
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
    @Transactional(readOnly = true)
    public ResponseEntity<SslResultDto> getSslResult(@PathVariable Long scanId) {
        // JOIN FETCH repository — required with spring.jpa.open-in-view=false
        ScanResult scan = scanResultRepo.findByIdWithRepository(scanId).orElse(null);
        if (scan == null)
            return ResponseEntity.notFound().build();

        boolean isDone = scan.getStatus() == ScanResult.ScanStatus.COMPLETED
                || scan.getStatus() == ScanResult.ScanStatus.FAILED;

        String resultsDir = scan.getResultsDir();
        boolean diskAvailable = resultsDir != null && !resultsDir.isBlank()
                && !resultsDir.startsWith("db://");

        // Prefer DB snapshot only when disk was already cleaned (full result frozen in DB).
        // While files still exist, rebuild from disk so SSL Labs / Censys async updates are picked up.
        if (!diskAvailable) {
            var stored = sslResultStoreService.findStored(scanId);
            if (stored.isPresent()) {
                SslResultDto fromDb = stored.get();
                fromDb.setScanStatus(scan.getStatus().name());
                if (fromDb.getDomain() == null || fromDb.getDomain().isBlank()) {
                    fromDb.setDomain(resolveSslDomain(scan));
                }
                refreshLiveSecurityHeaders(fromDb);
                return ResponseEntity.ok(fromDb);
            }
        }

        SslResultDto dto = SslResultDto.builder()
                .scanStatus(scan.getStatus().name())
                .domain(resolveSslDomain(scan))
                .grade("?")
                .certDaysLeft(-1)
                .chainComplete(true)
                .sourcesTotal(4)
                .build();

        // ── Source 1: Kali Linux (ssl-summary.json) ───────────────────
        if (isDone && diskAvailable) {
            File summaryFile = Path.of(resultsDir, "ssl-summary.json").toFile();
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
                    heartbleedFlag = resolveHeartbleed(resultsDir, heartbleedFlag);
                    if (heartbleedEv == null || heartbleedEv.isBlank()) {
                        heartbleedEv = buildHeartbleedEvidence(resultsDir, heartbleedFlag);
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
                    dto.setCrossOriginOpenerPolicy(headers.path("crossOriginOpenerPolicy").asBoolean(false));
                    dto.setCrossOriginResourcePolicy(headers.path("crossOriginResourcePolicy").asBoolean(false));
                    dto.setCrossOriginEmbedderPolicy(headers.path("crossOriginEmbedderPolicy").asBoolean(false));

                } catch (Exception e) {
                    // ssl-summary.json malformed — return partial DTO with status
                }
            }
        }

        // Live refresh of security headers (so nginx fixes appear without full Kali re-scan)
        refreshLiveSecurityHeaders(dto);

        // ── Source 2: SSL Labs (ssl-labs-result.json) ──────────────────
        File labsFile = diskAvailable ? Path.of(resultsDir, "ssl-labs-result.json").toFile() : null;
        if (labsFile != null && labsFile.exists()) {
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
        File censysFile = diskAvailable ? Path.of(resultsDir, "censys-result.json").toFile() : null;
        if (censysFile != null && censysFile.exists()) {
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
        File sslyzeFile = diskAvailable ? Path.of(resultsDir, "sslyze.json").toFile() : null;
        if (sslyzeFile != null && sslyzeFile.exists() && sslyzeFile.length() > 10) {
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

                        dto.setSslyzeVersion(sz.path("sslyze_version").asText(null));
                        dto.setSslyzeScanStarted(sz.path("date_scans_started").asText(null));
                        JsonNode loc = szScan.path("server_location");
                        int szPort = loc.path("port").asInt(443);
                        dto.setSslyzePort(szPort);
                        String sni = szScan.path("network_configuration")
                                .path("tls_server_name_indication").asText(null);
                        if (sni == null || sni.isBlank()) {
                            sni = loc.path("hostname").asText(null);
                        }
                        dto.setSslyzeSni(sni);

                        // Vulnerabilities
                        boolean hb = sr.path("heartbleed").path("result").path("is_vulnerable_to_heartbleed")
                                .asBoolean(false);
                        boolean ccs = sr.path("openssl_ccs_injection").path("result")
                                .path("is_vulnerable_to_ccs_injection").asBoolean(false);
                        boolean comp = sr.path("tls_compression").path("result").path("supports_compression")
                                .asBoolean(false);
                        Boolean secureRenego = null;
                        JsonNode renegoNode = sr.path("session_renegotiation").path("result");
                        if (!renegoNode.isMissingNode() && !renegoNode.isNull()) {
                            if (renegoNode.has("supports_secure_renegotiation")
                                    && !renegoNode.path("supports_secure_renegotiation").isNull()) {
                                secureRenego = renegoNode.path("supports_secure_renegotiation").asBoolean();
                            }
                        }
                        boolean renego = renegoNode.path("is_vulnerable_to_client_renegotiation_dos")
                                .asBoolean(false);
                        String robotRaw = sr.path("robot").path("result").path("robot_result").asText("UNKNOWN");
                        boolean robot = robotRaw.startsWith("VULNERABLE");
                        dto.setSslyzeHeartbleed(hb);
                        dto.setSslyzeRobot(robot);
                        dto.setSslyzeCcsInjection(ccs);
                        dto.setSslyzeCompression(comp);
                        dto.setSslyzeInsecureRenegotiation(renego);

                        dto.setTlsProtocols(buildTlsProtocolsFromSslyze(
                                sr, dto.getDomain(), szIp, szPort, sni,
                                dto.getSslyzeVersion(), dto.getSslyzeScanStarted(),
                                comp, secureRenego));

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

                            String completed = sz.path("date_scans_completed").asText(null);
                            dto.setCertificateDetail(buildCertificateDetailFromSslyze(
                                    dep, dto.getDomain(), szIp, szPort, sni,
                                    dto.getSslyzeVersion(), dto.getSslyzeScanStarted(), completed,
                                    dto.isOcspStapling()));
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
                if (diskAvailable) {
                    try {
                        java.nio.file.Files.writeString(Path.of(resultsDir, "sslyze-error.txt"),
                                e.getClass().getName() + ": " + e.getMessage());
                    } catch (Exception ignored) {
                    }
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

        // Protocol matrix: SSLyze details when READY, else Kali-only (never invent "DISABLED")
        if (dto.getTlsProtocols() == null || dto.getTlsProtocols().isEmpty()) {
            dto.setTlsProtocols(buildTlsProtocolsFromKali(dto));
        }
        if (dto.getCertificateDetail() == null) {
            dto.setCertificateDetail(buildCertificateDetailFromKali(dto));
        }

        // Persist full DTO (all fields). Delete disk only when SSL Labs/Censys are no longer PENDING.
        // Never fail the GET if DB persistence fails — the page must still show parsed results.
        if (isDone && diskAvailable && hasPersistableSslData(dto)) {
            try {
                sslResultStoreService.persist(scan, dto, canCleanupSslDisk(dto));
            } catch (Exception e) {
                // logged inside persist; keep serving the in-memory DTO
            }
        }

        return ResponseEntity.ok(dto);
    }

    /** True when at least one SSL source produced usable data worth storing. */
    private static boolean hasPersistableSslData(SslResultDto dto) {
        if (dto == null) {
            return false;
        }
        if (dto.getGrade() != null && !"?".equals(dto.getGrade()) && !dto.getGrade().isBlank()) {
            return true;
        }
        if ("READY".equals(dto.getSslyzeStatus()) || "READY".equals(dto.getSsllabsStatus())
                || "READY".equals(dto.getCensysStatus())) {
            return true;
        }
        return dto.getCertificateDetail() != null
                || (dto.getTlsProtocols() != null && !dto.getTlsProtocols().isEmpty());
    }

    /** Do not delete the folder while SSL Labs / Censys async jobs may still write JSON. */
    private static boolean canCleanupSslDisk(SslResultDto dto) {
        String labs = dto.getSsllabsStatus();
        String censys = dto.getCensysStatus();
        boolean labsDone = labs == null || !"PENDING".equalsIgnoreCase(labs);
        boolean censysDone = censys == null || !"PENDING".equalsIgnoreCase(censys);
        return labsDone && censysDone;
    }

    private String resolveSslDomain(ScanResult scan) {
        try {
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
        } catch (Exception e) {
            // Lazy proxy / missing session — fall through
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

            HeaderProbe probe = fetchHeaderProbe(client, url, true);
            // Always prefer GET if critical headers missing (some stacks omit them on HEAD)
            if (probe == null || !hasAnySecurityHeader(probe.headers)
                    || firstHeader(probe.headers, "x-frame-options") == null
                    || firstHeader(probe.headers, "x-content-type-options") == null) {
                HeaderProbe getProbe = fetchHeaderProbe(client, url, false);
                if (getProbe != null && hasAnySecurityHeader(getProbe.headers)) {
                    probe = getProbe;
                }
            }
            if (probe == null || probe.headers == null) {
                dto.setHeadersLiveChecked(false);
                return;
            }

            java.net.http.HttpHeaders hdrs = probe.headers;
            dto.setHeadersCheckedUrl(probe.finalUrl);
            dto.setHeadersHttpStatus(probe.status);

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
                dto.setXFrameOptionsValue(xfo.trim());
            }
            String xcto = firstHeader(hdrs, "x-content-type-options");
            if (xcto != null && !xcto.isBlank()) {
                dto.setXContentTypeOptionsValue(xcto.trim());
                if (xcto.toLowerCase(java.util.Locale.ROOT).contains("nosniff")) {
                    dto.setXContentTypeOptions(true);
                }
            }
            String referrer = firstHeader(hdrs, "referrer-policy");
            if (referrer != null && !referrer.isBlank()) {
                dto.setReferrerPolicy(true);
                dto.setReferrerPolicyValue(referrer.trim());
            }
            String permissions = firstHeader(hdrs, "permissions-policy");
            if (permissions == null || permissions.isBlank()) {
                permissions = firstHeader(hdrs, "feature-policy");
            }
            if (permissions != null && !permissions.isBlank()) {
                dto.setPermissionsPolicy(true);
                dto.setPermissionsPolicyValue(permissions.trim());
            }
            String coop = firstHeader(hdrs, "cross-origin-opener-policy");
            if (coop != null && !coop.isBlank()) {
                dto.setCrossOriginOpenerPolicy(true);
                dto.setCrossOriginOpenerPolicyValue(coop.trim());
            }
            String corp = firstHeader(hdrs, "cross-origin-resource-policy");
            if (corp != null && !corp.isBlank()) {
                dto.setCrossOriginResourcePolicy(true);
                dto.setCrossOriginResourcePolicyValue(corp.trim());
            }
            String coep = firstHeader(hdrs, "cross-origin-embedder-policy");
            if (coep != null && !coep.isBlank()) {
                dto.setCrossOriginEmbedderPolicy(true);
                dto.setCrossOriginEmbedderPolicyValue(coep.trim());
            }

            dto.setHeadersLiveChecked(true);
        } catch (Exception e) {
            dto.setHeadersLiveChecked(false);
        }
    }

    private static final class HeaderProbe {
        final java.net.http.HttpHeaders headers;
        final String finalUrl;
        final int status;
        HeaderProbe(java.net.http.HttpHeaders headers, String finalUrl, int status) {
            this.headers = headers;
            this.finalUrl = finalUrl;
            this.status = status;
        }
    }

    private static HeaderProbe fetchHeaderProbe(
            java.net.http.HttpClient client, String url, boolean head) throws Exception {
        java.net.http.HttpRequest.Builder b = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .timeout(java.time.Duration.ofSeconds(15));
        if (head) {
            b.method("HEAD", java.net.http.HttpRequest.BodyPublishers.noBody());
        } else {
            b.GET();
        }
        java.net.http.HttpResponse<Void> resp =
                client.send(b.build(), java.net.http.HttpResponse.BodyHandlers.discarding());
        String finalUrl = resp.uri() != null ? resp.uri().toString() : url;
        return new HeaderProbe(resp.headers(), finalUrl, resp.statusCode());
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

    private static final String[][] PROTOCOL_KEYS = {
            { "tls13", "TLS 1.3", "tls_1_3_cipher_suites" },
            { "tls12", "TLS 1.2", "tls_1_2_cipher_suites" },
            { "tls11", "TLS 1.1", "tls_1_1_cipher_suites" },
            { "tls10", "TLS 1.0", "tls_1_0_cipher_suites" },
            { "ssl30", "SSL 3.0", "ssl_3_0_cipher_suites" },
            { "ssl20", "SSL 2.0", "ssl_2_0_cipher_suites" },
    };

    private List<TlsProtocolDetailDto> buildTlsProtocolsFromSslyze(
            JsonNode sr, String domain, String ip, int port, String sni,
            String toolVersion, String scannedAt,
            boolean compression, Boolean secureRenegotiation) {
        List<TlsProtocolDetailDto> list = new ArrayList<>();
        String endpoint = (domain != null && !domain.isBlank())
                ? domain + ":" + port
                : (ip != null ? ip + ":" + port : null);
        for (String[] meta : PROTOCOL_KEYS) {
            list.add(parseSslyzeProtocol(
                    meta[0], meta[1], sr.path(meta[2]).path("result"),
                    endpoint, ip, port, sni, toolVersion, scannedAt,
                    compression, secureRenegotiation,
                    "tls13".equals(meta[0])));
        }
        return list;
    }

    private TlsProtocolDetailDto parseSslyzeProtocol(
            String id, String label, JsonNode result,
            String endpoint, String ip, int port, String sni,
            String toolVersion, String scannedAt,
            boolean compression, Boolean secureRenegotiation,
            boolean tls13) {
        if (result == null || result.isMissingNode() || result.isNull()) {
            return TlsProtocolDetailDto.builder()
                    .id(id).label(label).status("INCONCLUSIVE")
                    .endpoint(endpoint).ip(ip).port(port).sni(sni)
                    .tool("SSLyze").toolVersion(toolVersion).scannedAt(scannedAt)
                    .confidence("Faible")
                    .evidence("Bloc protocole absent ou illisible dans sslyze.json")
                    .ciphers(new ArrayList<>())
                    .build();
        }

        JsonNode accepted = result.path("accepted_cipher_suites");
        boolean hasAccepted = accepted.isArray() && accepted.size() > 0;
        boolean supportedFlag = result.path("is_tls_version_supported").asBoolean(hasAccepted);
        boolean enabled = supportedFlag || hasAccepted;

        List<TlsCipherSuiteDto> ciphers = new ArrayList<>();
        int weak = 0, forbidden = 0;
        boolean anyFs = false, anyAead = false;
        if (accepted.isArray()) {
            for (JsonNode entry : accepted) {
                TlsCipherSuiteDto c = mapCipherSuite(entry, tls13);
                ciphers.add(c);
                if ("WEAK".equals(c.getStrength())) weak++;
                if ("FORBIDDEN".equals(c.getStrength())) forbidden++;
                if (c.isForwardSecrecy()) anyFs = true;
                if (c.isAead()) anyAead = true;
            }
        }

        String evidence;
        if (enabled) {
            evidence = "is_tls_version_supported=true; accepted_cipher_suites=" + ciphers.size();
        } else {
            JsonNode rejected = result.path("rejected_cipher_suites");
            String err = "";
            if (rejected.isArray() && rejected.size() > 0) {
                err = rejected.get(0).path("error_message").asText("");
            }
            evidence = "is_tls_version_supported=false; accepted=0"
                    + (err.isBlank() ? "" : "; " + err);
        }

        return TlsProtocolDetailDto.builder()
                .id(id).label(label)
                .status(enabled ? "ENABLED" : "DISABLED")
                .handshakeOk(enabled)
                .acceptedCount(ciphers.size())
                .weakCount(weak)
                .forbiddenCount(forbidden)
                .forwardSecrecy(enabled ? (tls13 || anyFs) : null)
                .aead(enabled ? anyAead : null)
                .compression(compression)
                .secureRenegotiation(secureRenegotiation)
                .endpoint(endpoint).ip(ip).port(port).sni(sni)
                .tool("SSLyze").toolVersion(toolVersion).scannedAt(scannedAt)
                .confidence("Haute")
                .evidence(evidence)
                .ciphers(ciphers)
                .build();
    }

    private TlsCipherSuiteDto mapCipherSuite(JsonNode entry, boolean tls13) {
        JsonNode cs = entry.path("cipher_suite");
        String iana = cs.path("name").asText("");
        String openssl = cs.path("openssl_name").asText("");
        int keySize = cs.path("key_size").asInt(0);
        boolean anonymous = cs.path("is_anonymous").asBoolean(false);
        boolean fs = tls13 || (!entry.path("ephemeral_key").isMissingNode()
                && !entry.path("ephemeral_key").isNull());
        boolean aead = isAeadName(iana) || isAeadName(openssl);
        String keyExchange = inferKeyExchange(iana, openssl, tls13, fs);
        String encryption = inferEncryption(iana, openssl);
        String strength = classifyCipherStrength(iana, openssl, anonymous, fs, tls13);
        return TlsCipherSuiteDto.builder()
                .ianaName(iana)
                .opensslName(openssl)
                .encryption(encryption)
                .keyExchange(keyExchange)
                .keySize(keySize)
                .forwardSecrecy(fs)
                .aead(aead)
                .strength(strength)
                .build();
    }

    private static boolean isAeadName(String name) {
        if (name == null) return false;
        String u = name.toUpperCase(Locale.ROOT);
        return u.contains("GCM") || u.contains("CCM") || u.contains("CHACHA20") || u.contains("POLY1305");
    }

    private static String inferKeyExchange(String iana, String openssl, boolean tls13, boolean fs) {
        if (tls13) return "TLS 1.3 (ECDHE)";
        String u = ((iana != null ? iana : "") + " " + (openssl != null ? openssl : ""))
                .toUpperCase(Locale.ROOT);
        if (u.contains("ECDHE")) return "ECDHE";
        if (u.contains("_DHE_") || u.contains("DHE-") || u.contains("EDH")) return "DHE";
        if (u.contains("RSA_WITH") || u.contains("RSA-")) return "RSA";
        return fs ? "Ephemeral" : "Static";
    }

    private static String inferEncryption(String iana, String openssl) {
        String u = ((iana != null ? iana : "") + " " + (openssl != null ? openssl : ""))
                .toUpperCase(Locale.ROOT);
        if (u.contains("CHACHA20")) return "ChaCha20-Poly1305";
        if (u.contains("AES_256_GCM") || u.contains("AES256-GCM")) return "AES-256-GCM";
        if (u.contains("AES_128_GCM") || u.contains("AES128-GCM")) return "AES-128-GCM";
        if (u.contains("AES_256_CCM") || u.contains("AES256-CCM")) return "AES-256-CCM";
        if (u.contains("AES_128_CCM") || u.contains("AES128-CCM")) return "AES-128-CCM";
        if (u.contains("AES_256_CBC") || u.contains("AES256-CBC") || u.contains("AES256-SHA")) return "AES-256-CBC";
        if (u.contains("AES_128_CBC") || u.contains("AES128-CBC") || u.contains("AES128-SHA")) return "AES-128-CBC";
        if (u.contains("3DES") || u.contains("DES-CBC3")) return "3DES-CBC";
        if (u.contains("RC4")) return "RC4";
        if (u.contains("NULL")) return "NULL";
        return openssl != null && !openssl.isBlank() ? openssl : (iana != null ? iana : "—");
    }

    private static String classifyCipherStrength(String iana, String openssl, boolean anonymous,
                                                 boolean fs, boolean tls13) {
        String u = ((iana != null ? iana : "") + " " + (openssl != null ? openssl : ""))
                .toUpperCase(Locale.ROOT);
        if (anonymous || u.contains("NULL") || u.contains("EXPORT") || u.contains("RC4")
                || u.contains("MD5") || u.contains("DES-CBC3") || u.contains("3DES")
                || (u.contains("_DES_") && !u.contains("3DES")) || u.contains("IDEA")) {
            return "FORBIDDEN";
        }
        if (!tls13 && !fs) return "WEAK";
        if (!tls13 && !isAeadName(u) && (u.contains("CBC") || u.contains("SHA"))) return "WEAK";
        return "STRONG";
    }

    /**
     * When SSLyze is unavailable: Kali may mark TLS 1.0–1.3 as ENABLED only if true;
     * never report DISABLED without a real test. SSL 2.0/3.0 → NOT_TESTED.
     */
    private List<TlsProtocolDetailDto> buildTlsProtocolsFromKali(SslResultDto dto) {
        List<TlsProtocolDetailDto> list = new ArrayList<>();
        boolean kaliDone = "COMPLETED".equals(dto.getScanStatus()) || "FAILED".equals(dto.getScanStatus());
        String inconclusive = "ERROR".equals(dto.getSslyzeStatus()) ? "INCONCLUSIVE" : "NOT_TESTED";
        String conf = kaliDone ? "Moyenne" : "Faible";
        String tool = kaliDone ? "Kali (sslscan/nmap)" : null;

        list.add(kaliProto("tls13", "TLS 1.3", dto.isTls13(), kaliDone, inconclusive, conf, tool, dto));
        list.add(kaliProto("tls12", "TLS 1.2", dto.isTls12(), kaliDone, inconclusive, conf, tool, dto));
        list.add(kaliProto("tls11", "TLS 1.1", dto.isTls11(), kaliDone, inconclusive, conf, tool, dto));
        list.add(kaliProto("tls10", "TLS 1.0", dto.isTls10(), kaliDone, inconclusive, conf, tool, dto));
        // SSL never inferred from Kali summary
        list.add(TlsProtocolDetailDto.builder()
                .id("ssl30").label("SSL 3.0").status(inconclusive)
                .endpoint(dto.getDomain()).tool(tool).confidence(conf)
                .evidence("SSL 3.0 non testé (SSLyze indisponible)")
                .ciphers(new ArrayList<>())
                .build());
        list.add(TlsProtocolDetailDto.builder()
                .id("ssl20").label("SSL 2.0").status(inconclusive.equals("INCONCLUSIVE") ? "INCONCLUSIVE" : "NOT_TESTED")
                .endpoint(dto.getDomain()).tool(tool).confidence(conf)
                .evidence("SSL 2.0 non testé (SSLyze indisponible)")
                .ciphers(new ArrayList<>())
                .build());
        return list;
    }

    private TlsProtocolDetailDto kaliProto(
            String id, String label, boolean enabled, boolean kaliDone,
            String fallbackStatus, String confidence, String tool, SslResultDto dto) {
        String status;
        String evidence;
        Boolean handshake = null;
        if (enabled && kaliDone) {
            status = "ENABLED";
            handshake = true;
            evidence = "Activé selon ssl-summary.json (Kali)";
        } else if (!kaliDone) {
            status = "NOT_TESTED";
            evidence = "Scan Kali non terminé — protocole non testé";
        } else {
            // Kali reported false: do NOT claim DISABLED (may be incomplete probe)
            status = fallbackStatus;
            evidence = "Non confirmé comme désactivé (SSLyze indisponible; Kali n’a pas détecté d’offre)";
        }
        return TlsProtocolDetailDto.builder()
                .id(id).label(label).status(status)
                .handshakeOk(handshake)
                .endpoint(dto.getDomain())
                .tool(tool)
                .confidence(confidence)
                .evidence(evidence)
                .ciphers(new ArrayList<>())
                .build();
    }

    // ── Certificate detail (SSLyze / Kali) ────────────────────────────
    private CertificateDetailDto buildCertificateDetailFromSslyze(
            JsonNode dep, String domain, String ip, int port, String sni,
            String toolVersion, String started, String completed, boolean kaliOcspStapling) {

        JsonNode verified = dep.path("verified_certificate_chain");
        JsonNode received = dep.path("received_certificate_chain");
        JsonNode chainNode = (verified.isArray() && verified.size() > 0) ? verified : received;
        JsonNode leaf = (chainNode.isArray() && chainNode.size() > 0) ? chainNode.get(0) : null;
        String host = (sni != null && !sni.isBlank()) ? sni : domain;

        if (leaf == null || leaf.isMissingNode()) {
            return CertificateDetailDto.builder()
                    .tool("SSLyze").toolVersion(toolVersion).scannedAt(started)
                    .scanDuration(computeScanDuration(started, completed))
                    .endpoint(domain != null ? domain + ":" + port : null)
                    .ip(ip).port(port).sni(sni).confidence("Faible")
                    .testedHostname(host).validityStatus("UNKNOWN")
                    .hostnameMatch("NOT_TESTED").revocationStatus("NON_TESTE")
                    .transparencyStatus("NON_TESTE").ocspResponseStatus("NON_TESTE")
                    .ocspStaplingStatus("NON_TESTE").ocspUrlStatus("NON_TESTE")
                    .crlUrlStatus("NON_TESTE").keyUsage("NON_TESTE")
                    .extendedKeyUsage("NON_TESTE").basicConstraints("NON_TESTE")
                    .build();
        }

        CertNameDto subject = parseCertName(leaf.path("subject"));
        String cn = subject.getCommonName();
        String notBefore = leaf.path("not_valid_before").asText(null);
        String notAfter = leaf.path("not_valid_after").asText(null);
        ValidityInfo vi = computeValidity(notBefore, notAfter);

        List<CertSanEntryDto> sans = new ArrayList<>();
        JsonNode san = leaf.path("subject_alternative_name");
        if (san.path("dns_names").isArray()) {
            for (JsonNode n : san.path("dns_names")) {
                String v = n.asText("");
                sans.add(CertSanEntryDto.builder().type("dns").value(v)
                        .matchStatus(sanMatchStatus(host, v)).build());
            }
        }
        if (san.path("ip_addresses").isArray()) {
            for (JsonNode n : san.path("ip_addresses")) {
                String v = n.asText("");
                sans.add(CertSanEntryDto.builder().type("ip").value(v)
                        .matchStatus(host != null && host.equalsIgnoreCase(v) ? "MATCH" : "NO_MATCH")
                        .build());
            }
        }
        boolean wildcard = sans.stream().anyMatch(s -> s.getValue() != null && s.getValue().startsWith("*."));

        JsonNode pk = leaf.path("public_key");
        String alg = pk.path("algorithm").asText("");
        String keyType = alg.toUpperCase(Locale.ROOT).contains("EC") ? "EC"
                : (alg.toUpperCase(Locale.ROOT).contains("RSA") ? "RSA" : (alg.isBlank() ? null : alg));
        int keySize = pk.path("key_size").asInt(0);
        String curve = friendlyCurve(pk.path("ec_curve_name").asText(null));
        String sigOid = leaf.path("signature_algorithm_oid").path("name").asText("");
        String hash = leaf.path("signature_hash_algorithm").path("name").asText("");
        boolean weakKey = isWeakKey(keyType, keySize);
        boolean obsoleteSig = isObsoleteSignature(sigOid, hash);

        List<CertChainEntryDto> chain = buildChainEntries(chainNode,
                dep.path("received_chain_contains_anchor_certificate").asBoolean(false));
        boolean chainComplete = verified.isArray() && verified.size() > 0;
        boolean orderValid = dep.path("received_chain_has_valid_order").asBoolean(false);
        boolean intermediatePresent = chain.stream().anyMatch(c -> "INTERMEDIATE".equals(c.getType()));
        boolean rootRecognized = chainComplete
                || dep.path("received_chain_contains_anchor_certificate").asBoolean(false);
        CertNameDto issuer = parseCertName(leaf.path("issuer"));
        boolean selfSigned = subject.getRfc4514() != null
                && subject.getRfc4514().equalsIgnoreCase(issuer.getRfc4514());

        String validationError = null;
        List<CertTrustStoreDto> stores = new ArrayList<>();
        JsonNode pvs = dep.path("path_validation_results");
        if (pvs.isArray()) {
            for (JsonNode pv : pvs) {
                String platform = mapTrustStoreName(pv.path("trust_store").path("name").asText("?"));
                boolean ok = pv.path("was_validation_successful").asBoolean(false);
                String err = pv.path("validation_error").isNull() ? null
                        : pv.path("validation_error").asText(null);
                if (!ok && validationError == null && err != null && !err.isBlank()) {
                    validationError = err;
                }
                stores.add(CertTrustStoreDto.builder()
                        .platform(platform)
                        .status(ok ? "TRUSTED" : "NOT_TRUSTED")
                        .storeVersion(pv.path("trust_store").path("version").asText(null))
                        .validationError(err)
                        .build());
            }
        }
        for (String p : List.of("Mozilla", "Windows", "Apple", "Android", "Java")) {
            if (stores.stream().noneMatch(s -> p.equals(s.getPlatform()))) {
                stores.add(CertTrustStoreDto.builder().platform(p).status("NOT_TESTED").build());
            }
        }

        // SSLyze ran certificate_info: null OCSP response = checked, not stapled (NON_DETECTE),
        // not "NON_TESTE". Never claim "non révoqué" without a verified OCSP answer.
        boolean ocspPresent = !dep.path("ocsp_response").isNull() && !dep.path("ocsp_response").isMissingNode();
        Boolean ocspTrusted = dep.path("ocsp_response_is_trusted").isNull()
                ? null : dep.path("ocsp_response_is_trusted").asBoolean();
        String ocspResponseStatus = !ocspPresent ? "NON_DETECTE"
                : (ocspTrusted == null ? "INCONCLUSIF" : (ocspTrusted ? "CONFORME" : "NON_CONFORME"));
        String revocationStatus = ocspPresent
                ? (ocspTrusted == null ? "INCONCLUSIF" : (ocspTrusted ? "CONFORME" : "NON_CONFORME"))
                : "NON_DETECTE";
        String staplingStatus = (kaliOcspStapling || ocspPresent) ? "CONFORME" : "NON_DETECTE";

        int sct = dep.path("leaf_certificate_signed_certificate_timestamps_count").asInt(-1);
        String transparencyStatus = sct > 0 ? "CONFORME" : (sct == 0 ? "NON_DETECTE" : "NON_TESTE");

        String leafPem = leaf.path("as_pem").asText(null);
        X509ExtInfo ext = parseX509Extensions(leafPem);

        return CertificateDetailDto.builder()
                .validityStatus(vi.status).notBefore(notBefore).notAfter(notAfter)
                .totalValidityDays(vi.totalDays).daysRemaining(vi.daysLeft)
                .percentRemaining(vi.percent).recommendedRenewalDate(vi.renewal)
                .expired(vi.expired)
                .commonName(cn).testedHostname(host)
                .hostnameMatch(computeHostnameMatch(host, cn, sans))
                .wildcard(wildcard).sans(sans)
                .publicKeyAlgorithm(alg.isBlank() ? null : alg)
                .keyType(keyType).keySize(keySize > 0 ? keySize : null).curveName(curve)
                .signatureAlgorithm(friendlySignature(sigOid, hash))
                .hashAlgorithm(hash.isBlank() ? null : hash.toUpperCase(Locale.ROOT))
                .securityLevel(securityLevel(keyType, keySize, obsoleteSig, weakKey))
                .weakKey(weakKey).obsoleteSignature(obsoleteSig)
                .chainComplete(chainComplete).chainOrderValid(orderValid)
                .intermediatePresent(intermediatePresent).rootRecognized(rootRecognized)
                .selfSigned(selfSigned).validationError(validationError).chain(chain)
                .ocspUrlStatus(ext.ocspUrlStatus)
                .ocspUrl(ext.ocspUrl)
                .ocspResponseStatus(ocspResponseStatus)
                .revocationStatus(revocationStatus)
                .ocspStaplingStatus(staplingStatus)
                .crlUrlStatus(ext.crlUrlStatus)
                .crlUrl(ext.crlUrl)
                .transparencyStatus(transparencyStatus)
                .sctCount(sct >= 0 ? sct : null)
                .ctLogs(sct > 0
                        ? sct + " SCT embarqué(s) dans le certificat (journaux CT non nommés par SSLyze)"
                        : "Non disponible")
                .mustStaple(dep.path("leaf_certificate_has_must_staple_extension").asBoolean(false))
                .keyUsage(ext.keyUsage)
                .extendedKeyUsage(ext.extendedKeyUsage)
                .basicConstraints(ext.basicConstraints)
                .serverAuth(ext.serverAuth)
                .clientAuth(ext.clientAuth)
                .isCa(ext.isCa)
                .trustStores(stores)
                .endpoint(domain != null ? domain + ":" + port : null)
                .ip(ip).port(port).sni(sni).scannedAt(started)
                .scanDuration(computeScanDuration(started, completed))
                .tool("SSLyze").toolVersion(toolVersion).confidence("Haute")
                .sha256Fingerprint(fingerprintToHex(leaf.path("fingerprint_sha256").asText(null)))
                .serialNumber(serialToHex(leaf.path("serial_number")))
                .leafPem(leafPem)
                .ev(dep.path("leaf_certificate_is_ev").asBoolean(false))
                .build();
    }

    private CertificateDetailDto buildCertificateDetailFromKali(SslResultDto dto) {
        ValidityInfo vi = computeValidity(dto.getCertNotBefore(), dto.getCertNotAfterStr());
        String conf = "READY".equals(dto.getSslyzeStatus()) ? "Haute"
                : ("COMPLETED".equals(dto.getScanStatus()) ? "Moyenne" : "Faible");
        // Avoid ternary int/Integer unboxing NPE when vi.daysLeft is null (dates missing/"—")
        Integer daysRemaining = dto.getCertDaysLeft() >= 0
                ? Integer.valueOf(dto.getCertDaysLeft())
                : vi.daysLeft;
        return CertificateDetailDto.builder()
                .validityStatus(dto.isCertExpired() ? "EXPIRED" : vi.status)
                .notBefore(nullIfBlank(dto.getCertNotBefore()))
                .notAfter(nullIfBlank(dto.getCertNotAfterStr()))
                .totalValidityDays(vi.totalDays)
                .daysRemaining(daysRemaining)
                .percentRemaining(vi.percent)
                .recommendedRenewalDate(vi.renewal)
                .expired(dto.isCertExpired())
                .commonName(extractCn(dto.getCertSubject()))
                .testedHostname(dto.getDomain())
                .hostnameMatch("NOT_TESTED")
                .wildcard(dto.isCertWildcard())
                .sans(new ArrayList<>())
                .publicKeyAlgorithm(null)
                .keyType(guessKeyType(dto.getCertKeySize()))
                .keySize(parseKeySize(dto.getCertKeySize()))
                .curveName(null)
                .signatureAlgorithm(nullIfBlank(dto.getCertSignatureAlg()))
                .hashAlgorithm(null)
                .securityLevel("INCONNU")
                .weakKey(null).obsoleteSignature(null)
                .chainComplete(dto.isChainComplete())
                .chainOrderValid(null).intermediatePresent(null)
                .rootRecognized(dto.isSslyzeChainTrusted() ? true : null)
                .selfSigned(null).validationError(null).chain(new ArrayList<>())
                .ocspUrlStatus("NON_TESTE")
                .ocspResponseStatus("NON_TESTE")
                .revocationStatus("NON_TESTE")
                .ocspStaplingStatus(dto.isOcspStapling() || dto.isSslyzeOcspStapling()
                        ? "CONFORME" : "NON_DETECTE")
                .crlUrlStatus("NON_TESTE")
                .transparencyStatus(dto.isCertTransparency() ? "CONFORME" : "NON_DETECTE")
                .sctCount(null).ctLogs("Non disponible")
                .keyUsage("NON_TESTE").extendedKeyUsage("NON_TESTE").basicConstraints("NON_TESTE")
                .trustStores(List.of(
                        CertTrustStoreDto.builder().platform("Mozilla").status("NOT_TESTED").build(),
                        CertTrustStoreDto.builder().platform("Windows").status("NOT_TESTED").build(),
                        CertTrustStoreDto.builder().platform("Apple").status("NOT_TESTED").build(),
                        CertTrustStoreDto.builder().platform("Android").status("NOT_TESTED").build(),
                        CertTrustStoreDto.builder().platform("Java").status("NOT_TESTED").build()))
                .endpoint(dto.getDomain())
                .ip(dto.getSslyzeIpAddress())
                .tool("Kali (sslscan/openssl)")
                .confidence(conf)
                .serialNumber(nullIfBlank(dto.getCertSerialNumber()))
                .ev(dto.isCertEv())
                .build();
    }

    private static class ValidityInfo {
        String status; Integer totalDays; Integer daysLeft; Double percent; String renewal; Boolean expired;
    }

    private ValidityInfo computeValidity(String notBefore, String notAfter) {
        ValidityInfo v = new ValidityInfo();
        v.status = "UNKNOWN";
        Instant start = parseInstant(notBefore);
        Instant end = parseInstant(notAfter);
        Instant now = Instant.now();
        if (start != null && end != null) {
            v.totalDays = (int) ChronoUnit.DAYS.between(start, end);
            if (v.totalDays < 0) v.totalDays = 0;
        }
        if (end != null) {
            v.daysLeft = (int) ChronoUnit.DAYS.between(now, end);
            v.expired = v.daysLeft < 0;
            if (v.expired) v.status = "EXPIRED";
            else if (v.daysLeft < 15) v.status = "EXPIRING_CRITICAL";
            else if (v.daysLeft <= 30) v.status = "EXPIRING_SOON";
            else v.status = "VALID";
            v.renewal = end.minus(30, ChronoUnit.DAYS).atZone(ZoneOffset.UTC)
                    .toLocalDate().toString();
            if (v.totalDays != null && v.totalDays > 0) {
                double rem = Math.max(0, v.daysLeft);
                v.percent = Math.min(100.0, Math.round(rem * 1000.0 / v.totalDays) / 10.0);
            }
        }
        return v;
    }

    private Instant parseInstant(String raw) {
        if (raw == null || raw.isBlank() || "—".equals(raw) || "unknown".equalsIgnoreCase(raw)) return null;
        try {
            return Instant.parse(raw.contains("T") ? raw : raw.replace(' ', 'T') + "Z");
        } catch (Exception e) {
            try {
                return DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
                        .withZone(ZoneOffset.UTC).parse(raw, Instant::from);
            } catch (Exception e2) {
                return null;
            }
        }
    }

    private CertNameDto parseCertName(JsonNode node) {
        String rfc = node.path("rfc4514_string").asText(null);
        String cn = null, org = null, country = null;
        JsonNode attrs = node.path("attributes");
        if (attrs.isArray()) {
            for (JsonNode a : attrs) {
                String name = a.path("oid").path("name").asText("");
                String val = a.path("value").asText("");
                if ("commonName".equals(name)) cn = val;
                else if ("organizationName".equals(name)) org = val;
                else if ("countryName".equals(name)) country = val;
            }
        }
        if (cn == null) cn = extractCn(rfc);
        return CertNameDto.builder()
                .commonName(cn).organization(org).country(country)
                .countryName(countryNameFr(country)).rfc4514(rfc)
                .build();
    }

    private List<CertChainEntryDto> buildChainEntries(JsonNode chain, boolean containsAnchor) {
        List<CertChainEntryDto> out = new ArrayList<>();
        if (!chain.isArray()) return out;
        int n = chain.size();
        for (int i = 0; i < n; i++) {
            JsonNode c = chain.get(i);
            String type = i == 0 ? "SERVER"
                    : (i == n - 1 && containsAnchor ? "ROOT"
                    : (i == n - 1 ? "ROOT" : "INTERMEDIATE"));
            // If last cert is not an anchor but looks like root (self-signed), mark ROOT
            CertNameDto sub = parseCertName(c.path("subject"));
            CertNameDto iss = parseCertName(c.path("issuer"));
            if (i == n - 1 && sub.getRfc4514() != null
                    && sub.getRfc4514().equalsIgnoreCase(iss.getRfc4514())) {
                type = "ROOT";
            } else if (i > 0 && i < n - 1) {
                type = "INTERMEDIATE";
            } else if (i == n - 1 && !containsAnchor && n > 1) {
                type = "INTERMEDIATE";
            }
            String notAfter = c.path("not_valid_after").asText(null);
            ValidityInfo vi = computeValidity(null, notAfter);
            String sig = friendlySignature(
                    c.path("signature_algorithm_oid").path("name").asText(""),
                    c.path("signature_hash_algorithm").path("name").asText(""));
            out.add(CertChainEntryDto.builder()
                    .type(type).subject(sub).issuer(iss)
                    .serialNumber(serialToHex(c.path("serial_number")))
                    .notAfter(notAfter).signatureAlgorithm(sig)
                    .sha256Fingerprint(fingerprintToHex(c.path("fingerprint_sha256").asText(null)))
                    .status(Boolean.TRUE.equals(vi.expired) ? "EXPIRED" : "VALID")
                    .pem(c.path("as_pem").asText(null))
                    .build());
        }
        return out;
    }

    private static String sanMatchStatus(String host, String san) {
        if (host == null || host.isBlank() || san == null || san.isBlank()) return "N_A";
        String h = host.toLowerCase(Locale.ROOT);
        String s = san.toLowerCase(Locale.ROOT);
        if (h.equals(s)) return "MATCH";
        if (s.startsWith("*.") && h.endsWith(s.substring(1)) && h.indexOf('.') == h.length() - s.length() + 1) {
            return "WILDCARD_MATCH";
        }
        if (s.startsWith("*.")) {
            String suffix = s.substring(1);
            if (h.endsWith(suffix) && h.length() > suffix.length()) return "WILDCARD_MATCH";
        }
        return "NO_MATCH";
    }

    private static String computeHostnameMatch(String host, String cn, List<CertSanEntryDto> sans) {
        if (host == null || host.isBlank()) return "NOT_TESTED";
        if (sans != null) {
            for (CertSanEntryDto s : sans) {
                if ("MATCH".equals(s.getMatchStatus()) || "WILDCARD_MATCH".equals(s.getMatchStatus())) {
                    return "MATCH";
                }
            }
        }
        if (cn != null && ("MATCH".equals(sanMatchStatus(host, cn))
                || "WILDCARD_MATCH".equals(sanMatchStatus(host, cn)))) {
            return "MATCH";
        }
        return "MISMATCH";
    }

    private static String friendlyCurve(String curve) {
        if (curve == null || curve.isBlank()) return null;
        return switch (curve.toLowerCase(Locale.ROOT)) {
            case "secp256r1", "prime256v1" -> "P-256";
            case "secp384r1" -> "P-384";
            case "secp521r1" -> "P-521";
            default -> curve;
        };
    }

    private static String friendlySignature(String oidName, String hash) {
        if (oidName == null || oidName.isBlank()) {
            return hash != null && !hash.isBlank() ? hash.toUpperCase(Locale.ROOT) : null;
        }
        String n = oidName.toLowerCase(Locale.ROOT);
        if (n.contains("ecdsa") && n.contains("sha384")) return "ECDSA avec SHA-384";
        if (n.contains("ecdsa") && n.contains("sha256")) return "ECDSA avec SHA-256";
        if (n.contains("ecdsa") && n.contains("sha512")) return "ECDSA avec SHA-512";
        if (n.contains("sha256withrsa") || (n.contains("rsa") && n.contains("sha256"))) return "RSA avec SHA-256";
        if (n.contains("sha384withrsa")) return "RSA avec SHA-384";
        if (n.contains("sha1")) return "Signature SHA-1 (obsolète)";
        if (hash != null && !hash.isBlank()) return oidName + " (" + hash.toUpperCase(Locale.ROOT) + ")";
        return oidName;
    }

    private static boolean isWeakKey(String keyType, int keySize) {
        if (keySize <= 0) return false;
        if ("RSA".equals(keyType)) return keySize < 2048;
        if ("EC".equals(keyType)) return keySize < 224;
        return keySize < 128;
    }

    private static boolean isObsoleteSignature(String oid, String hash) {
        String u = ((oid == null ? "" : oid) + " " + (hash == null ? "" : hash)).toLowerCase(Locale.ROOT);
        return u.contains("sha1") || u.contains("md5");
    }

    private static String securityLevel(String keyType, int keySize, boolean obsoleteSig, boolean weakKey) {
        if (obsoleteSig || weakKey) return "FAIBLE";
        if ("EC".equals(keyType) && keySize >= 256) return "FORT";
        if ("RSA".equals(keyType) && keySize >= 3072) return "FORT";
        if ("RSA".equals(keyType) && keySize >= 2048) return "MOYEN";
        if ("EC".equals(keyType) && keySize >= 224) return "MOYEN";
        if (keyType == null && keySize <= 0) return "INCONNU";
        return "MOYEN";
    }

    private static String serialToHex(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) return null;
        try {
            if (node.isNumber()) {
                return node.bigIntegerValue().toString(16).toUpperCase(Locale.ROOT);
            }
            String t = node.asText("");
            if (t.isBlank()) return null;
            if (t.matches("(?i)[0-9a-f]+")) return t.toUpperCase(Locale.ROOT);
            return new java.math.BigInteger(t).toString(16).toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            return node.asText(null);
        }
    }

    private static String fingerprintToHex(String raw) {
        if (raw == null || raw.isBlank()) return null;
        if (raw.matches("(?i)[0-9a-f:]+") && !raw.contains("=")) {
            return raw.replace(":", "").toUpperCase(Locale.ROOT);
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(raw);
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02X", b));
            return sb.toString();
        } catch (Exception e) {
            return raw;
        }
    }

    private static String mapTrustStoreName(String name) {
        if (name == null) return "?";
        String n = name.toLowerCase(Locale.ROOT);
        if (n.contains("mozilla")) return "Mozilla";
        if (n.contains("windows") || n.contains("microsoft")) return "Windows";
        if (n.contains("apple")) return "Apple";
        if (n.contains("android") || n.contains("aosp")) return "Android";
        if (n.contains("java") || n.contains("oracle")) return "Java";
        return name;
    }

    private static String countryNameFr(String code) {
        if (code == null) return null;
        return switch (code.toUpperCase(Locale.ROOT)) {
            case "US" -> "États-Unis";
            case "FR" -> "France";
            case "GB", "UK" -> "Royaume-Uni";
            case "DE" -> "Allemagne";
            case "TN" -> "Tunisie";
            default -> code;
        };
    }

    /** Parsed X.509 extensions from leaf PEM (Key Usage, EKU, AIA OCSP, CRL DP). */
    private static class X509ExtInfo {
        String keyUsage = "NON_TESTE";
        String extendedKeyUsage = "NON_TESTE";
        String basicConstraints = "NON_TESTE";
        String ocspUrlStatus = "NON_TESTE";
        String crlUrlStatus = "NON_TESTE";
        Boolean serverAuth;
        Boolean clientAuth;
        Boolean isCa;
        String ocspUrl;
        String crlUrl;
    }

    private X509ExtInfo parseX509Extensions(String pem) {
        X509ExtInfo info = new X509ExtInfo();
        if (pem == null || pem.isBlank()) return info;
        try {
            byte[] der = pemToDer(pem);
            java.security.cert.CertificateFactory cf =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert =
                    (java.security.cert.X509Certificate) cf.generateCertificate(
                            new java.io.ByteArrayInputStream(der));

            boolean[] ku = cert.getKeyUsage();
            if (ku != null) {
                String[] names = {
                        "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
                        "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
                };
                List<String> active = new ArrayList<>();
                for (int i = 0; i < Math.min(ku.length, names.length); i++) {
                    if (ku[i]) active.add(names[i]);
                }
                info.keyUsage = active.isEmpty() ? "NON_DETECTE" : String.join(", ", active);
            } else {
                info.keyUsage = "NON_DETECTE";
            }

            List<String> ekuNames = new ArrayList<>();
            try {
                List<String> eku = cert.getExtendedKeyUsage();
                if (eku != null) {
                    for (String oid : eku) {
                        ekuNames.add(ekuOidLabel(oid));
                        if ("1.3.6.1.5.5.7.3.1".equals(oid)) info.serverAuth = true;
                        if ("1.3.6.1.5.5.7.3.2".equals(oid)) info.clientAuth = true;
                    }
                }
            } catch (Exception ignored) {}
            if (info.serverAuth == null) info.serverAuth = false;
            if (info.clientAuth == null) info.clientAuth = false;
            info.extendedKeyUsage = ekuNames.isEmpty() ? "NON_DETECTE" : String.join(", ", ekuNames);

            int pathLen = cert.getBasicConstraints();
            info.isCa = pathLen >= 0;
            info.basicConstraints = pathLen < 0
                    ? "CA:FALSE (certificat final)"
                    : ("CA:TRUE" + (pathLen == Integer.MAX_VALUE ? "" : ", pathLen=" + pathLen));

            // AIA / CRL from raw extensions (JDK exposes via getExtensionValue)
            info.ocspUrl = extractOcspUrl(cert);
            info.crlUrl = extractCrlUrl(cert);
            info.ocspUrlStatus = (info.ocspUrl != null && !info.ocspUrl.isBlank())
                    ? "CONFORME" : "NON_DETECTE";
            info.crlUrlStatus = (info.crlUrl != null && !info.crlUrl.isBlank())
                    ? "CONFORME" : "NON_DETECTE";
            // Store URL in status detail fields via keyUsage-style: put URL in DTO via ctLogs pattern
            // We overload: append URL into the status string for UI clarity
            if (info.ocspUrl != null) info.ocspUrlStatus = "CONFORME";
            if (info.crlUrl != null) info.crlUrlStatus = "CONFORME";
        } catch (Exception e) {
            // leave NON_TESTE defaults
        }
        return info;
    }

    private static byte[] pemToDer(String pem) {
        String b64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }

    private static String ekuOidLabel(String oid) {
        return switch (oid) {
            case "1.3.6.1.5.5.7.3.1" -> "serverAuth";
            case "1.3.6.1.5.5.7.3.2" -> "clientAuth";
            case "1.3.6.1.5.5.7.3.3" -> "codeSigning";
            case "1.3.6.1.5.5.7.3.4" -> "emailProtection";
            default -> oid;
        };
    }

    /**
     * Extract OCSP URI from Authority Information Access (OID 1.3.6.1.5.5.7.1.1).
     * Lightweight ASN.1 scan for URI tags (0x86) after OCSP OID bytes.
     */
    private static String extractOcspUrl(java.security.cert.X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
            if (ext == null) return null;
            // Extension value is OCTET STRING wrapping the AIA sequence
            byte[] aia = unwrapOctetString(ext);
            return findUriNearOid(aia, new byte[]{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01}); // 1.3.6.1.5.5.7.48.1 OCSP
        } catch (Exception e) {
            return null;
        }
    }

    private static String extractCrlUrl(java.security.cert.X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue("2.5.29.31"); // cRLDistributionPoints
            if (ext == null) return null;
            byte[] crl = unwrapOctetString(ext);
            // Any URI (context tag 0x86) in the CRL DP extension
            return findFirstUri(crl);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] unwrapOctetString(byte[] ext) {
        // DER: 0x04 <len> <content>
        if (ext == null || ext.length < 2 || ext[0] != 0x04) return ext;
        int len = ext[1] & 0xff;
        int offset = 2;
        if (len == 0x81) { len = ext[2] & 0xff; offset = 3; }
        else if (len == 0x82) { len = ((ext[2] & 0xff) << 8) | (ext[3] & 0xff); offset = 4; }
        byte[] out = new byte[len];
        System.arraycopy(ext, offset, out, 0, Math.min(len, ext.length - offset));
        return out;
    }

    private static String findUriNearOid(byte[] der, byte[] oidBytes) {
        if (der == null) return null;
        for (int i = 0; i < der.length - oidBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < oidBytes.length; j++) {
                if (der[i + j] != oidBytes[j]) { match = false; break; }
            }
            if (!match) continue;
            // search forward for URI tag 0x86 within next 80 bytes
            for (int k = i + oidBytes.length; k < Math.min(der.length - 2, i + oidBytes.length + 80); k++) {
                if ((der[k] & 0xff) == 0x86) {
                    int ulen = der[k + 1] & 0xff;
                    if (k + 2 + ulen <= der.length) {
                        return new String(der, k + 2, ulen, StandardCharsets.US_ASCII);
                    }
                }
            }
        }
        return findFirstUri(der);
    }

    private static String findFirstUri(byte[] der) {
        if (der == null) return null;
        for (int i = 0; i < der.length - 2; i++) {
            if ((der[i] & 0xff) == 0x86) {
                int ulen = der[i + 1] & 0xff;
                if (ulen > 0 && i + 2 + ulen <= der.length) {
                    String uri = new String(der, i + 2, ulen, StandardCharsets.US_ASCII);
                    if (uri.startsWith("http")) return uri;
                }
            }
        }
        return null;
    }

    private static String computeScanDuration(String started, String completed) {
        Instant a = null, b = null;
        try { if (started != null) a = Instant.parse(started); } catch (Exception ignored) {}
        try { if (completed != null) b = Instant.parse(completed); } catch (Exception ignored) {}
        if (a == null || b == null) return null;
        long sec = Math.max(0, Duration.between(a, b).getSeconds());
        if (sec < 60) return sec + " s";
        return (sec / 60) + " min " + (sec % 60) + " s";
    }

    private static String extractCn(String rfc) {
        if (rfc == null) return null;
        for (String part : rfc.split(",")) {
            String p = part.trim();
            if (p.toUpperCase(Locale.ROOT).startsWith("CN=")) return p.substring(3);
        }
        return rfc;
    }

    private static String nullIfBlank(String s) {
        return (s == null || s.isBlank() || "—".equals(s) || "unknown".equalsIgnoreCase(s)) ? null : s;
    }

    private static String guessKeyType(String keySize) {
        if (keySize == null) return null;
        String u = keySize.toUpperCase(Locale.ROOT);
        if (u.contains("EC")) return "EC";
        if (u.contains("RSA")) return "RSA";
        return null;
    }

    private static Integer parseKeySize(String keySize) {
        if (keySize == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d+)").matcher(keySize);
        return m.find() ? Integer.parseInt(m.group(1)) : null;
    }

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
