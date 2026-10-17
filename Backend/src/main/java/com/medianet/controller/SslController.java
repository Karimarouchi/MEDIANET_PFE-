package com.medianet.controller;

import com.medianet.dto.CertTransparencyResultDto;
import com.medianet.dto.DnsSecurityResultDto;
import com.medianet.dto.ScanRequest;
import com.medianet.dto.ScanResponse;
import com.medianet.dto.SslResultDto;
import com.medianet.entity.ScanResult;
import com.medianet.entity.User;
import com.medianet.repository.ScanResultRepo;
import com.medianet.service.CensysSslService;
import com.medianet.service.CertTransparencyService;
import com.medianet.service.DnsSecurityService;
import com.medianet.service.ScanService;
import com.medianet.service.SslAiService;
import com.medianet.service.SslLabsService;
import com.medianet.service.SslResultAssembler;
import com.medianet.service.SslTargetGuard;
import com.medianet.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SSL page endpoints. The result itself is built by {@link SslResultAssembler}; this class only checks who is
 * asking and what they target.
 */
@RestController
@RequestMapping("/api/ssl")
public class SslController {

    private final ScanService scanService;
    private final ScanResultRepo scanResultRepo;
    private final UserService userService;
    private final SslLabsService sslLabsService;
    private final CensysSslService censysSslService;
    private final SslAiService sslAiService;
    private final SslResultAssembler assembler;
    private final SslTargetGuard targetGuard;
    private final CertTransparencyService certTransparencyService;
    private final DnsSecurityService dnsSecurityService;

    public SslController(ScanService scanService, ScanResultRepo scanResultRepo,
            UserService userService, SslLabsService sslLabsService,
            CensysSslService censysSslService, SslAiService sslAiService,
            SslResultAssembler assembler, SslTargetGuard targetGuard,
            CertTransparencyService certTransparencyService,
            DnsSecurityService dnsSecurityService) {
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.userService = userService;
        this.sslLabsService = sslLabsService;
        this.censysSslService = censysSslService;
        this.sslAiService = sslAiService;
        this.assembler = assembler;
        this.targetGuard = targetGuard;
        this.certTransparencyService = certTransparencyService;
        this.dnsSecurityService = dnsSecurityService;
    }

    // ── GET /api/ssl/cert-transparency?domain=X → subdomains seen in CT logs ──
    @GetMapping("/cert-transparency")
    public ResponseEntity<CertTransparencyResultDto> getCertTransparency(
            @RequestParam String domain,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(certTransparencyService.lookup(SslTargetGuard.normalize(domain).host()));
    }

    // ── GET /api/ssl/dns-security?domain=X → SPF/DMARC/CAA posture ─────────
    @GetMapping("/dns-security")
    public ResponseEntity<DnsSecurityResultDto> getDnsSecurity(
            @RequestParam String domain,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(dnsSecurityService.lookup(SslTargetGuard.normalize(domain).host()));
    }

    // ── POST /api/ssl/scan → launch ssl-only scan ───────────────────
    @PostMapping("/scan")
    public ResponseEntity<ScanResponse> startSslScan(
            @RequestBody SslScanRequest req,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        // Format + DNS + internal-address check before anything connects to the target.
        String target = targetGuard.check(req.getDomain()).canonical();

        ScanRequest scanReq = new ScanRequest();
        scanReq.setScanMode("ssl-only");
        scanReq.setTargetDomain(target);
        scanReq.setRepoUrl("ssl://" + target); // stable DB identifier
        ScanResponse resp = scanService.startScan(scanReq, currentUser);

        // Fire SSL Labs + Censys analyses in parallel (non-blocking @Async)
        ScanResult scanEntity = scanResultRepo.findById(resp.getScanId()).orElse(null);
        if (scanEntity != null) {
            String dir = scanEntity.getResultsDir();
            sslLabsService.analyzeAsync(target, dir);
            censysSslService.analyzeAsync(target, dir);
        }

        return ResponseEntity.ok(resp);
    }

    // ── GET /api/ssl/scan/{scanId}/logs → SSE log stream ───────────
    @GetMapping(value = "/scan/{scanId}/logs", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamLogs(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            jakarta.servlet.http.HttpServletResponse response) {
        authorizedScan(authHeader, scanId);
        response.setHeader("X-Accel-Buffering", "no");
        response.setHeader("Cache-Control", "no-cache");
        return scanService.createLogEmitter(scanId);
    }

    // ── GET /api/ssl/scan/{scanId}/result → parsed SSL summary ─────
    // Not transactional on purpose: the live header check is a network call (see SslResultAssembler).
    @GetMapping("/scan/{scanId}/result")
    public ResponseEntity<SslResultDto> getSslResult(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        ScanResult scan = authorizedScan(authHeader, scanId);
        return ResponseEntity.ok(assembler.build(scan, true, true));
    }

    // ── GET /api/ssl/scan/{scanId}/previous → last finished scan of the same target, for comparison ─
    @GetMapping("/scan/{scanId}/previous")
    public ResponseEntity<Map<String, Object>> getPreviousSslResult(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        ScanResult scan = authorizedScan(authHeader, scanId);
        if (scan.getRepository() == null || scan.getStartedAt() == null) {
            return ResponseEntity.noContent().build();
        }
        ScanResult previous = scanResultRepo.findByRepositoryIdOrderByStartedAtDesc(scan.getRepository().getId())
                .stream()
                .filter(s -> !s.getId().equals(scanId))
                .filter(s -> s.getStatus() == ScanResult.ScanStatus.COMPLETED)
                .filter(s -> s.getStartedAt() != null && s.getStartedAt().isBefore(scan.getStartedAt()))
                .findFirst()
                .flatMap(s -> scanResultRepo.findByIdWithRepository(s.getId()))
                .orElse(null);
        if (previous == null) {
            return ResponseEntity.noContent().build();
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scanId", previous.getId());
        body.put("startedAt", previous.getStartedAt().toString());
        // Stored values only: the live header check would make both scans look identical.
        body.put("result", assembler.build(previous, false, false));
        return ResponseEntity.ok(body);
    }

    // ── POST /api/ssl/scan/{scanId}/cancel → stop the Kali container and the external lookups ─
    @PostMapping("/scan/{scanId}/cancel")
    public ResponseEntity<Void> cancelSslScan(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        ScanResult scan = authorizedScan(authHeader, scanId);
        scanService.stopScan(scanId);
        String dir = scan.getResultsDir();
        if (dir != null && !dir.isBlank() && !dir.startsWith("db://")) {
            sslLabsService.cancel(dir);
            assembler.markPendingSourcesCancelled(dir);
        }
        return ResponseEntity.ok().build();
    }

    // ── POST /api/ssl/ai-analysis → Gemini SSL assessment ─────────────
    @PostMapping("/ai-analysis")
    public ResponseEntity<java.util.Map<String, Object>> sslAiAnalysis(
            @RequestBody java.util.Map<String, Object> context,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader); // spends the system AI key: a real, active account is required
        return ResponseEntity.ok(sslAiService.analyze(context));
    }

    /** Loads the scan with its repository and checks the user may see it (was missing: any user could read any SSL result). */
    private ScanResult authorizedScan(String authHeader, Long scanId) {
        User user = userService.getRequiredUser(authHeader);
        scanService.getAuthorizedScan(user, scanId);
        return scanResultRepo.findByIdWithRepository(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan introuvable"));
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
}
