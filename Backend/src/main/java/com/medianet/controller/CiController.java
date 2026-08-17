package com.medianet.controller;

import com.medianet.dto.CiScanDto;
import com.medianet.dto.CiVerdictDto;
import com.medianet.dto.CiWhoamiDto;
import com.medianet.security.CiPrincipal;
import com.medianet.service.CiScanService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;

/**
 * CI-only API. Authenticated exclusively with {@code Authorization: Bearer vx_live_…}.
 * User JWTs and session cookies are rejected by {@code JwtAuthFilter}.
 */
@RestController
@RequestMapping("/api/ci")
public class CiController {

    private final CiScanService ciScanService;

    public CiController(CiScanService ciScanService) {
        this.ciScanService = ciScanService;
    }

    @GetMapping("/whoami")
    public ResponseEntity<CiWhoamiDto> whoami(HttpServletRequest request) {
        CiPrincipal principal = CiPrincipal.require(request);
        return ResponseEntity.ok(new CiWhoamiDto(
                principal.tokenId(),
                principal.name(),
                principal.tokenPrefix(),
                principal.clientId(),
                new ArrayList<>(principal.repositoryIds()),
                new ArrayList<>(principal.scopes())));
    }

    @PostMapping("/scans")
    public ResponseEntity<CiScanDto> startScan(
            HttpServletRequest request,
            @RequestBody StartCiScanRequest body) {
        CiPrincipal principal = CiPrincipal.require(request);
        return ResponseEntity.ok(ciScanService.startScan(
                principal,
                body != null ? body.repositoryId() : null,
                body != null ? body.commitSha() : null,
                body != null ? body.ref() : null,
                body != null ? body.githubRepo() : null));
    }

    @GetMapping("/scans/{scanId}")
    public ResponseEntity<CiScanDto> getScan(
            HttpServletRequest request,
            @PathVariable Long scanId) {
        CiPrincipal principal = CiPrincipal.require(request);
        return ResponseEntity.ok(ciScanService.getScan(principal, scanId));
    }

    @GetMapping("/verdict")
    public ResponseEntity<CiVerdictDto> getVerdict(
            HttpServletRequest request,
            @RequestParam(required = false) Long repositoryId,
            @RequestParam String sha,
            @RequestParam(required = false) String githubRepo) {
        CiPrincipal principal = CiPrincipal.require(request);
        return ResponseEntity.ok(ciScanService.getVerdict(principal, repositoryId, sha, githubRepo));
    }

    public record StartCiScanRequest(Long repositoryId, String commitSha, String ref, String githubRepo) {
    }
}
