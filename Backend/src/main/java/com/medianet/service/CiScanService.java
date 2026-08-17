package com.medianet.service;

import com.medianet.dto.CiScanDto;
import com.medianet.dto.CiVerdictDto;
import com.medianet.dto.CiVerdictFindingDto;
import com.medianet.dto.ScanRequest;
import com.medianet.dto.ScanResponse;
import com.medianet.entity.CveEntry;
import com.medianet.entity.PolicyDeviationStatus;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.User;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.PolicyDeviationRequestRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.security.CiPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@Service
public class CiScanService {

    private static final Logger log = LoggerFactory.getLogger(CiScanService.class);
    private static final Set<String> BLOCKING_SEVERITIES = Set.of("CRITICAL", "HIGH");
    public static final String SCOPE_SCAN = "ci:scan";
    public static final String SCOPE_VERDICT = "ci:verdict";

    private final ScanService scanService;
    private final ScanResultRepo scanResultRepo;
    private final RepositoryRepo repositoryRepo;
    private final CveEntryRepo cveEntryRepo;
    private final PolicyDeviationRequestRepo policyDeviationRequestRepo;
    private final CveAuditService cveAuditService;
    private final CiTokenService ciTokenService;
    private final String frontendUrl;

    public CiScanService(
            ScanService scanService,
            ScanResultRepo scanResultRepo,
            RepositoryRepo repositoryRepo,
            CveEntryRepo cveEntryRepo,
            PolicyDeviationRequestRepo policyDeviationRequestRepo,
            CveAuditService cveAuditService,
            CiTokenService ciTokenService,
            @Value("${github.oauth.frontend-url:}") String frontendUrl) {
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.repositoryRepo = repositoryRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.policyDeviationRequestRepo = policyDeviationRequestRepo;
        this.cveAuditService = cveAuditService;
        this.ciTokenService = ciTokenService;
        this.frontendUrl = frontendUrl;
    }

    @Transactional
    public CiScanDto startScan(CiPrincipal principal, Long repositoryId, String commitSha, String ref) {
        principal.assertHasScope(SCOPE_SCAN);
        Repository repo = requireScopedRepository(principal, repositoryId);
        String sha = requireCommitSha(commitSha);

        var reusable = scanResultRepo.findFirstByRepository_IdAndCommitShaIgnoreCaseAndStatusInOrderByStartedAtDesc(
                repositoryId, sha, List.of(ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.COMPLETED));
        if (reusable.isPresent()) {
            ScanResult existing = reusable.get();
            log.info("CI scan reused scanId={} repoId={} sha={} status={}",
                    existing.getId(), repositoryId, sha, existing.getStatus());
            return toScanDto(existing, true);
        }

        User owner = repo.getOwnerUser();
        if (owner != null) {
            owner.getLogin();
        }

        ScanRequest request = new ScanRequest();
        request.setRepoUrl(repo.getRepoUrl());
        request.setBranch(branchFromRef(ref, repo));
        request.setScanMode("auto");
        request.setCommitSha(sha);

        ScanResponse started = scanService.startScanOnRepository(repositoryId, request, owner);
        ScanResult created = scanResultRepo.findByIdWithRepository(started.getScanId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Scan not created"));
        log.info("CI scan started scanId={} repoId={} sha={}", created.getId(), repositoryId, sha);
        return toScanDto(created, false);
    }

    @Transactional(readOnly = true)
    public CiScanDto getScan(CiPrincipal principal, Long scanId) {
        principal.assertHasAnyScope(SCOPE_SCAN, SCOPE_VERDICT);
        ScanResult scan = scanResultRepo.findByIdWithRepository(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
        Long repoId = scan.getRepository() != null ? scan.getRepository().getId() : null;
        requireScopedRepository(principal, repoId);
        return toScanDto(scan, false);
    }

    @Transactional(readOnly = true)
    public CiVerdictDto getVerdict(CiPrincipal principal, Long repositoryId, String commitSha) {
        principal.assertHasScope(SCOPE_VERDICT);
        requireScopedRepository(principal, repositoryId);
        String sha = requireCommitSha(commitSha);

        ScanResult scan = scanResultRepo
                .findFirstByRepository_IdAndCommitShaIgnoreCaseOrderByStartedAtDesc(repositoryId, sha)
                .orElse(null);

        if (scan == null
                || scan.getStatus() == ScanStatus.RUNNING
                || scan.getStatus() == ScanStatus.PENDING) {
            return new CiVerdictDto(
                    "FAIL",
                    "SCAN_NOT_READY",
                    sha,
                    scan != null ? scan.getId() : null,
                    repositoryId,
                    List.of(),
                    List.of(),
                    reportUrl(scan != null ? scan.getId() : null, repositoryId));
        }

        if (scan.getStatus() == ScanStatus.FAILED) {
            return new CiVerdictDto(
                    "FAIL",
                    "SCAN_FAILED",
                    sha,
                    scan.getId(),
                    repositoryId,
                    List.of(),
                    List.of(),
                    reportUrl(scan.getId(), repositoryId));
        }

        List<CveEntry> cves = cveEntryRepo.findByScanResultId(scan.getId());
        return evaluate(scan, repositoryId, sha, cves);
    }

    CiVerdictDto evaluate(ScanResult scan, Long repositoryId, String sha, List<CveEntry> cves) {
        Map<String, CiVerdictFindingDto> blockingByKey = new LinkedHashMap<>();
        Map<String, CiVerdictFindingDto> ignoredByKey = new LinkedHashMap<>();

        for (CveEntry cve : cves == null ? List.<CveEntry>of() : cves) {
            if (!isBlockingSeverity(cve.getSeverity())) {
                continue;
            }
            String key = (nullToEmpty(cve.getCveId()) + "|" + nullToEmpty(cve.getPackageName())).toLowerCase(Locale.ROOT);
            String justification = justificationReason(cve.getCveId(), cve.getPackageName());
            CiVerdictFindingDto finding = new CiVerdictFindingDto(
                    cve.getCveId(),
                    normalizeSeverity(cve.getSeverity()),
                    cve.getPackageName(),
                    cve.getPackageVersion(),
                    justification != null,
                    justification);
            if (justification != null) {
                ignoredByKey.putIfAbsent(key, finding);
            } else {
                blockingByKey.putIfAbsent(key, finding);
            }
        }

        List<CiVerdictFindingDto> blocking = new ArrayList<>(blockingByKey.values());
        List<CiVerdictFindingDto> ignored = new ArrayList<>(ignoredByKey.values());
        boolean pass = blocking.isEmpty();
        return new CiVerdictDto(
                pass ? "PASS" : "FAIL",
                pass ? "PASS" : "BLOCKING_VULNS",
                sha,
                scan != null ? scan.getId() : null,
                repositoryId,
                blocking,
                ignored,
                reportUrl(scan != null ? scan.getId() : null, repositoryId));
    }

    static String requireCommitSha(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commitSha is required");
        }
        String sha = raw.trim().toLowerCase(Locale.ROOT);
        if (!sha.matches("[0-9a-f]{7,40}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "commitSha must be a git SHA (7-40 hex chars)");
        }
        return sha;
    }

    static boolean isBlockingSeverity(String severity) {
        return BLOCKING_SEVERITIES.contains(normalizeSeverity(severity));
    }

    private String justificationReason(String cveId, String packageName) {
        if (cveId == null || cveId.isBlank()) {
            return null;
        }
        if (cveAuditService.hasRiskAccepted(cveId, packageName)) {
            return "RISK_ACCEPTED";
        }
        String pkg = packageName != null ? packageName.trim() : "";
        if (policyDeviationRequestRepo.existsByStatusAndCveIdIgnoreCaseAndPackageNameIgnoreCase(
                PolicyDeviationStatus.APPROVED, cveId.trim(), pkg)) {
            return "POLICY_DEVIATION_APPROVED";
        }
        return null;
    }

    private Repository requireScopedRepository(CiPrincipal principal, Long repositoryId) {
        if (repositoryId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "repositoryId is required");
        }
        principal.assertCanAccessRepository(repositoryId);
        if (!ciTokenService.isRepositoryStillLinkedToClient(principal.clientId(), repositoryId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Repository is no longer linked to this client");
        }
        return repositoryRepo.findById(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found"));
    }

    private CiScanDto toScanDto(ScanResult scan, boolean reused) {
        Long scanId = scan.getId();
        Long repoId = scan.getRepository() != null ? scan.getRepository().getId() : null;
        int cveCount = scanId != null ? (int) cveEntryRepo.countByScanResultId(scanId) : 0;
        return new CiScanDto(
                scanId,
                repoId,
                scan.getCommitSha(),
                scan.getStatus() != null ? scan.getStatus().name() : null,
                reused,
                cveCount);
    }

    private String reportUrl(Long scanId, Long repoId) {
        String base = frontendUrl != null ? frontendUrl.trim().replaceAll("/+$", "") : "";
        StringBuilder url = new StringBuilder(base);
        url.append("/vulnerabilities");
        if (scanId != null) {
            url.append("?scanId=").append(scanId);
            if (repoId != null) {
                url.append("&repoId=").append(repoId);
            }
        } else if (repoId != null) {
            url.append("?repoId=").append(repoId);
        }
        return url.toString();
    }

    static String branchFromRef(String ref, Repository repo) {
        if (ref != null && !ref.isBlank()) {
            String value = ref.trim();
            if (value.startsWith("refs/heads/")) {
                return value.substring("refs/heads/".length());
            }
            if (value.startsWith("refs/tags/")) {
                return value.substring("refs/tags/".length());
            }
            if (!value.startsWith("refs/")) {
                return value;
            }
        }
        return repo != null ? repo.getBranch() : null;
    }

    private static String normalizeSeverity(String severity) {
        return severity == null ? "" : severity.trim().toUpperCase(Locale.ROOT);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
