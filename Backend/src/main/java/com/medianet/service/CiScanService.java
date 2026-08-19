package com.medianet.service;

import com.medianet.dto.CiScanDto;
import com.medianet.dto.CiVerdictDto;
import com.medianet.dto.CiVerdictFindingDto;
import com.medianet.dto.ScanRequest;
import com.medianet.dto.ScanResponse;
import com.medianet.entity.ClientRepository;
import com.medianet.entity.CveEntry;
import com.medianet.entity.PolicyDeviationStatus;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.User;
import com.medianet.repository.ClientRepositoryRepo;
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
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final CveEntryRepo cveEntryRepo;
    private final PolicyDeviationRequestRepo policyDeviationRequestRepo;
    private final CveAuditService cveAuditService;
    private final CiTokenService ciTokenService;
    private final NotificationService notificationService;
    private final String frontendUrl;

    public CiScanService(
            ScanService scanService,
            ScanResultRepo scanResultRepo,
            RepositoryRepo repositoryRepo,
            ClientRepositoryRepo clientRepositoryRepo,
            CveEntryRepo cveEntryRepo,
            PolicyDeviationRequestRepo policyDeviationRequestRepo,
            CveAuditService cveAuditService,
            CiTokenService ciTokenService,
            NotificationService notificationService,
            @Value("${github.oauth.frontend-url:}") String frontendUrl) {
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.repositoryRepo = repositoryRepo;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.policyDeviationRequestRepo = policyDeviationRequestRepo;
        this.cveAuditService = cveAuditService;
        this.ciTokenService = ciTokenService;
        this.notificationService = notificationService;
        this.frontendUrl = frontendUrl;
    }

    @Transactional
    public CiScanDto startScan(CiPrincipal principal, Long repositoryId, String commitSha, String ref) {
        return startScan(principal, repositoryId, commitSha, ref, null);
    }

    @Transactional
    public CiScanDto startScan(CiPrincipal principal, Long repositoryId, String commitSha, String ref,
            String githubRepo) {
        principal.assertHasScope(SCOPE_SCAN);
        Repository repo = resolveTargetRepository(principal, repositoryId, githubRepo);
        Long resolvedRepoId = repo.getId();
        String sha = requireCommitSha(commitSha);

        var reusable = scanResultRepo.findFirstByRepository_IdAndCommitShaIgnoreCaseAndStatusInOrderByStartedAtDesc(
                resolvedRepoId, sha, List.of(ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.COMPLETED));
        if (reusable.isPresent()) {
            ScanResult existing = reusable.get();
            log.info("CI scan reused scanId={} repoId={} sha={} status={}",
                    existing.getId(), resolvedRepoId, sha, existing.getStatus());
            notifyIfCiScanTerminal(existing);
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

        ScanResponse started = scanService.startScanOnRepository(resolvedRepoId, request, owner);
        ScanResult created = scanResultRepo.findByIdWithRepository(started.getScanId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Scan not created"));
        log.info("CI scan started scanId={} repoId={} sha={}", created.getId(), resolvedRepoId, sha);
        return toScanDto(created, false);
    }

    @Transactional(readOnly = true)
    public CiScanDto getScan(CiPrincipal principal, Long scanId) {
        principal.assertHasAnyScope(SCOPE_SCAN, SCOPE_VERDICT);
        ScanResult scan = scanResultRepo.findByIdWithRepository(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
        Long repoId = scan.getRepository() != null ? scan.getRepository().getId() : null;
        requireScopedRepository(principal, repoId);
        notifyIfCiScanTerminal(scan);
        return toScanDto(scan, false);
    }

    @Transactional(readOnly = true)
    public CiVerdictDto getVerdict(CiPrincipal principal, Long repositoryId, String commitSha) {
        return getVerdict(principal, repositoryId, commitSha, null);
    }

    @Transactional(readOnly = true)
    public CiVerdictDto getVerdict(CiPrincipal principal, Long repositoryId, String commitSha, String githubRepo) {
        principal.assertHasScope(SCOPE_VERDICT);
        Repository repo = resolveTargetRepository(principal, repositoryId, githubRepo);
        Long resolvedRepoId = repo.getId();
        String sha = requireCommitSha(commitSha);

        ScanResult scan = scanResultRepo
                .findFirstByRepository_IdAndCommitShaIgnoreCaseOrderByStartedAtDesc(resolvedRepoId, sha)
                .orElse(null);

        if (scan == null
                || scan.getStatus() == ScanStatus.RUNNING
                || scan.getStatus() == ScanStatus.PENDING) {
            return new CiVerdictDto(
                    "FAIL",
                    "SCAN_NOT_READY",
                    sha,
                    scan != null ? scan.getId() : null,
                    resolvedRepoId,
                    List.of(),
                    List.of(),
                    reportUrl(scan != null ? scan.getId() : null, resolvedRepoId));
        }

        if (scan.getStatus() == ScanStatus.FAILED) {
            notifyIfCiScanTerminal(scan);
            return new CiVerdictDto(
                    "FAIL",
                    "SCAN_FAILED",
                    sha,
                    scan.getId(),
                    resolvedRepoId,
                    List.of(),
                    List.of(),
                    reportUrl(scan.getId(), resolvedRepoId));
        }

        List<CveEntry> cves = cveEntryRepo.findByScanResultId(scan.getId());
        notifyIfCiScanTerminal(scan);
        return evaluate(scan, resolvedRepoId, sha, cves);
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

    /**
     * Never guess a repo. GitHub sends owner/name; Vulnix must scan that URL or fail.
     */
    Repository resolveTargetRepository(CiPrincipal principal, Long repositoryId, String githubRepo) {
        String wantedSlug = normalizeGithubSlug(githubRepo);

        if (repositoryId != null) {
            Repository repo = requireScopedRepository(principal, repositoryId);
            assertSlugMatchesIfProvided(repo, wantedSlug);
            return repo;
        }

        if (wantedSlug != null && !wantedSlug.isBlank()) {
            List<Repository> clientMatches = findClientReposBySlug(principal.clientId(), wantedSlug);
            if (clientMatches.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "No Vulnix repository matches GitHub project '" + wantedSlug
                                + "'. On the project page, link https://github.com/" + wantedSlug
                                + " then create a new CI token for that repo.");
            }
            List<Repository> allowed = clientMatches.stream()
                    .filter(repo -> principal.canAccessRepository(repo.getId()))
                    .toList();
            if (allowed.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "This CI token cannot scan '" + wantedSlug
                                + "'. Recreate the token on the project page and select that repository "
                                + "(do not reuse a token created for another app).");
            }
            if (allowed.size() > 1) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Several Vulnix repositories match " + wantedSlug);
            }
            return requireScopedRepository(principal, allowed.get(0).getId());
        }

        Set<Long> scopedIds = principal.repositoryIds() != null ? principal.repositoryIds() : Set.of();
        if (scopedIds.size() == 1) {
            return requireScopedRepository(principal, scopedIds.iterator().next());
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Cannot resolve repository. Send githubRepo as owner/name "
                        + "(GitHub Actions does this automatically).");
    }

    private void assertSlugMatchesIfProvided(Repository repo, String wantedSlug) {
        if (wantedSlug == null || wantedSlug.isBlank()) {
            return;
        }
        String actual = normalizeGithubSlug(repo.getRepoUrl());
        if (actual == null || !wantedSlug.equals(actual)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "GitHub project '" + wantedSlug + "' does not match Vulnix repository "
                            + repo.getId() + " (" + repo.getRepoUrl() + "). "
                            + "The CI token is tied to the wrong app.");
        }
    }

    private List<Repository> findClientReposBySlug(Long clientId, String wantedSlug) {
        if (clientId == null || wantedSlug == null) {
            return List.of();
        }
        List<Repository> matches = new ArrayList<>();
        for (ClientRepository link : clientRepositoryRepo.findByClient_Id(clientId)) {
            Repository repo = link.getRepository();
            if (repo != null && wantedSlug.equals(normalizeGithubSlug(repo.getRepoUrl()))) {
                matches.add(repo);
            }
        }
        return matches;
    }

    static String normalizeGithubSlug(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        value = value.replace('\\', '/');
        value = value.replaceFirst("^[a-z]+://", "");
        value = value.replaceFirst("^git@", "");
        value = value.replaceFirst("^github.com[:/]", "");
        value = value.replaceFirst("^gitlab.com[:/]", "");
        value = value.replaceFirst("^www.github.com[:/]", "");
        value = value.replaceAll("\\.git$", "");
        value = value.replaceAll("/+$", "");
        int idx = value.indexOf("github.com/");
        if (idx >= 0) {
            value = value.substring(idx + "github.com/".length());
        }
        int gl = value.indexOf("gitlab.com/");
        if (gl >= 0) {
            value = value.substring(gl + "gitlab.com/".length());
        }
        return value;
    }

    private void notifyIfCiScanTerminal(ScanResult scan) {
        if (scan == null || scan.getId() == null) {
            return;
        }
        ScanStatus status = scan.getStatus();
        if (status != ScanStatus.COMPLETED && status != ScanStatus.FAILED) {
            return;
        }
        try {
            notificationService.notifyCiScanFinished(scan.getId());
        } catch (Exception e) {
            log.warn("CI scan notification failed scanId={}", scan.getId(), e);
        }
    }

    private CiScanDto toScanDto(ScanResult scan, boolean reused) {
        Long scanId = scan.getId();
        Long repoId = scan.getRepository() != null ? scan.getRepository().getId() : null;
        String repoUrl = scan.getRepository() != null ? scan.getRepository().getRepoUrl() : null;
        int cveCount = scanId != null ? (int) cveEntryRepo.countByScanResultId(scanId) : 0;
        return new CiScanDto(
                scanId,
                repoId,
                repoUrl,
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
