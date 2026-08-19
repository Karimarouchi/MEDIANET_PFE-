package com.medianet.service;

import com.medianet.dto.CiScanDto;
import com.medianet.dto.CiVerdictDto;
import com.medianet.dto.ScanRequest;
import com.medianet.dto.ScanResponse;
import com.medianet.entity.ClientRepository;
import com.medianet.entity.ClientRepositoryId;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("CiScanService — quality gate CI")
class CiScanServiceTest {

    @Mock private ScanService scanService;
    @Mock private ScanResultRepo scanResultRepo;
    @Mock private RepositoryRepo repositoryRepo;
    @Mock private ClientRepositoryRepo clientRepositoryRepo;
    @Mock private CveEntryRepo cveEntryRepo;
    @Mock private PolicyDeviationRequestRepo policyDeviationRequestRepo;
    @Mock private CveAuditService cveAuditService;
    @Mock private CiTokenService ciTokenService;

    private CiScanService ciScanService;

    @BeforeEach
    void setUp() {
        ciScanService = new CiScanService(
                scanService,
                scanResultRepo,
                repositoryRepo,
                clientRepositoryRepo,
                cveEntryRepo,
                policyDeviationRequestRepo,
                cveAuditService,
                ciTokenService,
                "https://pfe.karimaoruchi.autolifeservices.com");
    }

    @Test
    @DisplayName("startScan() → refuse un dépôt hors scope du jeton")
    void startScan_rejectsRepoOutOfScope() {
        CiPrincipal principal = principal(Set.of(99L));
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> ciScanService.startScan(principal, 3L, "abc1234", "refs/heads/main"));
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        verify(scanService, never()).startScanOnRepository(any(), any(), any());
    }

    @Test
    @DisplayName("startScan() → réutilise un scan COMPLETED du même SHA")
    void startScan_reusesCompletedScanForSameSha() {
        CiPrincipal principal = principal(Set.of(3L));
        stubScopedRepo(3L);
        ScanResult existing = scan(88L, 3L, "a1b2c3d", ScanStatus.COMPLETED);
        when(scanResultRepo.findFirstByRepository_IdAndCommitShaIgnoreCaseAndStatusInOrderByStartedAtDesc(
                eq(3L), eq("a1b2c3d"), any())).thenReturn(Optional.of(existing));
        when(cveEntryRepo.countByScanResultId(88L)).thenReturn(4L);

        CiScanDto dto = ciScanService.startScan(principal, 3L, "A1B2C3D", "refs/heads/main");

        assertThat(dto.reused()).isTrue();
        assertThat(dto.scanId()).isEqualTo(88L);
        assertThat(dto.status()).isEqualTo("COMPLETED");
        assertThat(dto.cveCount()).isEqualTo(4);
        verify(scanService, never()).startScanOnRepository(any(), any(), any());
    }

    @Test
    @DisplayName("startScan() → lance un nouveau scan si aucun SHA réutilisable")
    void startScan_startsNewScanWhenMissing() {
        CiPrincipal principal = principal(Set.of(3L));
        Repository repo = stubScopedRepo(3L);
        when(scanResultRepo.findFirstByRepository_IdAndCommitShaIgnoreCaseAndStatusInOrderByStartedAtDesc(
                eq(3L), eq("a1b2c3d"), any())).thenReturn(Optional.empty());
        when(scanService.startScanOnRepository(eq(3L), any(ScanRequest.class), eq(repo.getOwnerUser())))
                .thenReturn(ScanResponse.builder().scanId(91L).repoId(3L).build());
        ScanResult created = scan(91L, 3L, "a1b2c3d", ScanStatus.RUNNING);
        when(scanResultRepo.findByIdWithRepository(91L)).thenReturn(Optional.of(created));
        when(cveEntryRepo.countByScanResultId(91L)).thenReturn(0L);

        CiScanDto dto = ciScanService.startScan(principal, 3L, "a1b2c3d", "refs/heads/main");

        assertThat(dto.reused()).isFalse();
        assertThat(dto.scanId()).isEqualTo(91L);
        assertThat(dto.status()).isEqualTo("RUNNING");
        verify(scanService).startScanOnRepository(eq(3L), any(ScanRequest.class), any());
    }

    @Test
    @DisplayName("getVerdict() → FAIL tant que le scan n'est pas terminé")
    void getVerdict_failClosedWhileRunning() {
        CiPrincipal principal = principal(Set.of(3L));
        stubScopedRepo(3L);
        ScanResult running = scan(88L, 3L, "a1b2c3d", ScanStatus.RUNNING);
        when(scanResultRepo.findFirstByRepository_IdAndCommitShaIgnoreCaseOrderByStartedAtDesc(3L, "a1b2c3d"))
                .thenReturn(Optional.of(running));

        CiVerdictDto verdict = ciScanService.getVerdict(principal, 3L, "a1b2c3d");

        assertThat(verdict.verdict()).isEqualTo("FAIL");
        assertThat(verdict.reason()).isEqualTo("SCAN_NOT_READY");
    }

    @Test
    @DisplayName("getVerdict() → FAIL si CVE CRITICAL non justifiée")
    void getVerdict_failsOnUnjustifiedCritical() {
        ScanResult completed = scan(88L, 3L, "a1b2c3d", ScanStatus.COMPLETED);
        CveEntry critical = cve("CVE-2024-1", "log4j-core", "CRITICAL");
        when(cveAuditService.hasRiskAccepted("CVE-2024-1", "log4j-core")).thenReturn(false);
        when(policyDeviationRequestRepo.existsByStatusAndCveIdIgnoreCaseAndPackageNameIgnoreCase(
                PolicyDeviationStatus.APPROVED, "CVE-2024-1", "log4j-core")).thenReturn(false);

        CiVerdictDto verdict = ciScanService.evaluate(completed, 3L, "a1b2c3d", List.of(critical));

        assertThat(verdict.verdict()).isEqualTo("FAIL");
        assertThat(verdict.reason()).isEqualTo("BLOCKING_VULNS");
        assertThat(verdict.blocking()).hasSize(1);
        assertThat(verdict.blocking().get(0).cveId()).isEqualTo("CVE-2024-1");
        assertThat(verdict.reportUrl()).contains("scanId=88");
    }

    @Test
    @DisplayName("getVerdict() → PASS si CRITICAL acceptée par le chef")
    void getVerdict_passesWhenRiskAccepted() {
        ScanResult completed = scan(88L, 3L, "a1b2c3d", ScanStatus.COMPLETED);
        CveEntry critical = cve("CVE-2024-1", "log4j-core", "CRITICAL");
        when(cveAuditService.hasRiskAccepted("CVE-2024-1", "log4j-core")).thenReturn(true);

        CiVerdictDto verdict = ciScanService.evaluate(completed, 3L, "a1b2c3d", List.of(critical));

        assertThat(verdict.verdict()).isEqualTo("PASS");
        assertThat(verdict.ignored()).hasSize(1);
        assertThat(verdict.ignored().get(0).reason()).isEqualTo("RISK_ACCEPTED");
        assertThat(verdict.blocking()).isEmpty();
    }

    @Test
    @DisplayName("getVerdict() → MEDIUM ne bloque pas")
    void getVerdict_mediumDoesNotBlock() {
        ScanResult completed = scan(88L, 3L, "a1b2c3d", ScanStatus.COMPLETED);
        CiVerdictDto verdict = ciScanService.evaluate(completed, 3L, "a1b2c3d",
                List.of(cve("CVE-2024-2", "lodash", "MEDIUM")));
        assertThat(verdict.verdict()).isEqualTo("PASS");
        assertThat(verdict.blocking()).isEmpty();
    }

    @Test
    @DisplayName("requireCommitSha() → refuse un SHA invalide")
    void requireCommitSha_rejectsInvalid() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> CiScanService.requireCommitSha("not-a-sha"));
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(CiScanService.requireCommitSha("ABCDEF0")).isEqualTo("abcdef0");
    }

    @Test
    @DisplayName("startScan() → sans id : utilise le seul dépôt du jeton")
    void startScan_resolvesSingleScopedRepoWithoutId() {
        CiPrincipal principal = principal(Set.of(3L));
        stubScopedRepo(3L);
        ScanResult existing = scan(88L, 3L, "a1b2c3d", ScanStatus.COMPLETED);
        when(scanResultRepo.findFirstByRepository_IdAndCommitShaIgnoreCaseAndStatusInOrderByStartedAtDesc(
                eq(3L), eq("a1b2c3d"), any())).thenReturn(Optional.of(existing));
        when(cveEntryRepo.countByScanResultId(88L)).thenReturn(1L);

        CiScanDto dto = ciScanService.startScan(principal, null, "a1b2c3d", "refs/heads/main", null);

        assertThat(dto.scanId()).isEqualTo(88L);
        assertThat(dto.reused()).isTrue();
    }

    @Test
    @DisplayName("startScan() → sans id : matche owner/name GitHub")
    void startScan_resolvesGithubSlug() {
        CiPrincipal principal = principal(Set.of(3L, 9L));
        Repository courtlinker = stubScopedRepo(3L);
        courtlinker.setRepoUrl("https://github.com/Karimarouchi/courtlinker.git");
        Repository other = new Repository();
        other.setId(9L);
        other.setRepoUrl("https://github.com/Karimarouchi/other");
        when(clientRepositoryRepo.findByClient_Id(2L)).thenReturn(List.of(
                ClientRepository.builder()
                        .id(new ClientRepositoryId(2L, 3L))
                        .repository(courtlinker)
                        .build(),
                ClientRepository.builder()
                        .id(new ClientRepositoryId(2L, 9L))
                        .repository(other)
                        .build()));
        ScanResult existing = scan(88L, 3L, "a1b2c3d", ScanStatus.COMPLETED);
        existing.getRepository().setRepoUrl("https://github.com/Karimarouchi/courtlinker.git");
        when(scanResultRepo.findFirstByRepository_IdAndCommitShaIgnoreCaseAndStatusInOrderByStartedAtDesc(
                eq(3L), eq("a1b2c3d"), any())).thenReturn(Optional.of(existing));
        when(cveEntryRepo.countByScanResultId(88L)).thenReturn(1L);

        CiScanDto dto = ciScanService.startScan(principal, null, "a1b2c3d", "refs/heads/main",
                "Karimarouchi/courtlinker");

        assertThat(dto.scanId()).isEqualTo(88L);
        assertThat(dto.repoUrl()).containsIgnoringCase("courtlinker");
    }

    @Test
    @DisplayName("startScan() → githubRepo CourtLinker + jeton e-commerce → refuse, ne scanne pas l'autre repo")
    void startScan_doesNotFallBackToUnrelatedTokenRepo() {
        CiPrincipal principal = principal(Set.of(3L));
        Repository ecommerce = new Repository();
        ecommerce.setId(3L);
        ecommerce.setRepoUrl("https://github.com/Karimarouchi/E-commerce-coussin");
        when(clientRepositoryRepo.findByClient_Id(2L)).thenReturn(List.of(
                ClientRepository.builder()
                        .id(new ClientRepositoryId(2L, 3L))
                        .repository(ecommerce)
                        .build()));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> ciScanService.startScan(principal, null, "a1b2c3d", "refs/heads/main",
                        "Karimarouchi/courtlinker"));

        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(ex.getReason()).containsIgnoringCase("karimarouchi/courtlinker");
        verify(scanService, never()).startScanOnRepository(any(), any(), any());
    }

    @Test
    @DisplayName("normalizeGithubSlug() → owner/name depuis une URL")
    void normalizeGithubSlug_fromUrl() {
        assertThat(CiScanService.normalizeGithubSlug("https://github.com/Karimarouchi/courtlinker.git"))
                .isEqualTo("karimarouchi/courtlinker");
        assertThat(CiScanService.normalizeGithubSlug("Karimarouchi/courtlinker"))
                .isEqualTo("karimarouchi/courtlinker");
        assertThat(CiScanService.normalizeGithubSlug("https://gitlab.com/antigone-agency/pfe-mediannet.git"))
                .isEqualTo("antigone-agency/pfe-mediannet");
    }

    @Test
    @DisplayName("branchFromRef() → enlève refs/heads/")
    void branchFromRef_stripsHeadsPrefix() {
        Repository repo = new Repository();
        repo.setBranch("develop");
        assertThat(CiScanService.branchFromRef("refs/heads/main", repo)).isEqualTo("main");
        assertThat(CiScanService.branchFromRef("refs/pull/12/head", repo)).isEqualTo("develop");
        assertThat(CiScanService.branchFromRef("feature/x", repo)).isEqualTo("feature/x");
    }

    private CiPrincipal principal(Set<Long> repoIds) {
        return new CiPrincipal(1L, "GitHub Actions", "vx_live_abcd", 2L, repoIds,
                Set.of("ci:scan", "ci:verdict"));
    }

    private Repository stubScopedRepo(Long repoId) {
        Repository repo = new Repository();
        repo.setId(repoId);
        repo.setRepoUrl("https://github.com/org/app");
        repo.setBranch("main");
        User owner = new User();
        owner.setId(9L);
        owner.setLogin("owner");
        repo.setOwnerUser(owner);
        when(ciTokenService.isRepositoryStillLinkedToClient(2L, repoId)).thenReturn(true);
        when(repositoryRepo.findById(repoId)).thenReturn(Optional.of(repo));
        return repo;
    }

    private static ScanResult scan(Long id, Long repoId, String sha, ScanStatus status) {
        Repository repo = new Repository();
        repo.setId(repoId);
        return ScanResult.builder()
                .id(id)
                .status(status)
                .commitSha(sha)
                .repository(repo)
                .resultsDir("/tmp/scan")
                .build();
    }

    private static CveEntry cve(String cveId, String pkg, String severity) {
        CveEntry entry = new CveEntry();
        entry.setCveId(cveId);
        entry.setPackageName(pkg);
        entry.setPackageVersion("1.0.0");
        entry.setSeverity(severity);
        return entry;
    }
}
