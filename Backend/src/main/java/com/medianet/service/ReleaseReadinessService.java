package com.medianet.service;

import com.medianet.dto.ClientDto;
import com.medianet.entity.CveEntry;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.SecretFinding;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.User;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.SecretFindingRepo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Project delivery date versus the vulnerabilities that currently block a release (CI blockers: actively exploited,
 * CRITICAL or HIGH). The verdict is a delay risk from simple, visible rules. There is deliberately NO estimate of the
 * days needed to fix: a model for it was tried and dropped because the history it needs (real fix delays) does not
 * exist yet, and an unreliable number is worse than none.
 */
@Service
public class ReleaseReadinessService {

    static final String DISCLAIMER =
            "Risque de retard par rapport à la date de livraison, pas une décision de passage. "
                    + "Règles : des bloqueurs ouverts (CVE exploitée, critique ou élevée) ne laissent jamais un risque faible ; "
                    + "il est élevé quand il reste 7 jours ou moins (14 avec une CVE exploitée activement) ou que la date est dépassée. "
                    + "Aucune durée de correction n'est estimée.";

    private final ClientService clientService;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final SecretFindingRepo secretFindingRepo;

    public ReleaseReadinessService(ClientService clientService, ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo, SecretFindingRepo secretFindingRepo) {
        this.clientService = clientService;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.secretFindingRepo = secretFindingRepo;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> build(User user, Long clientId) {
        ClientDto client = clientService.getVisibleClient(user, clientId);
        Set<Long> repoIds = new LinkedHashSet<>(
                client.getRepositoryIds() != null ? client.getRepositoryIds() : List.of());

        List<ScanResult> latest = repoIds.isEmpty()
                ? List.of()
                : scanResultRepo.findLatestByStatusPerRepository(ScanStatus.COMPLETED).stream()
                        .filter(s -> s.getRepository() != null && repoIds.contains(s.getRepository().getId()))
                        .toList();

        List<CveEntry> findings = latest.isEmpty()
                ? List.of()
                : cveEntryRepo.findByScanResultIdInWithRepository(latest.stream().map(ScanResult::getId).toList());

        Map<String, FindingAgg> byKey = new LinkedHashMap<>();
        for (CveEntry entry : findings) {
            if (entry.getCveId() == null || entry.getCveId().isBlank()) {
                continue;
            }
            byKey.computeIfAbsent(findingKey(entry), k -> new FindingAgg(entry)).absorb(entry);
        }

        List<FindingAgg> open = new ArrayList<>(byKey.values());
        List<FindingAgg> blockers = open.stream().filter(FindingAgg::isBlocking).sorted(priorityOrder()).toList();
        int kevBlockers = (int) blockers.stream().filter(a -> a.kevListed).count();

        Integer daysRemaining = daysRemaining(client.getReleaseDeadline());
        String delayRisk = delayRisk(daysRemaining, blockers.size(), kevBlockers);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", client.getId());
        body.put("clientName", client.getName());
        body.put("releaseDeadline", client.getReleaseDeadline() != null ? client.getReleaseDeadline().toString() : null);
        body.put("releaseLabel", client.getReleaseLabel());
        body.put("daysRemaining", daysRemaining);
        body.put("delayRisk", delayRisk);
        body.put("openFindingCount", open.size());
        body.put("blockingCount", blockers.size());
        body.put("kevBlockingCount", kevBlockers);
        body.put("scannedRepoCount", latest.size());
        body.put("disclaimer", DISCLAIMER);
        body.put("priorities", blockers.stream().map(FindingAgg::toMap).toList());
        body.put("blockingSecrets", blockingSecrets(latest).stream().map(ReleaseReadinessService::secretToMap).toList());
        return body;
    }

    private List<SecretFinding> blockingSecrets(List<ScanResult> latest) {
        if (latest.isEmpty()) {
            return List.of();
        }
        return secretFindingRepo
                .findByScanResultIdInWithRepository(latest.stream().map(ScanResult::getId).toList())
                .stream()
                .filter(ReleaseReadinessService::isBlockingSecret)
                .toList();
    }

    /**
     * A secret blocks the release when an analyst confirmed it, or when the model calls it likely real outside
     * tests and docs. A false positive, a review, or an unscored finding stays out of this list.
     */
    static boolean isBlockingSecret(SecretFinding secret) {
        if (secret == null) {
            return false;
        }
        String analyst = secret.getAnalystVerdict();
        if ("FALSE_POSITIVE".equals(analyst)) {
            return false;
        }
        if ("REAL".equals(analyst)) {
            return true;
        }
        return "LIKELY_REAL".equals(secret.getMlVerdict()) && !"TEST_OR_DOC".equals(secret.getMlScope());
    }

    private static Map<String, Object> secretToMap(SecretFinding secret) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", secret.getId());
        row.put("ruleId", secret.getRuleId());
        row.put("description", secret.getDescription());
        row.put("file", secret.getFile());
        row.put("repository", secret.getScanResult() != null
                ? repoShortName(secret.getScanResult().getRepository())
                : "dépôt");
        row.put("verdict", "REAL".equals(secret.getAnalystVerdict()) ? "REAL" : "LIKELY_REAL");
        return row;
    }

    static Integer daysRemaining(LocalDate deadline) {
        if (deadline == null) {
            return null;
        }
        return (int) ChronoUnit.DAYS.between(LocalDate.now(), deadline);
    }

    /**
     * Delay risk from visible rules. No deadline: no verdict. Date passed: ELEVE. No blocker: FAIBLE. Otherwise
     * blockers are still open, so the risk is never FAIBLE: ELEVE at 7 days or fewer (14 with an actively exploited
     * CVE), MOYEN above.
     */
    static String delayRisk(Integer daysRemaining, int blockers, int kevBlockers) {
        if (daysRemaining == null) {
            return null;
        }
        if (daysRemaining < 0) {
            return "ELEVE";
        }
        if (blockers == 0) {
            return "FAIBLE";
        }
        if (daysRemaining <= 7 || (kevBlockers > 0 && daysRemaining <= 14)) {
            return "ELEVE";
        }
        return "MOYEN";
    }

    /** Most urgent first: actively exploited, then severity, then CVSS, then how many repositories are hit. */
    static Comparator<FindingAgg> priorityOrder() {
        return Comparator
                .comparing((FindingAgg a) -> !a.kevListed)
                .thenComparing(a -> -severityRank(a.severity))
                .thenComparing(a -> a.cvssScore == null ? 0.0 : -a.cvssScore)
                .thenComparing(Comparator.comparingInt((FindingAgg a) -> a.repositories.size()).reversed())
                .thenComparing(a -> a.cveId, String.CASE_INSENSITIVE_ORDER);
    }

    static String findingKey(CveEntry entry) {
        String id = firstNonBlank(entry.getCanonicalId(), entry.getCveId());
        String pkg = entry.getPackageName() == null ? "" : entry.getPackageName().trim().toLowerCase(Locale.ROOT);
        return (id == null ? "" : id.trim().toUpperCase(Locale.ROOT)) + "|" + pkg;
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return b;
    }

    static int severityRank(String severity) {
        if (severity == null) {
            return 0;
        }
        return switch (severity.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "URGENT" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    static String repoShortName(Repository repo) {
        if (repo == null || repo.getRepoUrl() == null || repo.getRepoUrl().isBlank()) {
            return "dépôt";
        }
        String url = repo.getRepoUrl().replaceAll("\\.git$", "");
        int slash = url.lastIndexOf('/');
        return slash >= 0 ? url.substring(slash + 1) : url;
    }

    static final class FindingAgg {
        final String cveId;
        String packageName;
        String severity;
        Double cvssScore;
        boolean kevListed;
        boolean blocking;
        final Set<String> repositories = new LinkedHashSet<>();

        FindingAgg(CveEntry first) {
            this.cveId = firstNonBlank(first.getCanonicalId(), first.getCveId());
            absorb(first);
        }

        boolean isBlocking() {
            return blocking;
        }

        void absorb(CveEntry entry) {
            if (packageName == null || packageName.isBlank()) {
                packageName = entry.getPackageName() == null ? "" : entry.getPackageName().trim();
            }
            if (severityRank(entry.getSeverity()) > severityRank(severity)) {
                severity = entry.getSeverity();
            }
            if (entry.getCvssScore() != null && (cvssScore == null || entry.getCvssScore() > cvssScore)) {
                cvssScore = entry.getCvssScore();
            }
            if (entry.isKevListed()) {
                kevListed = true;
            }
            if (CiScanService.isBlocking(entry)) {
                blocking = true;
            }
            if (entry.getScanResult() != null && entry.getScanResult().getRepository() != null) {
                repositories.add(repoShortName(entry.getScanResult().getRepository()));
            }
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("cveId", cveId);
            m.put("packageName", packageName);
            m.put("severity", severity);
            m.put("cvssScore", cvssScore);
            m.put("kevListed", kevListed);
            m.put("blocking", blocking);
            m.put("repoCount", repositories.size());
            m.put("repositories", new ArrayList<>(repositories));
            return m;
        }
    }
}
