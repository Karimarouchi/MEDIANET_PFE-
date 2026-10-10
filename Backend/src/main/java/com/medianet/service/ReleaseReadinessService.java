package com.medianet.service;

import com.medianet.dto.ClientDto;
import com.medianet.entity.CveEntry;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.User;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.ScanResultRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Client delivery date vs the critical path (max remaining estimated days) of current CI blockers.
 * Verdict is delay risk, never a go / no-go for production.
 */
@Service
public class ReleaseReadinessService {

    private static final Logger log = LoggerFactory.getLogger(ReleaseReadinessService.class);
    static final double FALLBACK_MAE_DAYS = 2.0;
    static final String DISCLAIMER =
            "Risque de retard par rapport à la date client, pas une décision de passage. "
                    + "Le chemin critique est le max des jours restants estimés des bloqueurs CI (KEV ou CRITICAL/HIGH), "
                    + "pas une somme. Les jours restants = estimation Medianet − ancienneté du finding, ± MAE.";

    static final String RELIABILITY_NOTE =
            "Estimation des jours non fiable : le modèle a été entraîné sur trop peu de corrections réelles. "
                    + "Verdict basé sur des règles simples (nombre de bloqueurs, jours restants, CVE exploitées).";

    private final ClientService clientService;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final FeatureStoreBuilderService featureStoreBuilderService;
    private final MlPredictService mlPredictService;

    public ReleaseReadinessService(ClientService clientService, ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo, FeatureStoreBuilderService featureStoreBuilderService,
            MlPredictService mlPredictService) {
        this.clientService = clientService;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.featureStoreBuilderService = featureStoreBuilderService;
        this.mlPredictService = mlPredictService;
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
            FindingAgg agg = byKey.computeIfAbsent(findingKey(entry), k -> new FindingAgg(entry));
            agg.absorb(entry);
        }

        List<FindingAgg> open = new ArrayList<>(byKey.values());
        List<FindingAgg> blockers = open.stream().filter(FindingAgg::isBlocking).toList();

        boolean modelAvailable = true;
        int unscored = 0;
        try {
            unscored = scoreBlockers(blockers, repoIds);
        } catch (Exception e) {
            modelAvailable = false;
            unscored = blockers.size();
            log.warn("Release readiness ML unavailable for client {}: {}", clientId, e.getMessage());
        }

        Double estimatedDays = criticalPathDays(blockers.stream().map(a -> a.remainingDays).toList());
        if (blockers.isEmpty()) {
            estimatedDays = 0.0;
        }
        Double mae = blockers.stream().map(a -> a.estimatedDaysMae).filter(Objects::nonNull).findFirst().orElse(null);
        Integer daysRemaining = daysRemaining(client.getReleaseDeadline());
        // No CI blocker means no vulnerability-driven delay, even if the date has passed.
        // The day estimate is only trustworthy when the regression has a reliable MAE. Otherwise (too few real
        // fixes to learn from) we fall back to transparent rules instead of announcing a false "FAIBLE".
        boolean estimateReliable = blockers.isEmpty() || mae != null;
        int kevBlockers = (int) blockers.stream().filter(a -> a.kevListed).count();
        String delayRisk;
        String delayRiskBasis;
        if (blockers.isEmpty()) {
            delayRisk = daysRemaining == null ? null : "FAIBLE";
            delayRiskBasis = daysRemaining == null ? "NONE" : "RULES";
        } else if (estimateReliable) {
            delayRisk = delayRisk(daysRemaining, estimatedDays, mae);
            delayRiskBasis = delayRisk == null ? "NONE" : "MODEL";
        } else {
            delayRisk = rulesDelayRisk(daysRemaining, blockers.size(), kevBlockers);
            delayRiskBasis = delayRisk == null ? "NONE" : "RULES";
        }
        double[] interval = MlPredictService.daysInterval(estimatedDays, mae != null ? mae : FALLBACK_MAE_DAYS);

        List<Map<String, Object>> priorities = blockers.stream()
                .sorted(priorityOrder())
                .map(FindingAgg::toMap)
                .toList();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("clientId", client.getId());
        body.put("clientName", client.getName());
        body.put("releaseDeadline",
                client.getReleaseDeadline() != null ? client.getReleaseDeadline().toString() : null);
        body.put("releaseLabel", client.getReleaseLabel());
        body.put("daysRemaining", daysRemaining);
        body.put("estimatedRemediationDays", estimatedDays);
        body.put("estimatedDaysMae", mae);
        body.put("marginSource", mae != null ? "MAE" : "FIXED_2_DAYS");
        body.put("estimatedDaysLow", interval == null ? null : interval[0]);
        body.put("estimatedDaysHigh", interval == null ? null : interval[1]);
        body.put("delayRisk", delayRisk);
        body.put("delayRiskBasis", delayRiskBasis);
        body.put("estimateReliable", estimateReliable);
        body.put("reliabilityNote", estimateReliable ? null : RELIABILITY_NOTE);
        body.put("criticalPathNote",
                "max des jours restants estimés des bloqueurs CI (estimation − ancienneté) — "
                        + "les correctifs peuvent être faits en parallèle, ce n'est pas une somme.");
        body.put("openFindingCount", open.size());
        body.put("blockingCount", blockers.size());
        body.put("scannedRepoCount", latest.size());
        body.put("modelAvailable", modelAvailable);
        body.put("unscoredBlockingCount", unscored);
        body.put("estimateIncomplete", unscored > 0 && !blockers.isEmpty());
        body.put("disclaimer", DISCLAIMER);
        body.put("priorities", priorities);
        return body;
    }

    /**
     * Scores blockers in one batch. Returns how many blockers could not be scored
     * (no detection history), so the caller can flag an incomplete critical path.
     */
    private int scoreBlockers(List<FindingAgg> blockers, Set<Long> repoIds) {
        if (blockers.isEmpty()) {
            return 0;
        }
        List<FeatureStoreBuilderService.FindingKey> keys = blockers.stream()
                .map(a -> new FeatureStoreBuilderService.FindingKey(a.cveId, a.packageName))
                .toList();
        List<Optional<Map<String, Object>>> features = featureStoreBuilderService.buildInferenceFeaturesBatch(keys);

        List<Map<String, Object>> rows = new ArrayList<>();
        List<FindingAgg> scored = new ArrayList<>();
        for (int i = 0; i < blockers.size(); i++) {
            if (features.get(i).isPresent()) {
                rows.add(features.get(i).get());
                scored.add(blockers.get(i));
            }
        }
        if (rows.isEmpty()) {
            return blockers.size();
        }
        LocalDate today = LocalDate.now();
        List<MlPredictService.Prediction> predictions = mlPredictService.predictFeaturesBatch(rows);
        for (int i = 0; i < scored.size() && i < predictions.size(); i++) {
            MlPredictService.Prediction prediction = predictions.get(i);
            FindingAgg agg = scored.get(i);
            agg.remediationBand = prediction.remediationBand();
            agg.slaBreachProba = prediction.slaBreachProba();
            agg.estimatedDays = prediction.estimatedDays();
            agg.estimatedDaysMae = prediction.estimatedDaysMae();
            // The model predicts total time-to-fix from detection. A finding already open
            // for N days within this project only has (estimate - N) days left.
            agg.ageDays = featureStoreBuilderService.firstSeenInRepos(agg.cveId, agg.packageName, repoIds)
                    .map(seen -> (int) Math.max(0, ChronoUnit.DAYS.between(seen.toLocalDate(), today)))
                    .orElse(0);
            agg.remainingDays = remainingDays(prediction.estimatedDays(), agg.ageDays);
            double[] interval = MlPredictService.daysInterval(agg.remainingDays,
                    prediction.estimatedDaysMae() != null ? prediction.estimatedDaysMae() : FALLBACK_MAE_DAYS);
            if (interval != null) {
                agg.estimatedDaysLow = interval[0];
                agg.estimatedDaysHigh = interval[1];
            }
        }
        return blockers.size() - scored.size();
    }

    /** Time still needed = total estimate minus the time the finding has already been open. */
    static Double remainingDays(Double estimatedDays, int ageDays) {
        return estimatedDays == null ? null : Math.max(0.0, estimatedDays - ageDays);
    }

    static Integer daysRemaining(LocalDate deadline) {
        if (deadline == null) {
            return null;
        }
        return (int) ChronoUnit.DAYS.between(LocalDate.now(), deadline);
    }

    /**
     * Delay risk uses the MAE interval, not a certainty. Missing deadline or
     * missing estimate → no verdict. Deadline already passed → ELEVE.
     */
    static String delayRisk(Integer daysRemaining, Double estimatedDays, Double mae) {
        if (daysRemaining == null) {
            return null;
        }
        if (daysRemaining < 0) {
            return "ELEVE";
        }
        if (estimatedDays == null) {
            return null;
        }
        double margin = mae != null ? mae : FALLBACK_MAE_DAYS;
        if (estimatedDays > daysRemaining) {
            return "ELEVE";
        }
        if (estimatedDays + margin > daysRemaining) {
            return "MOYEN";
        }
        return "FAIBLE";
    }

    /**
     * Rule-based verdict used when the days model is not reliable: open CI blockers must be fixed before delivery, so
     * the risk can never be "FAIBLE"; it is "ELEVE" when little time is left (7 days, or 14 with an actively
     * exploited CVE) or the date has passed, "MOYEN" otherwise.
     */
    static String rulesDelayRisk(Integer daysRemaining, int blockers, int kevBlockers) {
        if (daysRemaining == null) {
            return null;
        }
        if (daysRemaining < 0 || (blockers > 0 && daysRemaining <= 7)
                || (kevBlockers > 0 && daysRemaining <= 14)) {
            return "ELEVE";
        }
        return blockers > 0 ? "MOYEN" : "FAIBLE";
    }

    static Double criticalPathDays(List<Double> estimatedDays) {
        return estimatedDays.stream().filter(Objects::nonNull).max(Double::compareTo).orElse(null);
    }

    static Comparator<FindingAgg> priorityOrder() {
        return Comparator
                .comparing((FindingAgg a) -> !a.kevListed)
                .thenComparing(a -> bandRank(a.remediationBand), Comparator.reverseOrder())
                .thenComparing(a -> a.remainingDays == null ? Double.NEGATIVE_INFINITY : a.remainingDays,
                        Comparator.reverseOrder())
                .thenComparing(Comparator.comparingInt((FindingAgg a) -> a.repositories.size()).reversed())
                .thenComparing(a -> a.cveId, String.CASE_INSENSITIVE_ORDER);
    }

    static int bandRank(String band) {
        if (band == null) {
            return 0;
        }
        return switch (band.toUpperCase(Locale.ROOT)) {
            case "ELEVE" -> 3;
            case "MOYEN" -> 2;
            case "FAIBLE" -> 1;
            default -> 0;
        };
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
        String remediationBand;
        Double slaBreachProba;
        Double estimatedDays;
        Double estimatedDaysMae;
        int ageDays;
        Double remainingDays;
        Double estimatedDaysLow;
        Double estimatedDaysHigh;

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
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("cveId", cveId);
            row.put("packageName", packageName == null || packageName.isBlank() ? null : packageName);
            row.put("severity", severity);
            row.put("cvssScore", cvssScore);
            row.put("kevListed", kevListed);
            row.put("blocking", blocking);
            row.put("repoCount", repositories.size());
            row.put("repositories", new ArrayList<>(repositories));
            row.put("remediationBand", remediationBand);
            row.put("slaBreachProba", slaBreachProba);
            row.put("estimatedDays", estimatedDays);
            row.put("ageDays", ageDays);
            row.put("remainingDays", remainingDays);
            row.put("estimatedDaysLow", estimatedDaysLow);
            row.put("estimatedDaysHigh", estimatedDaysHigh);
            return row;
        }
    }
}
