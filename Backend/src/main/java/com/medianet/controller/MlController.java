package com.medianet.controller;

import com.medianet.entity.CveMlFeature;
import com.medianet.entity.CveRemediationRecord;
import com.medianet.repository.CveMlFeatureRepo;
import com.medianet.repository.CveRemediationRecordRepo;
import com.medianet.service.EpssHistoricalIngestionService;
import com.medianet.service.FeatureStoreBuilderService;
import com.medianet.service.RemediationLabelService;
import com.medianet.service.UserService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/ml")
public class MlController {

    private final RemediationLabelService remediationLabelService;
    private final CveRemediationRecordRepo remediationRecordRepo;
    private final EpssHistoricalIngestionService epssHistoricalIngestionService;
    private final FeatureStoreBuilderService featureStoreBuilderService;
    private final CveMlFeatureRepo featureRepo;
    private final UserService userService;

    public MlController(RemediationLabelService remediationLabelService,
            CveRemediationRecordRepo remediationRecordRepo,
            EpssHistoricalIngestionService epssHistoricalIngestionService,
            FeatureStoreBuilderService featureStoreBuilderService,
            CveMlFeatureRepo featureRepo,
            UserService userService) {
        this.remediationLabelService = remediationLabelService;
        this.remediationRecordRepo = remediationRecordRepo;
        this.epssHistoricalIngestionService = epssHistoricalIngestionService;
        this.featureStoreBuilderService = featureStoreBuilderService;
        this.featureRepo = featureRepo;
        this.userService = userService;
    }

    // POST /api/ml/remediation-labels/recompute → rebuild the derived training labels
    @PostMapping("/remediation-labels/recompute")
    public ResponseEntity<RemediationLabelService.DerivationSummary> recompute(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(remediationLabelService.deriveAll());
    }

    // GET /api/ml/remediation-labels → inspect the derived records
    @GetMapping("/remediation-labels")
    public ResponseEntity<List<CveRemediationRecord>> list(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(remediationRecordRepo.findAll());
    }

    // GET /api/ml/epss-history/tracked-cves → which real CVEs are eligible for historical ingestion
    @GetMapping("/epss-history/tracked-cves")
    public ResponseEntity<Set<String>> trackedCves(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(epssHistoricalIngestionService.loadTrackedCveIds());
    }

    // POST /api/ml/epss-history/ingest → download weekly EPSS snapshots for our tracked CVEs
    @PostMapping("/epss-history/ingest")
    public ResponseEntity<EpssHistoricalIngestionService.IngestionSummary> ingestEpssHistory(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            @RequestParam(defaultValue = "7") int stepDays,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        LocalDate end = endDate != null ? endDate : LocalDate.now();
        return ResponseEntity.ok(epssHistoricalIngestionService.ingestRange(startDate, end, Math.max(stepDays, 1)));
    }

    // POST /api/ml/features/build → joins labels (Phase 0) + external signals (Phase 1) into the feature store
    @PostMapping("/features/build")
    public ResponseEntity<FeatureStoreBuilderService.BuildSummary> buildFeatures(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(featureStoreBuilderService.buildAll());
    }

    // GET /api/ml/features/export.csv → the feature store as CSV, ready for the Python training pipeline
    @GetMapping("/features/export.csv")
    public ResponseEntity<String> exportFeaturesCsv(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        List<CveMlFeature> rows = featureRepo.findAll();

        StringBuilder csv = new StringBuilder();
        csv.append("first_seen_at,canonical_id,package_name,cwe_id,severity,cvss_score,ecosystem,")
                .append("kev_listed,kev_ransomware,days_to_kev_listing,exploit_available,")
                .append("epss_score_at_detection,epss_score_latest,epss_score_trend,epss_observation_count,")
                .append("days_to_fix,sla_threshold_days,sla_breached\n");
        for (CveMlFeature f : rows) {
            csv.append(nullable(f.getFirstSeenAt())).append(',')
                    .append(csvField(f.getCanonicalId())).append(',')
                    .append(csvField(f.getPackageName())).append(',')
                    .append(csvField(f.getCweId())).append(',')
                    .append(csvField(f.getSeverity())).append(',')
                    .append(nullable(f.getCvssScore())).append(',')
                    .append(csvField(f.getEcosystem())).append(',')
                    .append(f.isKevListed()).append(',')
                    .append(f.isKevRansomware()).append(',')
                    .append(nullable(f.getDaysToKevListing())).append(',')
                    .append(f.isExploitAvailable()).append(',')
                    .append(nullable(f.getEpssScoreAtDetection())).append(',')
                    .append(nullable(f.getEpssScoreLatest())).append(',')
                    .append(nullable(f.getEpssScoreTrend())).append(',')
                    .append(f.getEpssObservationCount()).append(',')
                    .append(nullable(f.getDaysToFix())).append(',')
                    .append(f.getSlaThresholdDays()).append(',')
                    .append(f.isSlaBreached()).append('\n');
        }

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cve_ml_features.csv\"")
                .body(csv.toString());
    }

    private static String csvField(String value) {
        if (value == null) return "";
        String escaped = value.replace("\"", "\"\"");
        return "\"" + escaped + "\"";
    }

    private static String nullable(Object value) {
        return value != null ? String.valueOf(value) : "";
    }
}
