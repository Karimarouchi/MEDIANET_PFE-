package com.medianet.controller;

import com.medianet.entity.CveRemediationRecord;
import com.medianet.repository.CveRemediationRecordRepo;
import com.medianet.service.EpssHistoricalIngestionService;
import com.medianet.service.RemediationLabelService;
import com.medianet.service.UserService;
import org.springframework.format.annotation.DateTimeFormat;
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
    private final UserService userService;

    public MlController(RemediationLabelService remediationLabelService,
            CveRemediationRecordRepo remediationRecordRepo,
            EpssHistoricalIngestionService epssHistoricalIngestionService,
            UserService userService) {
        this.remediationLabelService = remediationLabelService;
        this.remediationRecordRepo = remediationRecordRepo;
        this.epssHistoricalIngestionService = epssHistoricalIngestionService;
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
}
