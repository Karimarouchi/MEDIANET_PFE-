package com.medianet.service;

import com.medianet.entity.EpssHistorySnapshot;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.EpssHistorySnapshotRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;

/**
 * Downloads historical daily EPSS score snapshots (github.com/empiricalsec/epss_scores,
 * FIRST.org's public archive) and stores the trajectory for CVEs actually seen in our
 * own scans — an external signal ("how has the industry-wide exploitation probability
 * of this CVE evolved over time?") that our own scan history alone cannot provide.
 *
 * Only CVEs we've actually encountered are persisted (each daily file covers the
 * entire public CVE catalogue, which we don't need), and dates are sampled at an
 * interval (weekly by default) rather than daily, to keep bandwidth/storage sane —
 * a trend signal doesn't need daily resolution.
 */
@Service
public class EpssHistoricalIngestionService {

    private static final Logger log = LoggerFactory.getLogger(EpssHistoricalIngestionService.class);
    private static final Pattern REAL_CVE = Pattern.compile("^CVE-\\d{4}-\\d+$");
    private static final String BASE_URL = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main";

    private final CveEntryRepo cveEntryRepo;
    private final EpssHistorySnapshotRepo snapshotRepo;
    private final RestTemplate restTemplate;

    public EpssHistoricalIngestionService(CveEntryRepo cveEntryRepo, EpssHistorySnapshotRepo snapshotRepo) {
        this.cveEntryRepo = cveEntryRepo;
        this.snapshotRepo = snapshotRepo;
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(8_000);
        factory.setReadTimeout(20_000);
        this.restTemplate = new RestTemplate(factory);
    }

    public record IngestionSummary(int datesAttempted, int datesIngested, int datesSkippedAlready,
            int datesMissing, int rowsSaved, int trackedCveCount) {
    }

    /** CVE identifiers actually present in our own scan history — the only ones worth tracking. */
    public Set<String> loadTrackedCveIds() {
        return cveEntryRepo.findDistinctCanonicalOrCveIds().stream()
                .filter(id -> id != null && REAL_CVE.matcher(id).matches())
                .collect(Collectors.toSet());
    }

    /**
     * Ingests one snapshot per {@code stepDays} between {@code start} and {@code end}
     * (inclusive), skipping dates already ingested. Safe to re-run — idempotent per date.
     */
    public IngestionSummary ingestRange(LocalDate start, LocalDate end, int stepDays) {
        Set<String> tracked = loadTrackedCveIds();
        if (tracked.isEmpty()) {
            log.warn("EPSS historical ingestion: no real CVE ids tracked yet — nothing to do.");
            return new IngestionSummary(0, 0, 0, 0, 0, 0);
        }

        int attempted = 0, ingested = 0, skipped = 0, missing = 0, rows = 0;
        for (LocalDate date = start; !date.isAfter(end); date = date.plusDays(stepDays)) {
            attempted++;
            if (snapshotRepo.existsBySnapshotDate(date)) {
                skipped++;
                continue;
            }
            int saved = ingestSnapshot(date, tracked);
            if (saved < 0) {
                missing++;
            } else {
                ingested++;
                rows += saved;
            }
        }

        log.info("EPSS historical ingestion done: {} dates attempted, {} ingested, {} already present, "
                        + "{} missing upstream, {} rows saved, {} CVEs tracked",
                attempted, ingested, skipped, missing, rows, tracked.size());
        return new IngestionSummary(attempted, ingested, skipped, missing, rows, tracked.size());
    }

    /** Returns rows saved, or -1 if the upstream file for that date doesn't exist (gap/out of range). */
    private int ingestSnapshot(LocalDate date, Set<String> trackedCveIds) {
        String url = BASE_URL + "/" + date.getYear() + "/epss_scores-" + date + ".csv.gz";
        try {
            byte[] gzipped = restTemplate.getForObject(URI.create(url), byte[].class);
            if (gzipped == null || gzipped.length == 0) return -1;

            List<EpssHistorySnapshot> matches = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new GZIPInputStream(new java.io.ByteArrayInputStream(gzipped)), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.isEmpty() || line.charAt(0) == '#' || line.startsWith("cve,")) continue;
                    String[] parts = line.split(",", 3);
                    if (parts.length < 3) continue;
                    String cveId = parts[0].trim();
                    if (!trackedCveIds.contains(cveId)) continue;
                    try {
                        matches.add(EpssHistorySnapshot.builder()
                                .cveId(cveId)
                                .snapshotDate(date)
                                .epssScore(Double.parseDouble(parts[1].trim()))
                                .percentile(Double.parseDouble(parts[2].trim()))
                                .build());
                    } catch (NumberFormatException ignored) {
                        // malformed row upstream — skip it, not worth failing the whole day for one row
                    }
                }
            }
            if (!matches.isEmpty()) {
                snapshotRepo.saveAll(matches);
            }
            return matches.size();
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                return -1; // no file for this date (gap in the archive, or before 2021-04-14)
            }
            log.warn("EPSS historical fetch failed for {}: {}", date, e.getMessage());
            return -1;
        } catch (IOException | RuntimeException e) {
            log.warn("EPSS historical fetch/parse failed for {}: {}", date, e.getMessage());
            return -1;
        }
    }
}
