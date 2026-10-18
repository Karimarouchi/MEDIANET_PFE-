package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.FindingKind;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.SecretFinding;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.SecretFindingRepo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Figures of the "Évolution" tab, one row per finished scan of a repository.
 *
 * The tab used to plot the raw number of finding rows: dependency CVEs plus Semgrep code alerts, with the same CVE
 * counted once per tool (Grype "postcss@7.0.39" and Dependency-Check "postcss:7.0"). Here a dependency vulnerability
 * is one CVE on one package, whatever the number of tools that saw it, split by severity; code alerts and secrets
 * are counted apart, secrets with the same groups as the "Sécurité du code" tab.
 */
@Service
public class RepositoryHistoryService {

    /** Dependency-Check writes "postcss:7.0" where Grype writes "postcss": drop a trailing ":<version>". */
    private static final Pattern VERSION_SUFFIX = Pattern.compile(":\\d[\\w.\\-]*$");

    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final SecretFindingRepo secretFindingRepo;

    public RepositoryHistoryService(ScanResultRepo scanResultRepo, CveEntryRepo cveEntryRepo,
            SecretFindingRepo secretFindingRepo) {
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.secretFindingRepo = secretFindingRepo;
    }

    /** Oldest first. Caller has already checked the user may see the repository. */
    @Transactional(readOnly = true)
    public List<Map<String, Object>> history(Long repositoryId) {
        List<ScanResult> scans = new ArrayList<>(scanResultRepo.findByRepositoryIdOrderByStartedAtDesc(repositoryId)
                .stream().filter(s -> s.getStatus() == ScanStatus.COMPLETED).toList());
        java.util.Collections.reverse(scans);
        List<Map<String, Object>> out = new ArrayList<>();
        for (ScanResult scan : scans) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("scanId", scan.getId());
            row.put("startedAt", scan.getStartedAt() != null ? scan.getStartedAt().toString() : null);
            row.put("commitSha", scan.getCommitSha());
            row.putAll(countFindings(cveEntryRepo.findByScanResultId(scan.getId())));
            row.put("secrets", countSecrets(secretFindingRepo.findByScanResultId(scan.getId())));
            out.add(row);
        }
        return out;
    }

    /** Unique dependency vulnerabilities by severity, and code alerts. Package-private for tests. */
    static Map<String, Object> countFindings(Collection<CveEntry> entries) {
        Map<String, String> worstByKey = new HashMap<>();
        int codeAlerts = 0;
        int rawRows = 0;
        for (CveEntry e : entries) {
            rawRows++;
            if (e.getFindingKind() == FindingKind.CODE_WEAKNESS) {
                codeAlerts++;
                continue;
            }
            String key = dependencyKey(e);
            String sev = normalizeSeverity(e.getSeverity());
            worstByKey.merge(key, sev, (a, b) -> rank(a) >= rank(b) ? a : b);
        }
        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (String s : List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")) {
            bySeverity.put(s, 0);
        }
        worstByKey.values().forEach(s -> bySeverity.merge(s, 1, Integer::sum));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("vulnerabilities", worstByKey.size());
        m.put("bySeverity", bySeverity);
        m.put("codeAlerts", codeAlerts);
        m.put("rawRows", rawRows);
        return m;
    }

    /**
     * {critical, high, kev} counted on unique dependency vulnerabilities (same key and worst-severity rule as
     * {@link #countFindings}), so a repo card and the Évolution tab show the same figures. A key is KEV when any
     * tool flagged it. Package-private for tests.
     */
    static long[] severeCounts(Collection<CveEntry> entries) {
        Map<String, String> worstByKey = new HashMap<>();
        Set<String> kevKeys = new HashSet<>();
        for (CveEntry e : entries) {
            if (e.getFindingKind() == FindingKind.CODE_WEAKNESS
                    || (e.getCveId() != null && e.getCveId().startsWith("npm|"))) {
                continue;
            }
            String key = dependencyKey(e);
            worstByKey.merge(key, normalizeSeverity(e.getSeverity()), (a, b) -> rank(a) >= rank(b) ? a : b);
            if (e.isKevListed()) {
                kevKeys.add(key);
            }
        }
        long critical = worstByKey.values().stream().filter("CRITICAL"::equals).count();
        long high = worstByKey.values().stream().filter("HIGH"::equals).count();
        return new long[] { critical, high, kevKeys.size() };
    }

    /** Same groups as the "Sécurité du code" tab (Frontend/src/utils/secretView.ts). Package-private for tests. */
    static Map<String, Integer> countSecrets(Collection<SecretFinding> secrets) {
        int toHandle = 0, testAndDocs = 0, toCheck = 0, falsePositives = 0, confirmed = 0;
        for (SecretFinding s : secrets) {
            String analyst = s.getAnalystVerdict();
            if ("REAL".equals(analyst)) {
                confirmed++;
                toHandle++;
                continue;
            }
            if ("FALSE_POSITIVE".equals(analyst) || "LIKELY_FALSE_POSITIVE".equals(s.getMlVerdict())) {
                falsePositives++;
            } else if ("LIKELY_REAL".equals(s.getMlVerdict())) {
                if ("TEST_OR_DOC".equals(s.getMlScope())) testAndDocs++;
                else toHandle++;
            } else {
                toCheck++; // REVIEW or not triaged
            }
        }
        Map<String, Integer> m = new LinkedHashMap<>();
        m.put("total", secrets.size());
        m.put("toHandle", toHandle);
        m.put("confirmed", confirmed);
        m.put("toCheck", toCheck);
        m.put("testAndDocs", testAndDocs);
        m.put("falsePositives", falsePositives);
        return m;
    }

    static String dependencyKey(CveEntry e) {
        String id = e.getCanonicalId() != null && !e.getCanonicalId().isBlank() ? e.getCanonicalId() : e.getCveId();
        String pkg = e.getPackageName() == null ? "" : e.getPackageName().trim().toLowerCase(Locale.ROOT);
        pkg = VERSION_SUFFIX.matcher(pkg).replaceFirst("");
        return (id == null ? "" : id.trim().toUpperCase(Locale.ROOT)) + "|" + pkg;
    }

    static String normalizeSeverity(String s) {
        if (s == null) return "UNKNOWN";
        return switch (s.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> "CRITICAL";
            case "HIGH" -> "HIGH";
            case "MEDIUM", "MODERATE" -> "MEDIUM";
            case "LOW", "NEGLIGIBLE" -> "LOW";
            default -> "UNKNOWN";
        };
    }

    private static int rank(String s) {
        return switch (s) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }
}
