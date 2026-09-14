package com.medianet.service;

import com.medianet.entity.AuthProvider;
import com.medianet.entity.Client;
import com.medianet.entity.ClientRepository;
import com.medianet.entity.CveEntry;
import com.medianet.entity.CveRemediationStatus;
import com.medianet.entity.FixKnowledge;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.CveOfficialGuidanceRepo;
import com.medianet.repository.FixKnowledgeRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ScanResultRepo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Blast radius: one CVE across the latest scan of every visible repository.
 */
@Service
public class CveExposureService {

    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final RepositoryRepo repositoryRepo;
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final FixKnowledgeRepo fixKnowledgeRepo;
    private final CveOfficialGuidanceRepo guidanceRepo;
    private final CveAuditService cveAuditService;
    private final CisaKevService cisaKevService;

    public CveExposureService(
            ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo,
            RepositoryRepo repositoryRepo,
            ClientRepositoryRepo clientRepositoryRepo,
            FixKnowledgeRepo fixKnowledgeRepo,
            CveOfficialGuidanceRepo guidanceRepo,
            CveAuditService cveAuditService,
            CisaKevService cisaKevService) {
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.repositoryRepo = repositoryRepo;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.fixKnowledgeRepo = fixKnowledgeRepo;
        this.guidanceRepo = guidanceRepo;
        this.cveAuditService = cveAuditService;
        this.cisaKevService = cisaKevService;
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> build(User user) {
        Set<Long> visible = visibleRepoIds(user);
        if (visible.isEmpty()) {
            return List.of();
        }

        List<ScanResult> latest = scanResultRepo.findLatestByStatusPerRepository(ScanStatus.COMPLETED)
                .stream()
                .filter(s -> s.getRepository() != null && visible.contains(s.getRepository().getId()))
                .toList();
        if (latest.isEmpty()) {
            return List.of();
        }

        List<Long> scanIds = latest.stream().map(ScanResult::getId).toList();
        List<CveEntry> cves = cveEntryRepo.findByScanResultIdInWithRepository(scanIds);

        Map<Long, String> clientsByRepo = clientNamesByRepo();
        Set<String> patchedRepoKeys = patchedRepoKeys();
        Map<String, String> chefByKey = chefVersions();

        Map<String, Boolean> closedCache = new HashMap<>();
        Map<String, ExposureAgg> byCve = new LinkedHashMap<>();
        LocalDateTime now = LocalDateTime.now();
        LocalDate today = now.toLocalDate();

        for (CveEntry c : cves) {
            if (c.getCveId() == null || c.getCveId().isBlank() || c.getScanResult() == null) {
                continue;
            }
            Repository repo = c.getScanResult().getRepository();
            if (repo == null || repo.getId() == null) {
                continue;
            }
            String cveId = c.getCveId().trim();
            String pkg = blank(c.getPackageName());
            boolean globallyClosed = closedCache.computeIfAbsent(keyOf(cveId, pkg),
                    k -> cveAuditService.hasFalsePositive(cveId, pkg)
                            || cveAuditService.hasRiskAccepted(cveId, pkg));
            boolean patchedHere = patchedRepoKeys.contains(repoPatchKey(cveId, pkg, repoSlug(repo)));
            boolean stillOpen = isRepoStillOpen(true, globallyClosed, patchedHere);

            String chef = chefByKey.get(keyOf(cveId, pkg));
            if (chef == null) {
                chef = chefByKey.get(keyOf(cveId, ""));
            }

            CisaKevService.KevEntry kev = cisaKevService.getKevEntry(cveId);
            boolean kevListed = c.isKevListed() || kev != null;
            String dateAdded = c.getKevDateAdded() != null ? c.getKevDateAdded()
                    : (kev != null ? kev.dateAdded() : null);
            String catalogDue = kev != null ? kev.dueDate() : null;
            LocalDate cisaDue = kevListed ? CveJournalSla.resolveCisaDueDate(catalogDue, dateAdded) : null;
            CveRemediationStatus clockStatus = stillOpen ? CveRemediationStatus.OPEN : CveRemediationStatus.FIXED;
            LocalDateTime firstSeen = c.getScanResult().getStartedAt();

            ExposureAgg agg = byCve.computeIfAbsent(cveId.toUpperCase(Locale.ROOT),
                    k -> new ExposureAgg(cveId));
            agg.absorb(c, kevListed);
            RepoHit hit = new RepoHit(
                    repo.getId(),
                    repoShortName(repo),
                    repo.getRepoUrl(),
                    repoSlug(repo),
                    repo.getGitProvider() != null ? repo.getGitProvider().name() : AuthProvider.GITHUB.name(),
                    repo.getBranch(),
                    clientsByRepo.get(repo.getId()),
                    pkg.isBlank() ? null : pkg,
                    c.getPackageVersion(),
                    c.getFilePath(),
                    c.getSource(),
                    c.getManifestFile(),
                    stillOpen ? "OPEN" : "PATCHED",
                    stillOpen,
                    kevListed,
                    CveJournalSla.isKevOverdue(kevListed && stillOpen, clockStatus, firstSeen, now),
                    CveJournalSla.isCisaOverdue(kevListed && stillOpen, clockStatus, cisaDue, today),
                    chef,
                    canPropagate(stillOpen, chef, c.getPackageVersion()));
            agg.addHit(hit);
        }

        List<Map<String, Object>> out = new ArrayList<>();
        for (ExposureAgg agg : byCve.values()) {
            out.add(agg.toMap());
        }
        out.sort((a, b) -> {
            int open = ((Number) b.get("openRepoCount")).intValue() - ((Number) a.get("openRepoCount")).intValue();
            if (open != 0) {
                return open;
            }
            int kev = Boolean.TRUE.equals(b.get("kevListed")) ? 1 : 0;
            kev -= Boolean.TRUE.equals(a.get("kevListed")) ? 1 : 0;
            if (kev != 0) {
                return kev;
            }
            return String.valueOf(a.get("cveId")).compareToIgnoreCase(String.valueOf(b.get("cveId")));
        });
        return out;
    }

    @Transactional(readOnly = true)
    public List<RepoHit> openTargets(User user, String cveId, String packageName) {
        if (cveId == null || cveId.isBlank()) {
            return List.of();
        }
        String wantedPkg = blank(packageName);
        List<RepoHit> hits = new ArrayList<>();
        for (Map<String, Object> row : build(user)) {
            if (!cveId.equalsIgnoreCase(String.valueOf(row.get("cveId")))) {
                continue;
            }
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> repos = (List<Map<String, Object>>) row.get("repositories");
            if (repos == null) {
                continue;
            }
            for (Map<String, Object> repo : repos) {
                if (!Boolean.TRUE.equals(repo.get("stillOpen"))) {
                    continue;
                }
                String pkg = String.valueOf(repo.get("packageName") == null ? "" : repo.get("packageName"));
                if (!wantedPkg.isBlank() && !wantedPkg.equalsIgnoreCase(pkg)) {
                    continue;
                }
                hits.add(RepoHit.fromMap(repo));
            }
        }
        return hits;
    }

    static boolean isRepoStillOpen(boolean presentInLatestScan, boolean globallyClosed, boolean patchedOnThisRepo) {
        return presentInLatestScan && !globallyClosed && !patchedOnThisRepo;
    }

    static boolean canPropagate(boolean stillOpen, String chefVersion, String currentVersion) {
        if (!stillOpen || chefVersion == null || chefVersion.isBlank()) {
            return false;
        }
        return currentVersion == null || currentVersion.isBlank()
                || !PolicyDeviationService.versionsEquivalent(chefVersion, currentVersion);
    }

    private Set<Long> visibleRepoIds(User user) {
        if (user != null && user.getRole() == UserRole.ADMIN) {
            return new HashSet<>(repositoryRepo.findAll().stream().map(Repository::getId).toList());
        }
        if (user == null || user.getId() == null) {
            return new HashSet<>(repositoryRepo.findAll().stream().map(Repository::getId).toList());
        }
        return new HashSet<>(repositoryRepo.findVisibleToEmployee(user.getId()).stream()
                .map(Repository::getId)
                .toList());
    }

    private Map<Long, String> clientNamesByRepo() {
        Map<Long, Set<String>> names = new HashMap<>();
        for (ClientRepository link : clientRepositoryRepo.findAllWithClientAndRepository()) {
            if (link.getRepository() == null || link.getRepository().getId() == null) {
                continue;
            }
            Client client = link.getClient();
            String name = client != null && client.getName() != null ? client.getName() : null;
            if (name == null || name.isBlank()) {
                continue;
            }
            names.computeIfAbsent(link.getRepository().getId(), k -> new java.util.LinkedHashSet<>()).add(name);
        }
        Map<Long, String> joined = new HashMap<>();
        names.forEach((id, set) -> joined.put(id, String.join(", ", set)));
        return joined;
    }

    private Set<String> patchedRepoKeys() {
        Set<String> keys = new HashSet<>();
        for (FixKnowledge k : fixKnowledgeRepo.findAllByOrderByCreatedAtDesc()) {
            if (k.getCveId() == null || k.getCveId().isBlank() || k.getRepoFullName() == null) {
                continue;
            }
            String slug = CiScanService.normalizeGithubSlug(k.getRepoFullName());
            if (slug == null || slug.isBlank()) {
                continue;
            }
            keys.add(repoPatchKey(k.getCveId(), blank(k.getPackageName()), slug));
        }
        return keys;
    }

    private Map<String, String> chefVersions() {
        Map<String, String> out = new HashMap<>();
        guidanceRepo.findAll().forEach(g -> {
            if (g.getStableVersion() == null || g.getStableVersion().isBlank()) {
                return;
            }
            out.putIfAbsent(keyOf(blank(g.getCveId()), blank(g.getPackageName())), g.getStableVersion().trim());
        });
        return out;
    }

    private static String repoPatchKey(String cveId, String packageName, String slug) {
        return blank(cveId).toLowerCase(Locale.ROOT) + "|" + blank(packageName).toLowerCase(Locale.ROOT)
                + "|" + blank(slug).toLowerCase(Locale.ROOT);
    }

    private static String keyOf(String cveId, String packageName) {
        return blank(cveId).toLowerCase(Locale.ROOT) + "|" + blank(packageName).toLowerCase(Locale.ROOT);
    }

    static String repoSlug(Repository repo) {
        if (repo == null) {
            return "";
        }
        String slug = CiScanService.normalizeGithubSlug(repo.getRepoUrl());
        return slug != null ? slug : "";
    }

    static String repoShortName(Repository repo) {
        String slug = repoSlug(repo);
        if (slug.contains("/")) {
            return slug.substring(slug.lastIndexOf('/') + 1);
        }
        return repo != null && repo.getRepoUrl() != null ? repo.getRepoUrl() : "dépôt";
    }

    private static String blank(String value) {
        return value == null ? "" : value.trim();
    }

    static final class RepoHit {
        final Long repositoryId;
        final String repoName;
        final String repoUrl;
        final String repoFullName;
        final String gitProvider;
        final String branch;
        final String clientName;
        final String packageName;
        final String packageVersion;
        final String filePath;
        final String source;
        final String manifestFile;
        final String status;
        final boolean stillOpen;
        final boolean kevListed;
        final boolean kevInternalOverdue;
        final boolean kevCisaOverdue;
        final String officialStableVersion;
        final boolean canPropagate;

        RepoHit(Long repositoryId, String repoName, String repoUrl, String repoFullName, String gitProvider,
                String branch, String clientName, String packageName, String packageVersion, String filePath,
                String source, String manifestFile, String status, boolean stillOpen, boolean kevListed,
                boolean kevInternalOverdue, boolean kevCisaOverdue, String officialStableVersion,
                boolean canPropagate) {
            this.repositoryId = repositoryId;
            this.repoName = repoName;
            this.repoUrl = repoUrl;
            this.repoFullName = repoFullName;
            this.gitProvider = gitProvider;
            this.branch = branch;
            this.clientName = clientName;
            this.packageName = packageName;
            this.packageVersion = packageVersion;
            this.filePath = filePath;
            this.source = source;
            this.manifestFile = manifestFile;
            this.status = status;
            this.stillOpen = stillOpen;
            this.kevListed = kevListed;
            this.kevInternalOverdue = kevInternalOverdue;
            this.kevCisaOverdue = kevCisaOverdue;
            this.officialStableVersion = officialStableVersion;
            this.canPropagate = canPropagate;
        }

        Map<String, Object> toMap() {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("repositoryId", repositoryId);
            row.put("repoName", repoName);
            row.put("repoUrl", repoUrl);
            row.put("repoFullName", repoFullName);
            row.put("gitProvider", gitProvider);
            row.put("branch", branch);
            row.put("clientName", clientName);
            row.put("packageName", packageName);
            row.put("packageVersion", packageVersion);
            row.put("filePath", filePath);
            row.put("source", source);
            row.put("manifestFile", manifestFile);
            row.put("status", status);
            row.put("stillOpen", stillOpen);
            row.put("kevListed", kevListed);
            row.put("kevInternalOverdue", kevInternalOverdue);
            row.put("kevCisaOverdue", kevCisaOverdue);
            row.put("officialStableVersion", officialStableVersion);
            row.put("canPropagate", canPropagate);
            return row;
        }

        static RepoHit fromMap(Map<String, Object> repo) {
            Number id = (Number) repo.get("repositoryId");
            return new RepoHit(
                    id != null ? id.longValue() : null,
                    str(repo.get("repoName")),
                    str(repo.get("repoUrl")),
                    str(repo.get("repoFullName")),
                    str(repo.get("gitProvider")),
                    str(repo.get("branch")),
                    str(repo.get("clientName")),
                    str(repo.get("packageName")),
                    str(repo.get("packageVersion")),
                    str(repo.get("filePath")),
                    str(repo.get("source")),
                    str(repo.get("manifestFile")),
                    str(repo.get("status")),
                    Boolean.TRUE.equals(repo.get("stillOpen")),
                    Boolean.TRUE.equals(repo.get("kevListed")),
                    Boolean.TRUE.equals(repo.get("kevInternalOverdue")),
                    Boolean.TRUE.equals(repo.get("kevCisaOverdue")),
                    str(repo.get("officialStableVersion")),
                    Boolean.TRUE.equals(repo.get("canPropagate")));
        }

        private static String str(Object value) {
            return value == null ? null : String.valueOf(value);
        }
    }

    private static final class ExposureAgg {
        final String cveId;
        String severity = "UNKNOWN";
        Double cvssScore;
        boolean kevListed;
        boolean kevRansomware;
        int openRepoCount;
        int patchedRepoCount;
        final Set<Long> repoIds = new HashSet<>();
        final Set<String> clients = new java.util.LinkedHashSet<>();
        final List<RepoHit> hits = new ArrayList<>();

        ExposureAgg(String cveId) {
            this.cveId = cveId;
        }

        void absorb(CveEntry c, boolean kev) {
            if (c.getSeverity() != null && rank(c.getSeverity()) > rank(severity)) {
                severity = c.getSeverity();
            }
            if (c.getCvssScore() != null && (cvssScore == null || c.getCvssScore() > cvssScore)) {
                cvssScore = c.getCvssScore();
            }
            if (kev || c.isKevListed()) {
                kevListed = true;
            }
            if (c.isKevRansomware()) {
                kevRansomware = true;
            }
        }

        void addHit(RepoHit hit) {
            hits.add(hit);
            if (hit.repositoryId != null) {
                repoIds.add(hit.repositoryId);
            }
            if (hit.clientName != null && !hit.clientName.isBlank()) {
                clients.add(hit.clientName);
            }
            if (hit.stillOpen) {
                openRepoCount++;
            } else {
                patchedRepoCount++;
            }
        }

        Map<String, Object> toMap() {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("cveId", cveId);
            row.put("severity", severity);
            row.put("cvssScore", cvssScore);
            row.put("kevListed", kevListed);
            row.put("kevRansomware", kevRansomware);
            row.put("repoCount", repoIds.size());
            row.put("openRepoCount", openRepoCount);
            row.put("patchedRepoCount", patchedRepoCount);
            row.put("clientCount", clients.size());
            row.put("exposureScore", openRepoCount);
            row.put("canPropagateCount", hits.stream().filter(h -> h.canPropagate).count());
            row.put("repositories", hits.stream().map(RepoHit::toMap).toList());
            return row;
        }

        private static int rank(String severity) {
            return switch (severity == null ? "" : severity.toUpperCase(Locale.ROOT)) {
                case "CRITICAL" -> 4;
                case "HIGH" -> 3;
                case "MEDIUM" -> 2;
                case "LOW" -> 1;
                default -> 0;
            };
        }
    }
}
