package com.medianet.controller;

import com.medianet.entity.CveAuditEvent;
import com.medianet.entity.User;
import com.medianet.service.CveExposureService;
import com.medianet.service.CveJournalService;
import com.medianet.service.FixPropagationService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/cve-journal")
public class CveJournalController {

    private final CveJournalService cveJournalService;
    private final CveExposureService cveExposureService;
    private final FixPropagationService fixPropagationService;
    private final UserService userService;
    @org.springframework.beans.factory.annotation.Autowired
    private com.medianet.service.ScanService scanService;

    public CveJournalController(
            CveJournalService cveJournalService,
            CveExposureService cveExposureService,
            FixPropagationService fixPropagationService,
            UserService userService) {
        this.cveJournalService = cveJournalService;
        this.cveExposureService = cveExposureService;
        this.fixPropagationService = fixPropagationService;
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getJournal(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        Map<String, Object> journal = cveJournalService.getJournal();
        journal.put("exposure", cveExposureService.build(user));
        if (user.getRole() != com.medianet.entity.UserRole.ADMIN) {
            hideForeignRepositories(journal, visibleRepoNames(user));
        }
        return ResponseEntity.ok(journal);
    }

    /** "owner/repo" of every repository the user can open (from their repository URLs). */
    private java.util.Set<String> visibleRepoNames(User user) {
        java.util.Set<String> names = new java.util.HashSet<>();
        for (var repo : scanService.getAllRepositories(user)) {
            String url = repo.getRepoUrl() == null ? "" : repo.getRepoUrl().trim().replaceAll("\\.git$", "");
            String[] parts = url.split("/");
            if (parts.length >= 2) {
                names.add((parts[parts.length - 2] + "/" + parts[parts.length - 1]).toLowerCase(java.util.Locale.ROOT));
            }
        }
        return names;
    }

    /**
     * The CVE catalog and the fixes are shared knowledge, but which repository each fix was made in is not: a
     * developer only sees the repository names of the projects they belong to.
     */
    @SuppressWarnings("unchecked")
    static void hideForeignRepositories(Map<String, Object> journal, java.util.Set<String> visible) {
        Object catalog = journal.get("catalog");
        if (!(catalog instanceof List<?> rows)) return;
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> r)) continue;
            Object iv = r.get("developerInterventions");
            if (!(iv instanceof List<?> list)) continue;
            for (Object o : list) {
                if (o instanceof Map<?, ?> m) {
                    Object name = m.get("repoFullName");
                    if (name != null && !visible.contains(name.toString().toLowerCase(java.util.Locale.ROOT))) {
                        ((Map<String, Object>) m).put("repoFullName", null);
                        ((Map<String, Object>) m).put("createdByLogin", null);
                    }
                }
            }
        }
    }

    /** Chef policy for a CVE+package — used by autofix priority. */
    @GetMapping("/policy")
    public ResponseEntity<Map<String, Object>> getPolicy(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam String cveId,
            @RequestParam(required = false) String packageName) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(cveJournalService.getPolicy(cveId, packageName));
    }

    /** Chronological audit timeline for a CVE. */
    @GetMapping("/timeline")
    public ResponseEntity<List<Map<String, Object>>> getTimeline(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam String cveId,
            @RequestParam(required = false) String packageName) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(cveJournalService.getTimeline(cveId, packageName));
    }

    /**
     * Recommandation IA automatique parmi les Fixed In (clé profil ou Gemini système).
     */
    @PostMapping("/recommend")
    public ResponseEntity<Map<String, Object>> recommend(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody RecommendRequest body) {
        User user = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(cveJournalService.recommendOfficialVersion(
                user,
                body.cveId(),
                body.packageName(),
                body.fixedVersion(),
                body.severity(),
                body.description(),
                body.ecosystem()));
    }

    @PutMapping("/official")
    public ResponseEntity<Map<String, Object>> upsertOfficial(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody OfficialGuidanceRequest body) {
        User user = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(cveJournalService.upsertOfficialGuidance(
                user,
                body.cveId(),
                body.packageName(),
                body.stableVersion(),
                body.comment()));
    }

    @DeleteMapping("/official/{id}")
    public ResponseEntity<Void> deleteOfficial(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User user = userService.getRequiredUser(authHeader);
        cveJournalService.deleteOfficialGuidance(user, id);
        return ResponseEntity.noContent().build();
    }

    public record RecommendRequest(
            String cveId,
            String packageName,
            String fixedVersion,
            String severity,
            String description,
            String ecosystem) {}

    @PostMapping("/false-positive")
    public ResponseEntity<Map<String, Object>> recordFalsePositive(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody FalsePositiveRequest body) {
        User user = userService.getRequiredUser(authHeader);
        CveAuditEvent event = cveJournalService.recordFalsePositive(
                user,
                body.cveId(),
                body.packageName(),
                body.reason(),
                body.expiresAt());
        return ResponseEntity.ok(cveJournalService.toAuditDto(event));
    }

    public record OfficialGuidanceRequest(
            String cveId,
            String packageName,
            String stableVersion,
            String comment) {}

    public record FalsePositiveRequest(
            String cveId,
            String packageName,
            String reason,
            LocalDateTime expiresAt) {}

    public record PropagateRequest(
            String cveId,
            String packageName,
            List<Long> repositoryIds) {}

    @PostMapping("/propagate")
    public ResponseEntity<Map<String, Object>> propagate(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody PropagateRequest body) {
        User user = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(fixPropagationService.propagate(
                user,
                body != null ? body.cveId() : null,
                body != null ? body.packageName() : null,
                body != null ? body.repositoryIds() : null));
    }
}
