package com.medianet.controller;

import com.medianet.entity.CveAuditEvent;
import com.medianet.entity.User;
import com.medianet.service.CveJournalService;
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
    private final UserService userService;

    public CveJournalController(CveJournalService cveJournalService, UserService userService) {
        this.cveJournalService = cveJournalService;
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getJournal(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(cveJournalService.getJournal());
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
}
