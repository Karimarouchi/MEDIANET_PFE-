package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.FixKnowledge;
import com.medianet.entity.FixKnowledgeStatus;
import com.medianet.entity.User;
import com.medianet.repository.FixKnowledgeRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class FixKnowledgeService {

    private static final Logger log = LoggerFactory.getLogger(FixKnowledgeService.class);
    private static final int MAX_CONTENT_FOR_LLM = 3500;

    private final FixKnowledgeRepo fixKnowledgeRepo;
    private final AiGatewayService aiGatewayService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public FixKnowledgeService(FixKnowledgeRepo fixKnowledgeRepo, AiGatewayService aiGatewayService) {
        this.fixKnowledgeRepo = fixKnowledgeRepo;
        this.aiGatewayService = aiGatewayService;
    }

    /**
     * Enrich an autofix preview with human memory + LLM recommendation.
     */
    public void enrichPreview(Map<String, Object> preview, String repoFullName, String packageName,
            String currentVersion, String fixedVersion, String cveId, User user) {
        if (preview == null) {
            return;
        }

        FixKnowledge best = findBestMatch(packageName, cveId, currentVersion, repoFullName);
        if (best == null) {
            preview.put("hasHumanKnowledge", false);
            log.info("[FixKnowledge] No memory for package='{}' cve='{}' repo='{}'",
                    packageName, cveId, repoFullName);
            return;
        }

        log.info("[FixKnowledge] Memory hit id={} package='{}' cve='{}' by={}",
                best.getId(), best.getPackageName(), best.getCveId(), best.getCreatedByLogin());
        preview.put("hasHumanKnowledge", true);
        preview.put("humanKnowledge", toDto(best));

        // Alternative lines for the human version so the UI can switch
        String humanContent = best.getDeveloperContent() != null ? best.getDeveloperContent() : "";
        preview.put("humanFixedContent", humanContent);
        preview.put("humanFixedLines", Arrays.asList(humanContent.split("\n", -1)));

        String aiContent = preview.get("fixedContent") != null
                ? String.valueOf(preview.get("fixedContent"))
                : "";
        Map<String, Object> advice = recommendWithLlm(user, cveId, packageName, currentVersion,
                fixedVersion, aiContent, best);
        preview.put("llmAdvice", advice);
    }

    public FixKnowledge findBestMatch(String packageName, String cveId, String fromVersion, String repoFullName) {
        String cve = blankToNull(cveId);
        String from = blankToNull(fromVersion);
        String repo = blankToNull(repoFullName);

        LinkedHashSet<FixKnowledge> candidates = new LinkedHashSet<>();

        // 1) Match by package aliases (maven coords, artifact, purl…)
        Collection<String> aliases = packageAliases(packageName);
        if (!aliases.isEmpty()) {
            candidates.addAll(fixKnowledgeRepo.findActiveByPackageNames(
                    FixKnowledgeStatus.ACTIVE, aliases));
        }

        // 2) Fallback: same CVE id (works across repos / package naming variants)
        if (cve != null) {
            candidates.addAll(fixKnowledgeRepo
                    .findByStatusAndCveIdIgnoreCaseOrderBySuccessCountDescUsageCountDescCreatedAtDesc(
                            FixKnowledgeStatus.ACTIVE, cve));
        }

        if (candidates.isEmpty()) {
            return null;
        }

        return candidates.stream()
                .sorted((a, b) -> Integer.compare(
                        score(b, cve, from, repo, aliases),
                        score(a, cve, from, repo, aliases)))
                .findFirst()
                .orElse(null);
    }

    private int score(FixKnowledge k, String cve, String from, String repo, Collection<String> aliases) {
        int s = 0;
        if (cve != null && cve.equalsIgnoreCase(k.getCveId())) s += 100;
        if (k.getPackageName() != null && aliases.contains(k.getPackageName().toLowerCase(Locale.ROOT))) {
            s += 80;
        }
        if (from != null && from.equals(k.getFromVersion())) s += 40;
        if (repo != null && repo.equalsIgnoreCase(k.getRepoFullName())) s += 20;
        s += k.getSuccessCount() * 5;
        s += k.getUsageCount();
        return s;
    }

    /**
     * Build lookup aliases so org.springframework:spring-webmvc matches spring-webmvc, purl, etc.
     */
    public Collection<String> packageAliases(String packageName) {
        LinkedHashSet<String> aliases = new LinkedHashSet<>();
        if (packageName == null || packageName.isBlank()) {
            return aliases;
        }
        String raw = packageName.trim();
        aliases.add(raw.toLowerCase(Locale.ROOT));

        String normalized = raw;
        if (normalized.startsWith("pkg:")) {
            // pkg:maven/org.springframework/spring-webmvc@6.1.14?type=jar
            String withoutPrefix = normalized.substring(4);
            int slash = withoutPrefix.indexOf('/');
            if (slash >= 0 && slash < withoutPrefix.length() - 1) {
                String remainder = withoutPrefix.substring(slash + 1);
                int at = remainder.indexOf('@');
                if (at > 0) remainder = remainder.substring(0, at);
                int q = remainder.indexOf('?');
                if (q > 0) remainder = remainder.substring(0, q);
                remainder = remainder.replace("%3A", ":").replace("%3a", ":");
                if (remainder.contains("/")) {
                    String[] parts = remainder.split("/", 2);
                    aliases.add((parts[0] + ":" + parts[1]).toLowerCase(Locale.ROOT));
                    aliases.add(parts[1].toLowerCase(Locale.ROOT));
                } else {
                    aliases.add(remainder.toLowerCase(Locale.ROOT));
                }
            }
        }

        if (normalized.contains(":")) {
            String[] parts = normalized.split(":", 2);
            if (parts.length == 2) {
                aliases.add(parts[1].toLowerCase(Locale.ROOT)); // artifactId only
            }
        }

        return aliases;
    }

    @Transactional
    public FixKnowledge saveHumanFix(
            User user,
            String repoFullName,
            String packageName,
            String cveId,
            String fromVersion,
            String toVersion,
            String filePath,
            String ecosystem,
            String aiContent,
            String developerContent,
            String reason) {

        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("Le motif (pourquoi) est obligatoire pour enregistrer une correction humaine.");
        }
        if (developerContent == null || developerContent.isBlank()) {
            throw new IllegalArgumentException("Le contenu développeur est vide.");
        }

        // Prefer canonical maven coordinates when possible
        String canonicalPackage = canonicalPackageName(packageName);

        FixKnowledge entry = FixKnowledge.builder()
                .cveId(blankToNull(cveId))
                .packageName(canonicalPackage)
                .ecosystem(blankToNull(ecosystem))
                .fromVersion(blankToNull(fromVersion))
                .toVersion(blankToNull(toVersion))
                .filePath(blankToNull(filePath))
                .repoFullName(blankToNull(repoFullName))
                .aiContent(aiContent)
                .developerContent(developerContent)
                .reason(reason.trim())
                .createdBy(user)
                .createdByLogin(user != null ? user.getLogin() : null)
                .status(FixKnowledgeStatus.ACTIVE)
                .build();

        FixKnowledge saved = fixKnowledgeRepo.save(entry);
        log.info("[FixKnowledge] Saved human fix id={} package={} cve={} by={}",
                saved.getId(), saved.getPackageName(), saved.getCveId(), saved.getCreatedByLogin());
        return saved;
    }

    private String canonicalPackageName(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return "";
        }
        Collection<String> aliases = packageAliases(packageName);
        // Prefer group:artifact form if present
        for (String a : aliases) {
            if (a.contains(":")) {
                return a;
            }
        }
        return packageName.trim();
    }

    @Transactional
    public void markUsed(Long knowledgeId) {
        if (knowledgeId == null) {
            return;
        }
        fixKnowledgeRepo.findById(knowledgeId).ifPresent(k -> {
            k.setUsageCount(k.getUsageCount() + 1);
            k.setLastUsedAt(LocalDateTime.now());
            fixKnowledgeRepo.save(k);
        });
    }

    @Transactional
    public void markScanOutcome(Long knowledgeId, boolean success) {
        if (knowledgeId == null) {
            return;
        }
        fixKnowledgeRepo.findById(knowledgeId).ifPresent(k -> {
            if (success) {
                k.setSuccessCount(k.getSuccessCount() + 1);
            } else {
                k.setFailCount(k.getFailCount() + 1);
                if (k.getFailCount() >= 3 && k.getFailCount() > k.getSuccessCount()) {
                    k.setStatus(FixKnowledgeStatus.DOUBTFUL);
                }
            }
            fixKnowledgeRepo.save(k);
        });
    }

    public Map<String, Object> toDto(FixKnowledge k) {
        Map<String, Object> dto = new LinkedHashMap<>();
        dto.put("id", k.getId());
        dto.put("cveId", k.getCveId());
        dto.put("packageName", k.getPackageName());
        dto.put("ecosystem", k.getEcosystem());
        dto.put("fromVersion", k.getFromVersion());
        dto.put("toVersion", k.getToVersion());
        dto.put("filePath", k.getFilePath());
        dto.put("repoFullName", k.getRepoFullName());
        dto.put("reason", k.getReason());
        dto.put("createdByLogin", k.getCreatedByLogin());
        dto.put("usageCount", k.getUsageCount());
        dto.put("successCount", k.getSuccessCount());
        dto.put("failCount", k.getFailCount());
        dto.put("status", k.getStatus() != null ? k.getStatus().name() : "ACTIVE");
        dto.put("createdAt", k.getCreatedAt() != null ? k.getCreatedAt().toString() : null);
        dto.put("lastUsedAt", k.getLastUsedAt() != null ? k.getLastUsedAt().toString() : null);
        return dto;
    }

    private Map<String, Object> recommendWithLlm(User user, String cveId, String packageName,
            String currentVersion, String fixedVersion, String aiContent, FixKnowledge human) {
        Map<String, Object> fallback = defaultAdvice(human);

        String prompt = """
                Tu es un agent de correctifs de sécurité (Vulnix).
                Compare la suggestion IA et une correction humaine déjà enregistrée.
                Réponds UNIQUEMENT en JSON valide (pas de markdown) avec exactement ces clés:
                {
                  "recommendation": "AI" | "HUMAN" | "NEEDS_REVIEW",
                  "confidence": nombre entre 0 et 1,
                  "summary": "phrase courte en français",
                  "why": "explication en français",
                  "risks": "risques éventuels en français",
                  "humanStillValid": true/false
                }

                CVE: %s
                Package: %s
                Version vulnérable: %s
                Version fix moteur/IA: %s

                Correction humaine connue:
                - Auteur: %s
                - Version choisie: %s
                - Motif: %s
                - Succès scans: %d
                - Échecs: %d
                - Utilisations: %d

                Extrait correctif IA:
                %s

                Extrait correctif humain:
                %s
                """.formatted(
                nullToDash(cveId),
                nullToDash(packageName),
                nullToDash(currentVersion),
                nullToDash(fixedVersion),
                nullToDash(human.getCreatedByLogin()),
                nullToDash(human.getToVersion()),
                nullToDash(human.getReason()),
                human.getSuccessCount(),
                human.getFailCount(),
                human.getUsageCount(),
                truncate(aiContent, MAX_CONTENT_FOR_LLM),
                truncate(human.getDeveloperContent(), MAX_CONTENT_FOR_LLM));

        try {
            String raw = aiGatewayService.generate(prompt, user);
            if (raw == null || raw.isBlank()) {
                return fallback;
            }
            String json = stripMarkdownFences(raw.trim());
            JsonNode root = objectMapper.readTree(json);
            Map<String, Object> advice = new LinkedHashMap<>();
            String rec = root.path("recommendation").asText("NEEDS_REVIEW").toUpperCase(Locale.ROOT);
            if (!Set.of("AI", "HUMAN", "NEEDS_REVIEW").contains(rec)) {
                rec = "NEEDS_REVIEW";
            }
            advice.put("recommendation", rec);
            advice.put("confidence", root.path("confidence").asDouble(0.5));
            advice.put("summary", root.path("summary").asText(fallback.get("summary").toString()));
            advice.put("why", root.path("why").asText(fallback.get("why").toString()));
            advice.put("risks", root.path("risks").asText(""));
            advice.put("humanStillValid", root.path("humanStillValid").asBoolean(true));
            advice.put("source", "LLM");
            return advice;
        } catch (Exception e) {
            log.warn("[FixKnowledge] LLM advice failed: {}", e.getMessage());
            return fallback;
        }
    }

    private Map<String, Object> defaultAdvice(FixKnowledge human) {
        Map<String, Object> advice = new LinkedHashMap<>();
        boolean preferHuman = human.getSuccessCount() > 0 || human.getUsageCount() > 0;
        advice.put("recommendation", preferHuman ? "HUMAN" : "NEEDS_REVIEW");
        advice.put("confidence", preferHuman ? 0.7 : 0.55);
        advice.put("summary", preferHuman
                ? "Une correction humaine connue existe pour ce package/CVE."
                : "Comparez la suggestion IA et la correction humaine.");
        advice.put("why", "Motif développeur : " + human.getReason()
                + (human.getCreatedByLogin() != null ? " (par " + human.getCreatedByLogin() + ")" : ""));
        advice.put("risks", "Vérifiez que la version humaine est toujours compatible avec le projet.");
        advice.put("humanStillValid", true);
        advice.put("source", "HEURISTIC");
        return advice;
    }

    private String stripMarkdownFences(String content) {
        if (content.startsWith("```")) {
            int firstNewline = content.indexOf('\n');
            if (firstNewline != -1) {
                content = content.substring(firstNewline + 1);
            }
        }
        if (content.endsWith("```")) {
            content = content.substring(0, content.lastIndexOf("```")).trim();
        }
        // Sometimes model wraps JSON in prose — try to extract {...}
        int start = content.indexOf('{');
        int end = content.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return content.substring(start, end + 1);
        }
        return content.trim();
    }

    private String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max) + "\n…(tronqué)";
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String nullToDash(String value) {
        return value == null || value.isBlank() ? "—" : value;
    }
}
