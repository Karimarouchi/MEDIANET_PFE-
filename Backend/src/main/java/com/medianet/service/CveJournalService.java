package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.*;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.CveOfficialGuidanceRepo;
import com.medianet.repository.FixKnowledgeRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class CveJournalService {

    private static final Logger log = LoggerFactory.getLogger(CveJournalService.class);
    private static final Pattern FIXED_SPLIT = Pattern.compile("[,;|/]+");

    private final CveEntryRepo cveEntryRepo;
    private final FixKnowledgeRepo fixKnowledgeRepo;
    private final CveOfficialGuidanceRepo guidanceRepo;
    private final CveAuditService cveAuditService;
    private final AiGatewayService aiGatewayService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CveJournalService(
            CveEntryRepo cveEntryRepo,
            FixKnowledgeRepo fixKnowledgeRepo,
            CveOfficialGuidanceRepo guidanceRepo,
            CveAuditService cveAuditService,
            AiGatewayService aiGatewayService) {
        this.cveEntryRepo = cveEntryRepo;
        this.fixKnowledgeRepo = fixKnowledgeRepo;
        this.guidanceRepo = guidanceRepo;
        this.cveAuditService = cveAuditService;
        this.aiGatewayService = aiGatewayService;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getJournal() {
        List<CveEntry> all = cveEntryRepo.findAll();
        Map<String, CatalogAgg> byKey = new LinkedHashMap<>();

        for (CveEntry c : all) {
            String cveId = blankToEmpty(c.getCveId());
            String pkg = blankToEmpty(c.getPackageName());
            if (cveId.isBlank() && pkg.isBlank()) continue;
            String key = keyOf(cveId, pkg);
            CatalogAgg agg = byKey.computeIfAbsent(key, k -> new CatalogAgg(cveId, pkg));
            agg.absorb(c);
        }

        Map<String, CveOfficialGuidance> guidanceByKey = guidanceRepo.findAll().stream()
                .collect(Collectors.toMap(
                        g -> keyOf(g.getCveId(), g.getPackageName()),
                        g -> g,
                        (a, b) -> a.getUpdatedAt() != null && b.getUpdatedAt() != null
                                && a.getUpdatedAt().isAfter(b.getUpdatedAt()) ? a : b,
                        LinkedHashMap::new));

        List<FixKnowledge> knowledge = fixKnowledgeRepo.findAllByOrderByCreatedAtDesc();
        Map<String, List<Map<String, Object>>> knowledgeByKey = new HashMap<>();
        for (FixKnowledge k : knowledge) {
            String key = keyOf(k.getCveId(), k.getPackageName());
            knowledgeByKey.computeIfAbsent(key, x -> new ArrayList<>()).add(toKnowledgeDto(k));
            if (!byKey.containsKey(key) && (k.getCveId() != null || k.getPackageName() != null)) {
                CatalogAgg agg = new CatalogAgg(blankToEmpty(k.getCveId()), blankToEmpty(k.getPackageName()));
                agg.fixedVersion = k.getToVersion();
                agg.severity = "UNKNOWN";
                byKey.put(key, agg);
            }
        }

        Map<String, Long> statusCounts = new LinkedHashMap<>();
        for (CveRemediationStatus s : CveRemediationStatus.values()) {
            statusCounts.put(s.name(), 0L);
        }

        List<Map<String, Object>> catalog = new ArrayList<>();
        for (CatalogAgg agg : byKey.values()) {
            String key = keyOf(agg.cveId, agg.packageName);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("cveId", agg.cveId.isBlank() ? null : agg.cveId);
            row.put("packageName", agg.packageName.isBlank() ? null : agg.packageName);
            row.put("severity", agg.severity);
            row.put("cvssScore", agg.cvssScore);
            row.put("epssScore", agg.epssScore);
            row.put("fixedVersion", agg.fixedVersion);
            row.put("source", agg.source);
            row.put("ecosystem", agg.ecosystem);
            row.put("description", agg.description);
            row.put("detectionCount", agg.detectionCount);
            row.put("kevListed", agg.kevListed);
            row.put("exploitAvailable", agg.exploitAvailable);

            CveOfficialGuidance g = guidanceByKey.get(key);
            if (g == null && !agg.cveId.isBlank()) {
                g = guidanceByKey.get(keyOf(agg.cveId, ""));
            }
            if (g != null) {
                row.put("officialStableVersion", g.getStableVersion());
                row.put("officialComment", g.getComment());
                row.put("officialUpdatedBy", g.getUpdatedByLogin());
                row.put("officialUpdatedById", g.getUpdatedBy() != null ? g.getUpdatedBy().getId() : null);
                row.put("officialUpdatedAt", g.getUpdatedAt() != null ? g.getUpdatedAt().toString() : null);
                row.put("guidanceId", g.getId());
            } else {
                row.put("officialStableVersion", null);
                row.put("officialComment", null);
                row.put("officialUpdatedBy", null);
                row.put("officialUpdatedById", null);
                row.put("officialUpdatedAt", null);
                row.put("guidanceId", null);
            }

            List<Map<String, Object>> interventions = knowledgeByKey.getOrDefault(key, List.of());
            row.put("developerInterventions", interventions);
            row.put("hasDeveloperFix", !interventions.isEmpty());
            row.put("hasOfficialGuidance", g != null);

            String latestDevVersion = interventions.isEmpty() ? null
                    : String.valueOf(interventions.get(0).get("toVersion"));
            boolean riskAccepted = cveAuditService.hasRiskAccepted(agg.cveId, agg.packageName);
            boolean falsePositive = cveAuditService.hasFalsePositive(agg.cveId, agg.packageName);
            CveRemediationStatus status = computeStatus(
                    g != null,
                    g != null ? g.getStableVersion() : null,
                    !interventions.isEmpty(),
                    latestDevVersion,
                    riskAccepted,
                    falsePositive,
                    agg.severity,
                    agg.kevListed,
                    agg.exploitAvailable,
                    VulnerabilityNormalizer.isRealFixedVersion(agg.fixedVersion));
            row.put("remediationStatus", status.name());
            row.put("remediationStatusLabel", statusLabel(status));
            statusCounts.merge(status.name(), 1L, Long::sum);

            // Preferred version for developers: CHEF > Fixed In (raw list kept separately)
            row.put("policySource", g != null ? "CHEF" : (agg.fixedVersion != null ? "SCAN" : null));
            row.put("preferredFixVersion", g != null ? g.getStableVersion() : null);

            catalog.add(row);
        }

        catalog.sort((a, b) -> {
            int sev = severityRank(String.valueOf(b.get("severity"))) - severityRank(String.valueOf(a.get("severity")));
            if (sev != 0) return sev;
            return String.valueOf(a.get("cveId")).compareToIgnoreCase(String.valueOf(b.get("cveId")));
        });

        List<Map<String, Object>> interventions = knowledge.stream().map(this::toKnowledgeDto).toList();

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalCves", catalog.size());
        stats.put("withOfficialGuidance", catalog.stream().filter(r -> Boolean.TRUE.equals(r.get("hasOfficialGuidance"))).count());
        stats.put("withDeveloperFix", catalog.stream().filter(r -> Boolean.TRUE.equals(r.get("hasDeveloperFix"))).count());
        stats.put("interventionCount", interventions.size());
        stats.put("byStatus", statusCounts);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("catalog", catalog);
        out.put("interventions", interventions);
        out.put("stats", stats);
        return out;
    }

    /** Policy lookup for autofix: chef version first. */
    public Map<String, Object> getPolicy(String cveId, String packageName) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("cveId", cveId);
        out.put("packageName", packageName);
        if (cveId == null || cveId.isBlank()) {
            out.put("officialStableVersion", null);
            out.put("policySource", null);
            return out;
        }
        String pkg = packageName != null ? packageName.trim() : "";
        Optional<CveOfficialGuidance> g = guidanceRepo
                .findByCveIdIgnoreCaseAndPackageNameIgnoreCase(cveId.trim(), pkg);
        if (g.isEmpty() && !pkg.isBlank()) {
            g = guidanceRepo.findByCveIdIgnoreCaseAndPackageNameIgnoreCase(cveId.trim(), "");
        }
        // Fallback: any official guidance for this CVE (package name variants)
        if (g.isEmpty()) {
            List<CveOfficialGuidance> any = guidanceRepo.findByCveIdIgnoreCaseOrderByUpdatedAtDesc(cveId.trim());
            if (!any.isEmpty()) {
                // Prefer artifact-id match if package is maven coords
                String artifact = pkg.contains(":") ? pkg.substring(pkg.lastIndexOf(':') + 1) : pkg;
                g = any.stream()
                        .filter(x -> {
                            String gp = x.getPackageName() != null ? x.getPackageName() : "";
                            return gp.equalsIgnoreCase(pkg)
                                    || gp.equalsIgnoreCase(artifact)
                                    || gp.endsWith(":" + artifact)
                                    || artifact.equalsIgnoreCase(gp.contains(":")
                                    ? gp.substring(gp.lastIndexOf(':') + 1) : gp);
                        })
                        .findFirst()
                        .or(() -> Optional.of(any.get(0)));
            }
        }
        if (g.isPresent()) {
            CveOfficialGuidance guidance = g.get();
            out.put("officialStableVersion", guidance.getStableVersion());
            out.put("officialComment", guidance.getComment());
            out.put("officialUpdatedBy", guidance.getUpdatedByLogin());
            out.put("guidanceId", guidance.getId());
            out.put("policySource", "CHEF");
        } else {
            out.put("officialStableVersion", null);
            out.put("officialComment", null);
            out.put("policySource", null);
        }
        return out;
    }

    public List<Map<String, Object>> getTimeline(String cveId, String packageName) {
        List<Map<String, Object>> timeline = new ArrayList<>(cveAuditService.listTimeline(cveId, packageName));

        // Backfill from guidance / knowledge if audit table is still empty for this CVE
        if (timeline.isEmpty() && cveId != null && !cveId.isBlank()) {
            String pkg = packageName != null ? packageName.trim() : "";
            guidanceRepo.findByCveIdIgnoreCaseAndPackageNameIgnoreCase(cveId.trim(), pkg)
                    .or(() -> guidanceRepo.findByCveIdIgnoreCaseAndPackageNameIgnoreCase(cveId.trim(), ""))
                    .ifPresent(g -> {
                        Map<String, Object> e = new LinkedHashMap<>();
                        e.put("id", null);
                        e.put("eventType", CveAuditEventType.POLICY_SET.name());
                        e.put("actorLogin", g.getUpdatedByLogin());
                        e.put("toVersion", g.getStableVersion());
                        e.put("officialVersion", g.getStableVersion());
                        e.put("message", g.getComment());
                        e.put("createdAt", g.getUpdatedAt() != null ? g.getUpdatedAt().toString() : null);
                        e.put("synthetic", true);
                        timeline.add(e);
                    });

            fixKnowledgeRepo.findByStatusAndCveIdIgnoreCaseOrderBySuccessCountDescUsageCountDescCreatedAtDesc(
                            FixKnowledgeStatus.ACTIVE, cveId.trim())
                    .stream()
                    .filter(k -> pkg.isBlank() || pkg.equalsIgnoreCase(blankToEmpty(k.getPackageName())))
                    .limit(10)
                    .forEach(k -> {
                        Map<String, Object> e = new LinkedHashMap<>();
                        e.put("id", k.getId());
                        e.put("eventType", CveAuditEventType.FIX_APPLIED.name());
                        e.put("actorLogin", k.getCreatedByLogin());
                        e.put("fromVersion", k.getFromVersion());
                        e.put("toVersion", k.getToVersion());
                        e.put("repoFullName", k.getRepoFullName());
                        e.put("message", k.getReason());
                        e.put("createdAt", k.getCreatedAt() != null ? k.getCreatedAt().toString() : null);
                        e.put("synthetic", true);
                        timeline.add(e);
                    });
        }

        timeline.sort((a, b) -> String.valueOf(b.get("createdAt")).compareTo(String.valueOf(a.get("createdAt"))));
        return timeline;
    }

    /**
     * Recommande automatiquement une version Fixed In pour le chef.
     * Utilise la clé IA du profil si présente, sinon Gemini système.
     * Ne se contente JAMAIS d'un « plus récent » comme seule justification.
     */
    public Map<String, Object> recommendOfficialVersion(
            User user,
            String cveId,
            String packageName,
            String fixedVersionRaw,
            String severity,
            String description,
            String ecosystem) {

        List<String> candidates = parseFixedVersions(fixedVersionRaw);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("cveId", cveId);
        out.put("packageName", packageName);
        out.put("candidates", candidates);

        if (candidates.isEmpty()) {
            out.put("recommendedVersion", null);
            out.put("rationale", "Aucune version Fixed In disponible pour ce CVE.");
            out.put("comparedToOthers", List.of());
            out.put("source", "NONE");
            return out;
        }

        Map<String, Object> llm = askLlmRecommendation(
                user, cveId, packageName, candidates, severity, description, ecosystem);

        if (llm != null && llm.get("recommendedVersion") != null) {
            String recommended = String.valueOf(llm.get("recommendedVersion"));
            String matched = matchCandidate(recommended, candidates);
            if (matched == null) {
                // Keep AI rationale but clamp version to Fixed In list
                matched = pickPreferredAmong(candidates, null);
                String extra = " (version proposée hors liste Fixed In — version retenue dans la liste : "
                        + matched + ").";
                Object rat = llm.get("rationale");
                llm.put("rationale", (rat != null ? rat.toString() : "") + extra);
            }
            out.put("recommendedVersion", matched);
            out.put("rationale", llm.get("rationale"));
            out.put("comparedToOthers", llm.getOrDefault("comparedToOthers", List.of()));
            out.put("source", "LLM");
            out.put("aiProvider", user != null && user.hasCustomAiKey() ? user.getAiProvider() : "GEMINI");
            out.put("aiError", null);
            return out;
        }

        // AI failed — expose error, no fake "most recent" story presented as IA
        String aiError = llm != null && llm.get("error") != null
                ? String.valueOf(llm.get("error"))
                : "L’IA n’a pas pu analyser ce CVE (clé Gemini / profil, quota, ou réponse invalide).";
        out.put("recommendedVersion", null);
        out.put("rationale", null);
        out.put("comparedToOthers", List.of());
        out.put("source", "ERROR");
        out.put("aiProvider", user != null && user.hasCustomAiKey() ? user.getAiProvider() : "GEMINI");
        out.put("aiError", aiError);
        return out;
    }

    private Map<String, Object> askLlmRecommendation(
            User user,
            String cveId,
            String packageName,
            List<String> candidates,
            String severity,
            String description,
            String ecosystem) {

        String desc = description;
        if (desc != null && desc.length() > 350) {
            desc = desc.substring(0, 350) + "…";
        }

        // Réponse IA minimale (version + 2 phrases). Comparaisons Fixed In = serveur.
        // Évite les JSON tronqués quand il y a beaucoup de Fixed In (ex. 6 versions).
        StringBuilder prompt = new StringBuilder();
        prompt.append("""
                Expert sécurité dépendances. Choisis UNE version politique chef parmi Fixed In.

                Réponds UNIQUEMENT ce JSON court et COMPLET (pas de markdown, pas d'autre champ) :
                {"recommendedVersion":"x.y.z","rationale":"deux phrases max"}

                Règles :
                - recommendedVersion = copie exacte d'une Fixed In.
                - rationale en français : pourquoi cette branche (6.x vs 5.x, 10.x vs 11.x…), pas seulement « la plus récente ».
                - Sois très concis pour que le JSON ne soit jamais coupé.

                """);
        prompt.append("CVE: ").append(safe(cveId)).append('\n');
        prompt.append("Package: ").append(safe(packageName)).append('\n');
        prompt.append("Écosystème: ").append(safe(ecosystem)).append('\n');
        prompt.append("Sévérité: ").append(safe(severity)).append('\n');
        prompt.append("Description: ").append(safe(desc)).append('\n');
        prompt.append("Fixed In: ").append(String.join(", ", candidates)).append('\n');

        String raw = null;
        try {
            raw = aiGatewayService.generate(prompt.toString(), user);
            if (raw == null || raw.isBlank()) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", "Réponse IA vide. Vérifiez la clé Gemini système ou votre clé dans Profil.");
                return err;
            }
            Map<String, Object> parsed = parseRecommendationPayload(raw, candidates);
            if (parsed.get("recommendedVersion") == null
                    || String.valueOf(parsed.get("recommendedVersion")).isBlank()) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", "L’IA n’a pas renvoyé de recommendedVersion utilisable.");
                return err;
            }
            return parsed;
        } catch (Exception e) {
            log.warn("[CveJournal] AI recommend failed: {}", e.getMessage());
            if (raw != null && !raw.isBlank()) {
                try {
                    Map<String, Object> recovered = parseRecommendationPayload(raw, candidates);
                    if (recovered.get("recommendedVersion") != null
                            && !String.valueOf(recovered.get("recommendedVersion")).isBlank()) {
                        return recovered;
                    }
                } catch (Exception ignored) {
                    // fall through
                }
            }
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("error", "Échec analyse IA : réponse incomplète. Réessayez.");
            return err;
        }
    }

    /**
     * Parse JSON IA, ou récupère version+raison si Gemini a tronqué la réponse.
     * Stratégie : regex D'ABORD (ne plante jamais), Jackson ensuite.
     */
    private Map<String, Object> parseRecommendationPayload(String raw, List<String> candidates) {
        String json = extractJson(raw == null ? "" : raw.trim());

        // 1) Toujours récupérer par regex — même JSON coupé au milieu de rationale
        String recommended = extractJsonStringField(json, "recommendedVersion");
        if (recommended == null) {
            Matcher loose = Pattern.compile(
                    "recommendedVersion\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
            if (loose.find()) recommended = loose.group(1).trim();
        }
        String rationale = extractJsonStringField(json, "rationale");
        if (rationale == null) {
            rationale = extractPartialRationale(json);
        }

        // 2) Si JSON complet, préférer Jackson (plus propre)
        try {
            JsonNode root = objectMapper.readTree(json);
            String rv = root.path("recommendedVersion").asText("");
            String rr = root.path("rationale").asText("");
            if (!rv.isBlank()) recommended = rv.trim();
            if (!rr.isBlank()) rationale = rr.trim();
        } catch (Exception ignored) {
            // JSON tronqué : on garde la récupération regex
        }

        if (recommended == null || recommended.isBlank()) {
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("recommendedVersion", null);
            return empty;
        }

        String matchedRec = matchCandidate(recommended, candidates);
        String chosen = matchedRec != null ? matchedRec : recommended;

        List<Map<String, String>> compared = new ArrayList<>();
        for (String c : candidates) {
            if (c.equalsIgnoreCase(chosen)) continue;
            Map<String, String> row = new LinkedHashMap<>();
            row.put("version", c);
            row.put("whyNot", explainWhyNotVsRecommended(c, chosen));
            compared.add(row);
        }

        if (rationale == null || rationale.isBlank()) {
            rationale = "Version " + chosen
                    + " proposée comme politique unique parmi les Fixed In, "
                    + "en privilégiant la branche la plus pertinente (compatibilité vs migration majeure).";
        } else {
            rationale = rationale.replaceAll("[\\s,;:]+$", "").trim();
            if (!rationale.endsWith(".") && !rationale.endsWith("!") && !rationale.endsWith("?")
                    && !rationale.endsWith("…")) {
                rationale = rationale + "…";
            }
        }

        Map<String, Object> parsed = new LinkedHashMap<>();
        parsed.put("recommendedVersion", chosen);
        parsed.put("rationale", rationale);
        parsed.put("comparedToOthers", compared);
        return parsed;
    }

    private static String extractJsonStringField(String json, String field) {
        if (json == null) return null;
        Pattern p = Pattern.compile(
                "\"" + Pattern.quote(field) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        Matcher m = p.matcher(json);
        if (m.find()) return unescapeJson(m.group(1));
        return null;
    }

    /** When rationale string was cut before the closing quote. */
    private static String extractPartialRationale(String json) {
        if (json == null) return null;
        Matcher m = Pattern.compile("\"rationale\"\\s*:\\s*\"([\\s\\S]*)").matcher(json);
        if (!m.find()) return null;
        String body = m.group(1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '\\' && i + 1 < body.length()) {
                sb.append(c).append(body.charAt(++i));
                continue;
            }
            if (c == '"') break;
            // Stop if we clearly hit another JSON structure without closing quote
            if (c == '{' || (c == ',' && body.regionMatches(i, ",\"comparedToOthers\"", 0, 20))) break;
            sb.append(c);
        }
        String out = unescapeJson(sb.toString().trim());
        return out.isBlank() ? null : out;
    }

    private static String unescapeJson(String s) {
        if (s == null) return null;
        return s.replace("\\\"", "\"")
                .replace("\\n", " ")
                .replace("\\r", "")
                .replace("\\t", " ")
                .replace("\\\\", "\\");
    }

    /** Fallback text only used to fill missing comparedToOthers rows — not the main rationale. */
    private static String explainWhyNotVsRecommended(String other, String recommended) {
        String[] o = other.split("\\.");
        String[] r = recommended != null ? recommended.split("\\.") : new String[0];
        String oMaj = o.length > 0 ? o[0] : "?";
        String rMaj = r.length > 0 ? r[0] : "?";
        String oLine = o.length > 1 ? o[0] + "." + o[1] + ".x" : oMaj + ".x";
        String rLine = r.length > 1 ? r[0] + "." + r[1] + ".x" : rMaj + ".x";
        if (!oMaj.equals(rMaj)) {
            return "Branche majeure " + oMaj + ".x (ligne " + oLine
                    + ") : correctif pour projets encore sur cette majeure, "
                    + "mais pas la référence unique si la politique cible la ligne " + rLine + ".";
        }
        if (o.length > 1 && r.length > 1 && !o[1].equals(r[1])) {
            return "Même majeure " + oMaj + " mais ligne " + oLine
                    + " : utile pour rester sur " + oLine
                    + " sans migrer vers " + rLine + " (breaking changes possibles entre mineurs).";
        }
        return "Correctif sur la même ligne que " + recommended
                + " mais ce n’est pas la version retenue comme référence politique.";
    }

    private static String safe(String s) {
        return s == null || s.isBlank() ? "—" : s.trim();
    }

    private static List<String> parseFixedVersions(String raw) {
        if (raw == null || raw.isBlank()) return List.of();
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String part : FIXED_SPLIT.split(raw)) {
            String v = part.trim().replaceAll("^[^0-9]*", "").trim();
            if (!v.isEmpty() && Character.isDigit(v.charAt(0))) {
                out.add(v);
            }
        }
        return new ArrayList<>(out);
    }

    private static String pickPreferredAmong(List<String> versions, String currentVersion) {
        if (versions == null || versions.isEmpty()) return null;
        List<String> sorted = new ArrayList<>(versions);
        sorted.sort((a, b) -> -compareVersions(a, b));
        if (currentVersion == null || currentVersion.isBlank()) {
            return sorted.get(0);
        }
        String cur = currentVersion.replaceAll("^[^0-9]*", "").split("[-+]")[0];
        String[] curParts = cur.split("\\.");
        String curMajor = curParts.length > 0 ? curParts[0] : "";
        String curMinor = curParts.length > 1 ? curParts[1] : "";

        List<String> sameMm = sorted.stream()
                .filter(v -> {
                    String[] p = v.split("\\.");
                    return p.length > 1 && p[0].equals(curMajor) && p[1].equals(curMinor);
                })
                .toList();
        if (!sameMm.isEmpty()) return sameMm.get(0);

        List<String> sameM = sorted.stream()
                .filter(v -> v.split("\\.")[0].equals(curMajor))
                .toList();
        if (!sameM.isEmpty()) return sameM.get(0);
        return sorted.get(0);
    }

    private static String matchCandidate(String recommended, List<String> candidates) {
        if (recommended == null || recommended.isBlank()) return null;
        String norm = recommended.replaceAll("^[^0-9]*", "").trim();
        for (String c : candidates) {
            if (c.equalsIgnoreCase(norm) || c.equalsIgnoreCase(recommended.trim())) return c;
        }
        return null;
    }

    private static int compareVersions(String a, String b) {
        String na = a.replaceAll("^[^0-9]*", "").split("[-+]")[0];
        String nb = b.replaceAll("^[^0-9]*", "").split("[-+]")[0];
        String[] pa = na.split("\\.");
        String[] pb = nb.split("\\.");
        int len = Math.max(pa.length, pb.length);
        for (int i = 0; i < len; i++) {
            int va = i < pa.length ? parseIntPart(pa[i]) : 0;
            int vb = i < pb.length ? parseIntPart(pb[i]) : 0;
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private static int parseIntPart(String s) {
        if (s == null || s.isBlank()) return 0;
        String digits = s.replaceAll("\\D.*", "");
        if (digits.isBlank()) return 0;
        try {
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String extractJson(String raw) {
        String s = raw.trim();
        if (s.startsWith("```")) {
            int start = s.indexOf('{');
            int end = s.lastIndexOf('}');
            if (start >= 0 && end > start) return s.substring(start, end + 1);
        }
        int start = s.indexOf('{');
        int end = s.lastIndexOf('}');
        if (start >= 0 && end > start) return s.substring(start, end + 1);
        return s;
    }

    /**
     * Définit la version stable officielle.
     * « Chef » = tout compte authentifié avec la permission Journal CVE (pas un rôle système séparé).
     * La modification est liée au compte ({@code updatedBy} + événement d'audit), comme pour les devs.
     */
    @Transactional
    public Map<String, Object> upsertOfficialGuidance(User user, String cveId, String packageName,
                                                      String stableVersion, String comment) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentification requise.");
        }
        if (cveId == null || cveId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Le CVE est requis.");
        }
        if (stableVersion == null || stableVersion.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La version stable est requise.");
        }

        String pkg = packageName != null ? packageName.trim() : "";
        CveOfficialGuidance guidance = guidanceRepo
                .findByCveIdIgnoreCaseAndPackageNameIgnoreCase(cveId.trim(), pkg)
                .orElseGet(CveOfficialGuidance::new);

        String previous = guidance.getStableVersion();
        String actorLogin = user.getLogin() != null ? user.getLogin() : user.getEmail();
        guidance.setCveId(cveId.trim());
        guidance.setPackageName(pkg);
        guidance.setStableVersion(stableVersion.trim());
        guidance.setComment(comment != null ? comment.trim() : null);
        guidance.setUpdatedBy(user);
        guidance.setUpdatedByLogin(actorLogin);

        CveOfficialGuidance saved = guidanceRepo.save(guidance);

        cveAuditService.record(
                CveAuditEventType.POLICY_SET,
                saved.getCveId(),
                saved.getPackageName(),
                user,
                previous,
                saved.getStableVersion(),
                saved.getStableVersion(),
                null,
                saved.getComment() != null ? saved.getComment()
                        : ("Version stable officielle définie par " + actorLogin + "."));

        Map<String, Object> dto = new LinkedHashMap<>();
        dto.put("id", saved.getId());
        dto.put("cveId", saved.getCveId());
        dto.put("packageName", saved.getPackageName());
        dto.put("stableVersion", saved.getStableVersion());
        dto.put("comment", saved.getComment());
        dto.put("updatedById", user.getId());
        dto.put("updatedByLogin", saved.getUpdatedByLogin());
        dto.put("updatedAt", saved.getUpdatedAt() != null ? saved.getUpdatedAt().toString() : null);
        return dto;
    }

    @Transactional
    public void deleteOfficialGuidance(User user, Long id) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentification requise.");
        }
        CveOfficialGuidance guidance = guidanceRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Guidance introuvable."));

        cveAuditService.record(
                CveAuditEventType.POLICY_CLEARED,
                guidance.getCveId(),
                guidance.getPackageName(),
                user,
                guidance.getStableVersion(),
                null,
                guidance.getStableVersion(),
                null,
                "Version officielle supprimée.");

        guidanceRepo.delete(guidance);
    }

    @Transactional
    public void recordFixApplied(User user, String cveId, String packageName,
                                 String fromVersion, String toVersion, String repoFullName,
                                 String reason, boolean riskAccepted) {
        Map<String, Object> policy = getPolicy(cveId, packageName);
        String official = policy.get("officialStableVersion") != null
                ? String.valueOf(policy.get("officialStableVersion")) : null;

        boolean deviation = official != null && toVersion != null
                && !versionsEquivalent(official, toVersion);

        CveAuditEventType type = riskAccepted ? CveAuditEventType.RISK_ACCEPTED
                : (deviation ? CveAuditEventType.POLICY_DEVIATION : CveAuditEventType.FIX_APPLIED);

        String message = reason;
        if (deviation && (message == null || message.isBlank())) {
            message = "Version choisie différente de la politique chef (" + official + ").";
        }

        cveAuditService.record(type, cveId, packageName, user,
                fromVersion, toVersion, official, repoFullName, message);

        if (riskAccepted && deviation) {
            // also keep an explicit RISK_ACCEPTED if type was already RISK_ACCEPTED — done
        } else if (riskAccepted && !deviation) {
            // nothing extra
        } else if (deviation) {
            // POLICY_DEVIATION already recorded
        }
    }

    @Transactional
    public CveAuditEvent recordFalsePositive(User user, String cveId, String packageName,
            String reason, LocalDateTime expiresAt) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentification requise.");
        }
        TreatmentValidation.requireReason(reason);
        CveAuditEvent event = cveAuditService.record(
                CveAuditEventType.FALSE_POSITIVE,
                cveId,
                packageName,
                user,
                null,
                null,
                null,
                null,
                reason.trim());
        return cveAuditService.saveExpiry(event, expiresAt);
    }

    public Map<String, Object> toAuditDto(CveAuditEvent event) {
        return cveAuditService.toDto(event);
    }

    public static CveRemediationStatus computeStatus(
            boolean hasGuidance,
            String officialVersion,
            boolean hasIntervention,
            String latestDevVersion,
            boolean riskAccepted,
            boolean falsePositive,
            String severity,
            boolean kevListed,
            boolean exploitAvailable,
            boolean fixAvailable) {

        if (falsePositive) {
            return CveRemediationStatus.FALSE_POSITIVE;
        }
        if (riskAccepted) {
            return CveRemediationStatus.ACCEPTED_RISK;
        }
        if (hasGuidance && hasIntervention && officialVersion != null && latestDevVersion != null
                && !versionsEquivalent(officialVersion, latestDevVersion)) {
            return CveRemediationStatus.ECART_POLITIQUE;
        }
        if (hasIntervention) {
            return CveRemediationStatus.FIXED;
        }
        if (hasGuidance || fixAvailable) {
            return CveRemediationStatus.FIX_AVAILABLE;
        }
        String sev = severity != null ? severity.toUpperCase(Locale.ROOT) : "";
        if (kevListed || exploitAvailable || "CRITICAL".equals(sev) || "HIGH".equals(sev)) {
            return CveRemediationStatus.IN_PROGRESS;
        }
        return CveRemediationStatus.OPEN;
    }

    public static String statusLabel(CveRemediationStatus status) {
        if (status == null) {
            return "Ouvert";
        }
        return switch (status) {
            case DETECTE, OPEN -> "Ouvert";
            case EVALUE, IN_PROGRESS -> "En cours";
            case VERSION_OFFICIELLE, FIX_AVAILABLE -> "Correctif disponible";
            case CORRIGE, FIXED -> "Corrigé";
            case ECART_POLITIQUE -> "Écart politique";
            case ACCEPTE_RISQUE, ACCEPTED_RISK -> "Risque accepté";
            case NO_FIX -> "Pas de correctif";
            case FALSE_POSITIVE -> "Faux positif";
        };
    }

    private static boolean versionsEquivalent(String a, String b) {
        if (a == null || b == null) return false;
        String na = a.replaceAll("^[^0-9]*", "").trim();
        String nb = b.replaceAll("^[^0-9]*", "").trim();
        return na.equalsIgnoreCase(nb);
    }

    private Map<String, Object> toKnowledgeDto(FixKnowledge k) {
        Map<String, Object> dto = new LinkedHashMap<>();
        dto.put("id", k.getId());
        dto.put("cveId", k.getCveId());
        dto.put("packageName", k.getPackageName());
        dto.put("fromVersion", k.getFromVersion());
        dto.put("toVersion", k.getToVersion());
        dto.put("reason", k.getReason());
        dto.put("createdByLogin", k.getCreatedByLogin());
        dto.put("repoFullName", k.getRepoFullName());
        dto.put("status", k.getStatus() != null ? k.getStatus().name() : "ACTIVE");
        dto.put("usageCount", k.getUsageCount());
        dto.put("createdAt", k.getCreatedAt() != null ? k.getCreatedAt().toString() : null);
        return dto;
    }

    private static String keyOf(String cveId, String packageName) {
        return blankToEmpty(cveId).toLowerCase(Locale.ROOT) + "|" + blankToEmpty(packageName).toLowerCase(Locale.ROOT);
    }

    private static String blankToEmpty(String s) {
        return s == null ? "" : s.trim();
    }

    private static int severityRank(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    private static class CatalogAgg {
        final String cveId;
        final String packageName;
        String severity = "UNKNOWN";
        Double cvssScore;
        Double epssScore;
        String fixedVersion;
        String source;
        String ecosystem;
        String description;
        int detectionCount;
        boolean kevListed;
        boolean exploitAvailable;

        CatalogAgg(String cveId, String packageName) {
            this.cveId = cveId;
            this.packageName = packageName;
        }

        void absorb(CveEntry c) {
            detectionCount++;
            if (c.getSeverity() != null && severityRank(c.getSeverity()) > severityRank(severity)) {
                severity = c.getSeverity();
            }
            if (c.getCvssScore() != null && (cvssScore == null || c.getCvssScore() > cvssScore)) {
                cvssScore = c.getCvssScore();
            }
            if (c.getEpssScore() != null && (epssScore == null || c.getEpssScore() > epssScore)) {
                epssScore = c.getEpssScore();
            }
            if (fixedVersion == null && c.getFixedVersion() != null && !c.getFixedVersion().isBlank()) {
                fixedVersion = c.getFixedVersion();
            }
            if (source == null && c.getSource() != null) source = c.getSource();
            if (ecosystem == null && c.getEcosystem() != null) ecosystem = c.getEcosystem();
            if ((description == null || description.isBlank()) && c.getDescription() != null) {
                description = c.getDescription();
            }
            if (c.isKevListed()) kevListed = true;
            if (c.isExploitAvailable()) exploitAvailable = true;
        }
    }
}
