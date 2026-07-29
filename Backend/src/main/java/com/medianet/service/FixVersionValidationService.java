package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Double-check a developer-chosen dependency version before commit.
 * Warns if the version may still be vulnerable or looks less safe than the scanner recommendation.
 */
@Service
public class FixVersionValidationService {

    private static final Logger log = LoggerFactory.getLogger(FixVersionValidationService.class);

    private final AiGatewayService aiGatewayService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public FixVersionValidationService(AiGatewayService aiGatewayService) {
        this.aiGatewayService = aiGatewayService;
    }

    public Map<String, Object> validate(
            User user,
            String packageName,
            String currentVersion,
            String recommendedVersion,
            String chosenVersion,
            String cveId,
            String ecosystem,
            String filePath,
            String fixedContentSnippet) {

        String chosen = blank(chosenVersion);
        String recommended = blank(recommendedVersion);
        String current = blank(currentVersion);

        // Try extract from content if not provided
        if (chosen == null && fixedContentSnippet != null && packageName != null) {
            chosen = extractVersionFromContent(fixedContentSnippet, packageName, filePath);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("packageName", packageName);
        result.put("cveId", cveId);
        result.put("currentVersion", current);
        result.put("recommendedVersion", recommended);
        result.put("chosenVersion", chosen);

        if (chosen == null || chosen.isBlank()) {
            result.put("verdict", "UNKNOWN");
            result.put("riskLevel", "MEDIUM");
            result.put("title", "Version choisie non détectée");
            result.put("summary",
                    "Impossible d'identifier clairement la version que vous avez saisie. "
                            + "Vérifiez manuellement qu'elle corrige bien le CVE avant de committer.");
            result.put("details", List.of(
                    "Relisez le diff et confirmez la balise <version> ou le numéro npm."));
            result.put("canProceed", true);
            result.put("source", "HEURISTIC");
            return result;
        }

        // Heuristic comparison vs scanner recommendation
        String heuristicVerdict = "OK";
        String riskLevel = "LOW";
        List<String> details = new ArrayList<>();

        if (recommended != null) {
            int cmp = compareVersions(chosen, recommended);
            if (cmp < 0) {
                heuristicVerdict = "RISKY";
                riskLevel = "HIGH";
                details.add("La version choisie (" + chosen + ") est INFÉRIEURE à la version "
                        + "recommandée par le scan (" + recommended + "). Elle peut encore être vulnérable.");
            } else if (cmp == 0) {
                heuristicVerdict = "OK";
                riskLevel = "LOW";
                details.add("La version choisie correspond à la recommandation du scan (" + recommended + ").");
            } else {
                heuristicVerdict = "OK";
                riskLevel = "LOW";
                details.add("La version choisie (" + chosen + ") est plus récente que la recommandation ("
                        + recommended + "). En général c'est bien, mais vérifiez les breaking changes.");
            }
        }

        if (current != null && compareVersions(chosen, current) <= 0) {
            heuristicVerdict = "RISKY";
            riskLevel = "HIGH";
            details.add("La version choisie (" + chosen + ") n'est pas strictement supérieure à la version "
                    + "vulnérable actuelle (" + current + ").");
        }

        // LLM double-check (best effort)
        Map<String, Object> llm = askLlm(user, packageName, current, recommended, chosen, cveId, ecosystem, details);
        if (llm != null) {
            result.putAll(llm);
            result.put("source", "LLM");
            // Never block harder than heuristic if LLM fails soft — but if LLM says RISKY, keep it
            if ("OK".equals(result.get("verdict")) && "RISKY".equals(heuristicVerdict)) {
                result.put("verdict", "RISKY");
                result.put("riskLevel", riskLevel);
            }
        } else {
            result.put("verdict", heuristicVerdict);
            result.put("riskLevel", riskLevel);
            result.put("title", "RISKY".equals(heuristicVerdict)
                    ? "Attention : version potentiellement risquée"
                    : "Version semble acceptable");
            result.put("summary", "RISKY".equals(heuristicVerdict)
                    ? "La version que vous avez choisie pourrait encore contenir des vulnérabilités."
                    : "Aucune alerte majeure détectée sur la version choisie par rapport au scan.");
            result.put("details", details);
            result.put("source", "HEURISTIC");
        }

        result.put("canProceed", true); // always allow override after explicit accept
        result.put("chosenVersion", chosen);
        result.put("recommendedVersion", recommended);
        return result;
    }

    private Map<String, Object> askLlm(User user, String packageName, String current, String recommended,
            String chosen, String cveId, String ecosystem, List<String> heuristicDetails) {
        String prompt = """
                Tu es un expert sécurité dépendances (Vulnix).
                Un développeur a CHOISI MANUELLEMENT une version pour corriger un CVE.
                Fais une double vérification. Réponds UNIQUEMENT en JSON valide (pas de markdown) :
                {
                  "verdict": "OK" | "RISKY" | "UNKNOWN",
                  "riskLevel": "LOW" | "MEDIUM" | "HIGH",
                  "title": "titre court en français",
                  "summary": "2 phrases max en français : la version est-elle fiable ? peut-elle encore être vulnérable ?",
                  "details": ["point 1", "point 2"],
                  "advice": "conseil court (garder / monter de version / vérifier changelog)"
                }

                Package: %s
                Ecosystem: %s
                CVE: %s
                Version vulnérable actuelle: %s
                Version recommandée par le scan: %s
                Version CHOISIE par le développeur: %s
                Indices heuristiques: %s

                Sois prudent : si la version choisie < recommandée, verdict=RISKY.
                """.formatted(
                nullDash(packageName),
                nullDash(ecosystem),
                nullDash(cveId),
                nullDash(current),
                nullDash(recommended),
                nullDash(chosen),
                heuristicDetails.isEmpty() ? "aucun" : String.join(" ; ", heuristicDetails));

        try {
            String raw = aiGatewayService.generate(prompt, user);
            if (raw == null || raw.isBlank()) return null;
            String json = extractJson(raw.trim());
            JsonNode root = objectMapper.readTree(json);
            Map<String, Object> out = new LinkedHashMap<>();
            String verdict = root.path("verdict").asText("UNKNOWN").toUpperCase(Locale.ROOT);
            if (!Set.of("OK", "RISKY", "UNKNOWN").contains(verdict)) verdict = "UNKNOWN";
            out.put("verdict", verdict);
            out.put("riskLevel", root.path("riskLevel").asText("MEDIUM").toUpperCase(Locale.ROOT));
            out.put("title", root.path("title").asText("Double vérification version"));
            out.put("summary", root.path("summary").asText(""));
            List<String> details = new ArrayList<>();
            if (root.path("details").isArray()) {
                root.path("details").forEach(n -> details.add(n.asText()));
            }
            out.put("details", details);
            out.put("advice", root.path("advice").asText(""));
            return out;
        } catch (Exception e) {
            log.warn("[FixVersionValidation] LLM failed: {}", e.getMessage());
            return null;
        }
    }

    public String extractVersionFromContent(String content, String packageName, String filePath) {
        if (content == null || packageName == null) return null;
        String artifact = packageName.contains(":")
                ? packageName.substring(packageName.lastIndexOf(':') + 1)
                : packageName;
        String file = filePath != null ? filePath.toLowerCase(Locale.ROOT) : "";

        if (file.endsWith("pom.xml") || content.contains("<artifactId>")) {
            // artifactId then version
            Pattern block = Pattern.compile(
                    "<artifactId>\\s*" + Pattern.quote(artifact) + "\\s*</artifactId>[\\s\\S]{0,240}?<version>\\s*([^<\\s]+)\\s*</version>",
                    Pattern.CASE_INSENSITIVE);
            Matcher m = block.matcher(content);
            String last = null;
            while (m.find()) last = m.group(1).trim();
            if (last != null) return last;

            // version then artifactId
            Pattern reverse = Pattern.compile(
                    "<version>\\s*([^<\\s]+)\\s*</version>[\\s\\S]{0,240}?<artifactId>\\s*"
                            + Pattern.quote(artifact) + "\\s*</artifactId>",
                    Pattern.CASE_INSENSITIVE);
            Matcher rm = reverse.matcher(content);
            while (rm.find()) last = rm.group(1).trim();
            if (last != null) return last;
        }

        // package.json style
        Pattern npm = Pattern.compile(
                "\"" + Pattern.quote(packageName) + "\"\\s*:\\s*\"\\^?~?([0-9][^\"\\s]*)\"");
        Matcher nm = npm.matcher(content);
        if (nm.find()) return nm.group(1);

        // overrides
        Pattern ov = Pattern.compile(
                "\"" + Pattern.quote(artifact) + "\"\\s*:\\s*\"\\^?~?([0-9][^\"\\s]*)\"");
        Matcher om = ov.matcher(content);
        if (om.find()) return om.group(1);

        return null;
    }

    /** Compare dotted versions; returns <0 if a<b, 0 if equal, >0 if a>b. */
    public int compareVersions(String a, String b) {
        if (a == null || b == null) return 0;
        String na = a.replaceAll("^[^0-9]*", "").split("[-+]")[0];
        String nb = b.replaceAll("^[^0-9]*", "").split("[-+]")[0];
        String[] pa = na.split("\\.");
        String[] pb = nb.split("\\.");
        int len = Math.max(pa.length, pb.length);
        for (int i = 0; i < len; i++) {
            int va = i < pa.length ? parseIntSafe(pa[i]) : 0;
            int vb = i < pb.length ? parseIntSafe(pb[i]) : 0;
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private int parseIntSafe(String s) {
        try {
            return Integer.parseInt(s.replaceAll("[^0-9].*", ""));
        } catch (Exception e) {
            return 0;
        }
    }

    private String extractJson(String content) {
        if (content.startsWith("```")) {
            int nl = content.indexOf('\n');
            if (nl >= 0) content = content.substring(nl + 1);
            if (content.endsWith("```")) content = content.substring(0, content.lastIndexOf("```")).trim();
        }
        int start = content.indexOf('{');
        int end = content.lastIndexOf('}');
        if (start >= 0 && end > start) return content.substring(start, end + 1);
        return content;
    }

    private String blank(String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }

    private String nullDash(String v) {
        return v == null || v.isBlank() ? "—" : v;
    }
}
