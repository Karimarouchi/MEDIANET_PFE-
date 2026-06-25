package com.medianet.service;

import com.medianet.dto.CveDto;
import com.medianet.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class GeminiSummaryService {

    private static final Logger log = LoggerFactory.getLogger(GeminiSummaryService.class);

    private final AiGatewayService aiGateway;

    public GeminiSummaryService(AiGatewayService aiGateway) {
        this.aiGateway = aiGateway;
    }

    /**
     * Generates a concise executive summary of the scan results.
     * Uses the user's configured AI provider, or falls back to system default Gemini.
     */
    public String generateScanSummary(List<CveDto> cves, User user) {
        if (cves == null || cves.isEmpty()) {
            return "Aucune vulnérabilité détectée dans ce scan.";
        }

        long critical = cves.stream().filter(c -> "CRITICAL".equals(c.getSeverity())).count();
        long high     = cves.stream().filter(c -> "HIGH".equals(c.getSeverity())).count();
        long medium   = cves.stream().filter(c -> "MEDIUM".equals(c.getSeverity())).count();
        long low      = cves.stream().filter(c -> "LOW".equals(c.getSeverity())).count();
        long withExploit = cves.stream().filter(CveDto::isExploitAvailable).count();
        long kevListed   = cves.stream().filter(CveDto::isKevListed).count();

        String topCves = cves.stream()
                .filter(c -> "CRITICAL".equals(c.getSeverity()) || "HIGH".equals(c.getSeverity()))
                .limit(5)
                .map(c -> String.format("- %s (%s, CVSS %.1f) dans %s",
                        c.getCveId() != null ? c.getCveId() : "N/A",
                        c.getSeverity(),
                        c.getCvssScore() != null ? c.getCvssScore() : 0.0,
                        c.getPackageName() != null ? c.getPackageName() : "inconnu"))
                .collect(Collectors.joining("\n"));

        String prompt = "Tu es un expert en cybersécurité. Analyse ces résultats de scan de sécurité "
                + "et génère un résumé exécutif concis en français (5-7 lignes maximum).\n\n"
                + "Statistiques du scan :\n"
                + "- Total : " + cves.size() + " vulnérabilités\n"
                + "- CRITICAL : " + critical + " | HIGH : " + high + " | MEDIUM : " + medium + " | LOW : " + low + "\n"
                + "- Avec exploit public : " + withExploit + "\n"
                + "- Dans le catalogue CISA KEV (exploitées activement) : " + kevListed + "\n"
                + "Top vulnérabilités critiques :\n" + topCves + "\n\n"
                + "Génère un résumé clair et actionnable pour un responsable sécurité. "
                + "Utilise des phrases courtes. Termine par une recommandation prioritaire. "
                + "Ne liste pas toutes les CVEs, donne une vue d'ensemble. "
                + "Réponds uniquement en français, sans markdown, sans titres, juste le texte du résumé.";

        return aiGateway.generate(prompt, user);
    }

    /**
     * Backward-compatible overload without user (uses system default).
     */
    public String generateScanSummary(List<CveDto> cves) {
        return generateScanSummary(cves, null);
    }
}
