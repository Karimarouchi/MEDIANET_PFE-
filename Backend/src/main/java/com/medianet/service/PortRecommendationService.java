package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.PortExposureDto;
import com.medianet.dto.PortRecommendationDto;
import com.medianet.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Génère des recommandations de sécurité IA pour les ports exposés d'un serveur.
 *
 * Comportement AI :
 *  - Si l'utilisateur a configuré une clé AI dans son profil → sa clé est utilisée (via AiGatewayService)
 *  - Sinon → clé Gemini système par défaut
 */
@Service
public class PortRecommendationService {

    private static final Logger log = LoggerFactory.getLogger(PortRecommendationService.class);

    private final AiGatewayService aiGatewayService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public PortRecommendationService(AiGatewayService aiGatewayService) {
        this.aiGatewayService = aiGatewayService;
    }

    /**
     * Génère des recommandations IA pour la liste de ports donnée.
     *
     * @param ports    Liste des ports exposés trouvés par le scan SSH
     * @param nodeType Type du serveur (ex: NGINX, APACHE, MYSQL, DOCKER_HOST, GENERIC…)
     * @param osName   Nom du système d'exploitation détecté (ex: Ubuntu 22.04)
     * @param user     Utilisateur authentifié (peut avoir une clé AI personnelle)
     * @return Liste de recommandations par port
     */
    public List<PortRecommendationDto> generateRecommendations(
            List<PortExposureDto> ports,
            String nodeType,
            String osName,
            User user) {

        if (ports == null || ports.isEmpty()) {
            return List.of();
        }

        String prompt = buildPrompt(ports, nodeType, osName);
        log.info("[PortRec] Calling AI for {} ports on nodeType={} os={}", ports.size(), nodeType, osName);

        String rawResponse = aiGatewayService.generate(prompt, user);
        if (rawResponse == null || rawResponse.isBlank()) {
            log.warn("[PortRec] AI returned empty response");
            return buildFallbackRecommendations(ports);
        }

        return parseAiResponse(rawResponse, ports);
    }

    // ── Prompt builder ──────────────────────────────────────────────────────────

    private String buildPrompt(List<PortExposureDto> ports, String nodeType, String osName) {
        StringBuilder portsList = new StringBuilder();
        for (PortExposureDto p : ports) {
            portsList.append(String.format(
                    "  - Port %d/%s | Service: %s | Process: %s | Exposition: %s | État: %s%n",
                    p.portNumber(),
                    p.protocol(),
                    nvl(p.serviceName(), "unknown"),
                    nvl(p.processName(), "unknown"),
                    nvl(p.exposureLevel(), "UNKNOWN"),
                    nvl(p.state(), "LISTEN")));
        }

        return """
                Tu es un expert en sécurité Linux et DevSecOps.
                Analyse les ports exposés du serveur suivant et fournis des recommandations de sécurité précises.

                Informations du serveur :
                  - Type de serveur (nodeType) : %s
                  - Système d'exploitation : %s

                Ports exposés à analyser :
                %s
                Réponds UNIQUEMENT avec un tableau JSON valide (pas de texte avant ou après), sans markdown, avec ce format exact :
                [
                  {
                    "portNumber": <numéro>,
                    "protocol": "<tcp|udp>",
                    "serviceName": "<nom du service>",
                    "riskReason": "<explication du risque en français, 1-2 phrases>",
                    "disableCommand": "<commande Linux exacte pour désactiver ce port/service>",
                    "severity": "<CRITICAL|WARNING|INFO>"
                  }
                ]

                Règles impératives :
                - severity = CRITICAL si le port est dangereux ou inutile (ex: telnet 23, FTP 21, RPC 111)
                - severity = WARNING si le port est potentiellement risqué selon le contexte (ex: base de données exposée)
                - severity = INFO si le port est normal/nécessaire pour ce type de serveur (ex: 80/443 pour NGINX, 22 SSH)
                - disableCommand : adapte la commande au nodeType '%s' et à l'OS '%s'
                  * Pour un service systemd : "sudo systemctl stop <service> && sudo systemctl disable <service>"
                  * Pour une règle firewall : "sudo ufw deny <port>/<proto>" ou "sudo firewall-cmd --remove-port=<port>/<proto> --permanent && sudo firewall-cmd --reload"
                  * Pour docker : "docker stop <container> && docker rm <container>"
                  * Si INFO (port normal) : disableCommand = "# Port requis pour ce serveur — ne pas désactiver"
                - riskReason en français, claire et concise
                - Inclus TOUS les ports fournis dans la réponse (un objet JSON par port)
                """.formatted(
                nvl(nodeType, "GENERIC"),
                nvl(osName, "Linux"),
                portsList,
                nvl(nodeType, "GENERIC"),
                nvl(osName, "Linux"));
    }

    // ── Response parser ─────────────────────────────────────────────────────────

    private List<PortRecommendationDto> parseAiResponse(String rawResponse, List<PortExposureDto> ports) {
        try {
            // Strip potential markdown code fences
            String cleaned = rawResponse.trim();
            if (cleaned.startsWith("```")) {
                int firstNewline = cleaned.indexOf('\n');
                int lastFence = cleaned.lastIndexOf("```");
                if (firstNewline > 0 && lastFence > firstNewline) {
                    cleaned = cleaned.substring(firstNewline + 1, lastFence).trim();
                }
            }
            // Find first '[' and last ']' to extract JSON array
            int start = cleaned.indexOf('[');
            int end = cleaned.lastIndexOf(']');
            if (start >= 0 && end > start) {
                cleaned = cleaned.substring(start, end + 1);
            }

            JsonNode array = objectMapper.readTree(cleaned);
            if (!array.isArray()) {
                log.warn("[PortRec] AI response is not a JSON array, using fallback");
                return buildFallbackRecommendations(ports);
            }

            List<PortRecommendationDto> result = new ArrayList<>();
            for (JsonNode node : array) {
                result.add(new PortRecommendationDto(
                        node.path("portNumber").asInt(0),
                        node.path("protocol").asText("tcp"),
                        node.path("serviceName").asText("unknown"),
                        node.path("riskReason").asText("Analyse indisponible."),
                        node.path("disableCommand").asText("# Commande non disponible"),
                        node.path("severity").asText("INFO")));
            }
            log.info("[PortRec] Parsed {} recommendations from AI", result.size());
            return result;

        } catch (Exception e) {
            log.error("[PortRec] Failed to parse AI response: {}", e.getMessage());
            return buildFallbackRecommendations(ports);
        }
    }

    // ── Fallback (si l'IA échoue) ───────────────────────────────────────────────

    private List<PortRecommendationDto> buildFallbackRecommendations(List<PortExposureDto> ports) {
        List<PortRecommendationDto> fallback = new ArrayList<>();
        for (PortExposureDto p : ports) {
            String severity = guessSeverity(p.portNumber());
            fallback.add(new PortRecommendationDto(
                    p.portNumber(),
                    nvl(p.protocol(), "tcp"),
                    nvl(p.serviceName(), nvl(p.processName(), "unknown")),
                    "Analyse IA indisponible. Vérifiez manuellement si ce port est nécessaire.",
                    severity.equals("INFO")
                            ? "# Port probablement requis — vérifiez manuellement"
                            : "sudo ufw deny " + p.portNumber() + "/" + nvl(p.protocol(), "tcp"),
                    severity));
        }
        return fallback;
    }

    private String guessSeverity(int port) {
        return switch (port) {
            case 22, 80, 443, 8080, 8443 -> "INFO";
            case 21, 23, 25, 110, 143, 161, 512, 513, 514, 2049 -> "CRITICAL";
            case 3306, 5432, 27017, 6379, 5672, 1433 -> "WARNING";
            default -> "WARNING";
        };
    }

    private String nvl(String val, String fallback) {
        return (val != null && !val.isBlank()) ? val : fallback;
    }
}
