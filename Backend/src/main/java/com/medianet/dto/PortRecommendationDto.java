package com.medianet.dto;

/**
 * Recommandation IA pour un port exposé :
 * - riskReason      : pourquoi ce port est un risque
 * - disableCommand  : commande pour le désactiver (adaptée au nodeType)
 * - severity        : CRITICAL | WARNING | INFO
 */
public record PortRecommendationDto(
        Integer portNumber,
        String protocol,
        String serviceName,
        String riskReason,
        String disableCommand,
        String severity) {
}
