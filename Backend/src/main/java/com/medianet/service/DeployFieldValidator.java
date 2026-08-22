package com.medianet.service;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Shared allowlist for deploy path / branch / domain.
 * Used on create, update, and at deploy time so a crafted payload cannot persist
 * a value that later gets interpolated into the SSH command.
 */
public final class DeployFieldValidator {

    private DeployFieldValidator() {
    }

    public static String normalizePath(String raw, boolean required) {
        String path = raw != null ? raw.trim() : "";
        if (path.isBlank()) {
            if (required) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Le chemin de déploiement est requis.");
            }
            return null;
        }
        if (path.length() > 255 || !path.startsWith("/") || path.contains("..") || !path.matches("/[A-Za-z0-9._/-]+")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Chemin invalide. Utilisez un chemin absolu simple, ex. /var/www/pfe/MEDIANET_PFE-");
        }
        return path;
    }

    public static String normalizeBranch(String raw) {
        String branch = raw != null && !raw.isBlank() ? raw.trim() : "main";
        if (!branch.matches("[A-Za-z0-9._/-]{1,80}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nom de branche invalide.");
        }
        return branch;
    }

    public static String normalizeDomain(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String domain = raw.trim().replaceFirst("(?i)^https?://", "").replaceAll("/+$", "");
        if (domain.length() > 255 || !domain.matches("[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Domaine invalide.");
        }
        return domain;
    }
}
