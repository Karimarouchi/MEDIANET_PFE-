package com.medianet.service;

import com.medianet.entity.DeployStrategy;
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

    /**
     * Health URL curled from the server after a deploy. Same allowlist idea as the other fields: it ends up in the
     * SSH command, so only plain http(s) URLs with safe characters are kept.
     */
    public static String normalizeHealthUrl(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String url = raw.trim();
        if (url.length() > 300 || !url.matches("(?i)https?://[A-Za-z0-9.-]+(:\\d{1,5})?(/[A-Za-z0-9._~/?=&%-]*)?")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Adresse de santé invalide. Exemple : http://localhost:8080/api/health");
        }
        return url;
    }

    /** Compose service name of the database to back up (e.g. "db"). Null when empty. */
    public static String normalizeService(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String s = raw.trim();
        if (!s.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,62}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nom de service invalide (ex. db).");
        }
        return s;
    }

    /** Full git commit id (what the CI tested), lower case. */
    public static String normalizeCommit(String raw) {
        String sha = raw == null ? "" : raw.trim().toLowerCase();
        if (!sha.matches("[0-9a-f]{40}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Commit invalide.");
        }
        return sha;
    }

    public static DeployStrategy normalizeStrategy(String raw) {
        if (raw == null || raw.isBlank()) {
            return DeployStrategy.DOCKER_COMPOSE;
        }
        try {
            return DeployStrategy.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Stratégie invalide. Utilisez DOCKER_COMPOSE ou STATIC_NGINX.");
        }
    }
}
