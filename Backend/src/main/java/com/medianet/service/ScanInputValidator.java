package com.medianet.service;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Checks the scan parameters that end up as environment variables of the Kali container (BRANCH, COMMIT_SHA,
 * TARGET_OS, COMPLIANCE_PROFILE, TARGET_DOMAIN, DAST_TARGET_URL, DOCKER_IMAGE) and as docker arguments.
 *
 * The scripts pass some of them to git, grype or nmap: a value starting with "-" becomes an option, an unquoted one
 * becomes several arguments, and a URL or domain makes the scanner connect to it. Every entry point (page, schedule,
 * API) goes through here, with the same internal-address refusal as the SSL page.
 */
@Component
public class ScanInputValidator {

    private static final Pattern BRANCH = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._/\\-]{0,199}$");
    private static final Pattern COMMIT = Pattern.compile("^[0-9a-fA-F]{7,40}$");
    private static final Pattern TARGET_OS = Pattern.compile(
            "^(ubuntu|debian|alpine|centos|rhel|rocky|almalinux|amazonlinux|fedora|oraclelinux|windows):[0-9][0-9.]{0,9}$");
    private static final Set<String> COMPLIANCE_PROFILES = Set.of("CIS_L1", "CIS_L2", "NIST_800-53", "PCI_DSS");
    private static final Pattern IMAGE = Pattern.compile("^[a-z0-9][a-z0-9._\\-/]{0,200}(:[A-Za-z0-9._\\-]{1,128})?(@sha256:[a-f0-9]{64})?$");

    private final SslTargetGuard targetGuard;

    public ScanInputValidator(SslTargetGuard targetGuard) {
        this.targetGuard = targetGuard;
    }

    public static String branch(String value) {
        if (isBlank(value)) return null;
        String v = value.trim();
        if (!BRANCH.matcher(v).matches() || v.contains("..") || v.endsWith(".lock") || v.endsWith("/")) {
            throw bad("Nom de branche invalide : « " + v + " ».");
        }
        return v;
    }

    public static String commitSha(String value) {
        if (isBlank(value)) return null;
        String v = value.trim();
        if (!COMMIT.matcher(v).matches()) {
            throw bad("Le commit doit être un identifiant hexadécimal de 7 à 40 caractères.");
        }
        return v.toLowerCase(Locale.ROOT);
    }

    public static String targetOs(String value) {
        if (isBlank(value)) return null;
        String v = value.trim().toLowerCase(Locale.ROOT);
        if (!TARGET_OS.matcher(v).matches()) {
            throw bad("Système cible invalide : attendu « distribution:version », par exemple ubuntu:22.04.");
        }
        return v;
    }

    public static String complianceProfile(String value) {
        if (isBlank(value)) return null;
        String v = value.trim().toUpperCase(Locale.ROOT);
        if (!COMPLIANCE_PROFILES.contains(v)) {
            throw bad("Profil de conformité inconnu : choisissez CIS_L1, CIS_L2, NIST_800-53 ou PCI_DSS.");
        }
        return v;
    }

    public static Integer containerPort(Integer value) {
        if (value == null) return null;
        if (value < 1 || value > 65535) {
            throw bad("Le port du conteneur doit être compris entre 1 et 65535.");
        }
        return value;
    }

    public static String dockerImage(String value) {
        if (isBlank(value)) return null;
        String v = value.trim();
        if (!IMAGE.matcher(v).matches()) {
            throw bad("Référence d'image Docker invalide : « " + v + " ».");
        }
        return v;
    }

    /** Domain scanned by the SSL tools in any mode: same format and internal-address check as the SSL page. */
    public String targetDomain(String value) {
        if (isBlank(value)) return null;
        return targetGuard.check(value).canonical();
    }

    /** DAST target: http(s) URL without credentials whose host resolves only to public addresses. */
    public String dastTargetUrl(String value) {
        if (isBlank(value)) return null;
        String v = value.trim();
        URI uri;
        try {
            uri = URI.create(v);
        } catch (IllegalArgumentException e) {
            throw bad("URL cible invalide.");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw bad("L'URL cible doit commencer par http:// ou https://.");
        }
        if (uri.getRawUserInfo() != null || uri.getHost() == null) {
            throw bad("L'URL cible ne doit pas contenir d'identifiants.");
        }
        SslTargetGuard.normalize(uri.getHost());
        targetGuard.resolvePublic(uri.getHost());
        return v;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
