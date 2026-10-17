package com.medianet.service;

import com.medianet.dto.SslResultDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Live check of the HTTP security headers of an SSL target, so a fix made on the web server shows up without a
 * full Kali re-scan.
 *
 * Runs outside any database transaction (the result page used to hold a pooled connection during this network
 * call), caches each answer for a few minutes (the page refreshes every 5 s while a scan runs), and follows
 * redirects by hand so every hop is checked against {@link SslTargetGuard}: a public site cannot redirect the
 * server to an internal address.
 */
@Service
public class SslHeaderProbeService {

    private static final Logger log = LoggerFactory.getLogger(SslHeaderProbeService.class);

    static final Duration CACHE_TTL = Duration.ofMinutes(5);
    static final Duration FAILURE_TTL = Duration.ofMinutes(1);
    private static final int MAX_REDIRECTS = 5;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(8);

    private final SslTargetGuard guard;
    private final HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final Map<String, Probe> cache = new ConcurrentHashMap<>();

    public SslHeaderProbeService(SslTargetGuard guard) {
        this.guard = guard;
    }

    /** Result of one live check. {@code headers} is null when the site could not be reached. */
    public record Probe(HttpHeaders headers, String finalUrl, int status, String error, Instant checkedAt) {
        boolean ok() {
            return headers != null;
        }
    }

    /** Refreshes the header fields of {@code dto} from the live site (cached). Never throws. */
    public void refresh(SslResultDto dto) {
        if (dto == null || dto.getDomain() == null || dto.getDomain().isBlank() || "?".equals(dto.getDomain())) {
            return;
        }
        SslTargetGuard.Target target;
        try {
            target = SslTargetGuard.normalize(dto.getDomain());
        } catch (Exception e) {
            dto.setHeadersLiveChecked(false);
            return;
        }
        Probe probe = probe(target);
        apply(dto, probe);
    }

    Probe probe(SslTargetGuard.Target target) {
        String key = target.canonical();
        Probe cached = cache.get(key);
        Instant now = Instant.now();
        if (cached != null) {
            Duration ttl = cached.ok() ? CACHE_TTL : FAILURE_TTL;
            if (cached.checkedAt().plus(ttl).isAfter(now)) {
                return cached;
            }
        }
        Probe fresh = fetch(target);
        cache.put(key, fresh);
        if (cache.size() > 500) {
            cache.entrySet().removeIf(e -> e.getValue().checkedAt().plus(CACHE_TTL).isBefore(now));
        }
        return fresh;
    }

    private Probe fetch(SslTargetGuard.Target target) {
        String start = "https://" + target.canonical() + "/";
        try {
            Probe head = follow(start, true);
            if (head.ok() && hasCoreHeaders(head.headers())) {
                return head;
            }
            // Some stacks only send security headers on GET.
            Probe get = follow(start, false);
            if (get.ok() && (hasAnySecurityHeader(get.headers()) || !head.ok())) {
                return get;
            }
            return head.ok() ? head : get;
        } catch (Exception e) {
            log.debug("[SSL] Live header check failed for {}: {}", target.canonical(), e.getMessage());
            return new Probe(null, start, 0, message(e), Instant.now());
        }
    }

    private Probe follow(String url, boolean head) throws Exception {
        URI uri = URI.create(url);
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!scheme.equals("https") && !scheme.equals("http")) {
                return new Probe(null, uri.toString(), 0, "Redirection vers un schéma non pris en charge", Instant.now());
            }
            try {
                guard.resolvePublic(uri.getHost());
            } catch (Exception e) {
                return new Probe(null, uri.toString(), 0, "Redirection refusée : " + message(e), Instant.now());
            }
            HttpRequest.Builder b = HttpRequest.newBuilder().uri(uri).timeout(REQUEST_TIMEOUT);
            if (head) {
                b.method("HEAD", HttpRequest.BodyPublishers.noBody());
            } else {
                b.GET();
            }
            HttpResponse<Void> resp = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
            int code = resp.statusCode();
            if (code >= 300 && code < 400 && resp.headers().firstValue("location").isPresent()) {
                uri = uri.resolve(resp.headers().firstValue("location").get().trim());
                continue;
            }
            return new Probe(resp.headers(), uri.toString(), code, null, Instant.now());
        }
        return new Probe(null, uri.toString(), 0, "Trop de redirections", Instant.now());
    }

    /** Copies the live values into the DTO. Only overwrites a field when the live site sent it. */
    static void apply(SslResultDto dto, Probe probe) {
        if (probe == null || !probe.ok()) {
            dto.setHeadersLiveChecked(false);
            return;
        }
        HttpHeaders hdrs = probe.headers();
        dto.setHeadersCheckedUrl(probe.finalUrl());
        dto.setHeadersHttpStatus(probe.status());

        String hsts = first(hdrs, "strict-transport-security");
        if (hsts != null) {
            dto.setHsts(true);
            dto.setHstsValue(hsts);
        }
        String csp = first(hdrs, "content-security-policy");
        String cspRo = first(hdrs, "content-security-policy-report-only");
        if (csp != null) {
            dto.setContentSecurityPolicy(true);
            dto.setCspReportOnly(false);
            dto.setCspValue(csp);
        } else if (cspRo != null) {
            dto.setContentSecurityPolicy(false);
            dto.setCspReportOnly(true);
            dto.setCspValue(cspRo);
        }
        String xfo = first(hdrs, "x-frame-options");
        if (xfo != null) {
            dto.setXFrameOptions(true);
            dto.setXFrameOptionsValue(xfo);
        }
        String xcto = first(hdrs, "x-content-type-options");
        if (xcto != null) {
            dto.setXContentTypeOptionsValue(xcto);
            if (xcto.toLowerCase(Locale.ROOT).contains("nosniff")) {
                dto.setXContentTypeOptions(true);
            }
        }
        String referrer = first(hdrs, "referrer-policy");
        if (referrer != null) {
            dto.setReferrerPolicy(true);
            dto.setReferrerPolicyValue(referrer);
        }
        String permissions = first(hdrs, "permissions-policy");
        if (permissions == null) {
            permissions = first(hdrs, "feature-policy");
        }
        if (permissions != null) {
            dto.setPermissionsPolicy(true);
            dto.setPermissionsPolicyValue(permissions);
        }
        String coop = first(hdrs, "cross-origin-opener-policy");
        if (coop != null) {
            dto.setCrossOriginOpenerPolicy(true);
            dto.setCrossOriginOpenerPolicyValue(coop);
        }
        String corp = first(hdrs, "cross-origin-resource-policy");
        if (corp != null) {
            dto.setCrossOriginResourcePolicy(true);
            dto.setCrossOriginResourcePolicyValue(corp);
        }
        String coep = first(hdrs, "cross-origin-embedder-policy");
        if (coep != null) {
            dto.setCrossOriginEmbedderPolicy(true);
            dto.setCrossOriginEmbedderPolicyValue(coep);
        }
        dto.setHeadersLiveChecked(true);
    }

    private static boolean hasCoreHeaders(HttpHeaders h) {
        return hasAnySecurityHeader(h) && first(h, "x-frame-options") != null
                && first(h, "x-content-type-options") != null;
    }

    private static boolean hasAnySecurityHeader(HttpHeaders h) {
        if (h == null || h.map().isEmpty()) {
            return false;
        }
        return first(h, "strict-transport-security") != null
                || first(h, "content-security-policy") != null
                || first(h, "content-security-policy-report-only") != null
                || first(h, "x-frame-options") != null
                || first(h, "x-content-type-options") != null;
    }

    private static String first(HttpHeaders h, String name) {
        String v = h.firstValue(name).orElse(null);
        return v == null || v.isBlank() ? null : v.trim();
    }

    private static String message(Exception e) {
        if (e instanceof org.springframework.web.server.ResponseStatusException rse && rse.getReason() != null) {
            return rse.getReason();
        }
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }
}
