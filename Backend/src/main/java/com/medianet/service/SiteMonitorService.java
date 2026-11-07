package com.medianet.service;

import com.medianet.entity.SiteCheck;
import com.medianet.repository.SiteCheckRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLException;

/**
 * Availability of the sites written on projects, checked by Vulnix itself: nothing to install or configure, the
 * domain of the project is enough. Every minute each domain gets one HTTP request; a status below 400 is "up"
 * (redirections are not followed: the site answered, and nothing can be sent elsewhere). Results are kept 7 days
 * and read by {@link UptimeService} in the same shape the overview already shows.
 */
@Service
public class SiteMonitorService {

    private static final Logger log = LoggerFactory.getLogger(SiteMonitorService.class);

    public static final String UP = "UP";
    public static final String DOWN = "DOWN";
    public static final String SKIPPED = "SKIPPED";
    static final Duration RETENTION = Duration.ofDays(7);
    private static final Pattern EXPLICIT_PORT = Pattern.compile("^(?:https?://)?[^/:]+:(\\d{1,5})(?:[/?#].*)?$");

    private final SiteCheckRepo repo;
    private final SslTargetGuard guard;
    private final Executor firstCheckExecutor;
    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    /** Domains whose very first check was already asked, so opening the overview twice does not start it twice. */
    private final Set<String> firstCheckAsked = ConcurrentHashMap.newKeySet();

    @Value("${vulnix.monitor.enabled:true}")
    private boolean enabled;

    @Autowired
    public SiteMonitorService(SiteCheckRepo repo, SslTargetGuard guard) {
        this(repo, guard, Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "site-monitor-first-check");
            t.setDaemon(true);
            return t;
        }));
    }

    SiteMonitorService(SiteCheckRepo repo, SslTargetGuard guard, Executor firstCheckExecutor) {
        this.repo = repo;
        this.guard = guard;
        this.firstCheckExecutor = firstCheckExecutor;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Test hook. */
    void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    // ------------------------------------------------------------------ scheduling

    @Scheduled(initialDelayString = "${vulnix.monitor.initial-delay-ms:30000}", fixedDelayString = "${vulnix.monitor.interval-ms:60000}")
    public void checkAll() {
        if (!enabled) return;
        for (String domain : monitoredDomains()) {
            try {
                checkNow(domain);
            } catch (RuntimeException e) {
                log.warn("Site check of {} failed unexpectedly: {}", domain, e.toString());
            }
        }
    }

    @Scheduled(initialDelay = 600_000L, fixedDelay = 3_600_000L)
    @Transactional
    public void purgeOld() {
        int n = repo.deleteOlderThan(LocalDateTime.now().minus(RETENTION));
        if (n > 0) log.info("Site checks: {} old result(s) deleted", n);
    }

    Set<String> monitoredDomains() {
        Set<String> out = new LinkedHashSet<>();
        for (String d : repo.projectDomains()) addIfValid(out, d);
        for (String d : repo.deploymentDomains()) addIfValid(out, d);
        return out;
    }

    private static void addIfValid(Set<String> out, String raw) {
        String d = clean(raw);
        if (!d.isEmpty()) out.add(d);
    }

    /** Same cleaning as the project domains are compared with: lower case, no scheme, no path. */
    static String clean(String raw) {
        if (raw == null) return "";
        return raw.trim().toLowerCase(Locale.ROOT).replaceFirst("^https?://", "").replaceAll("[/?#].*$", "");
    }

    // ------------------------------------------------------------------ one check

    /** Checks one site now and stores the result. {@code raw} may carry http:// to force plain HTTP. */
    public SiteCheck checkNow(String raw) {
        String domain = clean(raw);
        SiteCheck.SiteCheckBuilder b = SiteCheck.builder().domain(domain).checkedAt(LocalDateTime.now());
        SslTargetGuard.Target target;
        try {
            target = SslTargetGuard.normalize(raw);
        } catch (ResponseStatusException e) {
            return repo.save(b.state(SKIPPED).message(shorten("domaine invalide : " + domain)).build());
        }
        try {
            guard.resolvePublic(target.host());
        } catch (ResponseStatusException e) {
            String why = e.getReason() == null ? "" : e.getReason();
            if (why.contains("introuvable")) {
                return repo.save(b.state(DOWN).message("domaine introuvable (aucune réponse DNS)").build());
            }
            return repo.save(b.state(SKIPPED).message("adresse non publique : non surveillée").build());
        }
        URI uri = URI.create(urlOf(raw, target));
        long t0 = System.nanoTime();
        try {
            HttpResponse<Void> r = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "Vulnix-Monitor")
                    .GET().build(), HttpResponse.BodyHandlers.discarding());
            int ms = (int) Math.min(Integer.MAX_VALUE, (System.nanoTime() - t0) / 1_000_000L);
            int code = r.statusCode();
            b.statusCode(code).responseMs(ms);
            if (code < 400) {
                return repo.save(b.state(UP).message("HTTP " + code + " · " + ms + " ms").build());
            }
            return repo.save(b.state(DOWN).message("HTTP " + code).build());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return repo.save(b.state(DOWN).message("vérification interrompue").build());
        } catch (Exception e) {
            return repo.save(b.state(DOWN).message(reason(e)).build());
        }
    }

    /** https by default; http only when the project wrote http://. A port is kept only where private targets are allowed (dev). */
    String urlOf(String raw, SslTargetGuard.Target target) {
        String lower = raw.trim().toLowerCase(Locale.ROOT);
        String scheme = lower.startsWith("http://") ? "http" : "https";
        String port = "";
        if (guard.allowsPrivateTargets()) {
            Matcher m = EXPLICIT_PORT.matcher(lower);
            if (m.matches()) port = ":" + m.group(1);
        }
        return scheme + "://" + target.host() + port + "/";
    }

    static String reason(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null && t.getCause() != t) t = t.getCause();
        if (t instanceof HttpTimeoutException || e instanceof HttpTimeoutException) return "délai dépassé (8 s)";
        if (t instanceof SSLException) return "certificat ou connexion TLS refusés";
        // Refused connections surface as ConnectException, or as ClosedChannelException on some platforms.
        if (t instanceof ConnectException || e instanceof ConnectException || t instanceof ClosedChannelException) {
            return "connexion refusée ou interrompue";
        }
        if (t instanceof java.net.UnknownHostException) return "domaine introuvable (aucune réponse DNS)";
        String m = t.getMessage();
        return shorten(m == null || m.isBlank() ? t.getClass().getSimpleName() : m);
    }

    private static String shorten(String s) {
        return s.length() <= 250 ? s : s.substring(0, 250);
    }

    // ------------------------------------------------------------------ reading

    /** One line per domain: last status and availability over the last 24 hours. */
    public List<UptimeService.Monitor> snapshot(Set<String> domains) {
        List<UptimeService.Monitor> out = new ArrayList<>();
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        for (String raw : domains) {
            String d = clean(raw);
            if (d.isEmpty()) continue;
            long id = d.hashCode() & 0x7fffffffL;
            SiteCheck last = repo.findFirstByDomainOrderByCheckedAtDesc(d).orElse(null);
            if (last == null) {
                askFirstCheck(d);
                out.add(new UptimeService.Monitor(id, d, "PENDING", null, null, "première vérification en cours"));
                continue;
            }
            long up = repo.countSince(d, UP, since);
            long down = repo.countSince(d, DOWN, since);
            Double ratio = up + down == 0 ? null : (double) up / (double) (up + down);
            out.add(new UptimeService.Monitor(id, d, statusOf(last.getState()), ratio,
                    last.getCheckedAt() == null ? null : last.getCheckedAt().toString(), last.getMessage()));
        }
        return out;
    }

    static String statusOf(String state) {
        if (UP.equals(state)) return "UP";
        if (DOWN.equals(state)) return "DOWN";
        return "UNKNOWN";
    }

    private void askFirstCheck(String domain) {
        if (!enabled || !firstCheckAsked.add(domain)) return;
        firstCheckExecutor.execute(() -> {
            try {
                checkNow(domain);
            } catch (RuntimeException e) {
                log.debug("First site check of {} failed: {}", domain, e.toString());
            }
        });
    }
}
