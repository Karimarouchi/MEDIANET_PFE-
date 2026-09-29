package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.CertTransparencyEntryDto;
import com.medianet.dto.CertTransparencyResultDto;
import com.medianet.entity.Repository;
import com.medianet.entity.ServerNode;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ServerNodeRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Queries public Certificate Transparency logs (via crt.sh) to discover every
 * subdomain that has ever had a certificate issued for it — including
 * forgotten staging servers, old marketing subdomains, etc. ("shadow IT").
 * Each subdomain found is cross-referenced against the domains/servers
 * already known to Vulnix, so genuinely new/unmonitored assets stand out.
 */
@Service
public class CertTransparencyService {

    private static final Logger log = LoggerFactory.getLogger(CertTransparencyService.class);

    private final RestTemplate restTemplate;
    private final ObjectMapper mapper = new ObjectMapper();
    private final RepositoryRepo repositoryRepo;
    private final ServerNodeRepo serverNodeRepo;

    public CertTransparencyService(RepositoryRepo repositoryRepo, ServerNodeRepo serverNodeRepo) {
        this.repositoryRepo = repositoryRepo;
        this.serverNodeRepo = serverNodeRepo;
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5_000);
        factory.setReadTimeout(15_000);
        this.restTemplate = new RestTemplate(factory);
    }

    public CertTransparencyResultDto lookup(String rawDomain) {
        String domain = cleanDomain(rawDomain);
        Set<String> known = knownAssetDomains();

        Map<String, CertTransparencyEntryDto> bySubdomain = null;
        // crt.sh is a free public service that frequently returns transient 502s under
        // load — one retry after a short pause avoids surfacing a false "0 found".
        for (int attempt = 1; attempt <= 2 && bySubdomain == null; attempt++) {
            try {
                bySubdomain = fetchFromCrtSh(domain, known);
            } catch (Exception e) {
                log.warn("Certificate Transparency lookup failed for {} (attempt {}/2): {}",
                        domain, attempt, e.getMessage());
                if (attempt < 2) {
                    try {
                        Thread.sleep(800);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        }

        if (bySubdomain == null) {
            return new CertTransparencyResultDto(domain, List.of(), 0, 0, "ERROR");
        }

        List<CertTransparencyEntryDto> entries = new ArrayList<>(bySubdomain.values());
        entries.sort(Comparator.comparing(CertTransparencyEntryDto::subdomain));
        long unknown = entries.stream().filter(e -> !e.knownAsset()).count();
        return new CertTransparencyResultDto(domain, entries, entries.size(), (int) unknown, "OK");
    }

    private Map<String, CertTransparencyEntryDto> fetchFromCrtSh(String domain, Set<String> known) throws Exception {
        Map<String, CertTransparencyEntryDto> bySubdomain = new LinkedHashMap<>();
        // Build a pre-encoded URI directly: RestTemplate's String-URL overload treats its
        // input as a URI *template* and re-encodes it, which would double-encode our '%'
        // (already escaped to %25) into %2525 and break the crt.sh query.
        URI uri = URI.create("https://crt.sh/?q=" + URLEncoder.encode("%." + domain, StandardCharsets.UTF_8) + "&output=json");
        String body = restTemplate.getForObject(uri, String.class);
        JsonNode root = (body != null && !body.isBlank()) ? mapper.readTree(body) : null;
        if (root != null && root.isArray()) {
            for (JsonNode item : root) {
                String issuer = item.path("issuer_name").asText("");
                String notBefore = item.path("not_before").asText("");
                String notAfter = item.path("not_after").asText("");
                String nameValue = item.path("name_value").asText("");
                for (String rawSub : nameValue.split("\\n")) {
                    String sub = rawSub.trim().toLowerCase(Locale.ROOT);
                    if (sub.isEmpty() || sub.startsWith("*.")) continue;
                    if (!sub.equals(domain) && !sub.endsWith("." + domain)) continue; // reject "evilmedianet.tn" matching "medianet.tn"
                    bySubdomain.putIfAbsent(sub,
                            new CertTransparencyEntryDto(sub, issuer, notBefore, notAfter, known.contains(sub)));
                }
            }
        }
        return bySubdomain;
    }

    private Set<String> knownAssetDomains() {
        Set<String> known = new HashSet<>();
        for (Repository r : repositoryRepo.findAll()) {
            addDomain(known, r.getTargetDomain());
            String url = r.getRepoUrl();
            if (url != null && url.startsWith("ssl://")) {
                addDomain(known, url.substring("ssl://".length()));
            }
        }
        for (ServerNode s : serverNodeRepo.findAll()) {
            addDomain(known, s.getDomain());
            addDomain(known, s.getHost());
        }
        return known;
    }

    private static void addDomain(Set<String> set, String raw) {
        if (raw == null || raw.isBlank()) return;
        set.add(cleanDomain(raw));
    }

    private static String cleanDomain(String raw) {
        String d = raw.trim().toLowerCase(Locale.ROOT);
        d = d.replaceFirst("^https?://", "");
        if (d.contains("/")) d = d.substring(0, d.indexOf('/'));
        if (d.contains(":") && d.lastIndexOf(':') > d.lastIndexOf(']')) {
            d = d.substring(0, d.lastIndexOf(':'));
        }
        return d;
    }
}
