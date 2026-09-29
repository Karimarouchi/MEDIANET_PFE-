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
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

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

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();
    private final RepositoryRepo repositoryRepo;
    private final ServerNodeRepo serverNodeRepo;

    public CertTransparencyService(RepositoryRepo repositoryRepo, ServerNodeRepo serverNodeRepo) {
        this.repositoryRepo = repositoryRepo;
        this.serverNodeRepo = serverNodeRepo;
    }

    public CertTransparencyResultDto lookup(String rawDomain) {
        String domain = cleanDomain(rawDomain);
        Set<String> known = knownAssetDomains();
        Map<String, CertTransparencyEntryDto> bySubdomain = new LinkedHashMap<>();

        try {
            String url = "https://crt.sh/?q=" + URLEncoder.encode("%." + domain, StandardCharsets.UTF_8) + "&output=json";
            String body = restTemplate.getForObject(url, String.class);
            JsonNode root = (body != null && !body.isBlank()) ? mapper.readTree(body) : null;
            if (root != null && root.isArray()) {
                for (JsonNode item : root) {
                    String issuer = item.path("issuer_name").asText("");
                    String notBefore = item.path("not_before").asText("");
                    String notAfter = item.path("not_after").asText("");
                    String nameValue = item.path("name_value").asText("");
                    for (String rawSub : nameValue.split("\\n")) {
                        String sub = rawSub.trim().toLowerCase(Locale.ROOT);
                        if (sub.isEmpty() || sub.startsWith("*.") || !sub.endsWith(domain)) continue;
                        bySubdomain.putIfAbsent(sub,
                                new CertTransparencyEntryDto(sub, issuer, notBefore, notAfter, known.contains(sub)));
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Certificate Transparency lookup failed for {}: {}", domain, e.getMessage());
        }

        List<CertTransparencyEntryDto> entries = new ArrayList<>(bySubdomain.values());
        entries.sort(Comparator.comparing(CertTransparencyEntryDto::subdomain));
        long unknown = entries.stream().filter(e -> !e.knownAsset()).count();
        return new CertTransparencyResultDto(domain, entries, entries.size(), (int) unknown);
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
