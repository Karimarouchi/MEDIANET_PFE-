package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.ClientDto;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.User;
import com.medianet.repository.ServerDeploymentRepo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Availability of a project's sites, read from Uptime Kuma's public status page (installed next to Woodpecker in
 * vulnix-ci). Monitors are matched to the project by name: name a monitor after the domain (pfe.example.com).
 * Read-only: Vulnix never changes Uptime Kuma.
 */
@Service
public class UptimeService {

    private final ClientService clientService;
    private final ServerDeploymentRepo deploymentRepo;
    private final ObjectMapper json;
    private final String baseUrl;
    private final String slug;
    // HTTP/1.1: Uptime Kuma (Node) drops the cleartext HTTP/2 upgrade Java tries by default.
    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(3)).build();

    public UptimeService(ClientService clientService, ServerDeploymentRepo deploymentRepo, ObjectMapper json,
            @Value("${vulnix.uptime.url:}") String baseUrl,
            @Value("${vulnix.uptime.status-page:vulnix}") String slug) {
        this.clientService = clientService;
        this.deploymentRepo = deploymentRepo;
        this.json = json;
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        this.slug = slug;
    }

    public record Monitor(long id, String name, String status, Double uptime24h, String lastCheck, String message) {
    }

    public record ProjectUptime(boolean configured, boolean reachable, List<String> domains, List<Monitor> monitors) {
    }

    public ProjectUptime forProject(User user, Long clientId) {
        ClientDto client = clientService.getVisibleClient(user, clientId);
        Set<String> domains = new LinkedHashSet<>();
        if (client.getDomainName() != null && !client.getDomainName().isBlank()) domains.add(clean(client.getDomainName()));
        for (Long repoId : client.getRepositoryIds() == null ? List.<Long>of() : client.getRepositoryIds()) {
            for (ServerDeployment d : deploymentRepo.findByLinkedRepositoryId(repoId)) {
                if (d.getDomain() != null && !d.getDomain().isBlank()) domains.add(clean(d.getDomain()));
            }
        }
        if (baseUrl.isEmpty()) return new ProjectUptime(false, false, List.copyOf(domains), List.of());
        try {
            JsonNode page = get("/api/status-page/" + slug);
            JsonNode beats = get("/api/status-page/heartbeat/" + slug);
            return new ProjectUptime(true, true, List.copyOf(domains), match(page, beats, domains));
        } catch (Exception e) {
            return new ProjectUptime(true, false, List.copyOf(domains), List.of());
        }
    }

    /** Monitors of the status page whose name is one of the domains (or contains it). Package-private for tests. */
    static List<Monitor> match(JsonNode page, JsonNode beats, Set<String> domains) {
        List<Monitor> out = new ArrayList<>();
        for (JsonNode group : page.path("publicGroupList")) {
            for (JsonNode m : group.path("monitorList")) {
                String name = m.path("name").asText("");
                String n = clean(name);
                boolean ours = domains.stream().anyMatch(d -> n.equals(d) || n.contains(d) || d.contains(n) && !n.isEmpty());
                if (!ours) continue;
                long id = m.path("id").asLong();
                JsonNode list = beats.path("heartbeatList").path(String.valueOf(id));
                JsonNode last = list.isArray() && list.size() > 0 ? list.get(list.size() - 1) : null;
                JsonNode up = beats.path("uptimeList").path(id + "_24");
                out.add(new Monitor(id, name, status(last == null ? -1 : last.path("status").asInt(-1)),
                        up.isNumber() ? up.asDouble() : null,
                        last == null ? null : last.path("time").asText(null),
                        last == null ? null : last.path("msg").asText("")));
            }
        }
        return out;
    }

    static String status(int code) {
        return switch (code) {
            case 1 -> "UP";
            case 0 -> "DOWN";
            case 2 -> "PENDING";
            case 3 -> "MAINTENANCE";
            default -> "UNKNOWN";
        };
    }

    private static String clean(String s) {
        return s.trim().toLowerCase(Locale.ROOT).replaceFirst("^https?://", "").replaceAll("/.*$", "");
    }

    private JsonNode get(String path) throws Exception {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(Duration.ofSeconds(5)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) throw new IllegalStateException("Uptime Kuma " + r.statusCode());
        return json.readTree(r.body());
    }
}
