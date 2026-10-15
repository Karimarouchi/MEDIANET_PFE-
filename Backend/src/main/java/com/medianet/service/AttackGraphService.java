package com.medianet.service;

import com.medianet.dto.AttackGraphEdgeDto;
import com.medianet.dto.AttackGraphNodeDto;
import com.medianet.dto.AttackGraphResponseDto;
import com.medianet.dto.AttackPathDto;
import com.medianet.dto.RepositoryDto;
import com.medianet.entity.CveEntry;
import com.medianet.entity.FindingSeverity;
import com.medianet.entity.HardeningFinding;
import com.medianet.entity.ScanResult;
import com.medianet.entity.SecretFinding;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.ServerNode;
import com.medianet.entity.User;
import com.medianet.repository.ClientServerRepo;
import com.medianet.repository.ConfigSnapshotRepo;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.SecretFindingRepo;
import com.medianet.repository.ServerDeploymentRepo;
import com.medianet.serverscan.ServerVulnReport;
import com.medianet.serverscan.ServerVulnService;
import com.medianet.repository.ServerNodeRepo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds an "attack graph" for the repos/servers visible to a user: which
 * exposed secrets or remotely-exploitable CVEs let an attacker reach a
 * production server, and which weak server hardening amplifies that access.
 *
 * The graph is derived on the fly from existing relational data (no graph
 * database, no new tables) — repos, scans, CVEs, secrets, servers and their
 * config snapshots are already linked via foreign keys, so a bounded
 * in-memory traversal is enough at this data scale.
 */
@Service
public class AttackGraphService {

    private static final Set<String> RCE_LIKE_CWE = Set.of(
            "CWE-78", "CWE-94", "CWE-502", "CWE-918", "CWE-89");

    private final ScanService scanService;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final SecretFindingRepo secretFindingRepo;
    private final ServerNodeRepo serverNodeRepo;
    private final ConfigSnapshotRepo configSnapshotRepo;
    private final ClientService clientService;
    private final ClientServerRepo clientServerRepo;
    private final ServerVulnService serverVulnService;
    private final ServerDeploymentRepo serverDeploymentRepo;

    public AttackGraphService(ScanService scanService, ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo, SecretFindingRepo secretFindingRepo,
            ServerNodeRepo serverNodeRepo, ConfigSnapshotRepo configSnapshotRepo, ClientService clientService,
            ClientServerRepo clientServerRepo, ServerVulnService serverVulnService,
            ServerDeploymentRepo serverDeploymentRepo) {
        this.serverVulnService = serverVulnService;
        this.serverDeploymentRepo = serverDeploymentRepo;
        this.clientService = clientService;
        this.clientServerRepo = clientServerRepo;
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.secretFindingRepo = secretFindingRepo;
        this.serverNodeRepo = serverNodeRepo;
        this.configSnapshotRepo = configSnapshotRepo;
    }

    @Transactional(readOnly = true)
    public AttackGraphResponseDto buildGraph(User currentUser, Long clientId) {
        Map<String, AttackGraphNodeDto> nodes = new LinkedHashMap<>();
        Map<String, AttackGraphEdgeDto> edges = new LinkedHashMap<>();
        collect(currentUser, clientId, nodes, edges);
        return new AttackGraphResponseDto(new ArrayList<>(nodes.values()), new ArrayList<>(edges.values()));
    }

    @Transactional(readOnly = true)
    public List<AttackPathDto> computeTopPaths(User currentUser, Long targetServerId, Long clientId) {
        Map<String, AttackGraphNodeDto> nodes = new LinkedHashMap<>();
        Map<String, AttackGraphEdgeDto> edges = new LinkedHashMap<>();
        collect(currentUser, clientId, nodes, edges);

        // Index edges by target for quick lookup of "what reaches this server".
        Map<String, List<AttackGraphEdgeDto>> incomingByTarget = new LinkedHashMap<>();
        for (AttackGraphEdgeDto e : edges.values()) {
            incomingByTarget.computeIfAbsent(e.target(), k -> new ArrayList<>()).add(e);
        }

        List<AttackPathDto> paths = new ArrayList<>();
        for (AttackGraphNodeDto server : nodes.values()) {
            if (!"SERVER".equals(server.type()) || !server.critical()) continue;
            if (targetServerId != null && !server.id().equals("server-" + targetServerId)) continue;

            List<AttackGraphEdgeDto> incoming = incomingByTarget.getOrDefault(server.id(), List.of());
            List<AttackGraphEdgeDto> entryEdges = incoming.stream()
                    .filter(e -> "SECRET_ACCESS".equals(e.kind()) || "RCE_CVE".equals(e.kind()))
                    .toList();
            List<AttackGraphNodeDto> amplifiers = incoming.stream()
                    .filter(e -> "HARDENING_AMPLIFIER".equals(e.kind()))
                    .map(e -> nodes.get(e.source()))
                    .filter(n -> n != null)
                    .toList();
            double hardeningBonus = Math.min(5.0, incoming.stream()
                    .filter(e -> "HARDENING_AMPLIFIER".equals(e.kind()))
                    .mapToDouble(AttackGraphEdgeDto::weight)
                    .sum() * 0.5);

            for (AttackGraphEdgeDto entryEdge : entryEdges) {
                AttackGraphNodeDto entry = nodes.get(entryEdge.source());
                if (entry == null) continue;
                double score = entryEdge.weight() * 0.85 + hardeningBonus;
                List<String> pathNodeIds = new ArrayList<>();
                pathNodeIds.add(entry.id());
                pathNodeIds.add(server.id());
                amplifiers.forEach(a -> pathNodeIds.add(a.id()));

                paths.add(new AttackPathDto(
                        "path-" + entry.id() + "-" + server.id(),
                        pathNodeIds,
                        Math.round(score * 100.0) / 100.0,
                        buildNarrative(entry, server, amplifiers)));
            }
        }

        return paths.stream()
                .sorted((a, b) -> Double.compare(b.score(), a.score()))
                .limit(10)
                .toList();
    }

    // ==================== GRAPH CONSTRUCTION ====================

    /**
     * With a clientId the graph is limited to that project: only repositories already deployed on one of its
     * servers, and each of those repositories reaches only the server that actually hosts it (a front repo does
     * not point at the back server). The global view still follows {@code linkedRepositoryId} on the server.
     */
    private void collect(User currentUser, Long clientId, Map<String, AttackGraphNodeDto> nodes,
            Map<String, AttackGraphEdgeDto> edges) {
        List<ServerNode> projectServers = List.of();
        Set<Long> projectRepoIds = null;
        Map<Long, List<ServerNode>> projectServersByRepo = Map.of();
        if (clientId != null) {
            // throws 404/403 when the project does not exist or is not accessible to this user
            List<Long> visibleRepoIds = clientService.getVisibleClient(currentUser, clientId).getRepositoryIds();
            projectRepoIds = new LinkedHashSet<>(visibleRepoIds != null ? visibleRepoIds : List.of());
            projectServers = clientServerRepo.findServersByClientId(clientId);
            projectServersByRepo = serversByLinkedRepo(projectServers, projectRepoIds);
        }
        final Set<Long> allowedRepoIds = projectRepoIds;
        List<RepositoryDto> repos = scanService.getAllRepositories(currentUser).stream()
                .filter(r -> r.getRepoUrl() == null || !r.getRepoUrl().startsWith("ssl://"))
                .filter(r -> allowedRepoIds == null || allowedRepoIds.contains(r.getId()))
                .toList();

        for (RepositoryDto repo : repos) {
            // Project view: a repo with no deployment on this project's servers stays off the map.
            // Global view: servers that declare this repo via linkedRepositoryId.
            List<ServerNode> servers = clientId != null
                    ? projectServersByRepo.getOrDefault(repo.getId(), List.of())
                    : serverNodeRepo.findByLinkedRepositoryId(repo.getId());
            if (clientId != null && servers.isEmpty()) {
                continue;
            }

            String repoNodeId = "repo-" + repo.getId();
            nodes.putIfAbsent(repoNodeId, new AttackGraphNodeDto(
                    repoNodeId, "REPO", repoShortName(repo.getRepoUrl()), null, false,
                    Map.of("repoUrl", repo.getRepoUrl() != null ? repo.getRepoUrl() : "")));

            for (ServerNode server : servers) {
                addServerNode(nodes, server);
                addEdge(edges, "DEPLOYS", repoNodeId, "server-" + server.getId(), 0, "déployé sur");
                addHardeningNodesAndEdges(nodes, edges, server);
            }

            if (servers.isEmpty()) continue; // no attack path possible without a deployment target

            ScanResult latest = scanResultRepo.findFirstByRepositoryIdAndStatusOrderByStartedAtDesc(
                    repo.getId(), ScanResult.ScanStatus.COMPLETED);
            if (latest == null) continue;

            for (SecretFinding secret : secretFindingRepo.findByScanResultId(latest.getId())) {
                if (isNotAnEntryPoint(secret)) continue; // placeholders, ids and test/doc values are not a way into a server
                String secretNodeId = "secret-" + secret.getId();
                nodes.putIfAbsent(secretNodeId, new AttackGraphNodeDto(
                        secretNodeId, "SECRET",
                        (secret.getRuleId() != null ? secret.getRuleId() : "secret") + " — " + shortFile(secret.getFile()),
                        "HIGH", false,
                        Map.of("file", secret.getFile() != null ? secret.getFile() : "",
                                "line", secret.getStartLine() != null ? secret.getStartLine() : 0,
                                "commit", secret.getCommit() != null ? secret.getCommit() : "")));
                addEdge(edges, "CONTAINS", repoNodeId, secretNodeId, 0, "contient");

                double weight = secretWeight(secret.getRuleId());
                for (ServerNode server : servers) {
                    addEdge(edges, "SECRET_ACCESS", secretNodeId, "server-" + server.getId(), weight,
                            "donne accès à");
                }
            }

            for (CveEntry cve : cveEntryRepo.findByScanResultId(latest.getId())) {
                Double weight = cveWeight(cve);
                if (weight == null) continue; // not RCE-like: no attack-path edge
                String cveNodeId = "cve-" + cve.getId();
                String label = (cve.getCanonicalId() != null && !cve.getCanonicalId().isBlank())
                        ? cve.getCanonicalId() : cve.getCveId();
                nodes.putIfAbsent(cveNodeId, new AttackGraphNodeDto(
                        cveNodeId, "CVE", label + " (" + cve.getPackageName() + ")",
                        cve.getSeverity(), false,
                        Map.of("packageName", cve.getPackageName() != null ? cve.getPackageName() : "",
                                "kevListed", cve.isKevListed(),
                                "exploitAvailable", cve.isExploitAvailable())));
                addEdge(edges, "CONTAINS", repoNodeId, cveNodeId, 0, "contient");

                for (ServerNode server : servers) {
                    addEdge(edges, "RCE_CVE", cveNodeId, "server-" + server.getId(), weight,
                            "compromet");
                }
            }
        }

        // project servers are always shown, even when no repo deploys to them yet
        for (ServerNode server : projectServers) {
            addServerNode(nodes, server);
            addHardeningNodesAndEdges(nodes, edges, server);
        }
        // server-side vulnerabilities (open ports) for every server shown on the map
        List<Long> serverIdsOnMap = nodes.values().stream()
                .filter(n -> "SERVER".equals(n.type()))
                .map(n -> Long.valueOf(n.id().substring("server-".length())))
                .distinct()
                .toList(); // copied first: entries are added to `nodes` below
        serverIdsOnMap.forEach(sid -> serverNodeRepo.findById(sid)
                        .ifPresent(sv -> addServerVulnerabilityEntries(nodes, edges, sv)));
    }

    /** Repo id to the project servers that actually deploy it. A repo absent from this map stays off the graph. */
    private Map<Long, List<ServerNode>> serversByLinkedRepo(List<ServerNode> projectServers, Set<Long> allowedRepoIds) {
        Map<Long, List<ServerNode>> byRepo = new LinkedHashMap<>();
        for (ServerNode server : projectServers) {
            for (Long repoId : linkedRepositoryIds(server)) {
                if (allowedRepoIds != null && !allowedRepoIds.contains(repoId)) {
                    continue;
                }
                List<ServerNode> hosts = byRepo.computeIfAbsent(repoId, k -> new ArrayList<>());
                if (hosts.stream().noneMatch(existing -> existing.getId().equals(server.getId()))) {
                    hosts.add(server);
                }
            }
        }
        return byRepo;
    }

    /**
     * Deployments that name a repository win. When the server has none, the legacy single-repo field is the link.
     */
    private List<Long> linkedRepositoryIds(ServerNode server) {
        List<Long> fromDeployments = serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(server.getId()).stream()
                .map(ServerDeployment::getLinkedRepositoryId)
                .filter(id -> id != null)
                .distinct()
                .toList();
        if (!fromDeployments.isEmpty()) {
            return fromDeployments;
        }
        return server.getLinkedRepositoryId() != null ? List.of(server.getLinkedRepositoryId()) : List.of();
    }

    /**
     * Vulnerabilities of the server itself become entry points: a CVE on a port reachable from outside that is
     * actively exploited (KEV), has a public exploit, or is critical, can compromise the server directly.
     */
    private void addServerVulnerabilityEntries(Map<String, AttackGraphNodeDto> nodes,
            Map<String, AttackGraphEdgeDto> edges, ServerNode server) {
        ServerVulnReport report = serverVulnService.latestReport(server.getId()).orElse(null);
        if (report == null || report.ports() == null) return;
        String serverId = "server-" + server.getId();
        int added = 0;
        for (ServerVulnReport.PortFinding port : report.ports()) {
            if (!"EXTERNAL".equals(port.exposure())) continue;
            for (ServerVulnReport.VulnRef v : port.vulns()) {
                boolean critical = "CRITICAL".equals(v.severity());
                if (!(v.kev() || v.exploit() || critical)) continue;
                if (added >= 8) return; // keep the map readable
                String nodeId = "cve-srv" + server.getId() + "-" + v.id() + "-" + port.port();
                String service = (port.product() != null && !port.product().isBlank()) ? port.product() : port.service();
                nodes.putIfAbsent(nodeId, new AttackGraphNodeDto(
                        nodeId, "CVE", v.id() + " (" + service + " — port " + port.port() + ")", v.severity(), false,
                        Map.of("port", port.port(), "kevListed", v.kev(), "exploitAvailable", v.exploit())));
                double weight = 6 + (v.kev() ? 3 : 0) + (v.exploit() ? 2 : 0) + (critical ? 1 : 0);
                addEdge(edges, "RCE_CVE", nodeId, serverId, weight, "compromet");
                added++;
            }
        }
    }

    /** The analyst's call wins; otherwise the triage model's verdict. Untriaged secrets stay on the map. */
    static boolean isNotAnEntryPoint(SecretFinding secret) {
        if ("REAL".equals(secret.getAnalystVerdict())) return false;
        if ("FALSE_POSITIVE".equals(secret.getAnalystVerdict())) return true;
        if ("LIKELY_FALSE_POSITIVE".equals(secret.getMlVerdict())) return true;
        return "TEST_OR_DOC".equals(secret.getMlScope()); // example / test credentials rarely open a production server
    }

    private void addServerNode(Map<String, AttackGraphNodeDto> nodes, ServerNode server) {
        String id = "server-" + server.getId();
        boolean critical = server.getEnvironment() != null
                && server.getEnvironment().toLowerCase(Locale.ROOT).contains("prod");
        nodes.putIfAbsent(id, new AttackGraphNodeDto(
                id, "SERVER", server.getName(), null, critical,
                Map.of("host", server.getHost() != null ? server.getHost() : "",
                        "environment", server.getEnvironment() != null ? server.getEnvironment() : "")));
    }

    private void addHardeningNodesAndEdges(Map<String, AttackGraphNodeDto> nodes,
            Map<String, AttackGraphEdgeDto> edges, ServerNode server) {
        configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(server.getId())
                .ifPresent(snapshot -> {
                    for (HardeningFinding finding : snapshot.getFindings()) {
                        if (finding.getSeverity() == FindingSeverity.INFO) continue; // skip low-signal noise
                        String id = "hardening-" + finding.getId();
                        nodes.putIfAbsent(id, new AttackGraphNodeDto(
                                id, "HARDENING", finding.getTitle(), finding.getSeverity().name(), false,
                                Map.of("category", finding.getCategory() != null ? finding.getCategory() : "")));
                        addEdge(edges, "HARDENING_AMPLIFIER", id, "server-" + server.getId(),
                                hardeningWeight(finding.getSeverity()), "facilite l'escalade sur");
                    }
                });
    }

    private static void addEdge(Map<String, AttackGraphEdgeDto> edges, String kind,
            String source, String target, double weight, String label) {
        String id = kind + ":" + source + "->" + target;
        edges.putIfAbsent(id, new AttackGraphEdgeDto(id, source, target, kind, weight, label));
    }

    // ==================== SCORING RULES ====================

    private static double secretWeight(String ruleId) {
        if (ruleId == null) return 4;
        String r = ruleId.toLowerCase(Locale.ROOT);
        if (r.contains("private-key") || r.contains("ssh")) return 10;
        if (r.contains("aws") || r.contains("gcp") || r.contains("azure") || r.contains("google-cloud")) return 9;
        if (r.contains("database") || r.contains("postgres") || r.contains("mysql")
                || r.contains("mongodb") || r.contains("redis")) return 8;
        if (r.contains("docker") || r.contains("registry")) return 7;
        return 4;
    }

    /** Returns null when the CVE has no plausible remote-code-execution impact (no attack-path edge). */
    private static Double cveWeight(CveEntry cve) {
        String cwe = cve.getCweId();
        if (cwe == null || !RCE_LIKE_CWE.contains(cwe.toUpperCase(Locale.ROOT))) return null;
        double w = 6;
        if (cve.isKevListed()) w += 3;
        if (cve.isExploitAvailable()) w += 2;
        String sev = cve.getSeverity();
        if ("CRITICAL".equalsIgnoreCase(sev)) w += 1;
        else if ("HIGH".equalsIgnoreCase(sev)) w += 0.5;
        return w;
    }

    private static double hardeningWeight(FindingSeverity severity) {
        return switch (severity) {
            case CRITICAL -> 8;
            case WARNING -> 4;
            case INFO -> 1;
        };
    }

    // ==================== NARRATIVE ====================

    private static String buildNarrative(AttackGraphNodeDto entry, AttackGraphNodeDto server,
            List<AttackGraphNodeDto> amplifiers) {
        StringBuilder sb = new StringBuilder();
        if ("SECRET".equals(entry.type())) {
            sb.append("Secret exposé (").append(entry.label())
                    .append(") donnant accès au serveur ").append(server.label());
        } else {
            sb.append("CVE exploitable à distance ").append(entry.label())
                    .append(" permettant de compromettre le serveur ").append(server.label());
        }
        if (server.critical()) {
            sb.append(" — actif de PRODUCTION.");
        } else {
            sb.append(".");
        }
        if (!amplifiers.isEmpty()) {
            sb.append(" Facteurs aggravants : ")
                    .append(amplifiers.stream().map(AttackGraphNodeDto::label).collect(Collectors.joining(", ")))
                    .append(".");
        }
        return sb.toString();
    }

    private static String repoShortName(String url) {
        if (url == null || url.isBlank()) return "Dépôt";
        String cleaned = url.replaceAll("\\.git$", "");
        String[] parts = cleaned.split("/");
        return parts.length > 0 ? parts[parts.length - 1] : cleaned;
    }

    private static String shortFile(String path) {
        if (path == null || path.isBlank()) return "?";
        String[] parts = path.split("/");
        return parts.length > 0 ? parts[parts.length - 1] : path;
    }
}
