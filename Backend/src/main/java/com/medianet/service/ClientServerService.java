package com.medianet.service;

import com.medianet.entity.DeployRun;
import com.medianet.entity.Repository;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.ServerNode;
import com.medianet.entity.ServerNodeType;
import com.medianet.entity.SshAuthMethod;
import com.medianet.entity.User;
import com.medianet.entity.ClientServer;
import com.medianet.repository.ClientServerRepo;
import com.medianet.repository.DeployRunRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ServerDeploymentRepo;
import com.medianet.repository.ServerNodeRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Links servers (VPS) to a project; one project can run on several servers. */
@Service
public class ClientServerService {

    /** A repository actually deployed on a project server (front and back stay on their own machines). */
    public record ProjectDeploymentDto(
            Long id,
            String name,
            String deployPath,
            String domain,
            Long linkedRepositoryId,
            String repositoryName,
            String deployBranch,
            String deployStrategy,
            Boolean autoDeployEnabled,
            String lastStatus,
            String lastCommitSha) {
    }

    public record ProjectServerDto(Long id, String name, String host, String environment, String nodeType,
            boolean sshConfigured, List<ProjectDeploymentDto> deployments) {
    }

    private final ServerNodeRepo serverNodeRepo;
    private final ClientServerRepo clientServerRepo;
    private final ClientService clientService;
    private final ServerDeploymentRepo serverDeploymentRepo;
    private final RepositoryRepo repositoryRepo;
    private final DeployRunRepo deployRunRepo;

    public ClientServerService(ServerNodeRepo serverNodeRepo, ClientServerRepo clientServerRepo,
            ClientService clientService, ServerDeploymentRepo serverDeploymentRepo, RepositoryRepo repositoryRepo,
            DeployRunRepo deployRunRepo) {
        this.serverNodeRepo = serverNodeRepo;
        this.clientServerRepo = clientServerRepo;
        this.clientService = clientService;
        this.serverDeploymentRepo = serverDeploymentRepo;
        this.repositoryRepo = repositoryRepo;
        this.deployRunRepo = deployRunRepo;
    }

    @Transactional(readOnly = true)
    public List<ProjectServerDto> list(User user, Long clientId) {
        clientService.getVisibleClient(user, clientId); // 404/403 when the project is not accessible
        return mapServers(clientServerRepo.findServersByClientId(clientId));
    }

    @Transactional
    public List<ProjectServerDto> link(User user, Long clientId, Long serverId) {
        clientService.getVisibleClient(user, clientId);
        ServerNode server = serverNodeRepo.findById(serverId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Server not found"));
        if (!clientServerRepo.existsByClientIdAndServerNode_Id(clientId, serverId)) {
            clientServerRepo.save(ClientServer.builder().clientId(clientId).serverNode(server).build());
        }
        return list(user, clientId);
    }

    /**
     * Records a server (name, host, environment) without any SSH access: enough for the project's attack map.
     * Hardening scans need SSH credentials, which can be added later in Server Config.
     */
    @Transactional
    public List<ProjectServerDto> createLightweight(User user, Long clientId, String name, String host,
            String environment) {
        clientService.getVisibleClient(user, clientId);
        String n = name == null ? "" : name.trim();
        String h = host == null ? "" : host.trim();
        if (n.isEmpty() || n.length() > 180) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nom du serveur obligatoire (180 caractères max).");
        }
        if (h.isEmpty() || h.length() > 255 || h.contains("/") || h.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "L'hôte doit être une IP ou un nom de domaine.");
        }
        if (serverNodeRepo.existsByNameIgnoreCase(n)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Un serveur avec ce nom existe déjà.");
        }
        boolean prod = environment != null && environment.trim().toLowerCase(java.util.Locale.ROOT).startsWith("prod");
        ServerNode server = ServerNode.builder()
                .name(n)
                .host(h)
                .username("non-configure")
                .nodeType(prod ? ServerNodeType.PRODUCTION : ServerNodeType.STAGING)
                .environment(prod ? "PROD" : "TEST")
                .authMethod(SshAuthMethod.PASSWORD)
                .build();
        server = serverNodeRepo.save(server);
        clientServerRepo.save(ClientServer.builder().clientId(clientId).serverNode(server).build());
        return list(user, clientId);
    }

    @Transactional
    public void removeAllForClient(Long clientId) {
        clientServerRepo.deleteByClientId(clientId);
    }

    @Transactional
    public void unlink(User user, Long clientId, Long serverId) {
        clientService.getVisibleClient(user, clientId);
        clientServerRepo.deleteByClientIdAndServerNode_Id(clientId, serverId);
    }

    /**
     * Deployments that name a repository win. When a server has none, the legacy single-repo field on the
     * server itself is used, so older machines still show what they host.
     */
    private List<ProjectServerDto> mapServers(List<ServerNode> servers) {
        record Resolved(ServerNode server, List<ServerDeployment> deployments, Long legacyRepoId) {
        }
        List<Resolved> resolved = new ArrayList<>();
        Set<Long> repoIds = new LinkedHashSet<>();
        for (ServerNode server : servers) {
            List<ServerDeployment> linked = serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(server.getId()).stream()
                    .filter(d -> d.getLinkedRepositoryId() != null)
                    .toList();
            Long legacyRepoId = linked.isEmpty() ? server.getLinkedRepositoryId() : null;
            if (legacyRepoId != null) {
                repoIds.add(legacyRepoId);
            }
            linked.forEach(d -> repoIds.add(d.getLinkedRepositoryId()));
            resolved.add(new Resolved(server, linked, legacyRepoId));
        }
        Map<Long, String> names = repositoryNames(repoIds);
        return resolved.stream().map(r -> toDto(r.server, r.deployments, r.legacyRepoId, names)).toList();
    }

    private ProjectServerDto toDto(ServerNode server, List<ServerDeployment> deployments, Long legacyRepoId,
            Map<Long, String> names) {
        List<ProjectDeploymentDto> items = new ArrayList<>();
        if (!deployments.isEmpty()) {
            deployments.forEach(d -> items.add(toDeployment(d, names)));
        } else if (legacyRepoId != null) {
            items.add(legacyDeployment(server, names));
        }
        return new ProjectServerDto(server.getId(), server.getName(), server.getHost(), server.getEnvironment(),
                server.getNodeType() != null ? server.getNodeType().name() : null, sshConfigured(server), items);
    }

    private ProjectDeploymentDto toDeployment(ServerDeployment deployment, Map<Long, String> names) {
        DeployRun last = deployment.getId() == null ? null
                : deployRunRepo.findFirstByServerDeploymentIdOrderByStartedAtDesc(deployment.getId()).orElse(null);
        Long repoId = deployment.getLinkedRepositoryId();
        return new ProjectDeploymentDto(
                deployment.getId(),
                deployment.getName(),
                deployment.getDeployPath(),
                deployment.getDomain(),
                repoId,
                repoId != null ? names.get(repoId) : null,
                deployment.getDeployBranch(),
                deployment.getDeployStrategy() != null ? deployment.getDeployStrategy().name() : null,
                Boolean.TRUE.equals(deployment.getAutoDeployEnabled()),
                last != null && last.getStatus() != null ? last.getStatus().name() : null,
                last != null ? last.getCommitSha() : null);
    }

    private static ProjectDeploymentDto legacyDeployment(ServerNode server, Map<Long, String> names) {
        Long repoId = server.getLinkedRepositoryId();
        return new ProjectDeploymentDto(
                null,
                server.getName(),
                server.getDeployPath(),
                server.getDomain(),
                repoId,
                repoId != null ? names.get(repoId) : null,
                server.getDeployBranch(),
                server.getDeployStrategy() != null ? server.getDeployStrategy().name() : null,
                Boolean.TRUE.equals(server.getAutoDeployEnabled()),
                null,
                null);
    }

    private Map<Long, String> repositoryNames(Set<Long> repoIds) {
        Map<Long, String> names = new LinkedHashMap<>();
        if (repoIds.isEmpty()) {
            return names;
        }
        for (Repository repository : repositoryRepo.findAllById(repoIds)) {
            names.put(repository.getId(), repoShortName(repository.getRepoUrl()));
        }
        return names;
    }

    private static boolean sshConfigured(ServerNode server) {
        return (server.getEncryptedPassword() != null && !server.getEncryptedPassword().isBlank())
                || (server.getEncryptedPrivateKey() != null && !server.getEncryptedPrivateKey().isBlank());
    }

    private static String repoShortName(String url) {
        if (url == null || url.isBlank()) {
            return "Dépôt";
        }
        String cleaned = url.replaceAll("\\.git$", "");
        int slash = cleaned.lastIndexOf('/');
        return slash >= 0 && slash < cleaned.length() - 1 ? cleaned.substring(slash + 1) : cleaned;
    }
}
