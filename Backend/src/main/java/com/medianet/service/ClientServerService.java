package com.medianet.service;

import com.medianet.entity.ServerNode;
import com.medianet.entity.ServerNodeType;
import com.medianet.entity.SshAuthMethod;
import com.medianet.entity.User;
import com.medianet.entity.ClientServer;
import com.medianet.repository.ClientServerRepo;
import com.medianet.repository.ServerNodeRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/** Links servers (VPS) to a project; one project can run on several servers. */
@Service
public class ClientServerService {

    public record ProjectServerDto(Long id, String name, String host, String environment, String nodeType,
            boolean sshConfigured) {
    }

    private final ServerNodeRepo serverNodeRepo;
    private final ClientServerRepo clientServerRepo;
    private final ClientService clientService;

    public ClientServerService(ServerNodeRepo serverNodeRepo, ClientServerRepo clientServerRepo,
            ClientService clientService) {
        this.serverNodeRepo = serverNodeRepo;
        this.clientServerRepo = clientServerRepo;
        this.clientService = clientService;
    }

    @Transactional(readOnly = true)
    public List<ProjectServerDto> list(User user, Long clientId) {
        clientService.getVisibleClient(user, clientId); // 404/403 when the project is not accessible
        return clientServerRepo.findServersByClientId(clientId).stream().map(ClientServerService::toDto).toList();
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

    private static ProjectServerDto toDto(ServerNode s) {
        return new ProjectServerDto(s.getId(), s.getName(), s.getHost(), s.getEnvironment(),
                s.getNodeType() != null ? s.getNodeType().name() : null,
                (s.getEncryptedPassword() != null && !s.getEncryptedPassword().isBlank())
                        || (s.getEncryptedPrivateKey() != null && !s.getEncryptedPrivateKey().isBlank()));
    }
}
