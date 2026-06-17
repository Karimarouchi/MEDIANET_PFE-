package com.medianet.service;

import com.medianet.dto.*;
import com.medianet.entity.*;
import com.medianet.repository.ConfigSnapshotRepo;
import com.medianet.repository.ServerNodeRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ServerConfigService {

    private final ServerNodeRepo serverNodeRepo;
    private final ConfigSnapshotRepo configSnapshotRepo;
    private final TokenEncryptionService tokenEncryptionService;
    private final SshServerScanner sshServerScanner;

    public ServerConfigService(
            ServerNodeRepo serverNodeRepo,
            ConfigSnapshotRepo configSnapshotRepo,
            TokenEncryptionService tokenEncryptionService,
            SshServerScanner sshServerScanner) {
        this.serverNodeRepo = serverNodeRepo;
        this.configSnapshotRepo = configSnapshotRepo;
        this.tokenEncryptionService = tokenEncryptionService;
        this.sshServerScanner = sshServerScanner;
    }

    @Transactional(readOnly = true)
    public List<ServerNodeDto> getServers() {
        return serverNodeRepo.findAllByOrderByNodeTypeAscNameAsc().stream()
                .map(node -> toSummaryDto(node,
                        configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(node.getId()).orElse(null)))
                .toList();
    }

    @Transactional(readOnly = true)
    public ServerNodeDetailDto getServer(Long id) {
        ServerNode node = getServerNode(id);
        ConfigSnapshot latest = configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(id).orElse(null);
        return toDetailDto(node, latest);
    }

    @Transactional(readOnly = true)
    public ServerNodeDetailDto getLiveServer(Long id) {
        ServerNode node = getServerNode(id);
        ConfigSnapshot previous = configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(id).orElse(null);

        try {
            SshServerScanner.ScanReport report = sshServerScanner.scan(node);
            ConfigSnapshot liveSnapshot = buildSnapshot(node, report, previous);
            if (liveSnapshot.getCollectedAt() == null) {
                liveSnapshot.setCollectedAt(LocalDateTime.now());
            }
            return toDetailDto(node, liveSnapshot);
        } catch (Exception ex) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    buildConnectivityError(node, ex),
                    ex);
        }
    }

    @Transactional
    public ServerNodeDto createServer(ServerNodeRequest request) {
        if (serverNodeRepo.existsByNameIgnoreCase(request.name())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Un serveur avec ce nom existe déjà.");
        }

        validateRequest(request, true);

        ServerNode serverNode = new ServerNode();
        applyRequest(serverNode, request, true);

        try {
            sshServerScanner.verifyConnectivity(serverNode);
        } catch (Exception ex) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    buildConnectivityError(serverNode, ex),
                    ex);
        }

        ServerNode saved = serverNodeRepo.save(serverNode);
        return toSummaryDto(saved, null);
    }

    @Transactional
    public ServerNodeDto updateServer(Long id, ServerNodeRequest request) {
        ServerNode serverNode = getServerNode(id);
        String requestedName = safeTrim(request.name());
        if (!serverNode.getName().equalsIgnoreCase(requestedName)
                && serverNodeRepo.existsByNameIgnoreCase(requestedName)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Un serveur avec ce nom existe déjà.");
        }

        validateRequest(request, false);

        applyRequest(serverNode, request, false);

        try {
            sshServerScanner.verifyConnectivity(serverNode);
        } catch (Exception ex) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_GATEWAY,
                    buildConnectivityError(serverNode, ex),
                    ex);
        }

        ServerNode saved = serverNodeRepo.save(serverNode);
        ConfigSnapshot latest = configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(saved.getId())
                .orElse(null);
        return toSummaryDto(saved, latest);
    }

    @Transactional
    public void deleteServer(Long id) {
        ServerNode serverNode = getServerNode(id);
        try {
            serverNodeRepo.delete(serverNode);
            serverNodeRepo.flush();
        } catch (org.springframework.dao.DataIntegrityViolationException ex) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.CONFLICT,
                    "Ce serveur est utilisé par un ou plusieurs pipelines. "
                    + "Supprimez ou modifiez d'abord les pipelines qui le référencent, puis réessayez.");
        }
    }

    @Transactional
    public ServerNodeDetailDto scanServer(Long id) {
        ServerNode serverNode = getServerNode(id);
        ConfigSnapshot previous = configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(id).orElse(null);

        try {
            SshServerScanner.ScanReport report = sshServerScanner.scan(serverNode);
            ConfigSnapshot snapshot = buildSnapshot(serverNode, report, previous);
            configSnapshotRepo.save(snapshot);
            serverNode.setLastScannedAt(snapshot.getCollectedAt());
            serverNodeRepo.save(serverNode);
            return toDetailDto(serverNode, snapshot);
        } catch (Exception ex) {
            ConfigSnapshot failedSnapshot = buildFailureSnapshot(serverNode, ex);
            configSnapshotRepo.save(failedSnapshot);
            serverNode.setLastScannedAt(failedSnapshot.getCollectedAt());
            serverNodeRepo.save(serverNode);
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "SSH scan failed: " + ex.getMessage(), ex);
        }
    }

    @Transactional(readOnly = true)
    public List<HardeningFindingDto> getFindings(Long id) {
        ConfigSnapshot latest = configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Aucun snapshot serveur trouvé."));
        return latest.getFindings().stream()
                .sorted(this::compareSeverity)
                .map(this::toFindingDto)
                .toList();
    }

    private void applyRequest(ServerNode serverNode, ServerNodeRequest request, boolean creating) {
        ServerNodeType nodeType = parseNodeType(request.nodeType());
        SshAuthMethod authMethod = parseAuthMethod(request.authMethod());

        serverNode.setName(safeTrim(request.name()));
        serverNode.setHost(normalizeHost(request.host()));
        serverNode.setPort(request.port() != null ? request.port() : 22);
        serverNode.setUsername(normalizeUsername(request.username()));
        serverNode.setNodeType(nodeType);
        serverNode.setEnvironment(normalizeEnvironment(request.environment()));
        serverNode.setTemplateKey(normalizeTemplateKey(request.templateKey()));
        serverNode.setOwner(normalizeTextField(request.owner(), "owner", 180));
        serverNode.setClientName(normalizeTextField(request.clientName(), "clientName", 180));
        serverNode.setProjectName(normalizeTextField(request.projectName(), "projectName", 180));
        serverNode.setRunbookUrl(normalizeRunbookUrl(request.runbookUrl()));
        serverNode.setTags(serializeTags(request.tags()));
        serverNode.setNotes(normalizeTextField(request.notes(), "notes", 2500));
        serverNode.setAuthMethod(authMethod);
        serverNode.setDescription(normalizeTextField(request.description(), "description", 1200));
        serverNode.setEncryptedPassword(resolveEncryptedPassword(serverNode, request, authMethod, creating));
        serverNode.setEncryptedPrivateKey(resolveEncryptedPrivateKey(serverNode, request, authMethod, creating));
        serverNode.setEncryptedPrivateKeyPassphrase(
                resolveEncryptedPrivateKeyPassphrase(serverNode, request, authMethod, creating));
    }

    private void validateRequest(ServerNodeRequest request, boolean creating) {
        String host = normalizeHost(request.host());
        String username = normalizeUsername(request.username());

        if (request.port() == null || request.port() < 1 || request.port() > 65535) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le port SSH doit être compris entre 1 et 65535.");
        }

        if (host.contains("/")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "L'hôte SSH doit être une IP ou un hostname, pas une URL complète.");
        }

        if (username.length() < 2) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le nom d'utilisateur SSH doit contenir au moins 2 caractères.");
        }

        normalizeRunbookUrl(request.runbookUrl());
        normalizeTextField(request.owner(), "owner", 180);
        normalizeTextField(request.clientName(), "clientName", 180);
        normalizeTextField(request.projectName(), "projectName", 180);
        normalizeTextField(request.notes(), "notes", 2500);
        normalizeTextField(request.description(), "description", 1200);
        serializeTags(request.tags());

        if (creating && normalizeTemplateKey(request.templateKey()).equals("CUSTOM")
                && normalizeEnvironment(request.environment()).equals("LAB")
                && host.equalsIgnoreCase("localhost")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Précise un template pour localhost afin de distinguer Docker local, WSL ou une VM Linux.");
        }
    }

    private String resolveEncryptedPassword(
            ServerNode serverNode,
            ServerNodeRequest request,
            SshAuthMethod authMethod,
            boolean creating) {
        if (authMethod != SshAuthMethod.PASSWORD) {
            return null;
        }
        if (request.password() != null && !request.password().isBlank()) {
            return tokenEncryptionService.encrypt(request.password());
        }
        if (!creating && serverNode.getAuthMethod() == SshAuthMethod.PASSWORD
                && serverNode.getEncryptedPassword() != null) {
            return serverNode.getEncryptedPassword();
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Le mot de passe SSH est requis.");
    }

    private String resolveEncryptedPrivateKey(
            ServerNode serverNode,
            ServerNodeRequest request,
            SshAuthMethod authMethod,
            boolean creating) {
        if (authMethod != SshAuthMethod.PRIVATE_KEY) {
            return null;
        }
        if (request.privateKey() != null && !request.privateKey().isBlank()) {
            return tokenEncryptionService.encrypt(request.privateKey());
        }
        if (!creating && serverNode.getAuthMethod() == SshAuthMethod.PRIVATE_KEY
                && serverNode.getEncryptedPrivateKey() != null) {
            return serverNode.getEncryptedPrivateKey();
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La clé privée SSH est requise.");
    }

    private String resolveEncryptedPrivateKeyPassphrase(
            ServerNode serverNode,
            ServerNodeRequest request,
            SshAuthMethod authMethod,
            boolean creating) {
        if (authMethod != SshAuthMethod.PRIVATE_KEY) {
            return null;
        }
        if (request.privateKeyPassphrase() != null && !request.privateKeyPassphrase().isBlank()) {
            return tokenEncryptionService.encrypt(request.privateKeyPassphrase());
        }
        if (!creating && serverNode.getAuthMethod() == SshAuthMethod.PRIVATE_KEY) {
            return serverNode.getEncryptedPrivateKeyPassphrase();
        }
        return null;
    }

    private String buildConnectivityError(ServerNode serverNode, Exception ex) {
        String reason = ex.getMessage();
        if (reason == null || reason.isBlank()) {
            reason = "Le serveur ne répond pas au test SSH.";
        }

        String host = serverNode.getHost();
        int port = serverNode.getPort() != null ? serverNode.getPort() : 22;
        boolean isLocalhost = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host);
        boolean isConnectionRefused = reason.toLowerCase(java.util.Locale.ROOT).contains("connection refused");
        boolean isTimeout = reason.toLowerCase(java.util.Locale.ROOT).contains("timeout")
                || reason.toLowerCase(java.util.Locale.ROOT).contains("timed out");
        boolean isAuthFail = reason.toLowerCase(java.util.Locale.ROOT).contains("auth")
                || reason.toLowerCase(java.util.Locale.ROOT).contains("password")
                || reason.toLowerCase(java.util.Locale.ROOT).contains("publickey");

        String base = "Connexion SSH impossible pour " + host + ":" + port + ". ";

        if (isLocalhost && isConnectionRefused) {
            return base
                    + "Aucun serveur SSH n'ecoute sur le port " + port + " de cette machine. "
                    + "Solutions: "
                    + "(1) Activez OpenSSH Server: Parametres > Systeme > Fonctionnalites facultatives > Ajouter OpenSSH Server, puis 'net start sshd' en admin. "
                    + "(2) Si vous ciblez une VM (VirtualBox/VMware/WSL2), utilisez l'adresse IP reelle de la VM (ex: 192.168.56.x) plutot que localhost, "
                    + "ou configurez un transfert de port (NAT: hote 127.0.0.1:" + port + " -> invite 22). "
                    + "(3) Verifiez que le service SSH est demarre dans la VM: 'sudo systemctl start ssh'.";
        }

        if (isConnectionRefused) {
            return base
                    + "Port " + port + " refuse la connexion sur " + host + ". "
                    + "Verifiez que sshd est demarre (systemctl status ssh) et que le port est correct.";
        }

        if (isTimeout) {
            return base
                    + "La connexion a expire. Verifiez que l'hote " + host + " est accessible sur le reseau "
                    + "et que le pare-feu autorise le port " + port + ".";
        }

        if (isAuthFail) {
            return base
                    + "Echec d'authentification. Verifiez le nom d'utilisateur, le mot de passe ou la cle privee SSH.";
        }

        return base + "Verifier l'hote, le port et les identifiants SSH. Detail: " + reason;
    }

    private ServerNodeType parseNodeType(String raw) {
        try {
            return ServerNodeType.valueOf(normalizeEnum(raw));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Type de serveur invalide: " + raw);
        }
    }

    private SshAuthMethod parseAuthMethod(String raw) {
        try {
            return SshAuthMethod.valueOf(normalizeEnum(raw));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Méthode d'authentification invalide: " + raw);
        }
    }

    private String normalizeEnum(String raw) {
        return raw == null ? "" : raw.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }

    private String safeTrim(String value) {
        return value == null ? null : value.trim();
    }

    private String normalizeHost(String host) {
        String value = Objects.requireNonNullElse(safeTrim(host), "");
        if (value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "L'hôte SSH est requis.");
        }
        if (value.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "L'hôte SSH ne doit pas contenir d'espaces.");
        }
        return value;
    }

    private String normalizeUsername(String username) {
        String value = Objects.requireNonNullElse(safeTrim(username), "");
        if (value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "L'utilisateur SSH est requis.");
        }
        if (value.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "L'utilisateur SSH ne doit pas contenir d'espaces.");
        }
        return value;
    }

    private String normalizeTextField(String value, String fieldName, int maxLength) {
        String trimmed = safeTrim(value);
        if (trimmed == null || trimmed.isBlank()) {
            return null;
        }
        if (trimmed.length() > maxLength) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le champ " + fieldName + " dépasse la longueur maximale autorisée.");
        }
        return trimmed;
    }

    private String normalizeEnvironment(String value) {
        String trimmed = safeTrim(value);
        return trimmed == null || trimmed.isBlank() ? "LAB" : normalizeEnum(trimmed);
    }

    private String normalizeTemplateKey(String value) {
        String trimmed = safeTrim(value);
        return trimmed == null || trimmed.isBlank() ? "CUSTOM" : normalizeEnum(trimmed);
    }

    private String normalizeRunbookUrl(String value) {
        String trimmed = safeTrim(value);
        if (trimmed == null || trimmed.isBlank()) {
            return null;
        }
        if (!(trimmed.startsWith("http://") || trimmed.startsWith("https://"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le runbook doit être une URL http:// ou https:// valide.");
        }
        if (trimmed.length() > 1000) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le champ runbookUrl dépasse la longueur maximale autorisée.");
        }
        return trimmed;
    }

    private String serializeTags(List<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return null;
        }
        List<String> normalized = tags.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(tag -> !tag.isBlank())
                .map(tag -> tag.replace(',', ' '))
                .map(tag -> normalizeTextField(tag, "tags", 40))
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        if (normalized.size() > 12) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Limite atteinte: 12 tags maximum par serveur.");
        }
        return normalized.isEmpty() ? null : String.join(",", normalized);
    }

    private List<String> parseTags(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(tag -> !tag.isBlank())
                .distinct()
                .toList();
    }

    private ServerNode getServerNode(Long id) {
        return serverNodeRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Serveur introuvable."));
    }

    private ConfigSnapshot buildSnapshot(ServerNode serverNode, SshServerScanner.ScanReport report,
            ConfigSnapshot previous) {
        List<String> driftChanges = buildDriftChanges(previous, report);

        ConfigSnapshot snapshot = ConfigSnapshot.builder()
                .serverNode(serverNode)
                .status(ConfigSnapshotStatus.SUCCESS)
                .collectedAt(LocalDateTime.now())
                .hostname(report.hostname())
                .osName(report.osName())
                .kernelVersion(report.kernelVersion())
                .cpuSummary(report.cpuSummary())
                .memorySummary(report.memorySummary())
                .diskSummary(report.diskSummary())
                .firewallStatus(report.firewallStatus())
                .sshRootLogin(report.sshRootLogin())
                .dockerSummary(report.dockerSummary())
                .certificateSummary(report.certificateSummary())
                .journalExcerpt(report.journalExcerpt())
                .summary(buildSummary(report.findings()))
                .criticalCount(countSeverity(report.findings(), FindingSeverity.CRITICAL))
                .warningCount(countSeverity(report.findings(), FindingSeverity.WARNING))
                .infoCount(countSeverity(report.findings(), FindingSeverity.INFO))
                .driftSummary(String.join("\n", driftChanges))
                .rawHostname(report.rawOutputs().get("hostname"))
                .rawOsRelease(report.rawOutputs().get("osRelease"))
                .rawUname(report.rawOutputs().get("uname"))
                .rawCpu(report.rawOutputs().get("cpu"))
                .rawMemory(report.rawOutputs().get("memory"))
                .rawDisk(report.rawOutputs().get("disk"))
                .rawPorts(report.rawOutputs().get("ports"))
                .rawServices(firstNonBlank(report.rawOutputs().get("services"), "") + System.lineSeparator()
                        + firstNonBlank(report.rawOutputs().get("serviceUnitFiles"), ""))
                .rawFirewall(report.rawOutputs().get("firewall"))
                .rawSshd(report.rawOutputs().get("sshd"))
                .rawNginx(report.rawOutputs().get("nginx"))
                .rawDocker(report.rawOutputs().get("docker"))
                .rawJournal(report.rawOutputs().get("journal"))
                .build();

        for (SshServerScanner.PortExposureData port : report.ports()) {
            snapshot.getPortExposures().add(PortExposure.builder()
                    .configSnapshot(snapshot)
                    .portNumber(port.portNumber())
                    .protocol(port.protocol())
                    .bindAddress(port.bindAddress())
                    .processName(port.processName())
                    .serviceName(port.serviceName())
                    .exposureLevel(port.exposureLevel())
                    .state(port.state())
                    .build());
        }

        for (SshServerScanner.ServiceStatusData service : report.services()) {
            snapshot.getServices().add(ServiceStatus.builder()
                    .configSnapshot(snapshot)
                    .serviceName(service.serviceName())
                    .state(service.state())
                    .subState(service.subState())
                    .enabledStatus(service.enabledStatus())
                    .build());
        }

        for (SshServerScanner.FindingData finding : report.findings()) {
            snapshot.getFindings().add(HardeningFinding.builder()
                    .configSnapshot(snapshot)
                    .category(finding.category())
                    .severity(finding.severity())
                    .title(finding.title())
                    .description(finding.description())
                    .recommendation(finding.recommendation())
                    .detectedValue(finding.detectedValue())
                    .build());
        }

        return snapshot;
    }

    private ConfigSnapshot buildFailureSnapshot(ServerNode serverNode, Exception ex) {
        ConfigSnapshot snapshot = ConfigSnapshot.builder()
                .serverNode(serverNode)
                .status(ConfigSnapshotStatus.FAILED)
                .summary("Échec du scan SSH")
                .journalExcerpt(ex.getMessage())
                .criticalCount(1)
                .warningCount(0)
                .infoCount(0)
                .build();

        snapshot.getFindings().add(HardeningFinding.builder()
                .configSnapshot(snapshot)
                .category("SSH")
                .severity(FindingSeverity.CRITICAL)
                .title("Connexion SSH impossible")
                .description(ex.getMessage())
                .recommendation("Vérifier l'adresse, le port, le pare-feu et les identifiants SSH du serveur.")
                .detectedValue(serverNode.getHost() + ":" + serverNode.getPort())
                .build());
        return snapshot;
    }

    private List<String> buildDriftChanges(ConfigSnapshot previous, SshServerScanner.ScanReport current) {
        if (previous == null) {
            return List.of("Premier snapshot enregistré");
        }
        List<String> changes = new ArrayList<>();
        compare(changes, "Version du kernel", previous.getKernelVersion(), current.kernelVersion());
        compare(changes, "CPU / load average", previous.getCpuSummary(), current.cpuSummary());
        compare(changes, "Mémoire", previous.getMemorySummary(), current.memorySummary());
        compare(changes, "Disque racine", previous.getDiskSummary(), current.diskSummary());
        compare(changes, "Pare-feu", previous.getFirewallStatus(), current.firewallStatus());
        compare(changes, "SSH root login", previous.getSshRootLogin(), current.sshRootLogin());
        compare(changes, "Docker", previous.getDockerSummary(), current.dockerSummary());
        compare(changes, "Certificats", previous.getCertificateSummary(), current.certificateSummary());

        Set<String> previousPorts = previous.getPortExposures().stream()
                .map(port -> port.getPortNumber() + "/" + port.getProtocol() + "@" + port.getBindAddress())
                .collect(Collectors.toCollection(TreeSet::new));
        Set<String> currentPorts = current.ports().stream()
                .map(port -> port.portNumber() + "/" + port.protocol() + "@" + port.bindAddress())
                .collect(Collectors.toCollection(TreeSet::new));
        if (!previousPorts.equals(currentPorts)) {
            changes.add("Exposition réseau modifiée");
        }

        Set<String> previousServices = previous.getServices().stream()
                .map(service -> service.getServiceName() + ":" + service.getState() + ":" + service.getEnabledStatus())
                .collect(Collectors.toCollection(TreeSet::new));
        Set<String> currentServices = current.services().stream()
                .map(service -> service.serviceName() + ":" + service.state() + ":" + service.enabledStatus())
                .collect(Collectors.toCollection(TreeSet::new));
        if (!previousServices.equals(currentServices)) {
            changes.add("État des services modifié");
        }

        return changes.isEmpty() ? List.of("Aucune dérive détectée") : changes;
    }

    private void compare(List<String> changes, String label, String previousValue, String currentValue) {
        String prev = normalize(previousValue);
        String curr = normalize(currentValue);
        if (!Objects.equals(prev, curr)) {
            changes.add(label + " changé");
        }
    }

    private String normalize(String value) {
        return value == null ? null : value.trim();
    }

    private int countSeverity(List<SshServerScanner.FindingData> findings, FindingSeverity severity) {
        return (int) findings.stream().filter(finding -> finding.severity() == severity).count();
    }

    private String buildSummary(List<SshServerScanner.FindingData> findings) {
        if (findings.isEmpty()) {
            return "Aucune alerte critique détectée. La configuration semble stable.";
        }
        String headline = findings.get(0).title();
        return findings.size() + " finding(s) détecté(s) · priorité: " + headline;
    }

    private ServerNodeDto toSummaryDto(ServerNode node, ConfigSnapshot snapshot) {
        return new ServerNodeDto(
                node.getId(),
                node.getName(),
                node.getHost(),
                node.getPort(),
                node.getUsername(),
                node.getNodeType().name(),
                node.getEnvironment(),
                node.getTemplateKey(),
                node.getOwner(),
                node.getClientName(),
                node.getProjectName(),
                node.getRunbookUrl(),
                parseTags(node.getTags()),
                node.getNotes(),
                node.getDescription(),
                node.getLastScannedAt(),
                snapshot != null ? snapshot.getStatus().name() : null,
                snapshot != null ? snapshot.getCriticalCount() : 0,
                snapshot != null ? snapshot.getWarningCount() : 0,
                snapshot != null ? snapshot.getInfoCount() : 0,
                snapshot != null ? snapshot.getOsName() : null,
                snapshot != null ? snapshot.getKernelVersion() : null,
                snapshot != null ? snapshot.getFirewallStatus() : null);
    }

    private ServerNodeDetailDto toDetailDto(ServerNode node, ConfigSnapshot latest) {
        List<ConfigSnapshotDto> recentSnapshots = configSnapshotRepo
                .findTop5ByServerNodeIdOrderByCollectedAtDesc(node.getId())
                .stream()
                .map(this::toSnapshotDto)
                .toList();

        LocalDateTime effectiveLastScannedAt = latest != null && latest.getCollectedAt() != null
                ? latest.getCollectedAt()
                : node.getLastScannedAt();

        return new ServerNodeDetailDto(
                node.getId(),
                node.getName(),
                node.getHost(),
                node.getPort(),
                node.getUsername(),
                node.getNodeType().name(),
                node.getAuthMethod().name(),
                node.getEnvironment(),
                node.getTemplateKey(),
                node.getOwner(),
                node.getClientName(),
                node.getProjectName(),
                node.getRunbookUrl(),
                parseTags(node.getTags()),
                node.getNotes(),
                node.getDescription(),
                effectiveLastScannedAt,
                latest != null ? latest.getStatus().name() : null,
                latest != null ? latest.getHostname() : null,
                latest != null ? latest.getOsName() : null,
                latest != null ? latest.getKernelVersion() : null,
                latest != null ? latest.getCpuSummary() : null,
                latest != null ? latest.getMemorySummary() : null,
                latest != null ? latest.getDiskSummary() : null,
                latest != null ? latest.getFirewallStatus() : null,
                latest != null ? latest.getSshRootLogin() : null,
                latest != null ? latest.getDockerSummary() : null,
                latest != null ? latest.getCertificateSummary() : null,
                latest != null ? latest.getSummary() : null,
                latest != null ? latest.getJournalExcerpt() : null,
                latest != null ? latest.getCriticalCount() : 0,
                latest != null ? latest.getWarningCount() : 0,
                latest != null ? latest.getInfoCount() : 0,
                latest != null ? splitDrift(latest.getDriftSummary()) : List.of(),
                latest != null ? latest.getPortExposures().stream().map(this::toPortDto).toList() : List.of(),
                latest != null ? latest.getServices().stream().map(this::toServiceDto).toList() : List.of(),
                latest != null
                        ? latest.getFindings().stream().sorted(this::compareSeverity).map(this::toFindingDto).toList()
                        : List.of(),
                recentSnapshots);
    }

    private ConfigSnapshotDto toSnapshotDto(ConfigSnapshot snapshot) {
        return new ConfigSnapshotDto(
                snapshot.getId(),
                snapshot.getStatus().name(),
                snapshot.getCollectedAt(),
                snapshot.getSummary(),
                snapshot.getCriticalCount(),
                snapshot.getWarningCount(),
                snapshot.getInfoCount(),
                splitDrift(snapshot.getDriftSummary()));
    }

    private PortExposureDto toPortDto(PortExposure portExposure) {
        return new PortExposureDto(
                portExposure.getPortNumber(),
                portExposure.getProtocol(),
                portExposure.getBindAddress(),
                portExposure.getProcessName(),
                portExposure.getServiceName(),
                portExposure.getExposureLevel(),
                portExposure.getState());
    }

    private ServiceStatusDto toServiceDto(ServiceStatus serviceStatus) {
        return new ServiceStatusDto(
                serviceStatus.getServiceName(),
                serviceStatus.getState(),
                serviceStatus.getSubState(),
                serviceStatus.getEnabledStatus());
    }

    private HardeningFindingDto toFindingDto(HardeningFinding finding) {
        return new HardeningFindingDto(
                finding.getId(),
                finding.getCategory(),
                finding.getSeverity().name(),
                finding.getTitle(),
                finding.getDescription(),
                finding.getRecommendation(),
                finding.getDetectedValue());
    }

    private int compareSeverity(HardeningFinding left, HardeningFinding right) {
        return Integer.compare(severityRank(left.getSeverity()), severityRank(right.getSeverity()));
    }

    private int severityRank(FindingSeverity severity) {
        return switch (severity) {
            case CRITICAL -> 0;
            case WARNING -> 1;
            case INFO -> 2;
        };
    }

    private String firstNonBlank(String left, String right) {
        return (left != null && !left.isBlank()) ? left : right;
    }

    private List<String> splitDrift(String driftSummary) {
        if (driftSummary == null || driftSummary.isBlank()) {
            return List.of();
        }
        return Arrays.stream(driftSummary.split("\\R"))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .toList();
    }
}