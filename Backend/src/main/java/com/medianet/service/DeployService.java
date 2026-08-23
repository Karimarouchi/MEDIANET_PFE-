package com.medianet.service;

import com.medianet.dto.CiVerdictDto;
import com.medianet.dto.CiVerdictFindingDto;
import com.medianet.dto.DeployRunDto;
import com.medianet.dto.DeploySettingsRequest;
import com.medianet.dto.ServerDeploymentDto;
import com.medianet.entity.CveEntry;
import com.medianet.entity.DeployStrategy;
import com.medianet.entity.DeployRun;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.ServerNode;
import com.medianet.event.ScanFinishedEvent;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.DeployRunRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.ServerDeploymentRepo;
import com.medianet.repository.ServerNodeRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class DeployService {

    private static final Logger log = LoggerFactory.getLogger(DeployService.class);
    private static final Duration DEPLOY_TIMEOUT = Duration.ofMinutes(10);

    private final ServerNodeRepo serverNodeRepo;
    private final ServerDeploymentRepo serverDeploymentRepo;
    private final DeployRunRepo deployRunRepo;
    private final RepositoryRepo repositoryRepo;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final CiScanService ciScanService;
    private final SshCommandExecutor sshCommandExecutor;
    private final TransactionTemplate transactionTemplate;

    public DeployService(
            ServerNodeRepo serverNodeRepo,
            ServerDeploymentRepo serverDeploymentRepo,
            DeployRunRepo deployRunRepo,
            RepositoryRepo repositoryRepo,
            ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo,
            CiScanService ciScanService,
            SshCommandExecutor sshCommandExecutor,
            PlatformTransactionManager transactionManager) {
        this.serverNodeRepo = serverNodeRepo;
        this.serverDeploymentRepo = serverDeploymentRepo;
        this.deployRunRepo = deployRunRepo;
        this.repositoryRepo = repositoryRepo;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.ciScanService = ciScanService;
        this.sshCommandExecutor = sshCommandExecutor;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Transactional
    public List<ServerDeploymentDto> listDeployments(Long serverId) {
        ServerNode node = requireServer(serverId);
        migrateLegacyIfNeeded(node);
        return serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(serverId).stream()
                .map(this::toDeploymentDto)
                .toList();
    }

    @Transactional
    public ServerDeploymentDto createDeployment(Long serverId, DeploySettingsRequest request) {
        ServerNode node = requireServer(serverId);
        migrateLegacyIfNeeded(node);
        ServerDeployment deployment = ServerDeployment.builder()
                .serverNode(node)
                .name(normalizeName(request.name(), request.domain(), request.deployPath()))
                .deployPath(DeployFieldValidator.normalizePath(request.deployPath(), false))
                .domain(DeployFieldValidator.normalizeDomain(request.domain()))
                .linkedRepositoryId(resolveRepositoryId(request.linkedRepositoryId()))
                .deployBranch(DeployFieldValidator.normalizeBranch(request.deployBranch()))
                .deployStrategy(DeployFieldValidator.normalizeStrategy(request.deployStrategy()))
                .autoDeployEnabled(false)
                .build();
        ServerDeployment saved = serverDeploymentRepo.save(deployment);
        syncNodeSummary(node);
        return toDeploymentDto(saved);
    }

    @Transactional
    public ServerDeploymentDto updateDeployment(Long serverId, Long deploymentId, DeploySettingsRequest request) {
        ServerDeployment deployment = requireDeployment(serverId, deploymentId);
        applySettings(deployment, request);
        ServerDeployment saved = serverDeploymentRepo.save(deployment);
        syncNodeSummary(saved.getServerNode());
        return toDeploymentDto(saved);
    }

    @Transactional
    public void deleteDeployment(Long serverId, Long deploymentId) {
        ServerDeployment deployment = requireDeployment(serverId, deploymentId);
        ServerNode node = deployment.getServerNode();
        deployRunRepo.detachFromDeployment(deploymentId);
        serverDeploymentRepo.delete(deployment);
        syncNodeSummary(node);
    }

    @Transactional
    public ServerDeploymentDto setAutoDeploy(Long serverId, Long deploymentId, boolean enabled) {
        ServerDeployment deployment = requireDeployment(serverId, deploymentId);
        if (enabled) {
            if (deployment.getDeployPath() == null || deployment.getDeployPath().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Le chemin de déploiement est requis avant d'activer l'auto-deploy.");
            }
            if (deployment.getLinkedRepositoryId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Liez un dépôt Git avant d'activer l'auto-deploy.");
            }
        }
        deployment.setAutoDeployEnabled(enabled);
        ServerDeployment saved = serverDeploymentRepo.save(deployment);
        syncNodeSummary(saved.getServerNode());
        return toDeploymentDto(saved);
    }

    @Transactional(readOnly = true)
    public List<DeployRunDto> listRuns(Long serverId, Long deploymentId) {
        requireDeployment(serverId, deploymentId);
        return deployRunRepo.findTop20ByServerDeploymentIdOrderByStartedAtDesc(deploymentId).stream()
                .map(run -> toDto(run, List.of()))
                .toList();
    }

    public DeployRunDto deploy(Long serverId, Long deploymentId, boolean force, DeployRun.TriggerType triggerType) {
        PreparedDeploy prepared = transactionTemplate.execute(
                status -> prepareDeploy(serverId, deploymentId, force, triggerType));
        if (prepared == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Impossible de préparer le déploiement.");
        }
        if (prepared.blocked()) {
            return prepared.dto();
        }
        return executeRemote(prepared.runId(), prepared.serverId(), prepared.deploymentId(), prepared.blocking());
    }

    @Deprecated
    @Transactional
    public ServerNode updateDeploySettings(Long serverId, DeploySettingsRequest request) {
        ServerNode node = requireServer(serverId);
        migrateLegacyIfNeeded(node);
        List<ServerDeployment> deployments = serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(serverId);
        if (deployments.isEmpty()) {
            createDeployment(serverId, request);
        } else {
            updateDeployment(serverId, deployments.get(0).getId(), request);
        }
        return requireServer(serverId);
    }

    @Deprecated
    @Transactional
    public ServerNode setAutoDeploy(Long serverId, boolean enabled) {
        ServerNode node = requireServer(serverId);
        migrateLegacyIfNeeded(node);
        List<ServerDeployment> deployments = serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(serverId);
        if (deployments.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ajoutez d'abord un déploiement.");
        }
        setAutoDeploy(serverId, deployments.get(0).getId(), enabled);
        return requireServer(serverId);
    }

    @Deprecated
    public DeployRunDto deploy(Long serverId, boolean force, DeployRun.TriggerType triggerType) {
        List<ServerDeployment> deployments = transactionTemplate.execute(status -> {
            ServerNode node = requireServer(serverId);
            migrateLegacyIfNeeded(node);
            return serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(serverId);
        });
        if (deployments == null || deployments.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ajoutez d'abord un déploiement.");
        }
        return deploy(serverId, deployments.get(0).getId(), force, triggerType);
    }

    @Deprecated
    @Transactional(readOnly = true)
    public List<DeployRunDto> listDeploys(Long serverId) {
        requireServer(serverId);
        return deployRunRepo.findTop20ByServerNodeIdOrderByStartedAtDesc(serverId).stream()
                .map(run -> toDto(run, List.of()))
                .toList();
    }

    private PreparedDeploy prepareDeploy(Long serverId, Long deploymentId, boolean force, DeployRun.TriggerType triggerType) {
        ServerDeployment deployment = requireDeployment(serverId, deploymentId);
        ServerNode node = deployment.getServerNode();
        DeployFieldValidator.normalizePath(deployment.getDeployPath(), true);
        DeployFieldValidator.normalizeBranch(deployment.getDeployBranch());
        if (deployment.getLinkedRepositoryId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Liez un dépôt Git pour connaître le verdict CRITICAL / HIGH.");
        }

        LatestGate gate = latestGate(deployment.getLinkedRepositoryId());
        DeployRun.TriggerType effectiveTrigger = force ? DeployRun.TriggerType.FORCE : triggerType;
        boolean blocked = hasBlockingVulns(gate.verdict);

        DeployRun run = DeployRun.builder()
                .serverNode(node)
                .serverDeployment(deployment)
                .commitSha(gate.verdict.commitSha())
                .verdict(gate.verdict.reason())
                .status(blocked && !force ? DeployRun.Status.BLOCKED : DeployRun.Status.RUNNING)
                .triggerType(effectiveTrigger)
                .log(blocked && !force
                        ? buildBlockedLog(gate.verdict)
                        : "Déploiement lancé (" + effectiveTrigger.name() + ").\n")
                .startedAt(LocalDateTime.now())
                .finishedAt(blocked && !force ? LocalDateTime.now() : null)
                .build();
        run = deployRunRepo.saveAndFlush(run);
        return new PreparedDeploy(
                run.getId(),
                node.getId(),
                deployment.getId(),
                blocked && !force,
                toDto(run, gate.verdict.blocking()),
                gate.verdict.blocking());
    }

    private DeployRunDto executeRemote(
            Long runId,
            Long serverId,
            Long deploymentId,
            List<CiVerdictFindingDto> blocking) {
        ServerDeployment deployment = transactionTemplate.execute(status -> {
            ServerDeployment loaded = requireDeployment(serverId, deploymentId);
            loaded.getServerNode().getEncryptedPassword();
            loaded.getServerNode().getEncryptedPrivateKey();
            loaded.getServerNode().getEncryptedPrivateKeyPassphrase();
            return loaded;
        });
        if (deployment == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable.");
        }
        ServerNode node = deployment.getServerNode();
        String path = DeployFieldValidator.normalizePath(deployment.getDeployPath(), true);
        String branch = DeployFieldValidator.normalizeBranch(deployment.getDeployBranch());
        String command = buildDeployCommand(path, branch, deployment.getDeployStrategy());
        DeployRun started = transactionTemplate.execute(status -> deployRunRepo.findById(runId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable.")));
        StringBuilder liveLog = new StringBuilder(started != null && started.getLog() != null ? started.getLog() : "");
        if (blocking != null && !blocking.isEmpty()) {
            liveLog.append("Continuer quand même : déploiement forcé malgré CRITICAL / HIGH.\n");
        }
        liveLog.append("Cible : ").append(node.getUsername()).append('@').append(node.getHost())
                .append(':').append(node.getPort()).append('\n');
        liveLog.append("Commande : ").append(command).append('\n');

        DeployRun.Status finalStatus = DeployRun.Status.FAILED;
        try {
            SshCommandExecutor.CommandResult result = sshCommandExecutor.executeStreaming(
                    node,
                    command,
                    DEPLOY_TIMEOUT,
                    line -> liveLog.append(line).append('\n'));
            int exit = result.exitCode();
            if (exit == 0) {
                finalStatus = DeployRun.Status.SUCCESS;
                liveLog.append("Déploiement terminé (exit 0).\n");
            } else {
                liveLog.append("Échec SSH / commande (exit ").append(exit).append(").\n");
                if (exit == -1) {
                    liveLog.append("Le canal SSH s'est fermé sans code de sortie (session coupée ou timeout).\n");
                }
            }
        } catch (Exception e) {
            liveLog.append("Erreur : ").append(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()).append('\n');
            log.warn("[Deploy] SSH failed server={} deployment={} : {}", serverId, deploymentId, e.getMessage());
        }

        DeployRun.Status statusToSave = finalStatus;
        String logToSave = trimLog(liveLog.toString());
        DeployRunDto saved = transactionTemplate.execute(status -> {
            DeployRun run = deployRunRepo.findById(runId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
            run.setStatus(statusToSave);
            run.setLog(logToSave);
            run.setFinishedAt(LocalDateTime.now());
            return toDto(deployRunRepo.save(run), blocking);
        });
        if (saved == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Impossible d'enregistrer le déploiement.");
        }
        return saved;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void onScanFinished(ScanFinishedEvent event) {
        if (event == null || event.scanId() == null) {
            return;
        }
        autoDeployAfterScan(event.scanId());
    }

    public void autoDeployAfterScan(Long scanId) {
        ScanResult scan = scanResultRepo.findByIdWithRepository(scanId).orElse(null);
        if (scan == null || scan.getStatus() != ScanStatus.COMPLETED || scan.getRepository() == null) {
            return;
        }
        Long repoId = scan.getRepository().getId();
        serverNodeRepo.findByLinkedRepositoryId(repoId).forEach(this::migrateLegacyIfNeeded);
        List<ServerDeployment> targets = serverDeploymentRepo.findByLinkedRepositoryIdAndAutoDeployEnabledTrue(repoId);
        if (targets.isEmpty()) {
            return;
        }
        LatestGate gate = latestGate(repoId);
        for (ServerDeployment deployment : targets) {
            try {
                Long serverId = deployment.getServerNode().getId();
                if (hasBlockingVulns(gate.verdict)) {
                    DeployRun blocked = DeployRun.builder()
                            .serverNode(deployment.getServerNode())
                            .serverDeployment(deployment)
                            .commitSha(gate.verdict.commitSha())
                            .verdict(gate.verdict.reason())
                            .status(DeployRun.Status.BLOCKED)
                            .triggerType(DeployRun.TriggerType.AUTO)
                            .log(buildBlockedLog(gate.verdict))
                            .startedAt(LocalDateTime.now())
                            .finishedAt(LocalDateTime.now())
                            .build();
                    deployRunRepo.save(blocked);
                    continue;
                }
                deploy(serverId, deployment.getId(), false, DeployRun.TriggerType.AUTO);
            } catch (Exception e) {
                log.warn("[Deploy] Auto-deploy skipped deployment={} : {}", deployment.getId(), e.getMessage());
            }
        }
    }

    private void migrateLegacyIfNeeded(ServerNode node) {
        if (serverDeploymentRepo.countByServerNodeId(node.getId()) > 0) {
            return;
        }
        boolean hasLegacy = (node.getDeployPath() != null && !node.getDeployPath().isBlank())
                || (node.getDomain() != null && !node.getDomain().isBlank())
                || node.getLinkedRepositoryId() != null;
        if (!hasLegacy) {
            return;
        }
        ServerDeployment migrated = ServerDeployment.builder()
                .serverNode(node)
                .name(normalizeName(node.getProjectName(), node.getDomain(), node.getDeployPath()))
                .deployPath(node.getDeployPath())
                .domain(node.getDomain())
                .linkedRepositoryId(node.getLinkedRepositoryId())
                .deployBranch(node.getDeployBranch() != null ? node.getDeployBranch() : "main")
                .deployStrategy(node.getDeployStrategy() != null ? node.getDeployStrategy() : DeployStrategy.DOCKER_COMPOSE)
                .autoDeployEnabled(Boolean.TRUE.equals(node.getAutoDeployEnabled()))
                .build();
        serverDeploymentRepo.save(migrated);
    }

    private void applySettings(ServerDeployment deployment, DeploySettingsRequest request) {
        if (request.name() != null) {
            deployment.setName(normalizeName(request.name(), request.domain(), request.deployPath()));
        }
        deployment.setDeployPath(DeployFieldValidator.normalizePath(request.deployPath(), false));
        deployment.setDomain(DeployFieldValidator.normalizeDomain(request.domain()));
        deployment.setLinkedRepositoryId(resolveRepositoryId(request.linkedRepositoryId()));
        deployment.setDeployBranch(DeployFieldValidator.normalizeBranch(request.deployBranch()));
        deployment.setDeployStrategy(DeployFieldValidator.normalizeStrategy(request.deployStrategy()));
    }

    private void syncNodeSummary(ServerNode node) {
        List<ServerDeployment> deployments = serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(node.getId());
        if (deployments.isEmpty()) {
            node.setDeployPath(null);
            node.setDomain(null);
            node.setLinkedRepositoryId(null);
            node.setAutoDeployEnabled(false);
            serverNodeRepo.save(node);
            return;
        }
        ServerDeployment first = deployments.get(0);
        node.setDeployPath(first.getDeployPath());
        node.setDomain(first.getDomain());
        node.setLinkedRepositoryId(first.getLinkedRepositoryId());
        node.setDeployBranch(first.getDeployBranch());
        node.setDeployStrategy(first.getDeployStrategy());
        node.setAutoDeployEnabled(deployments.stream().anyMatch(item -> Boolean.TRUE.equals(item.getAutoDeployEnabled())));
        serverNodeRepo.save(node);
    }

    private LatestGate latestGate(Long repositoryId) {
        ScanResult scan = scanResultRepo.findFirstByRepositoryIdAndStatusOrderByStartedAtDesc(
                repositoryId, ScanStatus.COMPLETED);
        if (scan == null) {
            return new LatestGate(new CiVerdictDto(
                    "PASS",
                    "NO_COMPLETED_SCAN",
                    null,
                    null,
                    repositoryId,
                    List.of(),
                    List.of(),
                    null));
        }
        List<CveEntry> cves = cveEntryRepo.findByScanResultId(scan.getId());
        return new LatestGate(ciScanService.evaluate(scan, repositoryId, scan.getCommitSha(), cves));
    }

    private boolean hasBlockingVulns(CiVerdictDto verdict) {
        return verdict != null && verdict.blocking() != null && !verdict.blocking().isEmpty();
    }

    private String buildDeployCommand(String path, String branch, DeployStrategy strategy) {
        String pull = String.join(" && ",
                "export GIT_TERMINAL_PROMPT=0",
                "cd " + shellQuote(path),
                "pwd",
                "git fetch origin",
                "git checkout " + shellQuote(branch),
                "git pull --ff-only origin " + shellQuote(branch));
        if (strategy == DeployStrategy.STATIC_NGINX) {
            return pull + " && ((nginx -t && systemctl reload nginx)"
                    + " || (sudo -n nginx -t && sudo -n systemctl reload nginx))";
        }
        return pull + " && docker compose up -d --build";
    }

    private String buildBlockedLog(CiVerdictDto verdict) {
        StringBuilder sb = new StringBuilder();
        sb.append("Déploiement bloqué : ").append(verdict.reason()).append('\n');
        if (verdict.blocking() != null) {
            for (CiVerdictFindingDto finding : verdict.blocking()) {
                sb.append("- ").append(finding.severity()).append(' ')
                        .append(finding.cveId() != null ? finding.cveId() : "?")
                        .append(" ").append(finding.packageName() != null ? finding.packageName() : "")
                        .append(finding.packageVersion() != null ? "@" + finding.packageVersion() : "")
                        .append('\n');
            }
        }
        sb.append("Aucun déploiement distant n'a été exécuté.\n");
        return sb.toString();
    }

    private ServerNode requireServer(Long id) {
        return serverNodeRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Serveur introuvable."));
    }

    private ServerDeployment requireDeployment(Long serverId, Long deploymentId) {
        return serverDeploymentRepo.findByIdAndServerNodeId(deploymentId, serverId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
    }

    private Long resolveRepositoryId(Long repositoryId) {
        if (repositoryId == null) {
            return null;
        }
        Repository repo = repositoryRepo.findById(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Dépôt Git introuvable."));
        return repo.getId();
    }

    private String normalizeName(String raw, String domain, String path) {
        if (raw != null && !raw.isBlank()) {
            String name = raw.trim();
            if (name.length() > 180) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Le nom du déploiement est trop long.");
            }
            return name;
        }
        if (domain != null && !domain.isBlank()) {
            return DeployFieldValidator.normalizeDomain(domain);
        }
        if (path != null && !path.isBlank()) {
            String normalized = DeployFieldValidator.normalizePath(path, false);
            if (normalized != null) {
                int slash = normalized.lastIndexOf('/');
                return slash >= 0 && slash < normalized.length() - 1 ? normalized.substring(slash + 1) : normalized;
            }
        }
        return "Déploiement";
    }

    private String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private String trimLog(String logText) {
        if (logText == null) {
            return "";
        }
        return logText.length() > 20_000 ? logText.substring(logText.length() - 20_000) : logText;
    }

    private ServerDeploymentDto toDeploymentDto(ServerDeployment deployment) {
        DeployRun last = deployRunRepo.findFirstByServerDeploymentIdOrderByStartedAtDesc(deployment.getId()).orElse(null);
        return new ServerDeploymentDto(
                deployment.getId(),
                deployment.getServerNode() != null ? deployment.getServerNode().getId() : null,
                deployment.getName(),
                deployment.getDeployPath(),
                deployment.getDomain(),
                deployment.getLinkedRepositoryId(),
                deployment.getDeployBranch(),
                deployment.getDeployStrategy() != null ? deployment.getDeployStrategy().name() : "DOCKER_COMPOSE",
                Boolean.TRUE.equals(deployment.getAutoDeployEnabled()),
                last != null ? last.getStatus().name() : null,
                last != null ? last.getCommitSha() : null);
    }

    private DeployRunDto toDto(DeployRun run, List<CiVerdictFindingDto> blocking) {
        List<CiVerdictFindingDto> findings = blocking != null ? blocking : List.of();
        return new DeployRunDto(
                run.getId(),
                run.getServerNode() != null ? run.getServerNode().getId() : null,
                run.getServerDeployment() != null ? run.getServerDeployment().getId() : null,
                run.getCommitSha(),
                run.getVerdict(),
                run.getStatus().name(),
                run.getTriggerType().name(),
                run.getLog(),
                run.getStartedAt(),
                run.getFinishedAt(),
                run.getStatus() == DeployRun.Status.BLOCKED,
                new ArrayList<>(findings));
    }

    private record LatestGate(CiVerdictDto verdict) {
    }

    private record PreparedDeploy(
            Long runId,
            Long serverId,
            Long deploymentId,
            boolean blocked,
            DeployRunDto dto,
            List<CiVerdictFindingDto> blocking) {
    }
}
