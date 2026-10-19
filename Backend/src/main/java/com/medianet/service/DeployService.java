package com.medianet.service;

import com.medianet.entity.NotificationType;

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
    private final com.medianet.repository.CiPipelineLinkRepo ciPipelineLinkRepo;
    private NotificationService notificationService;
    private ServerDiskService serverDiskService;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setNotificationService(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setServerDiskService(ServerDiskService serverDiskService) {
        this.serverDiskService = serverDiskService;
    }
    /** One deploy at a time per deployment folder: two pushes close together must not build over each other. */
    private final java.util.concurrent.ConcurrentHashMap<Long, java.util.concurrent.locks.ReentrantLock> locks =
            new java.util.concurrent.ConcurrentHashMap<>();

    public DeployService(
            ServerNodeRepo serverNodeRepo,
            ServerDeploymentRepo serverDeploymentRepo,
            DeployRunRepo deployRunRepo,
            RepositoryRepo repositoryRepo,
            ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo,
            CiScanService ciScanService,
            SshCommandExecutor sshCommandExecutor,
            PlatformTransactionManager transactionManager,
            com.medianet.repository.CiPipelineLinkRepo ciPipelineLinkRepo) {
        this.serverNodeRepo = serverNodeRepo;
        this.serverDeploymentRepo = serverDeploymentRepo;
        this.deployRunRepo = deployRunRepo;
        this.repositoryRepo = repositoryRepo;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.ciScanService = ciScanService;
        this.sshCommandExecutor = sshCommandExecutor;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.ciPipelineLinkRepo = ciPipelineLinkRepo;
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
                .healthUrl(DeployFieldValidator.normalizeHealthUrl(request.healthUrl()))
                .backupEnabled(Boolean.TRUE.equals(request.backupEnabled()))
                .backupService(backupServiceOf(request))
                .approvalRequired(Boolean.TRUE.equals(request.approvalRequired()))
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
        requireDeployment(serverId, deploymentId);
        // The detach query clears the persistence context: reload what is used after it.
        deployRunRepo.detachFromDeployment(deploymentId);
        serverDeploymentRepo.deleteById(deploymentId);
        serverDeploymentRepo.flush();
        syncNodeSummary(requireServer(serverId));
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
        String pinned = transactionTemplate.execute(status -> serverDeploymentRepo.findById(deploymentId)
                .map(ServerDeployment::getPinnedCommit).orElse(null));
        if (pinned != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "La version " + pinned.substring(0, 12)
                    + " est épinglée sur ce serveur : reprenez le déploiement automatique avant de déployer la dernière version.");
        }
        java.util.concurrent.locks.ReentrantLock lock = locks.computeIfAbsent(deploymentId, id -> new java.util.concurrent.locks.ReentrantLock());
        if (!lock.tryLock()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Un déploiement est déjà en cours sur ce dossier.");
        }
        try {
            return deployLocked(serverId, deploymentId, force, triggerType);
        } finally {
            lock.unlock();
        }
    }

    /**
     * CD: puts on the server the exact commit of a green pipeline (tests, lint, build and Vulnix gate passed).
     * Returns null when another deploy of this folder is running: the watcher retries on its next round.
     */
    public DeployRunDto deployCommit(Long deploymentId, String commitSha, long pipelineNumber) {
        String sha = DeployFieldValidator.normalizeCommit(commitSha);
        java.util.concurrent.locks.ReentrantLock lock = locks.computeIfAbsent(deploymentId, id -> new java.util.concurrent.locks.ReentrantLock());
        if (!lock.tryLock()) {
            return null;
        }
        try {
            DeployRun created = transactionTemplate.execute(status -> {
                ServerDeployment deployment = serverDeploymentRepo.findById(deploymentId)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
                DeployFieldValidator.normalizePath(deployment.getDeployPath(), true);
                return deployRunRepo.saveAndFlush(DeployRun.builder()
                        .serverNode(deployment.getServerNode())
                        .serverDeployment(deployment)
                        .commitSha(sha)
                        .pipelineNumber(pipelineNumber)
                        .verdict("PIPELINE_VERT")
                        .status(DeployRun.Status.RUNNING)
                        .triggerType(DeployRun.TriggerType.CI)
                        .log("Pipeline #" + pipelineNumber + " vert (tests, lint, build, barrière Vulnix) : déploiement du commit " + sha + ".\n")
                        .startedAt(LocalDateTime.now())
                        .build());
            });
            if (created == null) {
                return null;
            }
            ServerDeployment deployment = transactionTemplate.execute(status -> requireLoaded(deploymentId));
            return executeRemote(created.getId(), deployment.getServerNode().getId(), deploymentId, List.of(), sha);
        } finally {
            lock.unlock();
        }
    }

    private ServerDeployment requireLoaded(Long deploymentId) {
        ServerDeployment d = serverDeploymentRepo.findById(deploymentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
        // Load the server and its credentials now: SSH runs after the transaction is closed.
        ServerNode n = d.getServerNode();
        n.getName();
        n.getEncryptedPassword();
        n.getEncryptedPrivateKey();
        n.getEncryptedPrivateKeyPassphrase();
        return d;
    }

    /**
     * Puts a version chosen by hand on the server (the latest is not reliable): same script as the CD (backup, exact
     * commit, health check, rollback). When it succeeds the version is pinned: green pipelines stop deploying here
     * until {@link #unpin}. Runs in the background, like an approved deploy.
     */
    public DeployRunDto deployChosenCommit(Long deploymentId, String commitSha, String who) {
        String sha = DeployFieldValidator.normalizeCommit(commitSha);
        java.util.concurrent.locks.ReentrantLock lock = locks.computeIfAbsent(deploymentId, id -> new java.util.concurrent.locks.ReentrantLock());
        if (lock.isLocked()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Un déploiement est déjà en cours sur ce dossier.");
        }
        DeployRun created = transactionTemplate.execute(status -> {
            ServerDeployment deployment = serverDeploymentRepo.findById(deploymentId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
            DeployFieldValidator.normalizePath(deployment.getDeployPath(), true);
            return deployRunRepo.saveAndFlush(DeployRun.builder()
                    .serverNode(deployment.getServerNode())
                    .serverDeployment(deployment)
                    .commitSha(sha)
                    .verdict("VERSION_CHOISIE")
                    .status(DeployRun.Status.RUNNING)
                    .triggerType(DeployRun.TriggerType.MANUAL)
                    .decidedBy(who)
                    .log("Version choisie par " + who + " : déploiement du commit " + sha + ".\n"
                            + "Si elle passe le contrôle de santé, elle sera épinglée : le déploiement automatique sera suspendu.\n")
                    .startedAt(LocalDateTime.now())
                    .build());
        });
        Long runId = created.getId();
        Long serverId = transactionTemplate.execute(status -> requireLoaded(deploymentId).getServerNode().getId());
        approvedRuns.submit(() -> {
            if (!lock.tryLock()) return;
            try {
                // executeRemote pins the version when it passes (verdict VERSION_CHOISIE).
                executeRemote(runId, serverId, deploymentId, List.of(), sha);
            } catch (Exception e) {
                log.warn("[Deploy] chosen version run {} failed: {}", runId, e.getMessage());
            } finally {
                lock.unlock();
            }
        });
        return toDto(created, List.of());
    }

    /** Resumes the automatic deployment: the next green pipeline deploys again (the pinned version stays in place). */
    public void unpin(Long deploymentId, String who) {
        transactionTemplate.executeWithoutResult(status -> {
            ServerDeployment d = serverDeploymentRepo.findById(deploymentId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
            if (d.getPinnedCommit() == null) return;
            log.info("[Deploy] deployment={} unpinned ({}) by {}", deploymentId, d.getPinnedCommit().substring(0, 12), who);
            d.setPinnedCommit(null);
            d.setPinnedAt(null);
            d.setPinnedBy(null);
            serverDeploymentRepo.save(d);
        });
    }

    /** Approved deploys run here: the HTTP request answers at once, the UI follows the run. */
    private final java.util.concurrent.ExecutorService approvedRuns = java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "cd-approved");
        t.setDaemon(true);
        return t;
    });

    /**
     * Green pipeline on a deployment that asks for approval: records a waiting run instead of deploying. A newer green
     * pipeline replaces an older request (never deploy an outdated version). Returns the waiting run.
     */
    public DeployRunDto requestApproval(Long deploymentId, String commitSha, long pipelineNumber) {
        String sha = DeployFieldValidator.normalizeCommit(commitSha);
        DeployRunDto dto = transactionTemplate.execute(status -> {
            ServerDeployment d = serverDeploymentRepo.findById(deploymentId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
            for (DeployRun old : deployRunRepo.findByServerDeploymentIdAndStatus(deploymentId, DeployRun.Status.PENDING_APPROVAL)) {
                old.setStatus(DeployRun.Status.SUPERSEDED);
                old.setFinishedAt(LocalDateTime.now());
                old.setLog((old.getLog() == null ? "" : old.getLog()) + "Remplacé par le pipeline #" + pipelineNumber + ", plus récent.\n");
                deployRunRepo.save(old);
            }
            DeployRun run = deployRunRepo.saveAndFlush(DeployRun.builder()
                    .serverNode(d.getServerNode())
                    .serverDeployment(d)
                    .commitSha(sha)
                    .pipelineNumber(pipelineNumber)
                    .verdict("ACCORD_DEMANDE")
                    .status(DeployRun.Status.PENDING_APPROVAL)
                    .triggerType(DeployRun.TriggerType.CI)
                    .log("Pipeline #" + pipelineNumber + " vert : en attente d'accord avant déploiement du commit " + sha + ".\n")
                    .startedAt(LocalDateTime.now())
                    .build());
            return toDto(run, List.of());
        });
        ServerDeployment d = transactionTemplate.execute(status -> requireLoaded(deploymentId));
        if (notificationService != null && d != null && d.getLinkedRepositoryId() != null) {
            String backup = Boolean.TRUE.equals(d.getBackupEnabled()) ? " La base sera sauvegardée juste avant." : "";
            notificationService.notifyRepositoryTeam(d.getLinkedRepositoryId(), NotificationType.DEPLOY_APPROVAL,
                    "Prêt à déployer : pipeline #" + pipelineNumber,
                    "Le pipeline #" + pipelineNumber + " est vert (tests, lint, build, barrière Vulnix). Le commit " + sha.substring(0, 8)
                            + " attend votre accord pour partir sur " + d.getServerNode().getName() + " (" + d.getDeployPath() + ")." + backup
                            + " Ouvrez l'onglet CI/CD du projet pour Déployer ou Refuser.",
                    null, dto.id());
        }
        return dto;
    }

    /** "Déployer" on a waiting run: checked, then executed in the background. */
    public DeployRunDto approve(Long runId, String who) {
        DeployRun run = transactionTemplate.execute(status -> deployRunRepo.findById(runId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable.")));
        if (run.getStatus() != DeployRun.Status.PENDING_APPROVAL) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Ce déploiement n'attend plus d'accord (" + run.getStatus() + ").");
        }
        Long deploymentId = run.getServerDeployment().getId();
        java.util.concurrent.locks.ReentrantLock lock = locks.computeIfAbsent(deploymentId, id -> new java.util.concurrent.locks.ReentrantLock());
        if (lock.isLocked()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Un déploiement est déjà en cours sur ce dossier.");
        }
        DeployRunDto started = transactionTemplate.execute(status -> {
            DeployRun r = deployRunRepo.findById(runId).orElseThrow();
            r.setStatus(DeployRun.Status.RUNNING);
            r.setDecidedBy(who);
            r.setStartedAt(LocalDateTime.now());
            r.setLog(r.getLog() + "Accord donné par " + who + ".\n");
            return toDto(deployRunRepo.save(r), List.of());
        });
        Long serverId = run.getServerNode().getId();
        String sha = run.getCommitSha();
        approvedRuns.submit(() -> {
            if (!lock.tryLock()) return;
            try {
                executeRemote(runId, serverId, deploymentId, List.of(), sha);
            } catch (Exception e) {
                log.warn("[Deploy] approved run {} failed: {}", runId, e.getMessage());
            } finally {
                lock.unlock();
            }
        });
        return started;
    }

    public DeployRunDto refuse(Long runId, String who) {
        return transactionTemplate.execute(status -> {
            DeployRun r = deployRunRepo.findById(runId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
            if (r.getStatus() != DeployRun.Status.PENDING_APPROVAL) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Ce déploiement n'attend plus d'accord (" + r.getStatus() + ").");
            }
            r.setStatus(DeployRun.Status.REFUSED);
            r.setDecidedBy(who);
            r.setFinishedAt(LocalDateTime.now());
            r.setLog(r.getLog() + "Refusé par " + who + " : rien n'a été déployé.\n");
            return toDto(deployRunRepo.save(r), List.of());
        });
    }

    /** Deployment that owns a run (access checks). */
    public Long deploymentOfRun(Long runId) {
        return transactionTemplate.execute(status -> deployRunRepo.findById(runId)
                .map(r -> r.getServerDeployment() != null ? r.getServerDeployment().getId() : null)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable.")));
    }

    private DeployRunDto deployLocked(Long serverId, Long deploymentId, boolean force, DeployRun.TriggerType triggerType) {
        PreparedDeploy prepared = transactionTemplate.execute(
                status -> prepareDeploy(serverId, deploymentId, force, triggerType));
        if (prepared == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Impossible de préparer le déploiement.");
        }
        if (prepared.blocked()) {
            return prepared.dto();
        }
        // Manual / scan-triggered deploy: latest commit of the branch, with the same check and rollback.
        return executeRemote(prepared.runId(), prepared.serverId(), prepared.deploymentId(), prepared.blocking(), null);
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
                    "Liez un dépôt Git pour connaître le verdict CRITICAL / HIGH / CISA KEV.");
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
            List<CiVerdictFindingDto> blocking,
            String targetSha) {
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
        String backupService = Boolean.TRUE.equals(deployment.getBackupEnabled())
                ? DeployFieldValidator.normalizeService(deployment.getBackupService()) : null;
        String command = buildDeployScript(path, branch, deployment.getDeployStrategy(), targetSha,
                DeployFieldValidator.normalizeHealthUrl(deployment.getHealthUrl()), backupService);
        DeployRun started = transactionTemplate.execute(status -> deployRunRepo.findById(runId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable.")));
        StringBuilder liveLog = new StringBuilder(started != null && started.getLog() != null ? started.getLog() : "");
        if (blocking != null && !blocking.isEmpty()) {
            liveLog.append("Continuer quand même : déploiement forcé malgré CRITICAL / HIGH / CISA KEV.\n");
        }
        liveLog.append("Cible : ").append(node.getUsername()).append('@').append(node.getHost())
                .append(':').append(node.getPort()).append('\n');
        liveLog.append("Dossier : ").append(path).append(" · branche ").append(branch)
                .append(targetSha != null ? " · commit " + targetSha : " · dernier commit de la branche").append('\n');

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
            } else if (exit == EXIT_BACKUP_FAILED) {
                finalStatus = DeployRun.Status.BACKUP_FAILED;
                liveLog.append("La sauvegarde de la base a échoué : rien n'a été déployé, la version en place continue de tourner.\n");
            } else if (exit == EXIT_ROLLED_BACK) {
                finalStatus = DeployRun.Status.ROLLED_BACK;
                liveLog.append("La nouvelle version n'a pas passé la vérification : la version précédente tourne de nouveau.\n");
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
        String deployedSha = deployedCommit(logToSave);
        Backup backup = backupOf(logToSave);
        DeployRunDto saved = transactionTemplate.execute(status -> {
            DeployRun run = deployRunRepo.findById(runId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
            run.setStatus(statusToSave);
            run.setLog(logToSave);
            if (deployedSha != null) {
                run.setCommitSha(deployedSha);
            }
            if (backup != null) {
                run.setBackupFile(backup.file());
                run.setBackupBytes(backup.bytes());
            }
            run.setFinishedAt(LocalDateTime.now());
            // A version chosen by hand is pinned in the same transaction as its result: there is no moment where
            // the run reads "SUCCESS" while a green pipeline could still replace it.
            if (statusToSave == DeployRun.Status.SUCCESS && "VERSION_CHOISIE".equals(run.getVerdict())) {
                String pinned = deployedSha != null ? deployedSha : run.getCommitSha();
                serverDeploymentRepo.findById(deploymentId).ifPresent(d -> {
                    d.setPinnedCommit(pinned);
                    d.setPinnedAt(LocalDateTime.now());
                    d.setPinnedBy(run.getDecidedBy());
                    serverDeploymentRepo.save(d);
                });
                run.setLog(run.getLog() + "[CD] Version " + pinned.substring(0, Math.min(12, pinned.length()))
                        + " épinglée : le déploiement automatique est suspendu sur ce serveur.\n");
                log.info("[Deploy] deployment={} pinned to {} by {}", deploymentId, pinned, run.getDecidedBy());
            }
            return toDto(deployRunRepo.save(run), blocking);
        });
        if (saved == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Impossible d'enregistrer le déploiement.");
        }
        notifyOutcome(deployment, saved, logToSave, backup);
        if (statusToSave == DeployRun.Status.SUCCESS && serverDiskService != null
                && deployment.getDeployStrategy() != DeployStrategy.STATIC_NGINX) {
            try {
                serverDiskService.measureAfterDeploy(deployment.getId());
            } catch (Exception e) {
                log.warn("[Deploy] disk check after deploy skipped: {}", e.getMessage());
            }
        }
        return saved;
    }

    record Backup(String file, long bytes) {
    }

    private static final java.util.regex.Pattern BACKUP_LINE =
            java.util.regex.Pattern.compile("\\[CD\\] Sauvegarde : (\\S+) \\((\\d+) octets\\)");

    /** Backup the script reported ("[CD] Sauvegarde : <file> (<n> octets) vérifiée"), or null. Package-private for tests. */
    static Backup backupOf(String log) {
        if (log == null) return null;
        java.util.regex.Matcher m = BACKUP_LINE.matcher(log);
        return m.find() ? new Backup(m.group(1), Long.parseLong(m.group(2))) : null;
    }

    /** Last lines of the output, for the e-mail of a failed or rolled back deploy. */
    static String tailOf(String log, int lines) {
        String[] all = log == null ? new String[0] : log.strip().split("\\R");
        return String.join("\n", java.util.Arrays.copyOfRange(all, Math.max(0, all.length - lines), all.length));
    }

    private void notifyOutcome(ServerDeployment d, DeployRunDto run, String logText, Backup backup) {
        if (notificationService == null || d.getLinkedRepositoryId() == null) return;
        String where = d.getServerNode().getName() + " (" + d.getDeployPath() + ")";
        String commit = run.commitSha() != null ? run.commitSha().substring(0, Math.min(8, run.commitSha().length())) : "?";
        String from = run.pipelineNumber() != null ? " (pipeline #" + run.pipelineNumber() + ")" : "";
        String saved = backup != null ? "\nSauvegarde de la base avant déploiement : " + backup.file() + " (" + human(backup.bytes()) + ")." : "";
        NotificationType type;
        String title;
        String message;
        switch (DeployRun.Status.valueOf(run.status())) {
            case SUCCESS -> {
                type = NotificationType.DEPLOY_SUCCESS;
                title = "Déployé : " + commit + " sur " + d.getServerNode().getName();
                message = "Le commit " + commit + from + " est en production sur " + where + "." + saved;
            }
            case ROLLED_BACK -> {
                type = NotificationType.DEPLOY_ROLLED_BACK;
                title = "Version précédente remise sur " + d.getServerNode().getName();
                message = "Le commit " + commit + from + " ne passait pas la vérification après démarrage : la version précédente tourne de nouveau sur "
                        + where + "." + saved + "\n\nDernières lignes :\n" + tailOf(logText, 12);
            }
            case BACKUP_FAILED -> {
                type = NotificationType.DEPLOY_BACKUP_FAILED;
                title = "Déploiement bloqué : sauvegarde impossible";
                message = "Rien n'a été déployé sur " + where + " : la sauvegarde de la base a échoué. La version en place continue de tourner."
                        + "\n\nDernières lignes :\n" + tailOf(logText, 12);
            }
            case FAILED -> {
                type = NotificationType.DEPLOY_FAILED;
                title = "Déploiement échoué sur " + d.getServerNode().getName();
                message = "Le déploiement du commit " + commit + from + " sur " + where + " a échoué : intervention nécessaire."
                        + "\n\nDernières lignes :\n" + tailOf(logText, 12);
            }
            default -> {
                return;
            }
        }
        try {
            notificationService.notifyRepositoryTeam(d.getLinkedRepositoryId(), type, title, message, null, run.id());
        } catch (Exception e) {
            log.warn("[Deploy] notification failed: {}", e.getMessage());
        }
    }

    static String human(long bytes) {
        if (bytes < 1024) return bytes + " o";
        double kb = bytes / 1024.0;
        if (kb < 1024) return String.format(java.util.Locale.FRANCE, "%.0f Ko", kb);
        double mb = kb / 1024.0;
        if (mb < 1024) return String.format(java.util.Locale.FRANCE, "%.1f Mo", mb);
        return String.format(java.util.Locale.FRANCE, "%.2f Go", mb / 1024.0);
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
        if (ciPipelineLinkRepo.findByRepositoryId(repoId).isPresent()) {
            // CI enabled: the CD waits for the whole pipeline (tests + gate), see CiDeployWatcher.
            return;
        }
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
        deployment.setHealthUrl(DeployFieldValidator.normalizeHealthUrl(request.healthUrl()));
        if (request.backupEnabled() != null) {
            deployment.setBackupEnabled(request.backupEnabled());
            deployment.setBackupService(backupServiceOf(request));
        }
        if (request.approvalRequired() != null) {
            deployment.setApprovalRequired(request.approvalRequired());
        }
    }

    private static String backupServiceOf(DeploySettingsRequest request) {
        String svc = DeployFieldValidator.normalizeService(request.backupService());
        if (Boolean.TRUE.equals(request.backupEnabled()) && svc == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Indiquez le service de la base de données dans docker-compose.yml (ex. db) pour la sauvegarde.");
        }
        return svc;
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

    static final int EXIT_ROLLED_BACK = 4;
    private static final java.util.regex.Pattern NEW_VERSION = java.util.regex.Pattern.compile("\\[CD\\] Nouvelle version : ([0-9a-f]{40})");

    /** Commit the script actually put in place (its "[CD] Nouvelle version" line), or null. */
    static String deployedCommit(String log) {
        if (log == null) return null;
        java.util.regex.Matcher m = NEW_VERSION.matcher(log);
        String last = null;
        while (m.find()) last = m.group(1);
        return last;
    }

    /**
     * Shell script run over SSH in the deployment folder. Exit codes: 0 deployed; 2 folder/git problem (nothing
     * changed); 3 commit not on the remote; 4 new version failed its check and the previous one runs again;
     * 5 rollback failed too. Every value is validated before (path, branch, commit, health URL).
     */
    static String buildDeployScript(String path, String branch, DeployStrategy strategy, String targetSha, String healthUrl) {
        return buildDeployScript(path, branch, strategy, targetSha, healthUrl, null);
    }

    public record CheckItem(String level, String text) {
    }

    public record CheckResult(boolean ok, List<CheckItem> items, String raw) {
    }

    /**
     * "Vérifier la configuration": everything the deploy needs, checked on the server WITHOUT changing anything
     * (no reset, no build, no restart, no write). Run it after the first manual install, before enabling the CD.
     */
    public CheckResult check(Long deploymentId) {
        ServerDeployment d = transactionTemplate.execute(status -> requireLoaded(deploymentId));
        ServerNode node = d.getServerNode();
        node.getEncryptedPassword();
        String path = DeployFieldValidator.normalizePath(d.getDeployPath(), true);
        String branch = DeployFieldValidator.normalizeBranch(d.getDeployBranch());
        String backup = Boolean.TRUE.equals(d.getBackupEnabled()) ? DeployFieldValidator.normalizeService(d.getBackupService()) : null;
        String script = buildCheckScript(path, branch, d.getDeployStrategy(), DeployFieldValidator.normalizeHealthUrl(d.getHealthUrl()), backup);
        String out;
        try {
            out = sshCommandExecutor.execute(node, script, Duration.ofMinutes(2)).output();
        } catch (Exception e) {
            return new CheckResult(false, List.of(new CheckItem("KO", "Connexion SSH impossible à " + node.getHost() + " : " + e.getMessage())), "");
        }
        List<CheckItem> items = parseCheck(out);
        items.add(0, new CheckItem("OK", "Connexion SSH à " + node.getUsername() + "@" + node.getHost()));
        return new CheckResult(items.stream().noneMatch(i -> i.level().equals("KO")), items, out);
    }

    static List<CheckItem> parseCheck(String out) {
        List<CheckItem> items = new ArrayList<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("^\\[(OK|KO|!)\\] (.+)$", java.util.regex.Pattern.MULTILINE)
                .matcher(out == null ? "" : out);
        while (m.find()) items.add(new CheckItem(m.group(1).equals("!") ? "WARN" : m.group(1), m.group(2).trim()));
        return items;
    }

    /** Read-only. Every value was validated before (path, branch, URL, service). Package-private for tests. */
    static String buildCheckScript(String path, String branch, DeployStrategy strategy, String healthUrl, String backupService) {
        List<String> l = new ArrayList<>();
        l.add("export GIT_TERMINAL_PROMPT=0");
        l.add("cd " + shellQuote(path) + " 2>/dev/null || { echo '[KO] Dossier introuvable : " + path + "'; exit 0; }");
        l.add("echo '[OK] Dossier présent : " + path + "'");
        l.add("if git rev-parse HEAD >/dev/null 2>&1; then echo \"[OK] Dépôt git, version en place : $(git rev-parse --short HEAD) ($(git log -1 --format=%cd --date=short))\"; else echo '[KO] Ce dossier n est pas un dépôt git (git clone à faire)'; exit 0; fi");
        l.add("if git fetch --dry-run origin " + shellQuote(branch) + " >/dev/null 2>&1; then echo '[OK] git fetch origin " + branch + " fonctionne'; else echo '[KO] git fetch impossible : le serveur n a pas accès au dépôt (clé de déploiement ?) ou la branche " + branch + " n existe pas'; fi");
        l.add("M=$(git status --porcelain --untracked-files=no | head -3 | tr '\\n' ' '); if [ -z \"$M\" ]; then echo '[OK] Aucun fichier suivi par git modifié à la main'; else echo \"[!] Fichiers suivis modifiés sur le serveur, ils seront écrasés au déploiement : $M\"; fi");
        l.add("if git ls-files --error-unmatch .env >/dev/null 2>&1; then echo '[KO] .env est suivi par git : il serait écrasé, ajoutez-le au .gitignore'; elif [ -f .env ]; then echo '[OK] .env présent et non suivi par git (jamais touché par le déploiement)'; else echo '[!] Pas de fichier .env dans le dossier'; fi");
        if (strategy == DeployStrategy.STATIC_NGINX) {
            l.add("if nginx -t >/dev/null 2>&1 || sudo -n nginx -t >/dev/null 2>&1; then echo '[OK] Configuration nginx valide'; else echo '[KO] nginx -t échoue (ou sudo sans mot de passe absent)'; fi");
        } else {
            l.add("if docker compose version >/dev/null 2>&1; then echo \"[OK] $(docker compose version --short 2>/dev/null | sed 's/^/Docker Compose /')\"; else echo '[KO] docker compose introuvable ou pas les droits Docker pour cet utilisateur'; exit 0; fi");
            l.add("if docker compose config -q >/dev/null 2>&1; then echo \"[OK] docker-compose.yml valide, services : $(docker compose config --services | tr '\\n' ' ')\"; else echo '[KO] docker-compose.yml absent ou invalide dans ce dossier'; fi");
            l.add("R=$(docker compose ps --format '{{.Service}} {{.State}}' 2>/dev/null | tr '\\n' ',' ); if [ -n \"$R\" ]; then echo \"[OK] Conteneurs en place : $R\"; else echo '[!] Aucun conteneur démarré : faites d abord la première installation à la main'; fi");
            if (backupService != null) {
                String svc = shellQuote(backupService);
                l.add("if docker compose config --services | grep -qx " + svc + "; then echo '[OK] Service " + backupService + " présent dans docker-compose.yml'; else echo '[KO] Service " + backupService + " absent de docker-compose.yml : la sauvegarde échouerait'; fi");
                l.add("S=$(docker compose exec -T " + svc + " sh -c 'U=\"${POSTGRES_USER:-postgres}\"; D=\"${POSTGRES_DB:-$U}\"; pg_dump -U \"$U\" -d \"$D\" -Fc | wc -c' 2>/dev/null | tr -d ' \\r'); "
                        + "if [ -n \"$S\" ] && [ \"$S\" -gt 100 ] 2>/dev/null; then echo \"[OK] Sauvegarde possible : $S octets (rien n a été écrit)\"; else echo '[KO] pg_dump impossible dans le service " + backupService + " (base arrêtée, pas PostgreSQL ?)'; fi");
            }
        }
        if (healthUrl != null) {
            String u = shellQuote(healthUrl);
            l.add("C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 " + u + " 2>/dev/null); if [ \"$C\" = 200 ]; then echo '[OK] Adresse de santé répond 200 : " + healthUrl.replace("'", "") + "'; "
                    + "elif [ -n \"$C\" ] && [ \"$C\" != 000 ]; then echo \"[KO] Adresse de santé répond $C (200 attendu)\"; else echo '[KO] Adresse de santé injoignable depuis le serveur'; fi");
        }
        l.add("P=/var/lib/docker; df -Pk \"$P\" >/dev/null 2>&1 || P=/; U=$(df -Pk \"$P\" | awk 'NR==2{print int($3*100/$2)}'); F=$(df -Ph \"$P\" | awk 'NR==2{print $4}'); "
                + "if [ \"$U\" -lt 85 ]; then echo \"[OK] Disque : $U % utilisés, $F libres\"; else echo \"[!] Disque : $U % utilisés, $F libres (un build peut échouer)\"; fi");
        return String.join("\n", l);
    }

    static final int EXIT_BACKUP_FAILED = 6;
    static final int KEEP_BACKUPS = 5;

    /**
     * @param backupService compose service of the PostgreSQL database to dump before anything changes (null = no backup).
     *                      Database and user are read inside that container ($POSTGRES_DB / $POSTGRES_USER): nothing stored.
     */
    static String buildDeployScript(String path, String branch, DeployStrategy strategy, String targetSha, String healthUrl,
            String backupService) {
        boolean nginx = strategy == DeployStrategy.STATIC_NGINX;
        String start = nginx
                ? "( (nginx -t && systemctl reload nginx) || (sudo -n nginx -t && sudo -n systemctl reload nginx) )"
                : "docker compose up -d --build";
        List<String> l = new ArrayList<>();
        l.add("export GIT_TERMINAL_PROMPT=0");
        l.add("cd " + shellQuote(path) + " || { echo '[CD] Dossier introuvable sur le serveur'; exit 2; }");
        l.add("PREV=$(git rev-parse HEAD) || { echo '[CD] Ce dossier n est pas un dépôt git'; exit 2; }");
        l.add("echo \"[CD] Version en place : $PREV\"");
        l.add("git fetch origin " + shellQuote(branch) + " || { echo '[CD] git fetch a échoué (accès au dépôt depuis le serveur ?)'; exit 2; }");
        l.add(targetSha != null
                ? "TARGET=" + shellQuote(targetSha)
                : "TARGET=$(git rev-parse " + shellQuote("origin/" + branch) + ")");
        l.add("git cat-file -e \"$TARGET^{commit}\" 2>/dev/null || { echo \"[CD] Commit $TARGET introuvable sur origin\"; exit 3; }");
        if (backupService != null) {
            String svc = shellQuote(backupService);
            String env = "U=\"${POSTGRES_USER:-postgres}\"; D=\"${POSTGRES_DB:-$U}\"; ";
            l.add("mkdir -p .vulnix-backups || exit " + EXIT_BACKUP_FAILED);
            l.add("F=\".vulnix-backups/avant-$(echo \"$TARGET\" | cut -c1-12)-$(date +%Y%m%d-%H%M%S).dump\"");
            l.add("echo \"[CD] Sauvegarde de la base (service " + backupService + ")…\"");
            l.add("if ! docker compose exec -T " + svc + " sh -c '" + env + "pg_dump -U \"$U\" -d \"$D\" -Fc' > \"$F\"; then rm -f \"$F\"; echo '[CD] Sauvegarde impossible : rien n a été déployé'; exit " + EXIT_BACKUP_FAILED + "; fi");
            l.add("SIZE=$(wc -c < \"$F\" | tr -d ' ')");
            l.add("if [ \"$SIZE\" -lt 100 ]; then rm -f \"$F\"; echo '[CD] Sauvegarde vide : rien n a été déployé'; exit " + EXIT_BACKUP_FAILED + "; fi");
            l.add("if ! docker compose exec -T " + svc + " pg_restore --list < \"$F\" > /dev/null 2>&1; then rm -f \"$F\"; echo '[CD] Sauvegarde illisible par pg_restore : rien n a été déployé'; exit " + EXIT_BACKUP_FAILED + "; fi");
            l.add("echo \"[CD] Sauvegarde : $PWD/$F ($SIZE octets) vérifiée\"");
            l.add("ls -1t .vulnix-backups/*.dump 2>/dev/null | tail -n +" + (KEEP_BACKUPS + 1) + " | while read -r old; do rm -f \"$old\"; done");
        }
        l.add("git reset --hard \"$TARGET\" || exit 2");
        l.add("echo \"[CD] Nouvelle version : $TARGET\"");
        l.add("OK=1");
        l.add(start + " || OK=0");
        l.add("if [ $OK = 1 ]; then");
        if (healthUrl != null) {
            String u = shellQuote(healthUrl);
            l.add("  echo '[CD] Vérification de santé : " + healthUrl.replace("'", "") + "'");
            l.add("  H=0; i=0");
            l.add("  while [ $i -lt 24 ]; do");
            l.add("    if curl -fsS -o /dev/null --max-time 5 " + u + " 2>/dev/null || wget -q -O /dev/null -T 5 " + u + " 2>/dev/null; then H=1; break; fi");
            l.add("    i=$((i+1)); sleep 5");
            l.add("  done");
            l.add("  [ $H = 1 ] || { echo '[CD] L application ne répond pas après 2 minutes'; OK=0; }");
        } else if (!nginx) {
            l.add("  sleep 20");
            l.add("  BAD=$(docker compose ps -a --format '{{.Name}} {{.State}} {{.ExitCode}}' | awk '$2==\"restarting\" || $2==\"dead\" || ($2==\"exited\" && $3!=\"0\")')");
            l.add("  [ -z \"$BAD\" ] || { echo '[CD] Conteneur arrêté ou qui redémarre en boucle :'; echo \"$BAD\"; OK=0; }");
        }
        l.add("fi");
        l.add("if [ $OK = 1 ]; then echo '[CD] Déploiement réussi'; exit 0; fi");
        l.add("if [ \"$PREV\" = \"$TARGET\" ]; then echo '[CD] Échec, et aucune version précédente différente à remettre'; exit 5; fi");
        l.add("echo \"[CD] Échec de la nouvelle version, retour à $PREV\"");
        l.add("git reset --hard \"$PREV\" && " + start + " && { echo '[CD] Version précédente rétablie'; exit " + EXIT_ROLLED_BACK + "; }");
        l.add("echo '[CD] Le retour arrière a aussi échoué : intervention manuelle nécessaire'; exit 5");
        return String.join("\n", l);
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

    private static String shellQuote(String value) {
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
                deployment.getHealthUrl(),
                Boolean.TRUE.equals(deployment.getBackupEnabled()),
                deployment.getBackupService(),
                Boolean.TRUE.equals(deployment.getApprovalRequired()),
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
                run.getPipelineNumber(),
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
