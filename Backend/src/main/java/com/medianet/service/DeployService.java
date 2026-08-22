package com.medianet.service;

import com.medianet.dto.CiVerdictDto;
import com.medianet.dto.CiVerdictFindingDto;
import com.medianet.dto.DeployRunDto;
import com.medianet.dto.DeploySettingsRequest;
import com.medianet.entity.CveEntry;
import com.medianet.entity.DeployRun;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.ServerNode;
import com.medianet.event.ScanFinishedEvent;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.DeployRunRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ScanResultRepo;
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
    private final DeployRunRepo deployRunRepo;
    private final RepositoryRepo repositoryRepo;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final CiScanService ciScanService;
    private final SshCommandExecutor sshCommandExecutor;
    private final TransactionTemplate transactionTemplate;

    public DeployService(
            ServerNodeRepo serverNodeRepo,
            DeployRunRepo deployRunRepo,
            RepositoryRepo repositoryRepo,
            ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo,
            CiScanService ciScanService,
            SshCommandExecutor sshCommandExecutor,
            PlatformTransactionManager transactionManager) {
        this.serverNodeRepo = serverNodeRepo;
        this.deployRunRepo = deployRunRepo;
        this.repositoryRepo = repositoryRepo;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.ciScanService = ciScanService;
        this.sshCommandExecutor = sshCommandExecutor;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Transactional
    public ServerNode updateDeploySettings(Long serverId, DeploySettingsRequest request) {
        ServerNode node = requireServer(serverId);
        node.setDeployPath(DeployFieldValidator.normalizePath(request.deployPath(), false));
        node.setDomain(DeployFieldValidator.normalizeDomain(request.domain()));
        node.setLinkedRepositoryId(resolveRepositoryId(request.linkedRepositoryId()));
        node.setDeployBranch(DeployFieldValidator.normalizeBranch(request.deployBranch()));
        return serverNodeRepo.save(node);
    }

    @Transactional
    public ServerNode setAutoDeploy(Long serverId, boolean enabled) {
        ServerNode node = requireServer(serverId);
        if (enabled) {
            if (node.getDeployPath() == null || node.getDeployPath().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Le chemin de déploiement est requis avant d'activer l'auto-deploy.");
            }
            if (node.getLinkedRepositoryId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Liez un dépôt Git avant d'activer l'auto-deploy.");
            }
        }
        node.setAutoDeployEnabled(enabled);
        return serverNodeRepo.save(node);
    }

    @Transactional(readOnly = true)
    public List<DeployRunDto> listDeploys(Long serverId) {
        requireServer(serverId);
        return deployRunRepo.findTop20ByServerNodeIdOrderByStartedAtDesc(serverId).stream()
                .map(run -> toDto(run, List.of()))
                .toList();
    }

    public DeployRunDto deploy(Long serverId, boolean force, DeployRun.TriggerType triggerType) {
        PreparedDeploy prepared = transactionTemplate.execute(status -> prepareDeploy(serverId, force, triggerType));
        if (prepared == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Impossible de préparer le déploiement.");
        }
        if (prepared.blocked()) {
            return prepared.dto();
        }
        return executeRemote(prepared.runId(), prepared.serverId(), prepared.blocking());
    }

    private PreparedDeploy prepareDeploy(Long serverId, boolean force, DeployRun.TriggerType triggerType) {
        ServerNode node = requireServer(serverId);
        DeployFieldValidator.normalizePath(node.getDeployPath(), true);
        DeployFieldValidator.normalizeBranch(node.getDeployBranch());
        if (node.getLinkedRepositoryId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Liez un dépôt Git pour connaître le verdict CRITICAL / HIGH.");
        }

        LatestGate gate = latestGate(node.getLinkedRepositoryId());
        DeployRun.TriggerType effectiveTrigger = force ? DeployRun.TriggerType.FORCE : triggerType;
        boolean blocked = !"PASS".equals(gate.verdict.reason());

        DeployRun run = DeployRun.builder()
                .serverNode(node)
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
                blocked && !force,
                toDto(run, gate.verdict.blocking()),
                gate.verdict.blocking());
    }

    private DeployRunDto executeRemote(Long runId, Long serverId, List<CiVerdictFindingDto> blocking) {
        DeployRun started = transactionTemplate.execute(status -> deployRunRepo.findById(runId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable.")));
        if (started == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable.");
        }
        ServerNode node = transactionTemplate.execute(status -> {
            ServerNode loaded = requireServer(serverId);
            loaded.getEncryptedPassword();
            loaded.getEncryptedPrivateKey();
            loaded.getEncryptedPrivateKeyPassphrase();
            return loaded;
        });
        if (node == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Serveur introuvable.");
        }
        String path = DeployFieldValidator.normalizePath(node.getDeployPath(), true);
        String branch = DeployFieldValidator.normalizeBranch(node.getDeployBranch());
        String command = buildDeployCommand(path, branch);
        StringBuilder liveLog = new StringBuilder(started.getLog() == null ? "" : started.getLog());
        if (!"PASS".equals(started.getVerdict())) {
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
            log.warn("[Deploy] SSH failed server={} : {}", node.getId(), e.getMessage());
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
        List<ServerNode> targets = serverNodeRepo.findByLinkedRepositoryIdAndAutoDeployEnabledTrue(repoId);
        if (targets.isEmpty()) {
            return;
        }
        LatestGate gate = latestGate(repoId);
        for (ServerNode node : targets) {
            try {
                if (!"PASS".equals(gate.verdict.reason())) {
                    DeployRun blocked = DeployRun.builder()
                            .serverNode(node)
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
                deploy(node.getId(), false, DeployRun.TriggerType.AUTO);
            } catch (Exception e) {
                log.warn("[Deploy] Auto-deploy skipped server={} : {}", node.getId(), e.getMessage());
            }
        }
    }

    private LatestGate latestGate(Long repositoryId) {
        ScanResult scan = scanResultRepo.findFirstByRepositoryIdOrderByStartedAtDesc(repositoryId);
        if (scan == null
                || scan.getStatus() == ScanStatus.RUNNING
                || scan.getStatus() == ScanStatus.PENDING) {
            return new LatestGate(new CiVerdictDto(
                    "FAIL",
                    "SCAN_NOT_READY",
                    scan != null ? scan.getCommitSha() : null,
                    scan != null ? scan.getId() : null,
                    repositoryId,
                    List.of(),
                    List.of(),
                    null));
        }
        if (scan.getStatus() == ScanStatus.FAILED) {
            return new LatestGate(new CiVerdictDto(
                    "FAIL",
                    "SCAN_FAILED",
                    scan.getCommitSha(),
                    scan.getId(),
                    repositoryId,
                    List.of(),
                    List.of(),
                    null));
        }
        List<CveEntry> cves = cveEntryRepo.findByScanResultId(scan.getId());
        return new LatestGate(ciScanService.evaluate(scan, repositoryId, scan.getCommitSha(), cves));
    }

    private String buildDeployCommand(String path, String branch) {
        return String.join(" && ",
                "export GIT_TERMINAL_PROMPT=0",
                "cd " + shellQuote(path),
                "pwd",
                "git fetch origin",
                "git checkout " + shellQuote(branch),
                "git pull --ff-only origin " + shellQuote(branch),
                "docker compose up -d --build");
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
        sb.append("Aucun git pull / docker compose n'a été exécuté.\n");
        return sb.toString();
    }

    private ServerNode requireServer(Long id) {
        return serverNodeRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Serveur introuvable."));
    }

    private Long resolveRepositoryId(Long repositoryId) {
        if (repositoryId == null) {
            return null;
        }
        Repository repo = repositoryRepo.findById(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Dépôt Git introuvable."));
        return repo.getId();
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

    private DeployRunDto toDto(DeployRun run, List<CiVerdictFindingDto> blocking) {
        List<CiVerdictFindingDto> findings = blocking != null ? blocking : List.of();
        return new DeployRunDto(
                run.getId(),
                run.getServerNode() != null ? run.getServerNode().getId() : null,
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
            boolean blocked,
            DeployRunDto dto,
            List<CiVerdictFindingDto> blocking) {
    }
}
