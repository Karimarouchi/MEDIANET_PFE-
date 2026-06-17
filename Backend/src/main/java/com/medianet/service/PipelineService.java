package com.medianet.service;

import com.medianet.dto.DockerHubCredentialDto;
import com.medianet.dto.PipelineDefinitionDto;
import com.medianet.dto.PipelineDefinitionRequest;
import com.medianet.dto.PipelineLogEventDto;
import com.medianet.dto.PipelinePresetDto;
import com.medianet.dto.PipelineRunDto;
import com.medianet.dto.PipelineStageRunDto;
import com.medianet.dto.ScanRequest;
import com.medianet.dto.ScanResponse;
import com.medianet.entity.AuthProvider;
import com.medianet.entity.CveEntry;
import com.medianet.entity.PipelineDefinition;
import com.medianet.entity.PipelineExecutionStatus;
import com.medianet.entity.PipelineRun;
import com.medianet.entity.PipelineStageRun;
import com.medianet.entity.PipelineStageType;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ServerNode;
import com.medianet.entity.ServerNodeType;
import com.medianet.entity.User;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.PipelineDefinitionRepo;
import com.medianet.repository.PipelineRunRepo;
import com.medianet.repository.PipelineStageRunRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.SecretFindingRepo;
import com.medianet.repository.ServerNodeRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@Transactional
public class PipelineService {

    private static final Logger log = LoggerFactory.getLogger(PipelineService.class);
    private static final Pattern IMAGE_TAG_PATTERN = Pattern.compile("(?:^|\\s)(?:-t|--tag)\\s+([^\\s]+)");

    private final PipelineDefinitionRepo pipelineDefinitionRepo;
    private final PipelineRunRepo pipelineRunRepo;
    private final PipelineStageRunRepo pipelineStageRunRepo;
    private final RepositoryRepo repositoryRepo;
    private final ServerNodeRepo serverNodeRepo;
    private final ScanService scanService;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final SecretFindingRepo secretFindingRepo;
    private final SshCommandExecutor sshCommandExecutor;
    private final UserService userService;
    private final PipelinePresetService pipelinePresetService;
    private final PipelineEventStreamService pipelineEventStreamService;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public PipelineService(
            PipelineDefinitionRepo pipelineDefinitionRepo,
            PipelineRunRepo pipelineRunRepo,
            PipelineStageRunRepo pipelineStageRunRepo,
            RepositoryRepo repositoryRepo,
            ServerNodeRepo serverNodeRepo,
            ScanService scanService,
            ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo,
            SecretFindingRepo secretFindingRepo,
            SshCommandExecutor sshCommandExecutor,
            UserService userService,
            PipelinePresetService pipelinePresetService,
            PipelineEventStreamService pipelineEventStreamService,
            ObjectMapper objectMapper) {
        this.pipelineDefinitionRepo = pipelineDefinitionRepo;
        this.pipelineRunRepo = pipelineRunRepo;
        this.pipelineStageRunRepo = pipelineStageRunRepo;
        this.repositoryRepo = repositoryRepo;
        this.serverNodeRepo = serverNodeRepo;
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.secretFindingRepo = secretFindingRepo;
        this.sshCommandExecutor = sshCommandExecutor;
        this.userService = userService;
        this.pipelinePresetService = pipelinePresetService;
        this.pipelineEventStreamService = pipelineEventStreamService;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public List<PipelineDefinitionDto> listPipelines(User currentUser) {
        return pipelineDefinitionRepo.findAllByOrderByUpdatedAtDesc().stream()
                .map(this::toDefinitionDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public PipelineDefinitionDto getPipeline(User currentUser, Long id) {
        return toDefinitionDto(getPipelineEntity(id));
    }

    @Transactional(readOnly = true)
    public PipelinePresetDto getMonolithPreset(User currentUser, Long repositoryId) {
        Repository repository = repositoryRepo.findById(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository source introuvable."));
        return pipelinePresetService.buildMonolithPreset(currentUser, repository);
    }

    @Transactional(readOnly = true)
    public DockerHubCredentialDto getDockerHubCredential(User currentUser) {
        return new DockerHubCredentialDto(userService.getDockerHubUsername(currentUser), userService.hasDockerHubCredential(currentUser));
    }

    public DockerHubCredentialDto saveDockerHubCredential(User currentUser, String username, String token) {
        User saved = userService.saveDockerHubCredential(currentUser, username, token);
        return new DockerHubCredentialDto(saved.getDockerHubUsername(), saved.hasDockerHubLinked());
    }

    public PipelineDefinitionDto createPipeline(User currentUser, PipelineDefinitionRequest request) {
        PipelineDefinition pipeline = new PipelineDefinition();
        applyRequest(pipeline, request, currentUser);
        pipeline.setCreatedBy(currentUser);
        PipelineDefinition saved = pipelineDefinitionRepo.save(pipeline);
        // Déclencher auto-scan en arrière-plan si un repo est lié
        if (saved.getRepository() != null) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    executor.submit(() -> triggerAutoScan(saved.getRepository(), currentUser));
                }
            });
        }
        return toDefinitionDto(saved);
    }

    public PipelineDefinitionDto updatePipeline(User currentUser, Long id, PipelineDefinitionRequest request) {
        PipelineDefinition pipeline = getPipelineEntity(id);
        Repository oldRepo = pipeline.getRepository();
        applyRequest(pipeline, request, pipeline.getCreatedBy() != null ? pipeline.getCreatedBy() : currentUser);
        PipelineDefinition saved = pipelineDefinitionRepo.save(pipeline);
        // Re-scanner si le repo a changé ou si aucun scan récent n'existe
        if (saved.getRepository() != null) {
            Repository newRepo = saved.getRepository();
            boolean repoChanged = oldRepo == null || !oldRepo.getId().equals(newRepo.getId());
            if (repoChanged) {
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        executor.submit(() -> triggerAutoScan(newRepo, currentUser));
                    }
                });
            }
        }
        return toDefinitionDto(saved);
    }

    public void deletePipeline(User currentUser, Long id) {
        pipelineDefinitionRepo.delete(getPipelineEntity(id));
    }

    public PipelineRunDto triggerRun(User currentUser, Long pipelineId) {
        PipelineDefinition pipeline = getPipelineEntity(pipelineId);
        if (pipelineRunRepo.existsByPipelineIdAndStatusIn(
                pipelineId,
                EnumSet.of(PipelineExecutionStatus.RUNNING, PipelineExecutionStatus.AWAITING_APPROVAL))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Un run est déjà en cours ou en attente d'approbation pour ce pipeline.");
        }

        // =====================================================================
        // SECURITY GATE — vérifie le dernier scan avant de lancer la pipeline
        // =====================================================================
        Repository linkedRepo = pipeline.getRepository();
        if (linkedRepo != null) {
            ScanResult latestScan = scanResultRepo.findFirstByRepositoryIdOrderByStartedAtDesc(linkedRepo.getId());
            if (latestScan == null) {
                // Aucun scan → lancer automatiquement et bloquer
                triggerAutoScan(linkedRepo, currentUser);
                return createBlockedRun(currentUser, pipeline,
                        "Aucun scan de sécurité disponible pour ce dépôt. " +
                        "Un scan a été lancé automatiquement. Réessayez une fois le scan terminé.");
            }
            if (latestScan.getStatus() == ScanResult.ScanStatus.RUNNING
                    || latestScan.getStatus() == ScanResult.ScanStatus.PENDING) {
                return createBlockedRun(currentUser, pipeline,
                        "Scan de sécurité en cours sur le dépôt. " +
                        "Réessayez une fois le scan terminé.");
            }
            if (latestScan.getStatus() == ScanResult.ScanStatus.COMPLETED) {
                List<CveEntry> latestCves = cveEntryRepo.findByScanResultId(latestScan.getId());
                int latestSecretCount = secretFindingRepo.findByScanResultId(latestScan.getId()).size();

                // 1. Secrets
                if (Boolean.TRUE.equals(pipeline.getFailOnSecrets()) && latestSecretCount > 0) {
                    return createBlockedRun(currentUser, pipeline,
                            "Pipeline BLOQUÉE : " + latestSecretCount + " secret(s) détecté(s) dans le dépôt " +
                            linkedRepo.getRepoUrl() + ". Supprimez les secrets exposés avant de relancer.");
                }
                // 2. CVE CRITICAL
                long criticalCount = latestCves.stream().filter(this::isCritical).count();
                if (Boolean.TRUE.equals(pipeline.getFailOnCritical()) && criticalCount > 0) {
                    return createBlockedRun(currentUser, pipeline,
                            "Pipeline BLOQUÉE : " + criticalCount + " CVE(s) CRITICAL dans le dépôt " +
                            linkedRepo.getRepoUrl() + ". Corrigez les vulnérabilités critiques avant de relancer.");
                }
                // 3. CVE HIGH avec correctif disponible
                long highWithFixCount = latestCves.stream()
                        .filter(c -> isHigh(c) && !isCritical(c)
                                && c.getFixedVersion() != null && !c.getFixedVersion().isBlank())
                        .count();
                if (highWithFixCount > 0) {
                    return createBlockedRun(currentUser, pipeline,
                            "Pipeline BLOQUÉE : " + highWithFixCount + " CVE(s) HIGH avec correctif disponible dans " +
                            linkedRepo.getRepoUrl() + ". Appliquez les correctifs avant de relancer.");
                }
                // 4. Vulnérabilité SAST critique (Semgrep)
                long sastCriticalCount = latestCves.stream()
                        .filter(c -> "semgrep".equalsIgnoreCase(c.getSource()) && isCritical(c))
                        .count();
                if (sastCriticalCount > 0) {
                    return createBlockedRun(currentUser, pipeline,
                            "Pipeline BLOQUÉE : " + sastCriticalCount + " vulnérabilité(s) SAST critique(s) (Semgrep) dans " +
                            linkedRepo.getRepoUrl() + ". Corrigez les failles avant de relancer.");
                }
                // 5. Mauvaise configuration IaC critique (Checkov / Trivy IaC)
                long iacCriticalCount = countIacCritical(latestScan.getId());
                if (iacCriticalCount > 0) {
                    return createBlockedRun(currentUser, pipeline,
                            "Pipeline BLOQUÉE : " + iacCriticalCount + " misconfiguration(s) IaC critique(s) dans " +
                            linkedRepo.getRepoUrl() + ". Corrigez les configurations IaC avant de relancer.");
                }
            }
        }
        // =====================================================================

        PipelineRun run = PipelineRun.builder()
                .pipeline(pipeline)
                .triggeredBy(currentUser)
                .status(PipelineExecutionStatus.PENDING)
                .approvalRequired(Boolean.TRUE.equals(pipeline.getApprovalRequired()))
                .startedAt(LocalDateTime.now())
                .summary("Run initialisé.")
                .build();
        run = pipelineRunRepo.save(run);

        List<PipelineStageRun> stages = initializeStages(run, pipeline);
        run.setStageRuns(stages);
        pipeline.setLastRunAt(LocalDateTime.now());
        pipelineDefinitionRepo.save(pipeline);
        pipelineRunRepo.save(run);

        PipelineRun persisted = getRunEntity(run.getId());
        emitLog(persisted, null, "Run pipeline initialisé pour " + pipeline.getName() + ".");
        emitSnapshot(persisted);

        Long persistedRunId = persisted.getId();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                executor.submit(() -> executeRun(persistedRunId, false));
            }
        });
        return toRunDto(persisted, true);
    }

    public PipelineRunDto approveRun(User currentUser, Long runId) {
        PipelineRun run = getRunEntity(runId);
        if (run.getStatus() != PipelineExecutionStatus.AWAITING_APPROVAL) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ce run n'attend pas d'approbation.");
        }

        PipelineStageRun approvalStage = findStage(run, PipelineStageType.APPROVAL);
        approvalStage.setStatus(PipelineExecutionStatus.SUCCESS);
        approvalStage.setStartedAt(firstNonNull(approvalStage.getStartedAt(), LocalDateTime.now()));
        approvalStage.setFinishedAt(LocalDateTime.now());
        approvalStage.setDetails("Approuvé manuellement par " + currentUser.getLogin() + ".");
        approvalStage.setLogOutput(appendText(approvalStage.getLogOutput(), "Manual approval granted."));
        pipelineStageRunRepo.save(approvalStage);

        run.setApprovedBy(currentUser);
        run.setApprovedAt(LocalDateTime.now());
        run.setStatus(PipelineExecutionStatus.RUNNING);
        run.setSummary("Approbation reçue, reprise du déploiement de production.");
        pipelineRunRepo.save(run);

        emitLog(run, approvalStage, "Approbation manuelle reçue, reprise de l'exécution.");
        emitSnapshot(run);

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                executor.submit(() -> executeRun(runId, true));
            }
        });
        return toRunDto(getRunEntity(runId), true);
    }

    @Transactional(readOnly = true)
    public List<PipelineRunDto> listRuns(User currentUser, Long pipelineId) {
        getPipelineEntity(pipelineId);
        return pipelineRunRepo.findByPipelineIdOrderByStartedAtDesc(pipelineId).stream()
                .map(run -> toRunDto(run, true))
                .toList();
    }

    @Transactional(readOnly = true)
    public PipelineRunDto getRun(User currentUser, Long runId) {
        return toRunDto(getRunEntity(runId), true);
    }

    private void applyRequest(PipelineDefinition pipeline, PipelineDefinitionRequest request, User owner) {
        Repository repository = request.repositoryId() != null
                ? repositoryRepo.findById(request.repositoryId())
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                                "Repository source introuvable."))
                : null;

        PipelinePresetDto preset = repository != null ? buildPresetSafely(owner, repository) : null;

        String resolvedName = firstNonBlank(
            trimToNull(request.name()),
            trimToNull(preset != null ? preset.name() : null),
            trimToNull(pipeline.getName()),
            derivePipelineName(repository,
                repository != null ? trimToNull(repository.getRepoUrl()) : trimToNull(request.repoUrl())));
        if (resolvedName == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Impossible de générer automatiquement le nom du pipeline sans repository valide.");
        }

        String resolvedRepoUrl = firstNonBlank(
            repository != null ? trimToNull(repository.getRepoUrl()) : null,
            trimToNull(request.repoUrl()),
            trimToNull(preset != null ? preset.repoUrl() : null),
            trimToNull(pipeline.getRepoUrl()));
        if (resolvedRepoUrl == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Sélectionne un repository connu ou renseigne une URL GitHub/GitLab.");
        }
        validateRepoUrl(resolvedRepoUrl);

        String buildCommand = firstNonBlank(
            normalizeCommand(request.buildCommand()),
            normalizeCommand(preset != null ? preset.buildCommand() : null),
            normalizeCommand(pipeline.getBuildCommand()));
        String testCommand = firstNonBlank(
            normalizeCommand(request.testCommand()),
            normalizeCommand(preset != null ? preset.testCommand() : null),
            normalizeCommand(pipeline.getTestCommand()));
        String dockerBuildCommand = firstNonBlank(
            normalizeCommand(request.dockerBuildCommand()),
            normalizeCommand(preset != null ? preset.dockerBuildCommand() : null),
            normalizeCommand(pipeline.getDockerBuildCommand()));
        String containerScanCommand = firstNonBlank(
            normalizeCommand(request.containerScanCommand()),
            normalizeCommand(preset != null ? preset.containerScanCommand() : null),
            normalizeCommand(pipeline.getContainerScanCommand()));
        String stagingDeployCommand = firstNonBlank(
            normalizeCommand(request.stagingDeployCommand()),
            normalizeCommand(preset != null ? preset.stagingDeployCommand() : null),
            normalizeCommand(pipeline.getStagingDeployCommand()));
        String dastCommand = firstNonBlank(
            normalizeCommand(request.dastCommand()),
            normalizeCommand(preset != null ? preset.dastCommand() : null),
            normalizeCommand(pipeline.getDastCommand()));
        String productionDeployCommand = firstNonBlank(
            normalizeCommand(request.productionDeployCommand()),
            normalizeCommand(preset != null ? preset.productionDeployCommand() : null),
            normalizeCommand(pipeline.getProductionDeployCommand()));
        String workspacePath = firstNonBlank(
            trimToNull(request.workspacePath()),
            trimToNull(preset != null ? preset.workspacePath() : null),
            trimToNull(pipeline.getWorkspacePath()));

        ServerNode runnerServer = resolveServer(request.runnerServerId(), pipeline.getRunnerServer(), AutoServerRole.RUNNER);
        ServerNode stagingServer = resolveServer(request.stagingServerId(), pipeline.getStagingServer(), AutoServerRole.STAGING);
        ServerNode productionServer = resolveServer(request.productionServerId(), pipeline.getProductionServer(), AutoServerRole.PRODUCTION);

        if ((buildCommand != null || testCommand != null || dockerBuildCommand != null || containerScanCommand != null)
                && runnerServer == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Aucun runner SSH n'a pu être déduit automatiquement. Sélectionne un serveur runner pour exécuter build/test/container.");
        }
        if (stagingDeployCommand != null && stagingServer == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Aucun serveur staging n'a pu être déduit automatiquement. Sélectionne un serveur staging pour le déploiement.");
        }
        if (dastCommand != null && stagingServer == null && runnerServer == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le DAST a besoin d'un runner ou d'un serveur staging pour exécuter la commande.");
        }
        if (productionDeployCommand != null && productionServer == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Aucun serveur production n'a pu être déduit automatiquement. Sélectionne un serveur production pour le déploiement.");
        }

        pipeline.setName(resolvedName);
        pipeline.setDescription(firstNonBlank(
            trimToNull(request.description()),
            trimToNull(preset != null ? preset.description() : null),
            trimToNull(pipeline.getDescription())));
        pipeline.setRepository(repository);
        pipeline.setRepoUrl(resolvedRepoUrl);
        pipeline.setSourceProvider(repository != null && repository.getGitProvider() != null
                ? repository.getGitProvider()
                : detectProvider(resolvedRepoUrl, owner));
        pipeline.setBranch(firstNonBlank(
            trimToNull(request.branch()),
            trimToNull(preset != null ? preset.branch() : null),
            repository != null ? trimToNull(repository.getBranch()) : null,
            trimToNull(pipeline.getBranch()),
            "main"));
        pipeline.setRunnerServer(runnerServer);
        pipeline.setStagingServer(stagingServer);
        pipeline.setProductionServer(productionServer);
        pipeline.setWorkspacePath(workspacePath);
        pipeline.setBuildCommand(buildCommand);
        pipeline.setTestCommand(testCommand);
        pipeline.setDockerBuildCommand(dockerBuildCommand);
        pipeline.setContainerScanCommand(containerScanCommand);
        pipeline.setStagingDeployCommand(stagingDeployCommand);
        pipeline.setDastCommand(dastCommand);
        pipeline.setProductionDeployCommand(productionDeployCommand);
        pipeline.setApprovalRequired(coalesceBoolean(
            request.approvalRequired(),
            preset != null ? preset.approvalRequired() : null,
            pipeline.getApprovalRequired(),
            Boolean.TRUE));
        pipeline.setFailOnCritical(coalesceBoolean(
            request.failOnCritical(),
            preset != null ? preset.failOnCritical() : null,
            pipeline.getFailOnCritical(),
            Boolean.TRUE));
        pipeline.setFailOnSecrets(coalesceBoolean(
            request.failOnSecrets(),
            preset != null ? preset.failOnSecrets() : null,
            pipeline.getFailOnSecrets(),
            Boolean.TRUE));
        pipeline.setActive(coalesceBoolean(
            request.active(),
            preset != null ? preset.active() : null,
            pipeline.getActive(),
            Boolean.TRUE));
    }

    private List<PipelineStageRun> initializeStages(PipelineRun run, PipelineDefinition pipeline) {
        List<PipelineStageRun> stages = new ArrayList<>();
        List<PipelineStageType> sequence = new ArrayList<>(List.of(
                PipelineStageType.SOURCE,
                PipelineStageType.BUILD,
                PipelineStageType.TEST,
                PipelineStageType.SECURITY_SCAN,
                PipelineStageType.QUALITY_GATE,
                PipelineStageType.DOCKER_BUILD,
                PipelineStageType.CONTAINER_SCAN,
                PipelineStageType.DEPLOY_STAGING,
                PipelineStageType.DAST_SCAN));
        if (Boolean.TRUE.equals(pipeline.getApprovalRequired())) {
            sequence.add(PipelineStageType.APPROVAL);
        }
        sequence.add(PipelineStageType.DEPLOY_PRODUCTION);

        int index = 1;
        for (PipelineStageType type : sequence) {
            stages.add(pipelineStageRunRepo.save(PipelineStageRun.builder()
                    .pipelineRun(run)
                    .stageType(type)
                    .stageOrder(index++)
                    .title(type.label())
                    .status(PipelineExecutionStatus.PENDING)
                    .build()));
        }
        return stages;
    }

    /**
     * Core async execution loop.
     *
     * FIX: Uses findByIdEager (JOIN FETCH) to load all lazy associations in one
     * query before the JPA session closes.  All subsequent DB writes use
     * @Modifying @Query methods that accept plain IDs/scalars, avoiding
     * save(entity) which would cascade to the uninitialized stageRuns collection
     * (CascadeType.ALL + orphanRemoval=true) and throw LazyInitializationException.
     */
    private void executeRun(Long runId, boolean resumeAfterApproval) {
        try {
        // Eagerly load run with pipeline + servers + triggeredBy in one query.
        PipelineRun run = getRunEntityEager(runId);
        PipelineDefinition pipeline = run.getPipeline();   // safe: JOIN FETCH'd
        List<PipelineStageRun> stages = pipelineStageRunRepo.findByPipelineRunIdOrderByStageOrderAsc(runId);
        int startIndex = resumeAfterApproval ? findStageIndex(stages, PipelineStageType.DEPLOY_PRODUCTION) : 0;

        // Mark run as RUNNING using a safe UPDATE query (no entity save needed).
        pipelineRunRepo.setStatus(runId, PipelineExecutionStatus.RUNNING);
        try { emitSnapshotById(runId); } catch (Exception sse) {
            System.err.println("[PIPELINE] emitSnapshotById failed (non-fatal): " + sse.getMessage());
        }

        try {
            for (int index = startIndex; index < stages.size(); index++) {
                PipelineStageRun stage = stages.get(index);
                StageResult result = executeStage(run, pipeline, stage);

                if (result.status() == PipelineExecutionStatus.AWAITING_APPROVAL) {
                    pipelineRunRepo.setStatusStageAndSummary(runId,
                            PipelineExecutionStatus.AWAITING_APPROVAL,
                            stage.getStageType(),
                            result.details());
                    emitSnapshotById(runId);
                    return;
                }
                if (result.status() == PipelineExecutionStatus.BLOCKED
                        || result.status() == PipelineExecutionStatus.FAILED) {
                    pipelineRunRepo.finishRun(runId, result.status(), stage.getStageType(),
                            LocalDateTime.now(), result.details());
                    emitLog(run, stage, result.details());
                    emitCompleteById(runId);
                    return;
                }
            }

            pipelineRunRepo.finishRun(runId, PipelineExecutionStatus.SUCCESS,
                    PipelineStageType.DEPLOY_PRODUCTION, LocalDateTime.now(),
                    "Pipeline exécuté avec succès.");
            emitCompleteById(runId);

        } catch (Exception ex) {
            PipelineStageRun currentStage = resolveCurrentStage(runId);
            if (currentStage != null) {
                String errorLog = appendText(currentStage.getLogOutput(), ex.toString());
                pipelineStageRunRepo.markFinished(currentStage.getId(),
                        PipelineExecutionStatus.FAILED,
                        trimMessage(ex.getMessage()),
                        errorLog,
                        null,
                        LocalDateTime.now());
            }
            pipelineRunRepo.finishRun(runId,
                    PipelineExecutionStatus.FAILED,
                    currentStage != null ? currentStage.getStageType() : null,
                    LocalDateTime.now(),
                    trimMessage(ex.getMessage()));
            emitLog(run, currentStage, trimMessage(ex.getMessage()));
            emitCompleteById(runId);
        }
        } catch (Throwable fatal) {
            // Catch-all: executor.submit() silently swallows exceptions — log them explicitly.
            System.err.println("[PIPELINE][FATAL] executeRun(" + runId + ") threw uncaught exception:");
            fatal.printStackTrace(System.err);
            try {
                pipelineRunRepo.finishRun(runId, PipelineExecutionStatus.FAILED, null,
                        LocalDateTime.now(), "Erreur interne: " + fatal.getMessage());
            } catch (Exception ignored) {}
        }
    }

    private StageResult executeStage(PipelineRun run, PipelineDefinition pipeline, PipelineStageRun stage) {
        // Mark stage as RUNNING via safe UPDATE (avoids cascade to uninitialized stageRuns).
        LocalDateTime stageStart = LocalDateTime.now();
        pipelineStageRunRepo.markRunning(stage.getId(), PipelineExecutionStatus.RUNNING, stageStart);
        stage.setStatus(PipelineExecutionStatus.RUNNING);
        stage.setStartedAt(stageStart);
        stage.setFinishedAt(null);
        stage.setDetails(null);

        pipelineRunRepo.setCurrentStage(run.getId(), stage.getStageType());
        emitLog(run, stage, "Stage " + stage.getTitle() + " démarré.");
        emitSnapshotById(run.getId());

        StageResult result = switch (stage.getStageType()) {
            case SOURCE -> executeSourceStage(run, pipeline, stage);
            case BUILD -> executeRemoteCommandStage(run, stage, pipeline.getRunnerServer(), pipeline.getWorkspacePath(),
                    pipeline.getBuildCommand(), Duration.ofMinutes(20), "Aucune commande de build configurée.");
            case TEST -> executeRemoteCommandStage(run, stage, pipeline.getRunnerServer(), pipeline.getWorkspacePath(),
                    pipeline.getTestCommand(), Duration.ofMinutes(25), "Aucune commande de test configurée.");
            case SECURITY_SCAN -> executeSecurityStage(run, pipeline, stage);
            case QUALITY_GATE -> executeQualityGateStage(run, pipeline, stage);
            case DOCKER_BUILD -> executeDockerBuildStage(run, pipeline, stage);
            case CONTAINER_SCAN -> executeRemoteCommandStage(run, stage, pipeline.getRunnerServer(), pipeline.getWorkspacePath(),
                    pipeline.getContainerScanCommand(), Duration.ofMinutes(20), "Aucune commande de scan conteneur configurée.");
            case DEPLOY_STAGING -> executeRemoteCommandStage(run, stage, pipeline.getStagingServer(), pipeline.getWorkspacePath(),
                    pipeline.getStagingDeployCommand(), Duration.ofMinutes(15), "Aucune commande de déploiement staging configurée.");
            case DAST_SCAN -> executeRemoteCommandStage(run, stage,
                    pipeline.getStagingServer() != null ? pipeline.getStagingServer() : pipeline.getRunnerServer(),
                    pipeline.getWorkspacePath(), pipeline.getDastCommand(), Duration.ofMinutes(20),
                    "Aucune commande DAST configurée.");
            case APPROVAL -> StageResult.awaiting("Run en attente d'approbation manuelle avant la production.");
            case DEPLOY_PRODUCTION -> executeRemoteCommandStage(run, stage, pipeline.getProductionServer(), pipeline.getWorkspacePath(),
                    pipeline.getProductionDeployCommand(), Duration.ofMinutes(15), "Aucune commande de déploiement production configurée.");
        };

        LocalDateTime stageEnd = result.status() != PipelineExecutionStatus.AWAITING_APPROVAL
                ? LocalDateTime.now() : null;
        pipelineStageRunRepo.markFinished(stage.getId(), result.status(), result.details(),
                result.logOutput(), result.relatedScanId(), stageEnd);
        // Keep local stage state in sync for use by emitLog callbacks.
        stage.setStatus(result.status());
        stage.setDetails(result.details());
        stage.setLogOutput(result.logOutput());
        stage.setRelatedScanId(result.relatedScanId());
        stage.setFinishedAt(stageEnd);

        pipelineRunRepo.setCurrentStage(run.getId(), stage.getStageType());
        emitSnapshotById(run.getId());
        return result;
    }

    private StageResult executeSourceStage(PipelineRun run, PipelineDefinition pipeline, PipelineStageRun stage) {
        String repoUrl = resolveRepoUrl(pipeline);
        if (repoUrl == null) {
            return StageResult.failed("Aucune source Git n'est configurée pour ce pipeline.", null);
        }
        if (pipeline.getRunnerServer() == null || trimToNull(pipeline.getWorkspacePath()) == null) {
            return StageResult.success(
                    "Source validée. Aucun checkout distant n'a été exécuté faute de runner/workspacePath.",
                    "Repository: " + repoUrl);
        }

        String authenticatedRepoUrl = buildAuthenticatedRepoUrl(repoUrl, pipeline.getSourceProvider(), run.getTriggeredBy());
        String command = buildSourceSyncCommand(authenticatedRepoUrl,
                trimToNull(pipeline.getBranch()) != null ? trimToNull(pipeline.getBranch()) : "main",
                pipeline.getWorkspacePath());
        return executeRemoteCommandStage(run, stage, pipeline.getRunnerServer(), null, command, Duration.ofMinutes(10),
                "Source stage skipped.");
    }

    private StageResult executeRemoteCommandStage(
            PipelineRun run,
            PipelineStageRun stage,
            ServerNode server,
            String workspacePath,
            String command,
            Duration timeout,
            String skipMessage) {
        if (trimToNull(command) == null) {
            emitLog(run, stage, skipMessage);
            return StageResult.skipped(skipMessage);
        }
        if (server == null) {
            return StageResult.failed("Aucun serveur SSH n'est configuré pour exécuter ce stage.", null);
        }

        StringBuilder liveOutput = new StringBuilder();
        try {
            String remoteCommand = workspacePath != null && !workspacePath.isBlank()
                    ? composeWorkspaceCommand(workspacePath, command)
                    : command;
            SshCommandExecutor.CommandResult result = sshCommandExecutor.executeStreaming(
                    server,
                    remoteCommand,
                    timeout,
                    line -> appendLiveLog(run, stage, line, liveOutput));
            if (result.exitCode() != 0) {
                return StageResult.failed("La commande distante a échoué avec le code " + result.exitCode() + ".",
                        preferOutput(liveOutput, result.output()));
            }
            return StageResult.success("Commande exécutée avec succès.", preferOutput(liveOutput, result.output()));
        } catch (Exception ex) {
            appendLiveLog(run, stage, trimMessage(ex.getMessage()), liveOutput);
            return StageResult.failed("Échec de l'exécution distante: " + trimMessage(ex.getMessage()),
                    liveOutput.length() > 0 ? liveOutput.toString().trim() : ex.toString());
        }
    }

    private StageResult executeSecurityStage(PipelineRun run, PipelineDefinition pipeline, PipelineStageRun stage) {
        String repoUrl = resolveRepoUrl(pipeline);
        if (repoUrl == null) {
            return StageResult.failed("Impossible de lancer le scan: aucune URL repository disponible.", null);
        }
        try {
            emitLog(run, stage, "Initialisation du scan sécurité pour " + repoUrl + ".");
            ScanRequest request = new ScanRequest();
            request.setRepoUrl(repoUrl);
            request.setBranch(trimToNull(pipeline.getBranch()));
            request.setScanMode("auto");

            ScanResponse response = scanService.startScan(request, run.getTriggeredBy());
            emitLog(run, stage, "Scan sécurité démarré: #" + response.getScanId());
            ScanResult scanResult = waitForScanCompletion(response.getScanId(), Duration.ofMinutes(60),
                    message -> emitLog(run, stage, message));
            pipelineRunRepo.setSecurityScanId(run.getId(), response.getScanId());
            run.setSecurityScanId(response.getScanId()); // keep in-memory state in sync
            emitSnapshotById(run.getId());

            if (scanResult.getStatus() != ScanResult.ScanStatus.COMPLETED) {
                return StageResult.failed(
                        "Le scan de sécurité a échoué.",
                        "Scan #" + response.getScanId() + " terminé avec le statut " + scanResult.getStatus());
            }

            int cveCount = cveEntryRepo.findByScanResultId(scanResult.getId()).size();
            int secretCount = secretFindingRepo.findByScanResultId(scanResult.getId()).size();
            String details = "Scan #" + scanResult.getId() + " terminé: " + cveCount + " CVE(s), " + secretCount
                    + " secret(s).";
            emitLog(run, stage, details);
            return StageResult.success(details, details, scanResult.getId());
        } catch (Exception ex) {
            return StageResult.failed("Security Scan en échec: " + trimMessage(ex.getMessage()), ex.toString());
        }
    }

    private StageResult executeQualityGateStage(PipelineRun run, PipelineDefinition pipeline, PipelineStageRun stage) {
        if (run.getSecurityScanId() == null) {
            emitLog(run, stage, "Quality Gate ignoré: aucun scan de sécurité rattaché.");
            return StageResult.skipped("Aucun scan de sécurité rattaché à ce run.");
        }

        List<CveEntry> cves = cveEntryRepo.findByScanResultId(run.getSecurityScanId());
        int secretCount = secretFindingRepo.findByScanResultId(run.getSecurityScanId()).size();
        long criticalCount = cves.stream().filter(this::isCritical).count();
        long highCount = cves.stream().filter(this::isHigh).count();
        long highWithFixCount = cves.stream()
                .filter(c -> isHigh(c) && !isCritical(c)
                        && c.getFixedVersion() != null && !c.getFixedVersion().isBlank())
                .count();
        long sastCriticalCount = cves.stream()
                .filter(c -> "semgrep".equalsIgnoreCase(c.getSource()) && isCritical(c))
                .count();
        long iacCriticalCount = countIacCritical(run.getSecurityScanId());

        String details = String.format(
                "Quality Gate: critical=%d, high=%d, highWithFix=%d, secrets=%d, sastCritical=%d, iacCritical=%d.",
                criticalCount, highCount, highWithFixCount, secretCount, sastCriticalCount, iacCriticalCount);
        emitLog(run, stage, details);

        if (Boolean.TRUE.equals(pipeline.getFailOnSecrets()) && secretCount > 0) {
            emitLog(run, stage, "Blocage: " + secretCount + " secret(s) détecté(s).");
            return StageResult.blocked(details + " Blocage: secrets détectés.");
        }
        if (Boolean.TRUE.equals(pipeline.getFailOnCritical()) && criticalCount > 0) {
            emitLog(run, stage, "Blocage: " + criticalCount + " CVE(s) CRITICAL.");
            return StageResult.blocked(details + " Blocage: CVE(s) critique(s) détectée(s).");
        }
        if (highWithFixCount > 0) {
            emitLog(run, stage, "Blocage: " + highWithFixCount + " CVE(s) HIGH avec correctif disponible.");
            return StageResult.blocked(details + " Blocage: CVE(s) HIGH avec fix disponible.");
        }
        if (sastCriticalCount > 0) {
            emitLog(run, stage, "Blocage: " + sastCriticalCount + " vulnérabilité(s) SAST critique(s) (Semgrep).");
            return StageResult.blocked(details + " Blocage: vulnérabilités SAST critiques détectées.");
        }
        if (iacCriticalCount > 0) {
            emitLog(run, stage, "Blocage: " + iacCriticalCount + " misconfiguration(s) IaC critique(s).");
            return StageResult.blocked(details + " Blocage: misconfiguration(s) IaC critique(s) détectée(s).");
        }
        return StageResult.success(details, details);
    }

    private StageResult executeDockerBuildStage(PipelineRun run, PipelineDefinition pipeline, PipelineStageRun stage) {
        StageResult buildResult = executeRemoteCommandStage(run, stage, pipeline.getRunnerServer(), pipeline.getWorkspacePath(),
                pipeline.getDockerBuildCommand(), Duration.ofMinutes(25), "Aucune commande Docker build configurée.");
        if (buildResult.status() != PipelineExecutionStatus.SUCCESS) {
            return buildResult;
        }

        User triggeredBy = run.getTriggeredBy();
        boolean hasDockerHub = userService.hasDockerHubCredential(triggeredBy);
        boolean hasGhcr = userService.hasGhcrCredential(triggeredBy);

        if (!hasDockerHub && !hasGhcr) {
            emitLog(run, stage, "Aucun credential Docker Hub ou GHCR configuré: push automatique ignoré.");
            return buildResult;
        }
        if (pipeline.getRunnerServer() == null) {
            return StageResult.failed("Push registre Docker impossible: aucun runner SSH configuré.", buildResult.logOutput());
        }

        List<String> images = extractImageRefs(trimToNull(pipeline.getDockerBuildCommand()));
        if (images.isEmpty()) {
            emitLog(run, stage, "Aucune image détectée dans la commande Docker build: push ignoré.");
            return buildResult;
        }

        StringBuilder pushOutput = new StringBuilder();
        try {
            // --- GHCR push (GitHub Container Registry) ---
            if (hasGhcr) {
                String ghcrUsername = triggeredBy.getLogin();
                String ghcrToken = userService.getGhcrToken(triggeredBy);
                emitLog(run, stage, "Connexion GHCR (ghcr.io) pour push automatique vers " + ghcrUsername + ".");
                sshCommandExecutor.executeStreaming(
                        pipeline.getRunnerServer(),
                        "printf %s " + shellLiteral(ghcrToken) + " | docker login ghcr.io -u " + shellLiteral(ghcrUsername) + " --password-stdin",
                        Duration.ofMinutes(2),
                        line -> appendLiveLog(run, stage, line, pushOutput));

                for (String image : images) {
                    String ghcrImage = qualifyGhcrImage(image, ghcrUsername);
                    if (!Objects.equals(ghcrImage, image)) {
                        sshCommandExecutor.executeStreaming(
                                pipeline.getRunnerServer(),
                                "docker tag " + shellLiteral(image) + " " + shellLiteral(ghcrImage),
                                Duration.ofMinutes(2),
                                line -> appendLiveLog(run, stage, line, pushOutput));
                    }
                    emitLog(run, stage, "Push GHCR: " + ghcrImage);
                    sshCommandExecutor.executeStreaming(
                            pipeline.getRunnerServer(),
                            "docker push " + shellLiteral(ghcrImage),
                            Duration.ofMinutes(20),
                            line -> appendLiveLog(run, stage, line, pushOutput));
                }
            }

            // --- Docker Hub push ---
            if (hasDockerHub) {
                String dhUsername = userService.getDockerHubUsername(triggeredBy);
                String dhToken = userService.getDockerHubToken(triggeredBy);
                if (dhUsername != null && !dhUsername.isBlank() && dhToken != null && !dhToken.isBlank()) {
                    emitLog(run, stage, "Connexion Docker Hub pour push automatique vers " + dhUsername + ".");
                    sshCommandExecutor.executeStreaming(
                            pipeline.getRunnerServer(),
                            "printf %s " + shellLiteral(dhToken) + " | docker login -u " + shellLiteral(dhUsername) + " --password-stdin",
                            Duration.ofMinutes(2),
                            line -> appendLiveLog(run, stage, line, pushOutput));

                    for (String image : images) {
                        String dhImage = qualifyDockerImage(image, dhUsername);
                        if (!Objects.equals(dhImage, image)) {
                            sshCommandExecutor.executeStreaming(
                                    pipeline.getRunnerServer(),
                                    "docker tag " + shellLiteral(image) + " " + shellLiteral(dhImage),
                                    Duration.ofMinutes(2),
                                    line -> appendLiveLog(run, stage, line, pushOutput));
                        }
                        emitLog(run, stage, "Push Docker Hub: " + dhImage);
                        sshCommandExecutor.executeStreaming(
                                pipeline.getRunnerServer(),
                                "docker push " + shellLiteral(dhImage),
                                Duration.ofMinutes(20),
                                line -> appendLiveLog(run, stage, line, pushOutput));
                    }
                }
            }

            String combinedOutput = appendText(buildResult.logOutput(), pushOutput.toString().trim());
            String registries = (hasGhcr ? "GHCR" : "") + (hasGhcr && hasDockerHub ? " + " : "") + (hasDockerHub ? "Docker Hub" : "");
            return StageResult.success("Docker build et push automatique exécutés (" + registries + ").", combinedOutput);
        } catch (Exception ex) {
            String combinedOutput = appendText(buildResult.logOutput(), pushOutput.toString().trim());
            return StageResult.failed("Docker build ok mais push registre en échec: " + trimMessage(ex.getMessage()), combinedOutput);
        }
    }

    private ScanResult waitForScanCompletion(Long scanId, Duration timeout, Consumer<String> statusConsumer) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        ScanResult.ScanStatus lastStatus = null;
        while (System.currentTimeMillis() < deadline) {
            ScanResult scan = scanResultRepo.findById(scanId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan introuvable."));
            if (scan.getStatus() != lastStatus && lastStatus != null && statusConsumer != null) {
                statusConsumer.accept("Scan sécurité: statut " + scan.getStatus());
            }
            lastStatus = scan.getStatus();
            if (scan.getStatus() != ScanResult.ScanStatus.RUNNING && scan.getStatus() != ScanResult.ScanStatus.PENDING) {
                return scan;
            }
            if (statusConsumer != null) {
                statusConsumer.accept("Scan sécurité toujours en cours...");
            }
            Thread.sleep(2_000);
        }
        throw new IllegalStateException("Timeout pendant l'attente du scan de sécurité.");
    }

    private void appendLiveLog(PipelineRun run, PipelineStageRun stage, String line, StringBuilder collector) {
        if (line == null || line.isBlank()) {
            return;
        }
        if (collector.length() > 0) {
            collector.append(System.lineSeparator());
        }
        collector.append(line);
        emitLog(run, stage, line);
    }

    private void emitLog(PipelineRun run, PipelineStageRun stage, String message) {
        if (run == null || message == null || message.isBlank()) {
            return;
        }
        pipelineEventStreamService.publish(run.getId(), new PipelineLogEventDto(
                "log",
                run.getId(),
                stage != null ? stage.getId() : null,
                stage != null && stage.getStageType() != null ? stage.getStageType().name() : null,
                message,
                null,
                LocalDateTime.now()));
    }

    private void emitSnapshot(PipelineRun run) {
        if (run == null) {
            return;
        }
        emitSnapshotById(run.getId());
    }

    private void emitComplete(PipelineRun run) {
        if (run == null) {
            return;
        }
        emitCompleteById(run.getId());
    }

    /** Safe to call from async executor thread — uses JOIN FETCH to avoid LazyInitializationException. */
    private void emitSnapshotById(Long runId) {
        PipelineRun fresh = getRunEntityEager(runId);
        PipelineRunDto snapshot = toRunDto(fresh, true);
        pipelineEventStreamService.publish(runId, new PipelineLogEventDto(
                "snapshot",
                runId,
                null,
                snapshot.currentStage(),
                snapshot.summary(),
                snapshot,
                LocalDateTime.now()));
    }

    /** Safe to call from async executor thread — uses JOIN FETCH to avoid LazyInitializationException. */
    private void emitCompleteById(Long runId) {
        PipelineRun fresh = getRunEntityEager(runId);
        PipelineRunDto snapshot = toRunDto(fresh, true);
        pipelineEventStreamService.publish(runId, new PipelineLogEventDto(
                "complete",
                runId,
                null,
                snapshot.currentStage(),
                snapshot.summary(),
                snapshot,
                LocalDateTime.now()));
    }

    private List<String> extractImageRefs(String command) {
        List<String> images = new ArrayList<>();
        if (command == null || command.isBlank()) {
            return images;
        }
        for (String line : command.split("\\R")) {
            Matcher matcher = IMAGE_TAG_PATTERN.matcher(line);
            while (matcher.find()) {
                images.add(matcher.group(1).trim());
            }
        }
        return images;
    }

    private String qualifyDockerImage(String image, String username) {
        String withoutTag = image.contains(":") ? image.substring(0, image.lastIndexOf(':')) : image;
        String tag = image.contains(":") ? image.substring(image.lastIndexOf(':')) : ":latest";
        if (withoutTag.contains("/")) {
            return image;
        }
        return username + "/" + withoutTag + tag;
    }

    private String qualifyGhcrImage(String image, String githubUsername) {
        if (image.startsWith("ghcr.io/")) {
            return image; // already fully qualified for GHCR
        }
        String withoutTag = image.contains(":") ? image.substring(0, image.lastIndexOf(':')) : image;
        String tag = image.contains(":") ? image.substring(image.lastIndexOf(':')) : ":latest";
        // Strip any existing registry prefix, keep only the bare image name.
        String imageName = withoutTag.contains("/") ? withoutTag.substring(withoutTag.lastIndexOf('/') + 1) : withoutTag;
        return "ghcr.io/" + githubUsername + "/" + imageName + tag;
    }

    private String preferOutput(StringBuilder streamed, String finalOutput) {
        if (streamed != null && streamed.length() > 0) {
            return streamed.toString().trim();
        }
        return finalOutput;
    }

    /**
     * Compte les misconfigurations IaC de sévérité HIGH ou CRITICAL en lisant
     * les fichiers JSON produits par Checkov et Trivy IaC dans le répertoire
     * de résultats du scan.
     */
    private long countIacCritical(Long scanResultId) {
        try {
            ScanResult scanResult = scanResultRepo.findById(scanResultId).orElse(null);
            if (scanResult == null || scanResult.getResultsDir() == null) {
                return 0L;
            }
            long count = 0L;

            // --- Checkov ---
            File checkovFile = new File(scanResult.getResultsDir(), "checkov.json");
            if (checkovFile.exists()) {
                JsonNode root = objectMapper.readTree(checkovFile);
                // Checkov peut produire un tableau (multi-runner) ou un objet unique
                JsonNode node = root.isArray() ? root.get(0) : root;
                JsonNode failedChecks = node.path("results").path("failed_checks");
                if (failedChecks.isArray()) {
                    for (JsonNode check : failedChecks) {
                        String sev = check.path("severity").asText("").toUpperCase(Locale.ROOT);
                        if ("CRITICAL".equals(sev) || "HIGH".equals(sev)) {
                            count++;
                        }
                    }
                }
            }

            // --- Trivy IaC ---
            File trivyIacFile = new File(scanResult.getResultsDir(), "trivy-iac.json");
            if (trivyIacFile.exists()) {
                JsonNode root = objectMapper.readTree(trivyIacFile);
                JsonNode results = root.path("Results");
                if (results.isArray()) {
                    for (JsonNode result : results) {
                        JsonNode misconfigs = result.path("Misconfigurations");
                        if (misconfigs.isArray()) {
                            for (JsonNode mc : misconfigs) {
                                String sev = mc.path("Severity").asText("").toUpperCase(Locale.ROOT);
                                String status = mc.path("Status").asText("").toUpperCase(Locale.ROOT);
                                if ("FAIL".equals(status) && ("CRITICAL".equals(sev) || "HIGH".equals(sev))) {
                                    count++;
                                }
                            }
                        }
                    }
                }
            }

            return count;
        } catch (Exception ex) {
            log.warn("Impossible de lire les résultats IaC (non bloquant): {}", ex.getMessage());
            return 0L;
        }
    }

    private boolean isCritical(CveEntry entry) {
        return (entry.getCvssScore() != null && entry.getCvssScore() >= 9.0d)
                || "CRITICAL".equalsIgnoreCase(entry.getSeverity());
    }

    private boolean isHigh(CveEntry entry) {
        return isCritical(entry)
                || (entry.getCvssScore() != null && entry.getCvssScore() >= 7.0d)
                || "HIGH".equalsIgnoreCase(entry.getSeverity());
    }

    private PipelineDefinition getPipelineEntity(Long id) {
        return pipelineDefinitionRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Pipeline introuvable."));
    }

    /**
     * Crée un pipeline run immédiatement en statut BLOCKED avec un message d'explication.
     * Aucun stage n'est exécuté — c'est un veto de sécurité.
     */
    private PipelineRunDto createBlockedRun(User triggeredBy, PipelineDefinition pipeline, String reason) {
        PipelineRun blocked = PipelineRun.builder()
                .pipeline(pipeline)
                .triggeredBy(triggeredBy)
                .status(PipelineExecutionStatus.BLOCKED)
                .approvalRequired(false)
                .startedAt(LocalDateTime.now())
                .finishedAt(LocalDateTime.now())
                .summary(reason)
                .build();
        blocked = pipelineRunRepo.save(blocked);
        pipeline.setLastRunAt(LocalDateTime.now());
        pipelineDefinitionRepo.save(pipeline);
        PipelineRun persisted = getRunEntity(blocked.getId());
        emitLog(persisted, null, "[SECURITY GATE] " + reason);
        emitSnapshot(persisted);
        return toRunDto(persisted, true);
    }

    /**
     * Déclenche un scan de sécurité automatique sur le repo lié à la pipeline.
     * Le scan tourne en arrière-plan via ScanService (non bloquant).
     */
    private void triggerAutoScan(Repository repo, User triggeredBy) {
        try {
            ScanRequest req = new ScanRequest();
            req.setRepoUrl(repo.getRepoUrl());
            req.setBranch(repo.getBranch() != null ? repo.getBranch() : "main");
            req.setScanMode("auto");
            scanService.startScan(req, triggeredBy);
        } catch (Exception e) {
            log.warn("Auto-scan pipeline failed for repo {}: {}", repo.getRepoUrl(), e.getMessage());
        }
    }

    private PipelineRun getRunEntity(Long id) {
        return pipelineRunRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Run pipeline introuvable."));
    }

    /**
     * Like getRunEntity but uses JOIN FETCH to eagerly load pipeline + servers +
     * triggeredBy in a single query.  Safe to call from the async executor thread
     * where there is no active JPA session.
     */
    private PipelineRun getRunEntityEager(Long id) {
        return pipelineRunRepo.findByIdEager(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Run pipeline introuvable."));
    }

    private PipelineStageRun findStage(PipelineRun run, PipelineStageType type) {
        return pipelineStageRunRepo.findByPipelineRunIdOrderByStageOrderAsc(run.getId()).stream()
                .filter(stage -> stage.getStageType() == type)
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Stage introuvable."));
    }

    private int findStageIndex(List<PipelineStageRun> stages, PipelineStageType type) {
        for (int index = 0; index < stages.size(); index++) {
            if (stages.get(index).getStageType() == type) {
                return index;
            }
        }
        return 0;
    }

    private PipelineStageRun resolveCurrentStage(Long runId) {
        return pipelineStageRunRepo.findByPipelineRunIdOrderByStageOrderAsc(runId).stream()
                .filter(stage -> stage.getStatus() == PipelineExecutionStatus.RUNNING)
                .findFirst()
                .orElse(null);
    }

    private ServerNode resolveServer(Long id, ServerNode currentValue, AutoServerRole role) {
        if (id != null) {
            return serverNodeRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Serveur introuvable."));
        }
        if (currentValue != null) {
            return currentValue;
        }
        return findAutoServer(role);
    }

    private ServerNode findAutoServer(AutoServerRole role) {
        List<ServerNode> activeServers = serverNodeRepo.findAllByOrderByNodeTypeAscNameAsc().stream()
                .filter(server -> Boolean.TRUE.equals(server.getActive()))
                .toList();
        List<ServerNode> directMatches = activeServers.stream()
                .filter(server -> matchesAutoRole(server, role))
                .toList();
        if (directMatches.size() == 1) {
            return directMatches.get(0);
        }
        if (role == AutoServerRole.RUNNER) {
            List<ServerNode> runnerCandidates = activeServers.stream()
                    .filter(server -> server.getNodeType() == ServerNodeType.SCANNER_NODE
                            || server.getNodeType() == ServerNodeType.CUSTOM)
                    .toList();
            if (runnerCandidates.size() == 1) {
                return runnerCandidates.get(0);
            }
        }
        if (activeServers.size() == 1) {
            return activeServers.get(0);
        }
        return null;
    }

    private boolean matchesAutoRole(ServerNode server, AutoServerRole role) {
        String searchable = searchableServerText(server);
        return switch (role) {
            case RUNNER -> searchable.contains("runner")
                    || searchable.contains("build")
                    || searchable.contains("ci")
                    || searchable.contains("scanner")
                    || server.getNodeType() == ServerNodeType.SCANNER_NODE;
            case STAGING -> server.getNodeType() == ServerNodeType.STAGING
                    || searchable.contains("staging")
                    || searchable.contains("stage")
                    || searchable.contains("preprod")
                    || searchable.contains("uat")
                    || searchable.contains("lab");
            case PRODUCTION -> server.getNodeType() == ServerNodeType.PRODUCTION
                    || searchable.contains("production")
                    || searchable.contains("prod");
        };
    }

    private String searchableServerText(ServerNode server) {
        return String.join(" ",
                server.getName() != null ? server.getName() : "",
                server.getEnvironment() != null ? server.getEnvironment() : "",
                server.getTemplateKey() != null ? server.getTemplateKey() : "",
                server.getOwner() != null ? server.getOwner() : "",
                server.getProjectName() != null ? server.getProjectName() : "",
                server.getDescription() != null ? server.getDescription() : "",
                server.getNotes() != null ? server.getNotes() : "",
                server.getTags() != null ? server.getTags() : "")
                .toLowerCase(Locale.ROOT);
    }

    private PipelinePresetDto buildPresetSafely(User owner, Repository repository) {
        try {
            return pipelinePresetService.buildMonolithPreset(owner, repository);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String derivePipelineName(Repository repository, String repoUrl) {
        String label = repository != null ? formatRepoLabel(repository.getRepoUrl()) : formatRepoLabel(repoUrl);
        if (label == null || label.isBlank()) {
            return null;
        }
        return label.replace('/', '-').replaceAll("[^A-Za-z0-9-]+", "-") + "-pipeline";
    }

    private PipelineDefinitionDto toDefinitionDto(PipelineDefinition pipeline) {
        PipelineRun lastRun = pipelineRunRepo.findFirstByPipelineIdOrderByStartedAtDesc(pipeline.getId());

        // Security gate info
        String scanStatus = null;
        Long criticalCount = null;
        Long scanResultId = null;
        if (pipeline.getRepository() != null) {
            ScanResult latestScan = scanResultRepo.findFirstByRepositoryIdOrderByStartedAtDesc(
                    pipeline.getRepository().getId());
            if (latestScan != null) {
                scanStatus = latestScan.getStatus().name();
                scanResultId = latestScan.getId();
                if (latestScan.getStatus() == ScanResult.ScanStatus.COMPLETED) {
                    criticalCount = cveEntryRepo.countByScanResultIdAndSeverity(latestScan.getId(), "CRITICAL");
                }
            }
        }

        return new PipelineDefinitionDto(
                pipeline.getId(),
                pipeline.getName(),
                pipeline.getDescription(),
                pipeline.getRepository() != null ? pipeline.getRepository().getId() : null,
                pipeline.getRepository() != null ? formatRepoLabel(pipeline.getRepository().getRepoUrl()) : null,
                resolveRepoUrl(pipeline),
                pipeline.getBranch(),
                pipeline.getSourceProvider() != null ? pipeline.getSourceProvider().name() : null,
                pipeline.getRunnerServer() != null ? pipeline.getRunnerServer().getId() : null,
                pipeline.getRunnerServer() != null ? pipeline.getRunnerServer().getName() : null,
                pipeline.getStagingServer() != null ? pipeline.getStagingServer().getId() : null,
                pipeline.getStagingServer() != null ? pipeline.getStagingServer().getName() : null,
                pipeline.getProductionServer() != null ? pipeline.getProductionServer().getId() : null,
                pipeline.getProductionServer() != null ? pipeline.getProductionServer().getName() : null,
                pipeline.getWorkspacePath(),
                pipeline.getBuildCommand(),
                pipeline.getTestCommand(),
                pipeline.getDockerBuildCommand(),
                pipeline.getContainerScanCommand(),
                pipeline.getStagingDeployCommand(),
                pipeline.getDastCommand(),
                pipeline.getProductionDeployCommand(),
                Boolean.TRUE.equals(pipeline.getApprovalRequired()),
                !Boolean.FALSE.equals(pipeline.getFailOnCritical()),
                !Boolean.FALSE.equals(pipeline.getFailOnSecrets()),
                !Boolean.FALSE.equals(pipeline.getActive()),
                pipeline.getCreatedAt(),
                pipeline.getUpdatedAt(),
                pipeline.getLastRunAt(),
                lastRun != null ? toRunDto(lastRun, false) : null,
                scanStatus,
                criticalCount,
                scanResultId);
    }

    private PipelineRunDto toRunDto(PipelineRun run, boolean includeStages) {
        List<PipelineStageRunDto> stages = includeStages
                ? pipelineStageRunRepo.findByPipelineRunIdOrderByStageOrderAsc(run.getId()).stream()
                        .map(this::toStageDto)
                        .toList()
                : List.of();
        return new PipelineRunDto(
                run.getId(),
                run.getPipeline() != null ? run.getPipeline().getId() : null,
                run.getPipeline() != null ? run.getPipeline().getName() : null,
                run.getStatus() != null ? run.getStatus().name() : null,
                run.getCurrentStage() != null ? run.getCurrentStage().name() : null,
                Boolean.TRUE.equals(run.getApprovalRequired()),
                run.getSecurityScanId(),
                run.getSummary(),
                run.getTriggeredBy() != null ? run.getTriggeredBy().getLogin() : null,
                run.getApprovedBy() != null ? run.getApprovedBy().getLogin() : null,
                run.getStartedAt(),
                run.getFinishedAt(),
                run.getApprovedAt(),
                stages);
    }

    private PipelineStageRunDto toStageDto(PipelineStageRun stage) {
        return new PipelineStageRunDto(
                stage.getId(),
                stage.getStageType() != null ? stage.getStageType().name() : null,
                stage.getTitle(),
                stage.getStageOrder(),
                stage.getStatus() != null ? stage.getStatus().name() : null,
                stage.getDetails(),
                stage.getLogOutput(),
                stage.getRelatedScanId(),
                stage.getStartedAt(),
                stage.getFinishedAt());
    }

    private String resolveRepoUrl(PipelineDefinition pipeline) {
        if (pipeline.getRepoUrl() != null && !pipeline.getRepoUrl().isBlank()) {
            return pipeline.getRepoUrl();
        }
        return pipeline.getRepository() != null ? pipeline.getRepository().getRepoUrl() : null;
    }

    private String formatRepoLabel(String repoUrl) {
        if (repoUrl == null || repoUrl.isBlank()) {
            return null;
        }
        String normalized = repoUrl.replace(".git", "");
        String[] parts = normalized.split("/");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "/" + parts[parts.length - 1];
        }
        return normalized;
    }

    private String buildAuthenticatedRepoUrl(String repoUrl, AuthProvider provider, User user) {
        if (repoUrl == null || repoUrl.isBlank() || user == null || provider == null) {
            return repoUrl;
        }

        String accessToken = userService.getAccessToken(user, provider);
        if (accessToken == null || accessToken.isBlank()) {
            return repoUrl;
        }

        String encodedToken = URLEncoder.encode(accessToken, StandardCharsets.UTF_8);
        return switch (provider) {
            case GITLAB -> repoUrl.startsWith("https://")
                    ? repoUrl.replaceFirst("^https://", "https://oauth2:" + encodedToken + "@")
                    : repoUrl;
            case GITHUB -> repoUrl.startsWith("https://")
                    ? repoUrl.replaceFirst("^https://", "https://x-access-token:" + encodedToken + "@")
                    : repoUrl;
            default -> repoUrl;
        };
    }

    private String buildSourceSyncCommand(String repoUrl, String branch, String workspacePath) {
        String safeWorkspace = shellLiteral(workspacePath);
        String safeParent = shellLiteral(parentDir(workspacePath));
        String safeRepo = shellLiteral(repoUrl);
        String safeBranch = shellLiteral(branch);
        return "workspace=" + safeWorkspace + "\n"
                + "parent=" + safeParent + "\n"
                + "repo=" + safeRepo + "\n"
                + "branch=" + safeBranch + "\n"
                + "mkdir -p \"$parent\"\n"
                + "if [ -d \"$workspace/.git\" ]; then\n"
                + "  cd \"$workspace\"\n"
                + "  git remote set-url origin \"$repo\"\n"
                + "  git fetch --all --prune\n"
                + "  git checkout \"$branch\"\n"
                + "  git pull origin \"$branch\"\n"
                + "elif [ -d \"$workspace\" ] && [ \"$(ls -A \"$workspace\" 2>/dev/null)\" ]; then\n"
                + "  echo \"Workspace path exists and is not a git repository: $workspace\"\n"
                + "  exit 1\n"
                + "else\n"
                + "  git clone --branch \"$branch\" \"$repo\" \"$workspace\"\n"
                + "fi";
    }

    private String composeWorkspaceCommand(String workspacePath, String command) {
        if (trimToNull(workspacePath) == null) {
            return command;
        }
        String prefix = "cd " + shellLiteral(workspacePath) + " && ";
        // Prefix each non-empty line with the workspace cd so that
        // sub-directory changes (e.g. "cd Backend") don't accumulate across lines.
        String[] lines = command.split("\\n");
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (sb.length() > 0) sb.append(" && ");
            sb.append(prefix).append(trimmed);
        }
        return sb.length() > 0 ? sb.toString() : command;
    }

    private String parentDir(String workspacePath) {
        String normalized = workspacePath.replace('\\', '/');
        int index = normalized.lastIndexOf('/');
        if (index <= 0) {
            return ".";
        }
        return normalized.substring(0, index);
    }

    private String shellLiteral(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private Boolean coalesceBoolean(Boolean... values) {
        for (Boolean value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private void validateRepoUrl(String repoUrl) {
        String lower = repoUrl.toLowerCase(Locale.ROOT);
        if (lower.startsWith("docker://") || lower.startsWith("ssl://") || lower.startsWith("dast://")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le pipeline attend une URL Git source, pas une entrée technique de scan.");
        }
    }

    private AuthProvider detectProvider(String repoUrl, User owner) {
        String lower = repoUrl.toLowerCase(Locale.ROOT);
        if (lower.contains("gitlab")) {
            return AuthProvider.GITLAB;
        }
        if (lower.contains("github")) {
            return AuthProvider.GITHUB;
        }
        return owner != null && owner.getPrimaryProvider() != null ? owner.getPrimaryProvider() : AuthProvider.GITHUB;
    }

    private String normalizeCommand(String value) {
        String trimmed = trimToNull(value);
        return trimmed != null ? trimmed.replace("\r\n", "\n") : null;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String trimMessage(String value) {
        if (value == null || value.isBlank()) {
            return "Erreur pipeline inconnue.";
        }
        return value.length() > 1000 ? value.substring(0, 1000) : value;
    }

    private String appendText(String existing, String addition) {
        if (addition == null || addition.isBlank()) {
            return existing;
        }
        if (existing == null || existing.isBlank()) {
            return addition;
        }
        return existing + System.lineSeparator() + addition;
    }

    private LocalDateTime firstNonNull(LocalDateTime value, LocalDateTime fallback) {
        return value != null ? value : fallback;
    }

    private enum AutoServerRole {
        RUNNER,
        STAGING,
        PRODUCTION
    }

    private record StageResult(PipelineExecutionStatus status, String details, String logOutput, Long relatedScanId) {
        static StageResult success(String details, String logOutput) {
            return new StageResult(PipelineExecutionStatus.SUCCESS, details, logOutput, null);
        }

        static StageResult success(String details, String logOutput, Long relatedScanId) {
            return new StageResult(PipelineExecutionStatus.SUCCESS, details, logOutput, relatedScanId);
        }

        static StageResult failed(String details, String logOutput) {
            return new StageResult(PipelineExecutionStatus.FAILED, details, logOutput, null);
        }

        static StageResult skipped(String details) {
            return new StageResult(PipelineExecutionStatus.SKIPPED, details, null, null);
        }

        static StageResult blocked(String details) {
            return new StageResult(PipelineExecutionStatus.BLOCKED, details, details, null);
        }

        static StageResult awaiting(String details) {
            return new StageResult(PipelineExecutionStatus.AWAITING_APPROVAL, details, null, null);
        }
    }
}
