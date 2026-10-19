package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.medianet.entity.CiPipelineLink;
import com.medianet.entity.ServerDeployment;
import com.medianet.repository.CiPipelineLinkRepo;
import com.medianet.repository.ServerDeploymentRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

/**
 * Continuous deployment: every 30 s, for each repository with CI and at least one deployment marked "automatic",
 * looks at the newest finished pipeline of the deployment branch. Green (tests, lint, build and Vulnix gate) →
 * the exact commit goes to the server; red → nothing moves. Each pipeline is handled once, and the first round
 * after the CD is switched on only records where things stand (the first install is done by hand).
 */
@Service
public class CiDeployWatcher {

    private static final Logger log = LoggerFactory.getLogger(CiDeployWatcher.class);
    private static final Set<String> FINISHED = Set.of("success", "failure", "error", "killed", "declined");
    private static final Set<String> DEPLOYABLE_EVENTS = Set.of("push", "manual");

    private final WoodpeckerClient woodpecker;
    private final CiPipelineLinkRepo linkRepo;
    private final ServerDeploymentRepo deploymentRepo;
    private final DeployService deployService;

    public CiDeployWatcher(WoodpeckerClient woodpecker, CiPipelineLinkRepo linkRepo, ServerDeploymentRepo deploymentRepo,
            DeployService deployService) {
        this.woodpecker = woodpecker;
        this.linkRepo = linkRepo;
        this.deploymentRepo = deploymentRepo;
        this.deployService = deployService;
    }

    /** What to do with the newest finished pipeline of a branch. Package-private for tests. */
    record Decision(Long newestFinished, JsonNode toDeploy) {
    }

    /**
     * @param pipelines Woodpecker's list, newest first
     * @param handled   newest pipeline already looked at (null = first round)
     */
    static Decision decide(JsonNode pipelines, String branch, Long handled) {
        for (JsonNode p : pipelines) {
            if (!branch.equals(p.path("branch").asText()) || !DEPLOYABLE_EVENTS.contains(p.path("event").asText())) {
                continue;
            }
            if (!FINISHED.contains(p.path("status").asText())) {
                continue; // still running: the decision waits for it to finish
            }
            long number = p.path("number").asLong();
            if (handled != null && number <= handled) {
                return new Decision(handled, null);
            }
            boolean green = "success".equals(p.path("status").asText());
            return new Decision(number, handled != null && green ? p : null);
        }
        return new Decision(handled, null);
    }

    /** Deploys take minutes: they run here, not on Spring's single scheduler thread (orphan scans, SSL alerts…). */
    private final java.util.concurrent.ExecutorService worker = java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "cd-watcher");
        t.setDaemon(true);
        return t;
    });
    private final java.util.concurrent.atomic.AtomicBoolean busy = new java.util.concurrent.atomic.AtomicBoolean();

    @Scheduled(initialDelay = 60_000L, fixedDelay = 30_000L)
    public void tick() {
        if (!woodpecker.isConfigured() || !busy.compareAndSet(false, true)) {
            return;
        }
        worker.submit(() -> {
            try {
                round();
            } finally {
                busy.set(false);
            }
        });
    }

    void round() {
        for (CiPipelineLink link : linkRepo.findAll()) {
            List<ServerDeployment> targets = deploymentRepo.findByLinkedRepositoryIdAndAutoDeployEnabledTrue(link.getRepositoryId());
            if (targets.isEmpty()) {
                continue;
            }
            try {
                handle(link, targets);
            } catch (Exception e) {
                log.warn("[CD] repo={} skipped this round: {}", link.getRepositoryId(), e.getMessage());
            }
        }
    }

    private void handle(CiPipelineLink link, List<ServerDeployment> targets) {
        JsonNode pipelines = woodpecker.pipelines(link.getWoodpeckerRepoId(), 10);
        // Deployments of one repository may follow different branches: one decision per branch.
        for (String branch : targets.stream().map(t -> t.getDeployBranch() == null ? "main" : t.getDeployBranch()).distinct().toList()) {
            Decision d = decide(pipelines, branch, link.getCdLastPipeline());
            if (d.toDeploy() != null) {
                long number = d.toDeploy().path("number").asLong();
                String sha = d.toDeploy().path("commit").asText();
                for (ServerDeployment t : targets) {
                    if (!branch.equals(t.getDeployBranch() == null ? "main" : t.getDeployBranch())) continue;
                    if (t.getPinnedCommit() != null) {
                        log.info("[CD] pipeline #{} green, deployment={} keeps its pinned version {}", number, t.getId(),
                                t.getPinnedCommit().substring(0, Math.min(12, t.getPinnedCommit().length())));
                        continue;
                    }
                    if (Boolean.TRUE.equals(t.getApprovalRequired())) {
                        log.info("[CD] pipeline #{} green, waiting for approval on deployment={}", number, t.getId());
                        deployService.requestApproval(t.getId(), sha, number);
                        continue;
                    }
                    log.info("[CD] pipeline #{} green, deploying {} to deployment={}", number, sha.substring(0, 12), t.getId());
                    if (deployService.deployCommit(t.getId(), sha, number) == null) {
                        log.info("[CD] deployment={} busy, retry next round", t.getId());
                        return; // keep cdLastPipeline: this pipeline is tried again
                    }
                }
            }
            if (d.newestFinished() != null && !d.newestFinished().equals(link.getCdLastPipeline())) {
                link.setCdLastPipeline(Math.max(d.newestFinished(), link.getCdLastPipeline() == null ? 0 : link.getCdLastPipeline()));
                linkRepo.save(link);
            }
        }
    }
}
