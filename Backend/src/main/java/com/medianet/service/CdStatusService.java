package com.medianet.service;

import com.medianet.entity.DeployRun;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.DeployRunRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ServerDeploymentRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;

/** Where a repository is deployed and what runs there: shown in the CI/CD tab and the project overview. */
@Service
public class CdStatusService {

    private final ServerDeploymentRepo deploymentRepo;
    private final DeployRunRepo runRepo;
    private final RepositoryRepo repositoryRepo;

    public CdStatusService(ServerDeploymentRepo deploymentRepo, DeployRunRepo runRepo, RepositoryRepo repositoryRepo) {
        this.deploymentRepo = deploymentRepo;
        this.runRepo = runRepo;
        this.repositoryRepo = repositoryRepo;
    }

    public record Run(Long id, String status, String trigger, String commitSha, Long pipelineNumber,
            LocalDateTime startedAt, LocalDateTime finishedAt, String logTail, String backupFile, Long backupBytes,
            String decidedBy) {
    }

    public record Target(Long deploymentId, Long serverId, String serverName, String host, String path, String branch,
            String domain, String strategy, String healthUrl, boolean automatic, boolean backupEnabled, String backupService,
            boolean approvalRequired, Run last, Run inProduction, Run pending, List<Run> backups,
            String pinnedCommit, java.time.LocalDateTime pinnedAt, String pinnedBy) {
    }

    @Transactional(readOnly = true)
    public List<Target> forRepository(User user, Long repositoryId) {
        requireRepositoryAccess(user, repositoryId);
        return deploymentRepo.findByLinkedRepositoryId(repositoryId).stream().map(this::target).toList();
    }

    /** Same rule as the repository pages: admin, or an employee assigned to a project of this repository. */
    public void requireRepositoryAccess(User user, Long repositoryId) {
        if (user == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        boolean allowed = repositoryId != null && (user.getRole() == UserRole.ADMIN
                ? repositoryRepo.existsById(repositoryId)
                : repositoryRepo.canEmployeeAccess(repositoryId, user.getId()));
        if (!allowed) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Repository not accessible");
    }

    /** Access to a deployment = access to the repository it deploys. */
    @Transactional(readOnly = true)
    public void requireDeploymentAccess(User user, Long deploymentId) {
        ServerDeployment d = deploymentRepo.findById(deploymentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
        requireRepositoryAccess(user, d.getLinkedRepositoryId());
    }

    private Target target(ServerDeployment d) {
        Run last = runRepo.findFirstByServerDeploymentIdOrderByStartedAtDesc(d.getId()).map(CdStatusService::run).orElse(null);
        Run prod = runRepo.findFirstByServerDeploymentIdAndStatusOrderByStartedAtDesc(d.getId(), DeployRun.Status.SUCCESS)
                .map(CdStatusService::run).orElse(null);
        Run pending = runRepo.findByServerDeploymentIdAndStatus(d.getId(), DeployRun.Status.PENDING_APPROVAL).stream()
                .max(java.util.Comparator.comparing(DeployRun::getStartedAt)).map(CdStatusService::run).orElse(null);
        List<Run> backups = runRepo.findTop5ByServerDeploymentIdAndBackupFileIsNotNullOrderByStartedAtDesc(d.getId()).stream()
                .map(CdStatusService::run).toList();
        return new Target(d.getId(), d.getServerNode().getId(), d.getServerNode().getName(), d.getServerNode().getHost(),
                d.getDeployPath(), d.getDeployBranch(), d.getDomain(),
                d.getDeployStrategy() != null ? d.getDeployStrategy().name() : "DOCKER_COMPOSE", d.getHealthUrl(),
                Boolean.TRUE.equals(d.getAutoDeployEnabled()), Boolean.TRUE.equals(d.getBackupEnabled()), d.getBackupService(),
                Boolean.TRUE.equals(d.getApprovalRequired()), last, prod, pending, backups,
                d.getPinnedCommit(), d.getPinnedAt(), d.getPinnedBy());
    }

    /** Last lines of the run output: enough to see why it failed or rolled back. Package-private for tests. */
    static String tail(String log, int lines) {
        if (log == null || log.isBlank()) return "";
        String[] all = log.strip().split("\\R");
        return String.join("\n", java.util.Arrays.copyOfRange(all, Math.max(0, all.length - lines), all.length));
    }

    private static Run run(DeployRun r) {
        return new Run(r.getId(), r.getStatus().name(), r.getTriggerType().name(), r.getCommitSha(), r.getPipelineNumber(),
                r.getStartedAt(), r.getFinishedAt(), tail(r.getLog(), 12), r.getBackupFile(), r.getBackupBytes(), r.getDecidedBy());
    }
}
