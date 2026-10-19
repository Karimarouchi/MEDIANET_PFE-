package com.medianet.service;

import com.medianet.entity.CiPipelineLink;
import com.medianet.entity.CiToken;
import com.medianet.entity.Client;
import com.medianet.entity.ClientRepository;
import com.medianet.entity.DeployRun;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ServerNode;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.AppNotificationRepo;
import com.medianet.repository.CiPipelineLinkRepo;
import com.medianet.repository.CiTokenRepo;
import com.medianet.repository.ClientRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.ClientServerRepo;
import com.medianet.repository.DeployRunRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.ScheduledScanRepository;
import com.medianet.repository.ServerDeploymentRepo;
import com.medianet.repository.ServerDiskReportRepo;
import com.medianet.repository.ServerNodeRepo;
import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Deletes a project and everything that only exists for it.
 *
 * <ul>
 *   <li>Repositories linked to this project only: deleted with their scans (CVE, secrets, SSL snapshot, result
 *       files), scheduled scans and CI. A repository shared with another project is only detached.</li>
 *   <li>Servers linked to this project only: deleted with their deployments, deployment history, disk report,
 *       configuration snapshots and vulnerability scans. Nothing is touched on the machine itself. A shared server
 *       is only detached.</li>
 *   <li>CI of the project: repositories deactivated in Woodpecker, CI tokens revoked then deleted.</li>
 *   <li>Notifications that open this project, project members, domain / SSL alert / delivery date (on the project).</li>
 * </ul>
 */
@Service
public class ProjectDeletionService {

    private static final Logger log = LoggerFactory.getLogger(ProjectDeletionService.class);

    public record Preview(Long projectId, String projectName,
                          List<String> repositoriesDeleted, List<String> repositoriesDetached, int scans,
                          List<String> serversDeleted, List<String> serversDetached, int deployments,
                          int ciRepositories, List<String> blockers) {
    }

    private record Plan(Client client, List<Repository> deleteRepos, List<Repository> detachRepos,
                        List<ServerNode> deleteServers, List<ServerNode> detachServers, List<CiPipelineLink> ciLinks) {
    }

    private final ClientRepo clientRepo;
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final ClientServerRepo clientServerRepo;
    private final RepositoryRepo repositoryRepo;
    private final ScanResultRepo scanResultRepo;
    private final ScheduledScanRepository scheduledScanRepo;
    private final ServerNodeRepo serverNodeRepo;
    private final ServerDeploymentRepo serverDeploymentRepo;
    private final DeployRunRepo deployRunRepo;
    private final ServerDiskReportRepo serverDiskReportRepo;
    private final CiPipelineLinkRepo ciLinkRepo;
    private final CiTokenRepo ciTokenRepo;
    private final AppNotificationRepo notificationRepo;
    private final ScanService scanService;
    private final CiPipelineService ciPipelineService;
    private final CiTokenService ciTokenService;
    private final EntityManager entityManager;

    public ProjectDeletionService(ClientRepo clientRepo, ClientRepositoryRepo clientRepositoryRepo,
            ClientServerRepo clientServerRepo, RepositoryRepo repositoryRepo, ScanResultRepo scanResultRepo,
            ScheduledScanRepository scheduledScanRepo, ServerNodeRepo serverNodeRepo,
            ServerDeploymentRepo serverDeploymentRepo, DeployRunRepo deployRunRepo,
            ServerDiskReportRepo serverDiskReportRepo, CiPipelineLinkRepo ciLinkRepo, CiTokenRepo ciTokenRepo,
            AppNotificationRepo notificationRepo, ScanService scanService, CiPipelineService ciPipelineService,
            CiTokenService ciTokenService, EntityManager entityManager) {
        this.clientRepo = clientRepo;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.clientServerRepo = clientServerRepo;
        this.repositoryRepo = repositoryRepo;
        this.scanResultRepo = scanResultRepo;
        this.scheduledScanRepo = scheduledScanRepo;
        this.serverNodeRepo = serverNodeRepo;
        this.serverDeploymentRepo = serverDeploymentRepo;
        this.deployRunRepo = deployRunRepo;
        this.serverDiskReportRepo = serverDiskReportRepo;
        this.ciLinkRepo = ciLinkRepo;
        this.ciTokenRepo = ciTokenRepo;
        this.notificationRepo = notificationRepo;
        this.scanService = scanService;
        this.ciPipelineService = ciPipelineService;
        this.ciTokenService = ciTokenService;
        this.entityManager = entityManager;
    }

    @Transactional(readOnly = true)
    public Preview preview(User user, Long clientId) {
        Plan plan = plan(user, clientId);
        int scans = 0;
        for (Repository r : plan.deleteRepos()) scans += scanResultRepo.findByRepositoryIdOrderByStartedAtDesc(r.getId()).size();
        int deployments = 0;
        for (ServerNode s : plan.deleteServers()) deployments += (int) serverDeploymentRepo.countByServerNodeId(s.getId());
        return new Preview(plan.client().getId(), plan.client().getName(),
                names(plan.deleteRepos()), names(plan.detachRepos()), scans,
                plan.deleteServers().stream().map(ServerNode::getName).toList(),
                plan.detachServers().stream().map(ServerNode::getName).toList(),
                deployments, plan.ciLinks().size(), blockers(plan));
    }

    /** {@code confirmName} must be the project name, as typed by the user (surrounding spaces ignored). */
    @Transactional
    public void delete(User user, Long clientId, String confirmName) {
        Plan plan = plan(user, clientId);
        Client client = plan.client();
        if (confirmName == null || !confirmName.trim().equals(client.getName().trim())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Le nom saisi ne correspond pas au nom du projet.");
        }
        List<String> blockers = blockers(plan);
        if (!blockers.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, String.join(" ", blockers));
        }

        // 1. CI first: Woodpecker stops calling Vulnix for these repositories, then the tokens disappear.
        for (CiPipelineLink link : plan.ciLinks()) ciPipelineService.forgetLink(link);
        for (CiToken token : ciTokenRepo.findDetailedByClientId(clientId)) ciTokenService.deletePermanently(token.getId());

        // 2. Repositories of this project only, with everything produced by their scans.
        List<Long> repoIds = plan.deleteRepos().stream().map(Repository::getId).toList();
        int scans = 0;
        for (Long repoId : repoIds) {
            scheduledScanRepo.deleteAll(scheduledScanRepo.findByRepositoryIdOrderByCreatedAtDesc(repoId));
            for (ScanResult scan : scanResultRepo.findByRepositoryIdOrderByStartedAtDesc(repoId)) {
                scanService.deleteScan(scan.getId());
                scans++;
            }
        }
        if (!repoIds.isEmpty()) {
            serverDeploymentRepo.unlinkRepositories(repoIds);
            serverNodeRepo.unlinkRepositories(repoIds);
            ciTokenRepo.removeRepositoriesFromScopes(repoIds);
        }

        // 3. Servers of this project only. Deployment history and deployments before the server (foreign keys).
        for (ServerNode server : plan.deleteServers()) {
            deployRunRepo.deleteAllOfServer(server.getId());
            serverDeploymentRepo.deleteAllOfServer(server.getId());
            serverDiskReportRepo.deleteAllOfServer(server.getId());
        }

        // 4. Notifications that would open a project that no longer exists, server links of the project.
        notificationRepo.deleteByProjectLink("/projects/" + clientId);
        clientServerRepo.deleteByClientId(clientId);
        entityManager.flush();
        entityManager.clear();

        // 5. The rows themselves: cascades remove project members, repository links, configuration snapshots and
        //    vulnerability scans of the servers.
        for (Long repoId : repoIds) repositoryRepo.findById(repoId).ifPresent(repositoryRepo::delete);
        for (ServerNode server : plan.deleteServers()) serverNodeRepo.findById(server.getId()).ifPresent(serverNodeRepo::delete);
        clientRepo.findById(clientId).ifPresent(clientRepo::delete);
        entityManager.flush();

        log.info("Project deleted id={} name='{}' by={}: {} repositories ({} scans) deleted, {} detached, "
                        + "{} servers deleted, {} detached, {} CI repositories turned off",
                clientId, client.getName(), user.getId(), repoIds.size(), scans, plan.detachRepos().size(),
                plan.deleteServers().size(), plan.detachServers().size(), plan.ciLinks().size());
    }

    private Plan plan(User user, Long clientId) {
        if (user == null || user.getRole() != UserRole.ADMIN) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Seul un administrateur peut supprimer un projet.");
        }
        Client client = clientRepo.findById(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projet introuvable."));

        List<Repository> deleteRepos = new ArrayList<>();
        List<Repository> detachRepos = new ArrayList<>();
        for (ClientRepository link : clientRepositoryRepo.findByClient_Id(clientId)) {
            Repository repo = link.getRepository();
            boolean shared = clientRepositoryRepo.findByRepository_Id(repo.getId()).stream()
                    .anyMatch(other -> !other.getClient().getId().equals(clientId));
            (shared ? detachRepos : deleteRepos).add(repo);
        }

        List<ServerNode> deleteServers = new ArrayList<>();
        List<ServerNode> detachServers = new ArrayList<>();
        for (ServerNode server : clientServerRepo.findServersByClientId(clientId)) {
            (clientServerRepo.countByServerNode_Id(server.getId()) > 1 ? detachServers : deleteServers).add(server);
        }

        // CI links that belong to this project, and those of repositories that are about to disappear.
        Set<Long> deleteRepoIds = new LinkedHashSet<>(deleteRepos.stream().map(Repository::getId).toList());
        List<CiPipelineLink> ciLinks = new ArrayList<>(ciLinkRepo.findByClientId(clientId));
        for (CiPipelineLink link : ciLinkRepo.findByRepositoryIdIn(deleteRepoIds)) {
            if (ciLinks.stream().noneMatch(l -> l.getId().equals(link.getId()))) ciLinks.add(link);
        }
        return new Plan(client, deleteRepos, detachRepos, deleteServers, detachServers, ciLinks);
    }

    /** What must finish before the project can go: a scan or a deployment in progress would be cut mid-way. */
    private List<String> blockers(Plan plan) {
        List<String> out = new ArrayList<>();
        for (Repository r : plan.deleteRepos()) {
            if (scanResultRepo.existsByRepositoryIdAndStatusIn(r.getId(),
                    List.of(ScanResult.ScanStatus.PENDING, ScanResult.ScanStatus.RUNNING))) {
                out.add("Un scan est en cours sur " + label(r) + " : attendez la fin ou arrêtez-le.");
            }
        }
        for (ServerNode s : plan.deleteServers()) {
            if (deployRunRepo.existsByServerNode_IdAndStatus(s.getId(), DeployRun.Status.RUNNING)) {
                out.add("Un déploiement est en cours sur le serveur " + s.getName() + " : attendez la fin.");
            }
        }
        return out;
    }

    private static List<String> names(List<Repository> repos) {
        return repos.stream().map(ProjectDeletionService::label).toList();
    }

    /** "owner/name" from the repository URL (https://github.com/owner/name(.git)). */
    static String label(Repository r) {
        String url = r.getRepoUrl() == null ? "" : r.getRepoUrl().trim();
        url = url.replaceAll("/+$", "").replaceAll("\\.git$", "");
        String[] parts = url.split("/");
        return parts.length >= 2 ? parts[parts.length - 2] + "/" + parts[parts.length - 1] : url;
    }
}
