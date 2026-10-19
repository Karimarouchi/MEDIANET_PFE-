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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("ProjectDeletionService — suppression complète d'un projet")
class ProjectDeletionServiceTest {

    @Mock private ClientRepo clientRepo;
    @Mock private ClientRepositoryRepo clientRepositoryRepo;
    @Mock private ClientServerRepo clientServerRepo;
    @Mock private RepositoryRepo repositoryRepo;
    @Mock private ScanResultRepo scanResultRepo;
    @Mock private ScheduledScanRepository scheduledScanRepo;
    @Mock private ServerNodeRepo serverNodeRepo;
    @Mock private ServerDeploymentRepo serverDeploymentRepo;
    @Mock private DeployRunRepo deployRunRepo;
    @Mock private ServerDiskReportRepo serverDiskReportRepo;
    @Mock private CiPipelineLinkRepo ciLinkRepo;
    @Mock private CiTokenRepo ciTokenRepo;
    @Mock private AppNotificationRepo notificationRepo;
    @Mock private ScanService scanService;
    @Mock private CiPipelineService ciPipelineService;
    @Mock private CiTokenService ciTokenService;
    @Mock private EntityManager entityManager;
    @Mock private ClientService clientService;

    private ProjectDeletionService service;

    private final User admin = User.builder().id(1L).role(UserRole.ADMIN).build();
    private final Client project = Client.builder().id(10L).name("RNIA PFE").build();
    private final Client other = Client.builder().id(20L).name("Autre").build();
    private final Repository own = Repository.builder().id(100L).repoUrl("https://github.com/karim/antigone.git").build();
    private final Repository shared = Repository.builder().id(200L).repoUrl("https://github.com/karim/commun").build();
    private final ServerNode ownServer = ServerNode.builder().id(300L).name("prod-antigone").build();
    private final ServerNode sharedServer = ServerNode.builder().id(400L).name("partagé").build();
    private final CiPipelineLink ci = CiPipelineLink.builder().id(7L).repositoryId(100L).clientId(10L).woodpeckerRepoId(2L).build();

    @BeforeEach
    void setUp() {
        service = new ProjectDeletionService(clientRepo, clientRepositoryRepo, clientServerRepo, repositoryRepo,
                scanResultRepo, scheduledScanRepo, serverNodeRepo, serverDeploymentRepo, deployRunRepo,
                serverDiskReportRepo, ciLinkRepo, ciTokenRepo, notificationRepo, scanService, ciPipelineService,
                ciTokenService, entityManager, clientService);
        lenient().when(clientRepo.findById(10L)).thenReturn(Optional.of(project));
        lenient().when(clientRepositoryRepo.findByClient_Id(10L))
                .thenReturn(List.of(link(project, own), link(project, shared)));
        lenient().when(clientRepositoryRepo.findByRepository_Id(100L)).thenReturn(List.of(link(project, own)));
        lenient().when(clientRepositoryRepo.findByRepository_Id(200L))
                .thenReturn(List.of(link(project, shared), link(other, shared)));
        lenient().when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(ownServer, sharedServer));
        lenient().when(clientServerRepo.countByServerNode_Id(300L)).thenReturn(1L);
        lenient().when(clientServerRepo.countByServerNode_Id(400L)).thenReturn(2L);
        lenient().when(ciLinkRepo.findByClientId(10L)).thenReturn(List.of(ci));
        lenient().when(ciLinkRepo.findByRepositoryIdIn(any())).thenReturn(List.of(ci));
        lenient().when(scanResultRepo.findByRepositoryIdOrderByStartedAtDesc(100L))
                .thenReturn(List.of(ScanResult.builder().id(51L).build(), ScanResult.builder().id(52L).build()));
        lenient().when(serverDeploymentRepo.countByServerNodeId(300L)).thenReturn(2L);
        lenient().when(repositoryRepo.findById(100L)).thenReturn(Optional.of(own));
        lenient().when(serverNodeRepo.findById(300L)).thenReturn(Optional.of(ownServer));
    }

    private static ClientRepository link(Client c, Repository r) {
        return ClientRepository.builder().client(c).repository(r).build();
    }

    @Test
    void previewSeparatesWhatIsDeletedFromWhatIsOnlyDetached() {
        ProjectDeletionService.Preview p = service.preview(admin, 10L);

        assertThat(p.projectName()).isEqualTo("RNIA PFE");
        assertThat(p.repositoriesDeleted()).containsExactly("karim/antigone");
        assertThat(p.repositoriesDetached()).containsExactly("karim/commun");
        assertThat(p.scans()).isEqualTo(2);
        assertThat(p.serversDeleted()).containsExactly("prod-antigone");
        assertThat(p.serversDetached()).containsExactly("partagé");
        assertThat(p.deployments()).isEqualTo(2);
        assertThat(p.ciRepositories()).isEqualTo(1);
        assertThat(p.blockers()).isEmpty();
    }

    @Test
    void deletesEverythingThatBelongsOnlyToTheProject() {
        CiToken token = CiToken.builder().id(9L).build();
        when(ciTokenRepo.findDetailedByClientId(10L)).thenReturn(List.of(token));

        service.delete(admin, 10L, "  RNIA PFE ");

        verify(ciPipelineService).forgetLink(ci);
        verify(ciTokenService).deletePermanently(9L);
        verify(scanService).deleteScan(51L);
        verify(scanService).deleteScan(52L);
        verify(scheduledScanRepo).findByRepositoryIdOrderByCreatedAtDesc(100L);
        verify(serverDeploymentRepo).unlinkRepositories(List.of(100L));
        verify(serverNodeRepo).unlinkRepositories(List.of(100L));
        verify(ciTokenRepo).removeRepositoriesFromScopes(List.of(100L));
        verify(deployRunRepo).deleteAllOfServer(300L);
        verify(serverDeploymentRepo).deleteAllOfServer(300L);
        verify(serverDiskReportRepo).deleteAllOfServer(300L);
        verify(notificationRepo).deleteByProjectLink("/projects/10");
        verify(clientServerRepo).deleteByClientId(10L);
        verify(repositoryRepo).delete(own);
        verify(serverNodeRepo).delete(ownServer);
        verify(clientRepo).delete(project);
        // Shared repository and shared server stay: only the project's links to them go.
        verify(repositoryRepo, never()).findById(200L);
        verify(scanResultRepo, never()).findByRepositoryIdOrderByStartedAtDesc(200L);
        verify(serverNodeRepo, never()).findById(400L);
        verify(deployRunRepo, never()).deleteAllOfServer(400L);
    }

    @Test
    void wrongConfirmationDeletesNothing() {
        assertThatThrownBy(() -> service.delete(admin, 10L, "RNIA"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("ne correspond pas");
        verify(clientRepo, never()).delete(any());
        verify(ciPipelineService, never()).forgetLink(any());
        verify(scanService, never()).deleteScan(anyLong());
    }

    @Test
    void scanOrDeploymentInProgressBlocksTheDeletion() {
        when(scanResultRepo.existsByRepositoryIdAndStatusIn(eq(100L), anyCollection())).thenReturn(true);
        when(deployRunRepo.existsByServerNode_IdAndStatus(300L, DeployRun.Status.RUNNING)).thenReturn(true);

        assertThat(service.preview(admin, 10L).blockers()).hasSize(2);
        assertThatThrownBy(() -> service.delete(admin, 10L, "RNIA PFE"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("scan est en cours")
                .hasMessageContaining("déploiement est en cours");
        verify(clientRepo, never()).delete(any());
        verify(ciPipelineService, never()).forgetLink(any());
    }

    @Test
    void onlyAnAdministratorCanDelete() {
        User employee = User.builder().id(2L).role(UserRole.EMPLOYEE).build();
        assertThatThrownBy(() -> service.delete(employee, 10L, "RNIA PFE"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("administrateur");
        verify(clientRepo, never()).delete(any());
    }

    @Test
    void repositoryLabelComesFromItsUrl() {
        assertThat(ProjectDeletionService.label(Repository.builder().repoUrl("https://github.com/a/b.git/").build()))
                .isEqualTo("a/b");
        assertThat(ProjectDeletionService.label(Repository.builder().repoUrl("https://gitlab.com/g/sub/p").build()))
                .isEqualTo("sub/p");
    }

    // ── one repository ──

    @Test
    void repositoryPreviewSaysWhetherItCanBeDeleted() {
        when(ciLinkRepo.findByRepositoryId(100L)).thenReturn(Optional.of(ci));
        ProjectDeletionService.RepoRemovalPreview own100 = service.repoRemovalPreview(admin, 10L, 100L);
        assertThat(own100.repository()).isEqualTo("karim/antigone");
        assertThat(own100.shared()).isFalse();
        assertThat(own100.canDelete()).isTrue();
        assertThat(own100.scans()).isEqualTo(2);
        assertThat(own100.ciEnabled()).isTrue();

        ProjectDeletionService.RepoRemovalPreview shared200 = service.repoRemovalPreview(admin, 10L, 200L);
        assertThat(shared200.shared()).isTrue();
        assertThat(shared200.canDelete()).isFalse();
    }

    @Test
    void detachingKeepsTheRepositoryButTurnsTheProjectsCiOff() {
        when(ciLinkRepo.findByRepositoryId(100L)).thenReturn(Optional.of(ci));

        service.removeRepository(admin, 10L, 100L, false);

        verify(ciPipelineService).removeLink(ci);
        verify(clientRepositoryRepo).deleteById(new com.medianet.entity.ClientRepositoryId(10L, 100L));
        verify(scanService, never()).deleteScan(anyLong());
        verify(repositoryRepo, never()).delete(any());
    }

    @Test
    void deletingTheRepositoryRemovesItsScans() {
        when(ciLinkRepo.findByRepositoryId(100L)).thenReturn(Optional.empty());

        service.removeRepository(admin, 10L, 100L, true);

        verify(clientRepositoryRepo).deleteById(new com.medianet.entity.ClientRepositoryId(10L, 100L));
        verify(scanService).deleteScan(51L);
        verify(scanService).deleteScan(52L);
        verify(serverDeploymentRepo).unlinkRepositories(List.of(100L));
        verify(repositoryRepo).delete(own);
    }

    @Test
    void aSharedRepositoryCanOnlyBeDetached() {
        assertThatThrownBy(() -> service.removeRepository(admin, 10L, 200L, true))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("autre projet");
        verify(clientRepositoryRepo, never()).deleteById(any());
    }

    @Test
    void anEmployeeMayDetachButNotDelete() {
        User employee = User.builder().id(2L).role(UserRole.EMPLOYEE).build();
        assertThat(service.repoRemovalPreview(employee, 10L, 100L).canDelete()).isFalse();
        assertThatThrownBy(() -> service.removeRepository(employee, 10L, 100L, true))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("administrateur");
        service.removeRepository(employee, 10L, 100L, false);
        verify(clientRepositoryRepo).deleteById(new com.medianet.entity.ClientRepositoryId(10L, 100L));
    }

    @Test
    void aRepositoryOfAnotherProjectIsRefused() {
        assertThatThrownBy(() -> service.removeRepository(admin, 10L, 999L, false))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("pas lié");
    }
}
