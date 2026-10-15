package com.medianet.service;

import com.medianet.entity.ClientServer;
import com.medianet.entity.ConfigSnapshot;
import com.medianet.entity.ConfigSnapshotStatus;
import com.medianet.entity.DeployRun;
import com.medianet.entity.DeployStrategy;
import com.medianet.entity.FindingSeverity;
import com.medianet.entity.HardeningFinding;
import com.medianet.entity.PortExposure;
import com.medianet.entity.Repository;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.ServerNode;
import com.medianet.repository.ClientServerRepo;
import com.medianet.repository.ConfigSnapshotRepo;
import com.medianet.repository.DeployRunRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ServerDeploymentRepo;
import com.medianet.serverscan.ServerVulnReport;
import com.medianet.serverscan.ServerVulnService;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.ServerNodeRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("ClientServerService — serveurs d'un projet")
class ClientServerServiceTest {

    @Mock private ServerNodeRepo serverNodeRepo;
    @Mock private ClientServerRepo clientServerRepo;
    @Mock private ClientService clientService;
    @Mock private ServerDeploymentRepo serverDeploymentRepo;
    @Mock private RepositoryRepo repositoryRepo;
    @Mock private DeployRunRepo deployRunRepo;
    @Mock private ConfigSnapshotRepo configSnapshotRepo;
    @Mock private ServerVulnService serverVulnService;

    private ClientServerService service;
    private final User admin = User.builder().id(1L).role(UserRole.ADMIN).build();

    @BeforeEach
    void setUp() {
        service = new ClientServerService(serverNodeRepo, clientServerRepo, clientService,
                serverDeploymentRepo, repositoryRepo, deployRunRepo, configSnapshotRepo, serverVulnService);
        lenient().when(serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(any())).thenReturn(List.of());
        lenient().when(configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(any())).thenReturn(Optional.empty());
        lenient().when(serverVulnService.latestReport(any())).thenReturn(Optional.empty());
    }

    @Test
    @DisplayName("link() rattache un serveur déjà utilisé par un autre projet (plusieurs projets possibles)")
    void link_allowsServerSharedByProjects() {
        ServerNode server = ServerNode.builder().id(5L).name("vps").host("1.2.3.4").build();
        when(serverNodeRepo.findById(5L)).thenReturn(Optional.of(server));
        when(clientServerRepo.existsByClientIdAndServerNode_Id(10L, 5L)).thenReturn(false);
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(server));

        List<ClientServerService.ProjectServerDto> result = service.link(admin, 10L, 5L);

        ArgumentCaptor<ClientServer> saved = ArgumentCaptor.forClass(ClientServer.class);
        verify(clientServerRepo).save(saved.capture());
        assertThat(saved.getValue().getClientId()).isEqualTo(10L);
        assertThat(result).extracting(ClientServerService.ProjectServerDto::name).containsExactly("vps");
    }

    @Test
    @DisplayName("link() ne crée pas de doublon")
    void link_isIdempotent() {
        ServerNode server = ServerNode.builder().id(5L).name("vps").host("1.2.3.4").build();
        when(serverNodeRepo.findById(5L)).thenReturn(Optional.of(server));
        when(clientServerRepo.existsByClientIdAndServerNode_Id(10L, 5L)).thenReturn(true);
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(server));

        service.link(admin, 10L, 5L);

        verify(clientServerRepo, never()).save(any());
    }

    @Test
    @DisplayName("createLightweight() crée un serveur sans SSH, TEST ou PROD, rattaché au projet")
    void createLightweight_buildsServerWithoutSsh() {
        when(serverNodeRepo.existsByNameIgnoreCase("vps-prod")).thenReturn(false);
        when(serverNodeRepo.save(any(ServerNode.class))).thenAnswer(inv -> inv.getArgument(0));
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of());

        service.createLightweight(admin, 10L, "vps-prod", "203.0.113.7", "PROD");

        ArgumentCaptor<ServerNode> saved = ArgumentCaptor.forClass(ServerNode.class);
        verify(serverNodeRepo).save(saved.capture());
        assertThat(saved.getValue().getEnvironment()).isEqualTo("PROD");
        assertThat(saved.getValue().getEncryptedPassword()).isNull();
        verify(clientServerRepo).save(any(ClientServer.class));
    }

    @Test
    @DisplayName("createLightweight() rejette une URL à la place d'un hôte")
    void createLightweight_rejectsUrlHost() {
        assertThatThrownBy(() -> service.createLightweight(admin, 10L, "x", "http://evil/x", "TEST"))
                .isInstanceOf(ResponseStatusException.class);
        verify(serverNodeRepo, never()).save(any());
    }

    @Test
    @DisplayName("list() renvoie les dépôts déployés, pas les autres dépôts du projet")
    void list_includesOnlyDeployedRepositories() {
        ServerNode front = ServerNode.builder().id(10L).name("front").host("10.0.0.1").environment("PROD").build();
        ServerDeployment deployment = ServerDeployment.builder()
                .id(3L)
                .serverNode(front)
                .name("ui")
                .deployPath("/var/www/front")
                .domain("app.example")
                .linkedRepositoryId(7L)
                .deployBranch("main")
                .deployStrategy(DeployStrategy.STATIC_NGINX)
                .autoDeployEnabled(true)
                .build();
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(front));
        when(serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(10L)).thenReturn(List.of(deployment));
        when(repositoryRepo.findAllById(any())).thenReturn(List.of(
                Repository.builder().id(7L).repoUrl("https://github.com/org/front.git").build()));
        when(deployRunRepo.findFirstByServerDeploymentIdOrderByStartedAtDesc(3L)).thenReturn(Optional.of(
                DeployRun.builder().status(DeployRun.Status.SUCCESS).commitSha("abc123def").build()));

        List<ClientServerService.ProjectServerDto> result = service.list(admin, 10L);

        assertThat(result).hasSize(1);
        ClientServerService.ProjectDeploymentDto deployed = result.get(0).deployments().get(0);
        assertThat(deployed.linkedRepositoryId()).isEqualTo(7L);
        assertThat(deployed.repositoryName()).isEqualTo("front");
        assertThat(deployed.deployBranch()).isEqualTo("main");
        assertThat(deployed.domain()).isEqualTo("app.example");
        assertThat(deployed.deployPath()).isEqualTo("/var/www/front");
        assertThat(deployed.deployStrategy()).isEqualTo("STATIC_NGINX");
        assertThat(deployed.autoDeployEnabled()).isTrue();
        assertThat(deployed.lastStatus()).isEqualTo("SUCCESS");
        assertThat(deployed.lastCommitSha()).isEqualTo("abc123def");
    }

    @Test
    @DisplayName("list() retombe sur le dépôt unique de l'ancien modèle quand aucun déploiement n'existe")
    void list_fallsBackToLegacyLinkedRepository() {
        ServerNode back = ServerNode.builder().id(11L).name("back").host("10.0.0.2").environment("PROD")
                .linkedRepositoryId(8L).deployBranch("release").build();
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(back));
        when(repositoryRepo.findAllById(any())).thenReturn(List.of(
                Repository.builder().id(8L).repoUrl("https://github.com/org/api.git").build()));

        List<ClientServerService.ProjectServerDto> result = service.list(admin, 10L);

        assertThat(result.get(0).deployments()).extracting(ClientServerService.ProjectDeploymentDto::repositoryName)
                .containsExactly("api");
        assertThat(result.get(0).deployments().get(0).linkedRepositoryId()).isEqualTo(8L);
    }

    @Test
    @DisplayName("list() rappelle les failles et les ports déjà ouverts, dont ceux hors 22/80/443")
    void list_reportsServerPostureFromTheLastScan() {
        ServerNode server = ServerNode.builder().id(5L).name("prod").host("1.2.3.4").environment("PROD").build();
        ConfigSnapshot snapshot = ConfigSnapshot.builder()
                .status(ConfigSnapshotStatus.SUCCESS)
                .portExposures(List.of(
                        PortExposure.builder().portNumber(443).protocol("tcp").serviceName("https").exposureLevel("PUBLIC").build(),
                        PortExposure.builder().portNumber(5432).protocol("tcp").serviceName("postgres").exposureLevel("PUBLIC").build(),
                        PortExposure.builder().portNumber(5432).protocol("tcp").serviceName("postgres").exposureLevel("LOCAL").build()))
                .findings(List.of(
                        HardeningFinding.builder().severity(FindingSeverity.CRITICAL).title("SSH root autorisé").build(),
                        HardeningFinding.builder().severity(FindingSeverity.INFO).title("Note").build()))
                .build();
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(server));
        when(configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(5L)).thenReturn(Optional.of(snapshot));
        when(serverVulnService.latestReport(5L)).thenReturn(Optional.of(new ServerVulnReport(
                "1.2.3.4", null, true, false,
                List.of(new ServerVulnReport.PortFinding(5432, "tcp", "postgres", "PostgreSQL", "14", "EXTERNAL",
                        List.of(new ServerVulnReport.VulnRef("CVE-2026-1", 9.8, "CRITICAL", true, true, null)))),
                List.of(),
                new ServerVulnReport.Summary(2, 2, 1, 0, 1, 0, 0, 0, 1),
                List.of())));

        ClientServerService.ProjectServerPosture posture = service.list(admin, 10L).get(0).posture();

        assertThat(posture.scanned()).isTrue();
        assertThat(posture.unexpectedPortCount()).isEqualTo(1);
        assertThat(posture.ports()).extracting(ClientServerService.ProjectPortUse::port).containsExactly(443, 5432, 5432);
        assertThat(posture.ports().get(1).unexpected()).isTrue();
        assertThat(posture.ports().get(0).unexpected()).isFalse();
        assertThat(posture.criticalCount()).isEqualTo(2);
        assertThat(posture.issues()).extracting(ClientServerService.ProjectServerIssue::title)
                .contains("SSH root autorisé", "CVE-2026-1 · port 5432");
    }

    @Test
    @DisplayName("unlink() ne retire que le lien avec ce projet")
    void unlink_removesOnlyThisProjectLink() {
        service.unlink(admin, 10L, 5L);

        verify(clientServerRepo).deleteByClientIdAndServerNode_Id(10L, 5L);
        verify(serverNodeRepo, never()).delete(any());
    }
}
