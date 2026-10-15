package com.medianet.service;

import com.medianet.dto.AttackGraphEdgeDto;
import com.medianet.dto.AttackGraphResponseDto;
import com.medianet.dto.ClientDto;
import com.medianet.dto.RepositoryDto;
import com.medianet.entity.ScanResult;
import com.medianet.entity.SecretFinding;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.ServerNode;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.ClientServerRepo;
import com.medianet.repository.ConfigSnapshotRepo;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.SecretFindingRepo;
import com.medianet.repository.ServerDeploymentRepo;
import com.medianet.repository.ServerNodeRepo;
import com.medianet.serverscan.ServerVulnService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("AttackGraphService — dépôts liés à leur serveur")
class AttackGraphProjectLinkTest {

    @Mock private ScanService scanService;
    @Mock private ScanResultRepo scanResultRepo;
    @Mock private CveEntryRepo cveEntryRepo;
    @Mock private SecretFindingRepo secretFindingRepo;
    @Mock private ServerNodeRepo serverNodeRepo;
    @Mock private ConfigSnapshotRepo configSnapshotRepo;
    @Mock private ClientService clientService;
    @Mock private ClientServerRepo clientServerRepo;
    @Mock private ServerVulnService serverVulnService;
    @Mock private ServerDeploymentRepo serverDeploymentRepo;

    private AttackGraphService service;
    private final User admin = User.builder().id(1L).role(UserRole.ADMIN).build();

    @BeforeEach
    void setUp() {
        service = new AttackGraphService(scanService, scanResultRepo, cveEntryRepo, secretFindingRepo,
                serverNodeRepo, configSnapshotRepo, clientService, clientServerRepo, serverVulnService,
                serverDeploymentRepo);
    }

    @Test
    @DisplayName("le front ne touche pas le serveur back, et un dépôt non lié est absent")
    void projectGraphLinksEachRepoOnlyToItsServer() {
        ServerNode front = ServerNode.builder().id(10L).name("Front").host("front.example").environment("PROD").build();
        ServerNode back = ServerNode.builder().id(11L).name("Back").host("back.example").environment("PROD").build();
        when(clientService.getVisibleClient(admin, 2L)).thenReturn(ClientDto.builder()
                .id(2L).repositoryIds(List.of(1L, 2L, 3L)).build());
        when(clientServerRepo.findServersByClientId(2L)).thenReturn(List.of(front, back));
        when(serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(10L)).thenReturn(List.of(
                ServerDeployment.builder().serverNode(front).linkedRepositoryId(1L).name("ui").build()));
        when(serverDeploymentRepo.findByServerNodeIdOrderByIdAsc(11L)).thenReturn(List.of(
                ServerDeployment.builder().serverNode(back).linkedRepositoryId(2L).name("api").build()));
        when(scanService.getAllRepositories(admin)).thenReturn(List.of(
                repo(1L, "https://github.com/org/front.git"),
                repo(2L, "https://github.com/org/api.git"),
                repo(3L, "https://github.com/org/unused.git")));

        ScanResult frontScan = ScanResult.builder().id(50L).status(ScanResult.ScanStatus.COMPLETED).resultsDir("/tmp").build();
        when(scanResultRepo.findFirstByRepositoryIdAndStatusOrderByStartedAtDesc(1L, ScanResult.ScanStatus.COMPLETED))
                .thenReturn(frontScan);
        when(scanResultRepo.findFirstByRepositoryIdAndStatusOrderByStartedAtDesc(eq(2L), any())).thenReturn(null);
        when(secretFindingRepo.findByScanResultId(50L)).thenReturn(List.of(
                SecretFinding.builder().id(7L).ruleId("private-key").file("keys/id_rsa").mlVerdict("LIKELY_REAL").build()));
        when(cveEntryRepo.findByScanResultId(50L)).thenReturn(List.of());
        when(configSnapshotRepo.findTopByServerNodeIdOrderByCollectedAtDesc(any())).thenReturn(Optional.empty());
        when(serverNodeRepo.findById(10L)).thenReturn(Optional.of(front));
        when(serverNodeRepo.findById(11L)).thenReturn(Optional.of(back));
        when(serverVulnService.latestReport(any())).thenReturn(Optional.empty());

        AttackGraphResponseDto graph = service.buildGraph(admin, 2L);

        assertThat(graph.nodes()).extracting(n -> n.id())
                .contains("repo-1", "repo-2", "server-10", "server-11", "secret-7")
                .doesNotContain("repo-3");
        assertThat(graph.edges())
                .filteredOn(e -> "DEPLOYS".equals(e.kind()))
                .extracting(AttackGraphEdgeDto::source, AttackGraphEdgeDto::target)
                .containsExactlyInAnyOrder(tuple("repo-1", "server-10"), tuple("repo-2", "server-11"));
        assertThat(graph.edges())
                .filteredOn(e -> "SECRET_ACCESS".equals(e.kind()))
                .extracting(AttackGraphEdgeDto::source, AttackGraphEdgeDto::target)
                .containsExactly(tuple("secret-7", "server-10"));
    }

    private static RepositoryDto repo(Long id, String url) {
        return RepositoryDto.builder().id(id).repoUrl(url).build();
    }
}
