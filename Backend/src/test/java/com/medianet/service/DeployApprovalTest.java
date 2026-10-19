package com.medianet.service;

import com.medianet.entity.DeployRun;
import com.medianet.entity.NotificationType;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.ServerNode;
import com.medianet.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Approval before deploy: a green pipeline waits, a newer one replaces it, Refuser / Déployer change its state. */
class DeployApprovalTest {

    private static final String SHA1 = "1".repeat(40);
    private static final String SHA2 = "2".repeat(40);

    private DeployRunRepo runs;
    private NotificationService notifications;
    private DeployService service;
    private final List<DeployRun> saved = new ArrayList<>();
    private ServerDeployment deployment;

    @BeforeEach
    void setUp() {
        ServerDeploymentRepo deployments = mock(ServerDeploymentRepo.class);
        runs = mock(DeployRunRepo.class);
        notifications = mock(NotificationService.class);
        ServerNode node = ServerNode.builder().name("prod").host("10.0.0.5").build();
        node.setId(8L);
        deployment = ServerDeployment.builder().serverNode(node).name("antigone").deployPath("/opt/antigone/app")
                .linkedRepositoryId(18L).backupEnabled(true).backupService("db").approvalRequired(true).autoDeployEnabled(true).build();
        deployment.setId(1L);
        when(deployments.findById(1L)).thenReturn(Optional.of(deployment));
        // In-memory run table.
        when(runs.saveAndFlush(any())).thenAnswer(i -> store(i.getArgument(0)));
        when(runs.save(any())).thenAnswer(i -> store(i.getArgument(0)));
        when(runs.findById(anyLong())).thenAnswer(i -> saved.stream().filter(r -> r.getId().equals(i.getArgument(0))).findFirst());
        when(runs.findByServerDeploymentIdAndStatus(eq(1L), any())).thenAnswer(i ->
                saved.stream().filter(r -> r.getStatus() == i.getArgument(1)).toList());
        service = new DeployService(null, deployments, runs, null, null, null, null, null,
                mock(PlatformTransactionManager.class), mock(CiPipelineLinkRepo.class));
        service.setNotificationService(notifications);
    }

    private DeployRun store(DeployRun r) {
        if (r.getId() == null) {
            r.setId((long) saved.size() + 1);
            saved.add(r);
        }
        return r;
    }

    @Test
    void greenPipelineWaitsAndTheTeamIsAsked() {
        service.requestApproval(1L, SHA1, 12);
        assertThat(saved).singleElement().satisfies(r -> {
            assertThat(r.getStatus()).isEqualTo(DeployRun.Status.PENDING_APPROVAL);
            assertThat(r.getCommitSha()).isEqualTo(SHA1);
            assertThat(r.getPipelineNumber()).isEqualTo(12L);
            assertThat(r.getTriggerType()).isEqualTo(DeployRun.TriggerType.CI);
        });
        verify(notifications).notifyRepositoryTeam(eq(18L), eq(NotificationType.DEPLOY_APPROVAL),
                eq("Prêt à déployer : pipeline #12"), contains("La base sera sauvegardée juste avant."), isNull(), eq(1L));
    }

    @Test
    void aNewerGreenPipelineReplacesTheOlderRequest() {
        service.requestApproval(1L, SHA1, 12);
        service.requestApproval(1L, SHA2, 13);
        assertThat(saved.get(0).getStatus()).isEqualTo(DeployRun.Status.SUPERSEDED);
        assertThat(saved.get(1).getStatus()).isEqualTo(DeployRun.Status.PENDING_APPROVAL);
        assertThat(saved.get(1).getCommitSha()).isEqualTo(SHA2);
        assertThatThrownBy(() -> service.approve(1L, "karim")).isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("n'attend plus d'accord");
    }

    @Test
    void refuseMovesNothingAndRecordsWho() {
        service.requestApproval(1L, SHA1, 12);
        service.refuse(1L, "karim");
        DeployRun r = saved.get(0);
        assertThat(r.getStatus()).isEqualTo(DeployRun.Status.REFUSED);
        assertThat(r.getDecidedBy()).isEqualTo("karim");
        assertThat(r.getFinishedAt()).isBeforeOrEqualTo(LocalDateTime.now());
        assertThatThrownBy(() -> service.refuse(1L, "karim")).isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void approveStartsTheDeploy() {
        service.requestApproval(1L, SHA1, 12);
        service.approve(1L, "karim");
        DeployRun r = saved.get(0);
        assertThat(r.getStatus()).isIn(DeployRun.Status.RUNNING, DeployRun.Status.FAILED); // runs in the background
        assertThat(r.getDecidedBy()).isEqualTo("karim");
        assertThat(r.getLog()).contains("Accord donné par karim.");
    }

    @Test
    void aPinnedVersionRefusesDeployingTheLatestUntilResumed() {
        deployment.setPinnedCommit(SHA1);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.deploy(8L, 1L, false, DeployRun.TriggerType.MANUAL))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class)
                .hasMessageContaining("épinglée");
        service.unpin(1L, "admin");
        assertThat(deployment.getPinnedCommit()).isNull();
        assertThat(deployment.getPinnedBy()).isNull();
    }

    @Test
    void aChosenVersionMustBeAFullCommit() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.deployChosenCommit(1L, "abc123", "admin"))
                .isInstanceOf(org.springframework.web.server.ResponseStatusException.class)
                .hasMessageContaining("Commit invalide");
        assertThat(saved).isEmpty();
    }
}
