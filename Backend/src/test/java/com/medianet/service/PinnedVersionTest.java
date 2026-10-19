package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CiPipelineLink;
import com.medianet.entity.ServerDeployment;
import com.medianet.repository.CiPipelineLinkRepo;
import com.medianet.repository.ServerDeploymentRepo;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** A version chosen by hand is kept: green pipelines leave a pinned deployment alone. */
class PinnedVersionTest {

    private static final String NEW = "b".repeat(40);

    @Test
    void greenPipelineSkipsThePinnedDeploymentButDeploysTheOthers() throws Exception {
        WoodpeckerClient woodpecker = mock(WoodpeckerClient.class);
        CiPipelineLinkRepo links = mock(CiPipelineLinkRepo.class);
        ServerDeploymentRepo deployments = mock(ServerDeploymentRepo.class);
        DeployService deploy = mock(DeployService.class);
        CiPipelineLink link = CiPipelineLink.builder().id(1L).repositoryId(9L).clientId(2L).woodpeckerRepoId(4L)
                .cdLastPipeline(5L).build();
        ServerDeployment pinned = ServerDeployment.builder().id(11L).deployBranch("main").autoDeployEnabled(true)
                .pinnedCommit("a".repeat(40)).build();
        ServerDeployment free = ServerDeployment.builder().id(12L).deployBranch("main").autoDeployEnabled(true).build();
        when(links.findAll()).thenReturn(List.of(link));
        when(deployments.findByLinkedRepositoryIdAndAutoDeployEnabledTrue(9L)).thenReturn(List.of(pinned, free));
        when(woodpecker.pipelines(4L, 10)).thenReturn(new ObjectMapper().readTree(
                "[{\"number\":6,\"status\":\"success\",\"branch\":\"main\",\"event\":\"push\",\"commit\":\"" + NEW + "\"}]"));
        when(deploy.deployCommit(anyLong(), anyString(), anyLong())).thenReturn(
                new com.medianet.dto.DeployRunDto(1L, 1L, 12L, NEW, 6L, null, "SUCCESS", "CI", null, null, null, false, List.of()));

        new CiDeployWatcher(woodpecker, links, deployments, deploy).round();

        verify(deploy, never()).deployCommit(eq(11L), any(), anyLong());
        verify(deploy, never()).requestApproval(eq(11L), any(), anyLong());
        verify(deploy).deployCommit(12L, NEW, 6L);
        // The baseline moves on: resuming later does not deploy this unreliable pipeline after the fact.
        assertThat(link.getCdLastPipeline()).isEqualTo(6L);
    }
}
