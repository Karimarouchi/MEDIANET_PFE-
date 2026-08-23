package com.medianet.repository;

import com.medianet.entity.DeployRun;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface DeployRunRepo extends JpaRepository<DeployRun, Long> {
    List<DeployRun> findTop20ByServerNodeIdOrderByStartedAtDesc(Long serverNodeId);

    List<DeployRun> findTop20ByServerDeploymentIdOrderByStartedAtDesc(Long serverDeploymentId);

    Optional<DeployRun> findFirstByServerDeploymentIdOrderByStartedAtDesc(Long serverDeploymentId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE DeployRun r SET r.serverDeployment = null WHERE r.serverDeployment.id = :deploymentId")
    void detachFromDeployment(@Param("deploymentId") Long deploymentId);
}
