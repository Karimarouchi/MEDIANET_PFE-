package com.medianet.repository;

import com.medianet.entity.ServerDeployment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ServerDeploymentRepo extends JpaRepository<ServerDeployment, Long> {
    List<ServerDeployment> findByServerNodeIdOrderByIdAsc(Long serverNodeId);

    Optional<ServerDeployment> findByIdAndServerNodeId(Long id, Long serverNodeId);

    @Query("SELECT d FROM ServerDeployment d JOIN FETCH d.serverNode WHERE d.linkedRepositoryId = :repoId AND d.autoDeployEnabled = true")
    List<ServerDeployment> findByLinkedRepositoryIdAndAutoDeployEnabledTrue(@Param("repoId") Long linkedRepositoryId);

    long countByServerNodeId(Long serverNodeId);
}
