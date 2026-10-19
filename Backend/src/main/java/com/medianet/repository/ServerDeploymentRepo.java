package com.medianet.repository;

import com.medianet.entity.ServerDeployment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface ServerDeploymentRepo extends JpaRepository<ServerDeployment, Long> {
    List<ServerDeployment> findByServerNodeIdOrderByIdAsc(Long serverNodeId);

    Optional<ServerDeployment> findByIdAndServerNodeId(Long id, Long serverNodeId);

    @Query("SELECT d FROM ServerDeployment d JOIN FETCH d.serverNode WHERE d.linkedRepositoryId = :repoId AND d.autoDeployEnabled = true")
    List<ServerDeployment> findByLinkedRepositoryIdAndAutoDeployEnabledTrue(@Param("repoId") Long linkedRepositoryId);

    @Query("SELECT d FROM ServerDeployment d JOIN FETCH d.serverNode WHERE d.linkedRepositoryId = :repoId ORDER BY d.id")
    List<ServerDeployment> findByLinkedRepositoryId(@Param("repoId") Long linkedRepositoryId);

    long countByServerNodeId(Long serverNodeId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM ServerDeployment d WHERE d.serverNode.id = :serverId")
    int deleteAllOfServer(@Param("serverId") Long serverId);

    /** Deployments on servers that are kept forget a repository that is being deleted. */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE ServerDeployment d SET d.linkedRepositoryId = null WHERE d.linkedRepositoryId IN :repoIds")
    int unlinkRepositories(@Param("repoIds") Collection<Long> repoIds);
}
