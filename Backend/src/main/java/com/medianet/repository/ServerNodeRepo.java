package com.medianet.repository;

import com.medianet.entity.ServerNode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface ServerNodeRepo extends JpaRepository<ServerNode, Long> {
    boolean existsByNameIgnoreCase(String name);

    List<ServerNode> findAllByOrderByNodeTypeAscNameAsc();

    List<ServerNode> findByLinkedRepositoryIdAndAutoDeployEnabledTrue(Long linkedRepositoryId);

    List<ServerNode> findByLinkedRepositoryId(Long linkedRepositoryId);

    /** Servers that are kept forget a repository that is being deleted (legacy single-repo field). */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE ServerNode s SET s.linkedRepositoryId = null WHERE s.linkedRepositoryId IN :repoIds")
    int unlinkRepositories(@Param("repoIds") Collection<Long> repoIds);
}
