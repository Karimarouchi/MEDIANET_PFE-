package com.medianet.repository;

import com.medianet.entity.SiteCheck;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface SiteCheckRepo extends JpaRepository<SiteCheck, Long> {

    Optional<SiteCheck> findFirstByDomainOrderByCheckedAtDesc(String domain);

    @Query("SELECT COUNT(c) FROM SiteCheck c WHERE c.domain = :domain AND c.state = :state AND c.checkedAt >= :since")
    long countSince(@Param("domain") String domain, @Param("state") String state, @Param("since") LocalDateTime since);

    /** Domains written on projects: the sites to watch. */
    @Query("SELECT DISTINCT c.domainName FROM Client c WHERE c.domainName IS NOT NULL AND c.domainName <> ''")
    java.util.List<String> projectDomains();

    /** Domains of the deployments (production sites of the servers). */
    @Query("SELECT DISTINCT d.domain FROM ServerDeployment d WHERE d.domain IS NOT NULL AND d.domain <> ''")
    java.util.List<String> deploymentDomains();

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM SiteCheck c WHERE c.checkedAt < :before")
    int deleteOlderThan(@Param("before") LocalDateTime before);
}
