package com.medianet.repository;

import com.medianet.entity.ServerDiskReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface ServerDiskReportRepo extends JpaRepository<ServerDiskReport, Long> {

    Optional<ServerDiskReport> findByServerNodeId(Long serverNodeId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM ServerDiskReport r WHERE r.serverNodeId = :serverId")
    int deleteAllOfServer(@Param("serverId") Long serverId);
}
