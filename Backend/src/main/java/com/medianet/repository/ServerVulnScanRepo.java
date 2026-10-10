package com.medianet.repository;

import com.medianet.entity.ServerVulnScan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ServerVulnScanRepo extends JpaRepository<ServerVulnScan, Long> {
    Optional<ServerVulnScan> findFirstByServerNode_IdOrderByStartedAtDesc(Long serverNodeId);
}
