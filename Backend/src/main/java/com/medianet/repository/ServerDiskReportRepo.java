package com.medianet.repository;

import com.medianet.entity.ServerDiskReport;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ServerDiskReportRepo extends JpaRepository<ServerDiskReport, Long> {

    Optional<ServerDiskReport> findByServerNodeId(Long serverNodeId);
}
