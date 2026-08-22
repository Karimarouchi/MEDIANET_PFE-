package com.medianet.repository;

import com.medianet.entity.DeployRun;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DeployRunRepo extends JpaRepository<DeployRun, Long> {
    List<DeployRun> findTop20ByServerNodeIdOrderByStartedAtDesc(Long serverNodeId);
}
