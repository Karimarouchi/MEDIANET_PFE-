package com.medianet.repository;

import com.medianet.entity.ConfigSnapshot;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ConfigSnapshotRepo extends JpaRepository<ConfigSnapshot, Long> {
    Optional<ConfigSnapshot> findTopByServerNodeIdOrderByCollectedAtDesc(Long serverNodeId);

    List<ConfigSnapshot> findTop5ByServerNodeIdOrderByCollectedAtDesc(Long serverNodeId);
}