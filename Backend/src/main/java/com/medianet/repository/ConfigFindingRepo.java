package com.medianet.repository;

import com.medianet.entity.ConfigFinding;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ConfigFindingRepo extends JpaRepository<ConfigFinding, Long> {
    List<ConfigFinding> findByScanResultId(Long scanResultId);

    long countByScanResultId(Long scanResultId);
}
