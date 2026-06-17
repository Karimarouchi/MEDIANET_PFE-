package com.medianet.repository;

import com.medianet.entity.SecretFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SecretFindingRepo extends JpaRepository<SecretFinding, Long> {
    List<SecretFinding> findByScanResultId(Long scanResultId);
}
