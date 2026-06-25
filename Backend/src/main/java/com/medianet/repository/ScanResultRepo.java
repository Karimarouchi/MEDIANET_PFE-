package com.medianet.repository;

import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ScanResultRepo extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findByRepositoryIdOrderByStartedAtDesc(Long repositoryId);

    List<ScanResult> findByRepositoryIdInOrderByStartedAtDesc(java.util.Collection<Long> repositoryIds);

    List<ScanResult> findAllByOrderByStartedAtDesc();

    List<ScanResult> findAllByRepositoryOwnerLoginOrderByStartedAtDesc(String ownerLogin);

    ScanResult findFirstByRepositoryIdOrderByStartedAtDesc(Long repositoryId);

    boolean existsByRepositoryIdAndStatusIn(Long repositoryId, java.util.Collection<ScanStatus> statuses);
}
