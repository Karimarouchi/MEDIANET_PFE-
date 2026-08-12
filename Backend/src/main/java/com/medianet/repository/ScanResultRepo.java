package com.medianet.repository;

import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ScanResultRepo extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findByRepositoryIdOrderByStartedAtDesc(Long repositoryId);

    List<ScanResult> findByRepositoryIdInOrderByStartedAtDesc(java.util.Collection<Long> repositoryIds);

    List<ScanResult> findAllByOrderByStartedAtDesc();

    List<ScanResult> findAllByRepositoryOwnerLoginOrderByStartedAtDesc(String ownerLogin);

    ScanResult findFirstByRepositoryIdOrderByStartedAtDesc(Long repositoryId);

    boolean existsByRepositoryIdAndStatusIn(Long repositoryId, java.util.Collection<ScanStatus> statuses);

    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.repository WHERE s.id = :id")
    Optional<ScanResult> findByIdWithRepository(@Param("id") Long id);

    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.repository ORDER BY s.startedAt DESC")
    List<ScanResult> findAllWithRepositoryOrderByStartedAtDesc();

    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.repository r WHERE r.id IN :repoIds ORDER BY s.startedAt DESC")
    List<ScanResult> findByRepositoryIdInWithRepositoryOrderByStartedAtDesc(
            @Param("repoIds") java.util.Collection<Long> repoIds);
}
