package com.medianet.repository;

import com.medianet.entity.EpssHistorySnapshot;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDate;
import java.util.List;

public interface EpssHistorySnapshotRepo extends JpaRepository<EpssHistorySnapshot, Long> {

    boolean existsBySnapshotDate(LocalDate snapshotDate);

    List<EpssHistorySnapshot> findByCveIdOrderBySnapshotDateAsc(String cveId);

    long countBySnapshotDate(LocalDate snapshotDate);
}
