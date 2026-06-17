package com.medianet.repository;

import com.medianet.entity.CveEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface CveEntryRepo extends JpaRepository<CveEntry, Long> {
    List<CveEntry> findByScanResultId(Long scanResultId);

    long countByScanResultIdAndSeverity(Long scanResultId, String severity);

    @org.springframework.data.jpa.repository.Query("SELECT c FROM CveEntry c WHERE c.cvssScore IS NULL OR c.severity = 'UNKNOWN'")
    List<CveEntry> findAllMissingEnrichment();

    @org.springframework.data.jpa.repository.Query("SELECT COUNT(c) FROM CveEntry c WHERE c.cvssScore IS NULL OR c.severity = 'UNKNOWN'")
    long countMissingEnrichment();
}
