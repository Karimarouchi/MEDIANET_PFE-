package com.medianet.repository;

import com.medianet.entity.SecretFinding;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SecretFindingRepo extends JpaRepository<SecretFinding, Long> {
    List<SecretFinding> findByScanResultId(Long scanResultId);

    @org.springframework.data.jpa.repository.Query("""
            SELECT DISTINCT s FROM SecretFinding s
            JOIN FETCH s.scanResult scan
            JOIN FETCH scan.repository
            WHERE scan.id IN :ids
            """)
    List<SecretFinding> findByScanResultIdInWithRepository(
            @org.springframework.data.repository.query.Param("ids") java.util.Collection<Long> ids);

    long countByScanResultId(Long scanResultId);

    /**
     * Secrets worth acting on: not a probable false positive, and not in a test/example/doc file unless the analyst
     * confirmed them. The analyst's call always wins over the model.
     */
    @org.springframework.data.jpa.repository.Query("""
            select count(s) from SecretFinding s where s.scanResult.id = :scanId and (
              s.analystVerdict = 'REAL' or (s.analystVerdict is null and (
                s.mlVerdict is null or (s.mlVerdict <> 'LIKELY_FALSE_POSITIVE'
                  and (s.mlScope is null or s.mlScope <> 'TEST_OR_DOC')))))
            """)
    long countOpenByScanResultId(@org.springframework.data.repository.query.Param("scanId") Long scanId);
}
