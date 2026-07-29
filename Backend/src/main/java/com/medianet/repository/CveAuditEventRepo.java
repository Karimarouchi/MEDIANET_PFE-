package com.medianet.repository;

import com.medianet.entity.CveAuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CveAuditEventRepo extends JpaRepository<CveAuditEvent, Long> {

    @Query("""
            SELECT e FROM CveAuditEvent e
            WHERE LOWER(e.cveId) = LOWER(:cveId)
              AND LOWER(COALESCE(e.packageName, '')) = LOWER(:packageName)
            ORDER BY e.createdAt DESC
            """)
    List<CveAuditEvent> findTimeline(
            @Param("cveId") String cveId,
            @Param("packageName") String packageName);

    @Query("""
            SELECT e FROM CveAuditEvent e
            WHERE LOWER(e.cveId) = LOWER(:cveId)
            ORDER BY e.createdAt DESC
            """)
    List<CveAuditEvent> findByCveIdIgnoreCaseOrderByCreatedAtDesc(@Param("cveId") String cveId);

    boolean existsByCveIdIgnoreCaseAndPackageNameIgnoreCaseAndEventType(
            String cveId, String packageName, com.medianet.entity.CveAuditEventType eventType);
}
