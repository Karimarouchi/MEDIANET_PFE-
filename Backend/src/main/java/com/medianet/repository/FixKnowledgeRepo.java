package com.medianet.repository;

import com.medianet.entity.FixKnowledge;
import com.medianet.entity.FixKnowledgeStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface FixKnowledgeRepo extends JpaRepository<FixKnowledge, Long> {

    List<FixKnowledge> findByStatusAndPackageNameIgnoreCaseOrderBySuccessCountDescUsageCountDescCreatedAtDesc(
            FixKnowledgeStatus status, String packageName);

    List<FixKnowledge> findByStatusAndCveIdIgnoreCaseOrderBySuccessCountDescUsageCountDescCreatedAtDesc(
            FixKnowledgeStatus status, String cveId);

    List<FixKnowledge> findAllByOrderByCreatedAtDesc();

    @Query("""
            SELECT f FROM FixKnowledge f
            WHERE f.status = :status
              AND LOWER(f.packageName) IN :names
            ORDER BY f.successCount DESC, f.usageCount DESC, f.createdAt DESC
            """)
    List<FixKnowledge> findActiveByPackageNames(
            @Param("status") FixKnowledgeStatus status,
            @Param("names") Collection<String> names);
}
