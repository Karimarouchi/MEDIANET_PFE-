package com.medianet.repository;

import com.medianet.entity.PolicyDeviationRequest;
import com.medianet.entity.PolicyDeviationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PolicyDeviationRequestRepo extends JpaRepository<PolicyDeviationRequest, Long> {

    List<PolicyDeviationRequest> findByStatusOrderByCreatedAtDesc(PolicyDeviationStatus status);

    @Query("""
            SELECT r FROM PolicyDeviationRequest r
            WHERE r.status = com.medianet.entity.PolicyDeviationStatus.PENDING
            ORDER BY r.createdAt DESC
            """)
    List<PolicyDeviationRequest> findAllPending();

    boolean existsByStatusAndCveIdIgnoreCaseAndPackageNameIgnoreCase(
            PolicyDeviationStatus status, String cveId, String packageName);
}
