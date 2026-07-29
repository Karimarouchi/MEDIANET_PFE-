package com.medianet.repository;

import com.medianet.entity.CveOfficialGuidance;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CveOfficialGuidanceRepo extends JpaRepository<CveOfficialGuidance, Long> {

    Optional<CveOfficialGuidance> findByCveIdIgnoreCaseAndPackageNameIgnoreCase(String cveId, String packageName);

    List<CveOfficialGuidance> findByCveIdIgnoreCaseOrderByUpdatedAtDesc(String cveId);

    List<CveOfficialGuidance> findAllByOrderByUpdatedAtDesc();
}