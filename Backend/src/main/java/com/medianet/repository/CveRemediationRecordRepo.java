package com.medianet.repository;

import com.medianet.entity.CveRemediationRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CveRemediationRecordRepo extends JpaRepository<CveRemediationRecord, Long> {

    @Modifying
    @Query("DELETE FROM CveRemediationRecord")
    void deleteAllRecords();

    List<CveRemediationRecord> findBySlaBreachedIsNotNull();

    long countBySlaBreachedTrue();

    long countBySlaBreachedFalse();
}
