package com.medianet.repository;

import com.medianet.entity.CveMlFeature;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface CveMlFeatureRepo extends JpaRepository<CveMlFeature, Long> {

    @Modifying
    @Query("DELETE FROM CveMlFeature")
    void deleteAllFeatures();
}
