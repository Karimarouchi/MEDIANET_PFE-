package com.medianet.repository;

import com.medianet.entity.SupplyChainScore;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface SupplyChainScoreRepo extends JpaRepository<SupplyChainScore, Long> {

    List<SupplyChainScore> findByEcosystemAndNameIn(String ecosystem, Collection<String> names);
}
