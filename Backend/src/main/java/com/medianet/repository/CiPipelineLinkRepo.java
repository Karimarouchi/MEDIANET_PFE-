package com.medianet.repository;

import com.medianet.entity.CiPipelineLink;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface CiPipelineLinkRepo extends JpaRepository<CiPipelineLink, Long> {

    Optional<CiPipelineLink> findByRepositoryId(Long repositoryId);

    Optional<CiPipelineLink> findByWoodpeckerRepoId(Long woodpeckerRepoId);

    List<CiPipelineLink> findByRepositoryIdIn(Collection<Long> repositoryIds);

    List<CiPipelineLink> findByClientId(Long clientId);
}
