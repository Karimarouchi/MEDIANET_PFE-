package com.medianet.repository;

import com.medianet.entity.PipelineDefinition;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PipelineDefinitionRepo extends JpaRepository<PipelineDefinition, Long> {
    List<PipelineDefinition> findAllByOrderByUpdatedAtDesc();
}