package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * A repository whose CI runs on Woodpecker, driven by Vulnix. Vulnix provides the pipeline (config extension)
 * and the scan step authenticates with the CI token {@code ciTokenId}, stored only as a Woodpecker secret.
 */
@Entity
@Table(name = "ci_pipeline_links", indexes = {
        @Index(name = "idx_ci_pipeline_repo", columnList = "repository_id", unique = true),
        @Index(name = "idx_ci_pipeline_wp_repo", columnList = "woodpecker_repo_id", unique = true)
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CiPipelineLink {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "repository_id", nullable = false)
    private Long repositoryId;

    /** Project the CI token is scoped to. */
    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "woodpecker_repo_id", nullable = false)
    private Long woodpeckerRepoId;

    /** owner/name on the forge, checked against each config request. */
    @Column(name = "forge_full_name", nullable = false, length = 255)
    private String forgeFullName;

    @Column(name = "ci_token_id")
    private Long ciTokenId;

    @Column(name = "enabled_by_user_id")
    private Long enabledByUserId;

    @Column(name = "enabled_at", nullable = false)
    private Instant enabledAt;

    /**
     * Newest finished pipeline the CD already looked at. Null until the first check, which only records the current
     * state: what was there before the CD was switched on is never deployed (the first install is done by hand).
     */
    @Column(name = "cd_last_pipeline")
    private Long cdLastPipeline;
}
