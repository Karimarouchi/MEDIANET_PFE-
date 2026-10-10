package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Cached supply-chain screening result of ONE registry package version. The content of a published
 * version does not change, so the score is reused across scans until it expires or the model changes.
 */
@Entity
@Table(name = "supply_chain_scores", uniqueConstraints = @UniqueConstraint(columnNames = { "ecosystem", "name",
        "version" }), indexes = @Index(name = "idx_sc_score_name", columnList = "ecosystem, name"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SupplyChainScore {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 32)
    private String ecosystem;

    @Column(nullable = false, length = 300)
    private String name;

    @Column(nullable = false, length = 120)
    private String version;

    /** SCORED, NOT_FOUND, TOO_LARGE, UNSUPPORTED_ECOSYSTEM... (transient errors are never stored). */
    @Column(nullable = false, length = 40)
    private String status;

    /** KNOWN_MALICIOUS, HIGH_CONFIDENCE, REVIEW, LOW or null when not scored. */
    @Column(length = 24)
    private String tier;

    private Double suspicionProba;

    @Column(length = 40)
    private String probableType;

    /** JSON array of human-readable reasons. */
    @Column(columnDefinition = "TEXT")
    private String reasonsJson;

    @Column(length = 80)
    private String knownMaliciousId;

    @Column(length = 40)
    private String modelVersion;

    @Column(nullable = false)
    private LocalDateTime scoredAt;
}
