package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "ci_tokens", indexes = {
        @Index(name = "idx_ci_token_hash", columnList = "token_hash", unique = true),
        @Index(name = "idx_ci_token_client", columnList = "client_id")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CiToken {

    public static final String LIVE_PREFIX = "vx_live_";
    public static final String TEST_PREFIX = "vx_test_";
    public static final String DEFAULT_SCOPES = "ci:scan,ci:verdict";
    public static final int DISPLAY_PREFIX_LENGTH = 16;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String name;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "token_prefix", nullable = false, length = 32)
    private String tokenPrefix;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "client_id", nullable = false)
    @OnDelete(action = OnDeleteAction.CASCADE)
    private Client client;

    @Column(name = "created_by_user_id")
    private Long createdByUserId;

    @Column(nullable = false, length = 255)
    @Builder.Default
    private String scopes = DEFAULT_SCOPES;

    @Builder.Default
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "ci_token_repositories",
            joinColumns = @JoinColumn(name = "token_id"),
            inverseJoinColumns = @JoinColumn(name = "repository_id")
    )
    private Set<Repository> repositories = new LinkedHashSet<>();

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
        if (scopes == null || scopes.isBlank()) {
            scopes = DEFAULT_SCOPES;
        }
    }

    public boolean isActive() {
        if (revokedAt != null) {
            return false;
        }
        return expiresAt == null || expiresAt.isAfter(Instant.now());
    }
}
