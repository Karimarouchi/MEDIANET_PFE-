package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "repositories")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Repository {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String repoUrl;

    /** GitHub login of the user who owns this repository entry */
    private String ownerLogin;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_user_id")
    private User ownerUser;

    @Enumerated(EnumType.STRING)
    @Column(name = "git_provider", nullable = false)
    @Builder.Default
    private AuthProvider gitProvider = AuthProvider.GITHUB;

    private String branch;
    private String scanMode;
    private String targetDomain;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime lastScannedAt;

    @Builder.Default
    @OneToMany(mappedBy = "repository", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("startedAt DESC")
    private List<ScanResult> scanResults = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "repository", cascade = CascadeType.ALL, orphanRemoval = true)
    private java.util.Set<ClientRepository> clientLinks = new java.util.LinkedHashSet<>();

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        if (gitProvider == null) {
            gitProvider = AuthProvider.GITHUB;
        }
    }
}
