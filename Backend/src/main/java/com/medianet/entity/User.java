package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String login;

    private String name;

    @Column(name = "avatar_url")
    private String avatarUrl;

    private String email;

    @Column(name = "profile_url")
    private String profileUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private UserRole role = UserRole.EMPLOYEE;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "access_role_id")
    private AccessRole accessRole;

    @Column(nullable = false)
    @Builder.Default
    private Boolean suspended = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "primary_provider", nullable = false)
    @Builder.Default
    private AuthProvider primaryProvider = AuthProvider.GITHUB;

    @Column(name = "gh_token", columnDefinition = "TEXT")
    private String ghToken;

    @Column(name = "gl_token", columnDefinition = "TEXT")
    private String glToken;

    @Column(name = "docker_hub_username", length = 180)
    private String dockerHubUsername;

    @Column(name = "docker_hub_token", columnDefinition = "TEXT")
    private String dockerHubToken;

    @Column(name = "password_hash", length = 120)
    private String passwordHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (role == null) {
            role = UserRole.EMPLOYEE;
        }
        if (suspended == null) {
            suspended = false;
        }
        if (primaryProvider == null) {
            primaryProvider = AuthProvider.GITHUB;
        }
    }

    public boolean hasGithubLinked() {
        return ghToken != null && !ghToken.isBlank();
    }

    public boolean hasGitlabLinked() {
        return glToken != null && !glToken.isBlank();
    }

    public boolean hasLocalPassword() {
        return passwordHash != null && !passwordHash.isBlank();
    }

    public boolean hasDockerHubLinked() {
        return dockerHubUsername != null && !dockerHubUsername.isBlank()
                && dockerHubToken != null && !dockerHubToken.isBlank();
    }
}