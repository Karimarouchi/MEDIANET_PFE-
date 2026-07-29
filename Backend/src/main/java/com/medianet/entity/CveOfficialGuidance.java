package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Version stable officielle pour un CVE (+ package).
 * Définie par tout compte ayant la permission Journal CVE (« chef » = cette permission, pas un rôle système).
 * Liée au compte via {@link #updatedBy} / {@link #updatedByLogin}, comme les interventions développeurs.
 */
@Entity
@Table(name = "cve_official_guidance", indexes = {
        @Index(name = "idx_cve_official_cve_pkg", columnList = "cve_id, package_name", unique = true)
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CveOfficialGuidance {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", nullable = false, length = 64)
    private String cveId;

    @Column(name = "package_name", nullable = false, length = 255)
    @Builder.Default
    private String packageName = "";

    @Column(name = "stable_version", nullable = false, length = 128)
    private String stableVersion;

    @Column(name = "comment", columnDefinition = "TEXT")
    private String comment;

    @Column(name = "updated_by_login", length = 120)
    private String updatedByLogin;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "updated_by_id")
    private User updatedBy;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        if (updatedAt == null) updatedAt = now;
        if (packageName == null) packageName = "";
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
        if (packageName == null) packageName = "";
    }
}
