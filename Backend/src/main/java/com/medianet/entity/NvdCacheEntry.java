package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "nvd_cache")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NvdCacheEntry {

    /** CVE-ID as primary key (e.g. "CVE-2024-57699") */
    @Id
    private String cveId;

    @Column(columnDefinition = "TEXT")
    private String description;

    /** French translation of the description (auto-translated via MyMemory API). */
    @Column(columnDefinition = "TEXT")
    private String descriptionFr;

    private Double cvssScore;

    /** e.g. CRITICAL / HIGH / MEDIUM / LOW */
    private String severity;

    @Column(columnDefinition = "TEXT")
    private String cvssVector;

    /** ISO-8601 date when the CVE was published on NVD */
    private String publishedDate;

    /** Cached at timestamp — used to expire stale entries after 30 days */
    private LocalDateTime cachedAt;

    /**
     * OS platform affected by this CVE, derived from CPE data.
     * Values: "WINDOWS", "LINUX", "CROSS_PLATFORM"
     */
    @Column(name = "affected_os")
    private String affectedOs;
}
