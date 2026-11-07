package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * One availability check of a project's site, made by Vulnix itself (see SiteMonitorService). {@code state} is
 * UP, DOWN or SKIPPED (address not public or not a valid domain: not checked, so it never counts in the uptime).
 */
@Entity
@Table(name = "site_checks", indexes = {
        @Index(name = "idx_site_check_domain_time", columnList = "domain, checked_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SiteCheck {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Lower-case domain as the project wrote it, without scheme or path. */
    @Column(nullable = false, length = 255)
    private String domain;

    @Column(name = "checked_at", nullable = false)
    private LocalDateTime checkedAt;

    @Column(nullable = false, length = 10)
    private String state;

    private Integer statusCode;

    private Integer responseMs;

    @Column(length = 255)
    private String message;
}
