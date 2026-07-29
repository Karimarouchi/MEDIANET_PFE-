package com.medianet.entity;

/**
 * Application permissions.
 * PIPELINE is kept only so Hibernate can still read legacy DB rows; treat it as CVE_JOURNAL.
 */
public enum AccessPermission {
    DASHBOARD,
    REPOSITORIES,
    PROJECTS,
    SCANS,
    VULNERABILITIES,
    SSL_ANALYSIS,
    SERVER_CONFIG,
    CVE_JOURNAL,
    /** @deprecated legacy alias of {@link #CVE_JOURNAL} — do not assign to new roles */
    @Deprecated
    PIPELINE,
    PROFILE,
    ADMIN_USERS,
    ADMIN_ROLES,
    ADMIN_PROJECTS
}
