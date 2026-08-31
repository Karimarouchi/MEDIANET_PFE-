package com.medianet.entity;

/**
 * Family of a scanner finding. CWE/Semgrep must never be merged with CVE/GHSA.
 */
public enum FindingKind {
    DEPENDENCY,
    CODE_WEAKNESS,
    DAST
}
