package com.medianet.entity;

/**
 * Lifecycle status of a CVE+package in the remediation journal (Sprint A).
 */
public enum CveRemediationStatus {
    DETECTE,
    EVALUE,
    VERSION_OFFICIELLE,
    CORRIGE,
    ECART_POLITIQUE,
    ACCEPTE_RISQUE
}
