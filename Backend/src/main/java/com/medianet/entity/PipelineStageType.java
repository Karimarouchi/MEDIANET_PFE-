package com.medianet.entity;

public enum PipelineStageType {
    SOURCE("Source"),
    BUILD("Build"),
    TEST("Tests"),
    SECURITY_SCAN("Security Scan"),
    QUALITY_GATE("Quality Gate"),
    DOCKER_BUILD("Docker Build"),
    CONTAINER_SCAN("Container Scan"),
    DEPLOY_STAGING("Deploy Staging"),
    DAST_SCAN("DAST Scan"),
    APPROVAL("Approval"),
    DEPLOY_PRODUCTION("Production Deploy");

    private final String label;

    PipelineStageType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}