package com.medianet.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ScanRequest {
    // For repo-based scans: required. For docker-image mode: set to dockerImage
    // value.
    private String repoUrl;
    private String branch;
    private String scanMode;
    private String targetDomain;
    private String dastTargetUrl;

    // Docker image scanning (mode = docker-image)
    private String dockerImage; // e.g. antigoneagency/ecommerce-frontoffice:latest
    private Integer containerPort; // e.g. 3000

    // Idée 3 — OS cible : passed as --distro to Grype
    // e.g. "ubuntu:22.04", "alpine:3.18", "debian:12", "windows:2022"
    private String targetOs;

    // Idée 2 — OpenSCAP compliance profile
    // e.g. "CIS_L1", "CIS_L2", "NIST_800-53", "PCI_DSS"
    private String complianceProfile;
}
