package com.medianet.dto;

import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertificateDetailDto {

    /** VALID | EXPIRING_SOON | EXPIRING_CRITICAL | EXPIRED | UNKNOWN */
    private String validityStatus;
    private String notBefore;
    private String notAfter;
    private Integer totalValidityDays;
    private Integer daysRemaining;
    private Double percentRemaining;
    private String recommendedRenewalDate;
    private Boolean expired;

    private String commonName;
    private String testedHostname;
    /** MATCH | MISMATCH | NOT_TESTED */
    private String hostnameMatch;
    private Boolean wildcard;
    @Builder.Default
    private List<CertSanEntryDto> sans = new ArrayList<>();

    private String publicKeyAlgorithm;
    private String keyType;
    private Integer keySize;
    private String curveName;
    private String signatureAlgorithm;
    private String hashAlgorithm;
    /** FORT | MOYEN | FAIBLE | INCONNU */
    private String securityLevel;
    private Boolean weakKey;
    private Boolean obsoleteSignature;

    private Boolean chainComplete;
    private Boolean chainOrderValid;
    private Boolean intermediatePresent;
    private Boolean rootRecognized;
    private Boolean selfSigned;
    private String validationError;
    @Builder.Default
    private List<CertChainEntryDto> chain = new ArrayList<>();

    /** CONFORME | NON_CONFORME | NON_DETECTE | NON_TESTE | INCONCLUSIF */
    private String ocspUrlStatus;
    /** Actual AIA OCSP URI when present in the certificate. */
    private String ocspUrl;
    private String ocspResponseStatus;
    private String revocationStatus;
    private String ocspStaplingStatus;
    private String crlUrlStatus;
    /** CRL Distribution Point URI when present. */
    private String crlUrl;
    private String transparencyStatus;
    private Integer sctCount;
    private String ctLogs;
    private Boolean mustStaple;

    /** NON_TESTE when extensions absent from source */
    private String keyUsage;
    private String extendedKeyUsage;
    private Boolean serverAuth;
    private Boolean clientAuth;
    private String basicConstraints;
    private Boolean isCa;

    @Builder.Default
    private List<CertTrustStoreDto> trustStores = new ArrayList<>();

    private String endpoint;
    private String ip;
    private Integer port;
    private String sni;
    private String scannedAt;
    private String scanDuration;
    private String tool;
    private String toolVersion;
    private String confidence;
    private String sha256Fingerprint;
    private String serialNumber;
    private String leafPem;
    private Boolean ev;
}
