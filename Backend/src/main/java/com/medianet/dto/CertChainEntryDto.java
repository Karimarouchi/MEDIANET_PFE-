package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertChainEntryDto {
    /** SERVER | INTERMEDIATE | ROOT */
    private String type;
    private CertNameDto subject;
    private CertNameDto issuer;
    private String serialNumber;
    private String notAfter;
    private String signatureAlgorithm;
    private String sha256Fingerprint;
    /** VALID | EXPIRED | UNKNOWN */
    private String status;
    private String pem;
}
