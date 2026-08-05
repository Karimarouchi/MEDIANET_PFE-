package com.medianet.dto;

import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TlsProtocolDetailDto {
    /** tls13 | tls12 | tls11 | tls10 | ssl30 | ssl20 */
    private String id;
    private String label;
    /** ENABLED | DISABLED | NOT_TESTED | INCONCLUSIVE */
    private String status;
    private Boolean handshakeOk;
    private int acceptedCount;
    private int weakCount;
    private int forbiddenCount;
    private Boolean forwardSecrecy;
    private Boolean aead;
    private Boolean compression;
    private Boolean secureRenegotiation;
    private String endpoint;
    private String ip;
    private Integer port;
    private String sni;
    private String tool;
    private String toolVersion;
    private String scannedAt;
    /** Haute | Moyenne | Faible */
    private String confidence;
    private String evidence;

    @Builder.Default
    private List<TlsCipherSuiteDto> ciphers = new ArrayList<>();
}
