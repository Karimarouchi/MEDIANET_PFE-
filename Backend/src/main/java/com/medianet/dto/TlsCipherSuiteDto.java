package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TlsCipherSuiteDto {
    /** IANA cipher suite name, e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    private String ianaName;
    private String opensslName;
    /** Encryption algorithm / mode (AES-256-GCM, ChaCha20-Poly1305, …) */
    private String encryption;
    /** Key exchange (ECDHE, DHE, RSA, TLS 1.3 KEX, …) */
    private String keyExchange;
    private int keySize;
    private boolean forwardSecrecy;
    private boolean aead;
    /** STRONG | WEAK | FORBIDDEN */
    private String strength;
}
