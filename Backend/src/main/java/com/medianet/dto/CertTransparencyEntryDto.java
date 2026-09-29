package com.medianet.dto;

/** One subdomain observed in public Certificate Transparency logs (via crt.sh). */
public record CertTransparencyEntryDto(
        String subdomain,
        String issuer,
        String notBefore,
        String notAfter,
        boolean knownAsset) {
}
