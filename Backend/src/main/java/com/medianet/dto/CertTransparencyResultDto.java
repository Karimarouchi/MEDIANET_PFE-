package com.medianet.dto;

import java.util.List;

public record CertTransparencyResultDto(
        String domain,
        List<CertTransparencyEntryDto> subdomains,
        int totalCertificates,
        int unknownCount) {
}
