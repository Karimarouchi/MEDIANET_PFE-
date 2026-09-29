package com.medianet.dto;

import java.util.List;

/** status: "OK" (lookup succeeded, subdomains may legitimately be empty) or
 *  "ERROR" (crt.sh could not be reached / errored — distinct from "zero found"). */
public record CertTransparencyResultDto(
        String domain,
        List<CertTransparencyEntryDto> subdomains,
        int totalCertificates,
        int unknownCount,
        String status) {
}
