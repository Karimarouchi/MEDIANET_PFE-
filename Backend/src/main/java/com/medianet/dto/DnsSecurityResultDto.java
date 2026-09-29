package com.medianet.dto;

import java.util.List;

public record DnsSecurityResultDto(
        String domain,
        String spfRecord,
        boolean spfPresent,
        String dmarcRecord,
        boolean dmarcPresent,
        String dmarcPolicy,
        List<String> caaRecords,
        String caaStatus) {
}
