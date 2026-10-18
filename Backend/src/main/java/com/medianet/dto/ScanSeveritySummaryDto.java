package com.medianet.dto;

/** Counts from one completed scan: critical, high, and CISA KEV. */
public record ScanSeveritySummaryDto(Long scanId, long critical, long high, long kev) {
}
