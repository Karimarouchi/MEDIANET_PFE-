package com.medianet.dto;

public record ServiceStatusDto(
        String serviceName,
        String state,
        String subState,
        String enabledStatus) {
}