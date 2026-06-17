package com.medianet.dto;

public record PortExposureDto(
        Integer portNumber,
        String protocol,
        String bindAddress,
        String processName,
        String serviceName,
        String exposureLevel,
        String state) {
}