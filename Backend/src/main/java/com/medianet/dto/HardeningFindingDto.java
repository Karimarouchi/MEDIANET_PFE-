package com.medianet.dto;

public record HardeningFindingDto(
        Long id,
        String category,
        String severity,
        String title,
        String description,
        String recommendation,
        String detectedValue) {
}