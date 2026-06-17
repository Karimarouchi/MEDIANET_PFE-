package com.medianet.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record ServerNodeRequest(
        @NotBlank String name,
        @NotBlank String host,
        @NotNull @Min(1) Integer port,
        @NotBlank String username,
        @NotBlank String nodeType,
        @NotBlank String authMethod,
        String environment,
        String templateKey,
        String owner,
        String clientName,
        String projectName,
        String runbookUrl,
        List<String> tags,
        String notes,
        String password,
        String privateKey,
        String privateKeyPassphrase,
        String description) {
}