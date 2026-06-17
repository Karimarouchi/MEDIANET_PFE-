package com.medianet.dto;

public record DockerHubCredentialDto(
        String username,
        boolean hasToken) {
}