package com.medianet.dto;

public record DockerHubCredentialRequest(
        String username,
        String token) {
}