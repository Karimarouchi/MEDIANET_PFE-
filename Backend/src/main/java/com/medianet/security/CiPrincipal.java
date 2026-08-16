package com.medianet.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;

/**
 * Authenticated CI service-account, attached to the request by {@code JwtAuthFilter}.
 * Never carries the raw token.
 */
public record CiPrincipal(
        Long tokenId,
        String name,
        String tokenPrefix,
        Long clientId,
        Set<Long> repositoryIds,
        Set<String> scopes
) {
    public static final String REQUEST_ATTR = "vulnix.ciPrincipal";

    public static CiPrincipal require(HttpServletRequest request) {
        Object attr = request.getAttribute(REQUEST_ATTR);
        if (attr instanceof CiPrincipal principal) {
            return principal;
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "CI token required");
    }

    public boolean hasScope(String scope) {
        return scope != null && scopes != null && scopes.contains(scope);
    }

    public boolean canAccessRepository(Long repositoryId) {
        return repositoryId != null && repositoryIds != null && repositoryIds.contains(repositoryId);
    }

    public void assertCanAccessRepository(Long repositoryId) {
        if (!canAccessRepository(repositoryId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Repository not in CI token scope");
        }
    }
}
