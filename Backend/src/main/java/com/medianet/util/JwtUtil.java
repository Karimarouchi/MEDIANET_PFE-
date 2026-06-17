package com.medianet.util;

import com.medianet.entity.AccessPermission;
import com.medianet.entity.AccessRole;
import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.EnumSet;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private Key signingKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(String.valueOf(user.getId()))
                .claim("userId", user.getId())
                .claim("login", user.getLogin())
                .claim("name", user.getName() != null ? user.getName() : user.getLogin())
                .claim("avatar", user.getAvatarUrl() != null ? user.getAvatarUrl() : "")
                .claim("email", user.getEmail() != null ? user.getEmail() : "")
                .claim("url", user.getProfileUrl() != null ? user.getProfileUrl() : "")
                .claim("role", user.getRole() != null ? user.getRole().name() : UserRole.EMPLOYEE.name())
                .claim("systemRole", user.getRole() != null ? user.getRole().name() : UserRole.EMPLOYEE.name())
                .claim("roleName", resolveRoleName(user))
                .claim("accessRoleKey", resolveRoleKey(user))
                .claim("permissions", resolvePermissionNames(user))
                .claim("suspended", Boolean.TRUE.equals(user.getSuspended()))
                .claim("provider",
                        user.getPrimaryProvider() != null ? user.getPrimaryProvider().name()
                                : AuthProvider.LOCAL.name())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 7L * 24 * 3600 * 1000))
                .signWith(signingKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateProviderLinkState(Long userId, AuthProvider provider) {
        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .claim("userId", userId)
                .claim("stateType", "provider-link")
                .claim("provider", provider.name())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 10L * 60 * 1000))
                .signWith(signingKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isValidProviderLinkState(String state, AuthProvider provider) {
        Claims claims = parseClaims(state);
        if (claims == null) {
            return false;
        }
        String stateType = claims.get("stateType", String.class);
        String stateProvider = claims.get("provider", String.class);
        return "provider-link".equals(stateType) && provider.name().equals(stateProvider);
    }

    /**
     * Extracts the GitHub login claim from a "Bearer <token>" Authorization header.
     * Returns null if the header is absent, malformed, or the token is invalid.
     */
    public String extractLogin(String authHeader) {
        Claims claims = parseClaimsFromAuthHeader(authHeader);
        return claims != null ? claims.get("login", String.class) : null;
    }

    public Long extractUserId(String authHeader) {
        Claims claims = parseClaimsFromAuthHeader(authHeader);
        if (claims == null) {
            return null;
        }
        Object value = claims.get("userId");
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String stringValue && !stringValue.isBlank()) {
            return Long.parseLong(stringValue);
        }
        String subject = claims.getSubject();
        return subject != null && !subject.isBlank() ? Long.parseLong(subject) : null;
    }

    public UserRole extractRole(String authHeader) {
        Claims claims = parseClaimsFromAuthHeader(authHeader);
        String role = claims != null ? claims.get("role", String.class) : null;
        if (role == null) {
            return null;
        }
        try {
            return UserRole.valueOf(role);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public AuthProvider extractProvider(String authHeader) {
        Claims claims = parseClaimsFromAuthHeader(authHeader);
        String provider = claims != null ? claims.get("provider", String.class) : null;
        if (provider == null) {
            return null;
        }
        try {
            return AuthProvider.valueOf(provider);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public Long extractUserIdFromState(String state) {
        Claims claims = parseClaims(state);
        if (claims == null) {
            return null;
        }
        Object value = claims.get("userId");
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String stringValue && !stringValue.isBlank()) {
            return Long.parseLong(stringValue);
        }
        return null;
    }

    public Claims parseClaimsFromAuthHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        return parseClaims(authHeader.substring(7));
    }

    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            return null;
        }
    }

    private String resolveRoleName(User user) {
        AccessRole accessRole = user.getAccessRole();
        if (accessRole != null && accessRole.getName() != null && !accessRole.getName().isBlank()) {
            return accessRole.getName();
        }
        return user.getRole() != null ? user.getRole().name() : UserRole.EMPLOYEE.name();
    }

    private String resolveRoleKey(User user) {
        AccessRole accessRole = user.getAccessRole();
        if (accessRole != null && accessRole.getRoleKey() != null && !accessRole.getRoleKey().isBlank()) {
            return accessRole.getRoleKey();
        }
        return user.getRole() != null ? user.getRole().name() : UserRole.EMPLOYEE.name();
    }

    private List<String> resolvePermissionNames(User user) {
        return resolvePermissions(user).stream().map(Enum::name).toList();
    }

    private LinkedHashSet<AccessPermission> resolvePermissions(User user) {
        AccessRole accessRole = user.getAccessRole();
        if (accessRole != null && accessRole.getPermissions() != null && !accessRole.getPermissions().isEmpty()) {
            return new LinkedHashSet<>(accessRole.getPermissions());
        }
        return new LinkedHashSet<>(user.getRole() == UserRole.ADMIN
                ? EnumSet.allOf(AccessPermission.class)
                : EnumSet.of(
                        AccessPermission.DASHBOARD,
                        AccessPermission.REPOSITORIES,
                        AccessPermission.SCANS,
                        AccessPermission.VULNERABILITIES,
                        AccessPermission.SSL_ANALYSIS,
                        AccessPermission.SERVER_CONFIG,
                        AccessPermission.PIPELINE,
                        AccessPermission.PROFILE));
    }
}
