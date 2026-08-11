package com.medianet.service;

import com.medianet.entity.RefreshToken;
import com.medianet.entity.User;
import com.medianet.repository.RefreshTokenRepo;
import com.medianet.repository.UserRepo;
import com.medianet.util.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class AuthSessionService {

    private final RefreshTokenRepo refreshTokenRepo;
    private final UserRepo userRepo;
    private final JwtUtil jwtUtil;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${jwt.refresh-token-days:7}")
    private long refreshTokenDays;

    public AuthSessionService(RefreshTokenRepo refreshTokenRepo, UserRepo userRepo, JwtUtil jwtUtil) {
        this.refreshTokenRepo = refreshTokenRepo;
        this.userRepo = userRepo;
        this.jwtUtil = jwtUtil;
    }

    public record SessionTokens(String accessToken, String refreshToken) {
    }

    @Transactional
    public SessionTokens issueSession(User user) {
        String accessToken = jwtUtil.generateToken(user);
        String refreshRaw = generateRefreshToken();
        persistRefreshToken(user.getId(), refreshRaw);
        return new SessionTokens(accessToken, refreshRaw);
    }

    @Transactional
    public SessionTokens refreshSession(String refreshRaw) {
        RefreshToken stored = requireActiveRefreshToken(refreshRaw);
        User user = userRepo.findById(stored.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
        if (Boolean.TRUE.equals(user.getSuspended())) {
            stored.setRevokedAt(Instant.now());
            refreshTokenRepo.save(stored);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is suspended");
        }

        stored.setRevokedAt(Instant.now());
        refreshTokenRepo.save(stored);

        return issueSession(user);
    }

    @Transactional
    public void revokeRefreshToken(String refreshRaw) {
        if (refreshRaw == null || refreshRaw.isBlank()) {
            return;
        }
        refreshTokenRepo.findByTokenHash(hash(refreshRaw)).ifPresent(token -> {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(Instant.now());
                refreshTokenRepo.save(token);
            }
        });
    }

    @Transactional
    public void revokeAllForUser(Long userId) {
        if (userId == null) {
            return;
        }
        refreshTokenRepo.revokeAllActiveForUser(userId, Instant.now());
    }

    private RefreshToken requireActiveRefreshToken(String refreshRaw) {
        if (refreshRaw == null || refreshRaw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token required");
        }
        RefreshToken stored = refreshTokenRepo.findByTokenHash(hash(refreshRaw))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token"));
        if (!stored.isActive()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token expired or revoked");
        }
        return stored;
    }

    private void persistRefreshToken(Long userId, String refreshRaw) {
        RefreshToken entity = RefreshToken.builder()
                .userId(userId)
                .tokenHash(hash(refreshRaw))
                .expiresAt(Instant.now().plusSeconds(refreshTokenDays * 24L * 3600L))
                .build();
        refreshTokenRepo.save(entity);
    }

    private String generateRefreshToken() {
        byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashed);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to hash refresh token", e);
        }
    }
}
