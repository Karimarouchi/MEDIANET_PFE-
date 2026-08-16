package com.medianet.service;

import com.medianet.dto.CiTokenCreatedDto;
import com.medianet.dto.CiTokenDto;
import com.medianet.entity.CiToken;
import com.medianet.entity.Client;
import com.medianet.entity.ClientRepositoryId;
import com.medianet.entity.Repository;
import com.medianet.entity.User;
import com.medianet.repository.CiTokenRepo;
import com.medianet.repository.ClientRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.security.CiPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CiTokenService {

    private static final Logger log = LoggerFactory.getLogger(CiTokenService.class);
    private static final int RANDOM_BYTES = 32;
    private static final int DEFAULT_TTL_DAYS = 90;
    private static final int MAX_TTL_DAYS = 365;
    static final Set<String> DEFAULT_SCOPE_SET = Set.of("ci:scan", "ci:verdict");

    private final CiTokenRepo ciTokenRepo;
    private final ClientRepo clientRepo;
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final RepositoryRepo repositoryRepo;
    private final SecureRandom secureRandom = new SecureRandom();

    public CiTokenService(CiTokenRepo ciTokenRepo, ClientRepo clientRepo,
            ClientRepositoryRepo clientRepositoryRepo, RepositoryRepo repositoryRepo) {
        this.ciTokenRepo = ciTokenRepo;
        this.clientRepo = clientRepo;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.repositoryRepo = repositoryRepo;
    }

    public static boolean isCiTokenValue(String raw) {
        if (raw == null || raw.isBlank()) {
            return false;
        }
        String value = raw.trim();
        return (value.startsWith(CiToken.LIVE_PREFIX) || value.startsWith(CiToken.TEST_PREFIX))
                && value.length() >= CiToken.LIVE_PREFIX.length() + 20;
    }

    static String hashToken(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashed);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to hash CI token", e);
        }
    }

    @Transactional
    public CiTokenCreatedDto createToken(User admin, String name, Long clientId, List<Long> repositoryIds,
            Integer expiresInDays) {
        if (admin == null || admin.getId() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }
        String trimmedName = name != null ? name.trim() : "";
        if (trimmedName.isEmpty() || trimmedName.length() > 80) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token name is required (max 80 characters)");
        }
        if (clientId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientId is required");
        }
        if (repositoryIds == null || repositoryIds.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one repositoryId is required");
        }

        Client client = clientRepo.findById(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));

        Set<Long> requested = repositoryIds.stream()
                .filter(id -> id != null && id > 0)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (requested.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one repositoryId is required");
        }

        Set<Repository> repositories = new LinkedHashSet<>();
        for (Long repoId : requested) {
            if (!clientRepositoryRepo.existsById(new ClientRepositoryId(clientId, repoId))) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Repository " + repoId + " is not linked to this client");
            }
            Repository repository = repositoryRepo.findById(repoId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found"));
            repositories.add(repository);
        }

        Instant expiresAt = resolveExpiry(expiresInDays);
        String plaintext = generatePlaintext();
        Instant now = Instant.now();

        CiToken token = CiToken.builder()
                .name(trimmedName)
                .tokenHash(hashToken(plaintext))
                .tokenPrefix(plaintext.substring(0, Math.min(CiToken.DISPLAY_PREFIX_LENGTH, plaintext.length())))
                .client(client)
                .createdByUserId(admin.getId())
                .scopes(CiToken.DEFAULT_SCOPES)
                .repositories(repositories)
                .expiresAt(expiresAt)
                .createdAt(now)
                .build();
        token = ciTokenRepo.save(token);

        log.info("CI token created prefix={} clientId={} repoCount={} createdBy={}",
                token.getTokenPrefix(), clientId, repositories.size(), admin.getId());

        return new CiTokenCreatedDto(
                token.getId(),
                token.getName(),
                plaintext,
                token.getTokenPrefix(),
                client.getId(),
                client.getName(),
                repositoryIdsOf(token),
                repositoryUrlsOf(token),
                scopeList(token.getScopes()),
                token.getExpiresAt(),
                token.getCreatedAt());
    }

    @Transactional(readOnly = true)
    public List<CiTokenDto> listByClient(Long clientId) {
        if (clientId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientId is required");
        }
        if (!clientRepo.existsById(clientId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found");
        }
        return ciTokenRepo.findDetailedByClientId(clientId).stream()
                .sorted(Comparator.comparing(CiToken::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .map(this::toDto)
                .toList();
    }

    @Transactional
    public CiTokenDto revoke(Long tokenId) {
        CiToken token = ciTokenRepo.findById(tokenId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "CI token not found"));
        if (token.getRevokedAt() == null) {
            token.setRevokedAt(Instant.now());
            token = ciTokenRepo.save(token);
            log.info("CI token revoked prefix={} id={}", token.getTokenPrefix(), token.getId());
        }
        return toDto(token);
    }

    @Transactional
    public Optional<CiPrincipal> authenticate(String rawToken) {
        if (!isCiTokenValue(rawToken)) {
            return Optional.empty();
        }
        String hash = hashToken(rawToken.trim());
        Optional<CiToken> found = ciTokenRepo.findDetailedByTokenHash(hash);
        if (found.isEmpty() || !found.get().isActive()) {
            return Optional.empty();
        }
        CiToken token = found.get();
        token.setLastUsedAt(Instant.now());
        ciTokenRepo.save(token);
        return Optional.of(toPrincipal(token));
    }

    public boolean isRepositoryStillLinkedToClient(Long clientId, Long repositoryId) {
        if (clientId == null || repositoryId == null) {
            return false;
        }
        return clientRepositoryRepo.existsById(new ClientRepositoryId(clientId, repositoryId));
    }

    private Instant resolveExpiry(Integer expiresInDays) {
        int days = expiresInDays == null ? DEFAULT_TTL_DAYS : expiresInDays;
        if (days < 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "expiresInDays must be 0 or a positive number");
        }
        if (days == 0) {
            return null;
        }
        if (days > MAX_TTL_DAYS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "expiresInDays cannot exceed " + MAX_TTL_DAYS);
        }
        return Instant.now().plus(days, ChronoUnit.DAYS);
    }

    private String generatePlaintext() {
        byte[] bytes = new byte[RANDOM_BYTES];
        secureRandom.nextBytes(bytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return CiToken.LIVE_PREFIX + secret;
    }

    private CiPrincipal toPrincipal(CiToken token) {
        Set<Long> repoIds = token.getRepositories() == null
                ? Set.of()
                : token.getRepositories().stream()
                        .map(Repository::getId)
                        .collect(Collectors.toCollection(LinkedHashSet::new));
        return new CiPrincipal(
                token.getId(),
                token.getName(),
                token.getTokenPrefix(),
                token.getClient().getId(),
                Set.copyOf(repoIds),
                new LinkedHashSet<>(scopeList(token.getScopes())));
    }

    private CiTokenDto toDto(CiToken token) {
        Client client = token.getClient();
        return new CiTokenDto(
                token.getId(),
                token.getName(),
                token.getTokenPrefix(),
                client != null ? client.getId() : null,
                client != null ? client.getName() : null,
                repositoryIdsOf(token),
                repositoryUrlsOf(token),
                scopeList(token.getScopes()),
                token.getExpiresAt(),
                token.getLastUsedAt(),
                token.getRevokedAt(),
                token.getCreatedAt(),
                token.isActive());
    }

    private static List<Long> repositoryIdsOf(CiToken token) {
        if (token.getRepositories() == null) {
            return List.of();
        }
        return token.getRepositories().stream()
                .sorted(Comparator.comparing(Repository::getId, Comparator.nullsLast(Long::compareTo)))
                .map(Repository::getId)
                .toList();
    }

    private static List<String> repositoryUrlsOf(CiToken token) {
        if (token.getRepositories() == null) {
            return List.of();
        }
        return token.getRepositories().stream()
                .sorted(Comparator.comparing(Repository::getId, Comparator.nullsLast(Long::compareTo)))
                .map(Repository::getRepoUrl)
                .toList();
    }

    private static List<String> scopeList(String scopes) {
        if (scopes == null || scopes.isBlank()) {
            return new ArrayList<>(DEFAULT_SCOPE_SET);
        }
        return Arrays.stream(scopes.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
