package com.medianet.controller;

import com.medianet.dto.GitRepoDto;
import com.medianet.dto.UserDto;
import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import com.medianet.repository.UserRepo;
import com.medianet.service.AccessRoleService;
import com.medianet.service.GitLabService;
import com.medianet.service.TokenEncryptionService;
import com.medianet.service.UserService;
import com.medianet.util.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    @Value("${github.client.id}")
    private String githubClientId;

    @Value("${github.client.secret}")
    private String githubClientSecret;

    @Value("${github.oauth.redirect-uri}")
    private String githubRedirectUri;

    @Value("${github.oauth.frontend-url}")
    private String frontendUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final UserService userService;
    private final UserRepo userRepo;
    private final JwtUtil jwtUtil;
    private final GitLabService gitLabService;
    private final TokenEncryptionService tokenEncryptionService;
    private final AccessRoleService accessRoleService;

    public AuthController(UserService userService, UserRepo userRepo, JwtUtil jwtUtil,
            GitLabService gitLabService, TokenEncryptionService tokenEncryptionService,
            AccessRoleService accessRoleService) {
        this.userService = userService;
        this.userRepo = userRepo;
        this.jwtUtil = jwtUtil;
        this.gitLabService = gitLabService;
        this.tokenEncryptionService = tokenEncryptionService;
        this.accessRoleService = accessRoleService;
    }

    @GetMapping("/github")
    public ResponseEntity<Void> loginWithGitHub() {
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(buildGithubAuthorizationUrl(null)))
                .build();
    }

    @GetMapping("/github/link-url")
    public ResponseEntity<Map<String, String>> buildGithubLinkUrl(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        String state = jwtUtil.generateProviderLinkState(currentUser.getId(), AuthProvider.GITHUB);
        return ResponseEntity.ok(Map.of("url", buildGithubAuthorizationUrl(state)));
    }

    @GetMapping("/github/callback")
    public ResponseEntity<Void> githubCallback(
            @RequestParam String code,
            @RequestParam(required = false) String state) {
        try {
            String accessToken = exchangeGithubCode(code);
            Map<String, Object> githubUser = fetchGithubUser(accessToken);

            if (state != null && !state.isBlank()) {
                if (!jwtUtil.isValidProviderLinkState(state, AuthProvider.GITHUB)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid state");
                }
                Long userId = jwtUtil.extractUserIdFromState(state);
                if (userId == null) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing state user");
                }
                User currentUser = userRepo.findById(userId)
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
                userService.linkGithubAccount(currentUser, githubUser, accessToken);
                return ResponseEntity.status(HttpStatus.FOUND)
                        .location(URI.create(frontendUrl + "/profile?linked=github"))
                        .build();
            }

            User user = userService.upsertGithubUser(githubUser, accessToken);
            String jwt = jwtUtil.generateToken(user);
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendUrl + "/auth/callback?token=" + jwt))
                    .build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendUrl + "/login?error=oauth_failed"))
                    .build();
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> loginWithEmailPassword(@RequestBody LocalLoginRequest request) {
        User user = userService.authenticateLocalUser(request.email(), request.password());
        String jwt = jwtUtil.generateToken(user);
        return ResponseEntity.ok(Map.of(
                "token", jwt,
                "user", toUserDto(user)));
    }

    @GetMapping("/gitlab/link-url")
    public ResponseEntity<Map<String, String>> buildGitlabLinkUrl(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        String state = jwtUtil.generateProviderLinkState(currentUser.getId(), AuthProvider.GITLAB);
        return ResponseEntity.ok(Map.of("url", gitLabService.buildLinkAuthorizationUrl(state)));
    }

    @GetMapping("/gitlab/callback")
    public ResponseEntity<Void> gitlabCallback(
            @RequestParam String code,
            @RequestParam String state) {
        try {
            if (!jwtUtil.isValidProviderLinkState(state, AuthProvider.GITLAB)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid state");
            }
            Long userId = jwtUtil.extractUserIdFromState(state);
            if (userId == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing state user");
            }
            User user = userRepo.findById(userId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
            String accessToken = gitLabService.exchangeCodeForToken(code);
            Map<String, Object> profile = gitLabService.fetchCurrentUser(accessToken);
            userService.linkGitlabAccount(user, profile, accessToken);
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendUrl + "/profile?linked=gitlab"))
                    .build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendUrl + "/profile?error=gitlab_link_failed"))
                    .build();
        }
    }

    @PostMapping("/link-token")
    public ResponseEntity<UserDto> linkToken(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody LinkTokenRequest body) {
        User currentUser = userService.getRequiredUser(authHeader);
        AuthProvider provider = AuthProvider.valueOf(body.provider().toUpperCase());

        if (provider == AuthProvider.GITHUB) {
            Map<String, Object> githubUser = fetchGithubUser(body.token());
            currentUser = userService.linkGithubAccount(currentUser, githubUser, body.token());
        } else if (provider == AuthProvider.GITLAB) {
            Map<String, Object> gitlabUser = gitLabService.validatePersonalAccessToken(body.gitlabUrl(), body.token());
            currentUser = userService.linkGitlabAccount(currentUser, gitlabUser, body.token(), body.gitlabUrl());
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported provider");
        }

        return ResponseEntity.ok(toUserDto(currentUser));
    }

    @GetMapping("/me")
    public ResponseEntity<UserDto> me(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        return ResponseEntity.ok(toUserDto(userService.getRequiredUser(authHeader)));
    }

    @GetMapping("/github/repos")
    public ResponseEntity<List<GitRepoDto>> getUserRepos(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        String accessToken = userService.getAccessToken(user, AuthProvider.GITHUB);
        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.ok(List.of());
        }
        try {
            return ResponseEntity.ok(fetchGithubRepos(accessToken));
        } catch (Exception e) {
            return ResponseEntity.ok(List.of());
        }
    }

    @GetMapping("/gitlab/projects")
    public ResponseEntity<List<GitRepoDto>> getGitlabProjects(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        String accessToken = userService.getAccessToken(user, AuthProvider.GITLAB);
        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.ok(List.of());
        }
        try {
            return ResponseEntity.ok(gitLabService.listProjects(user.getGitlabUrl(), accessToken));
        } catch (Exception e) {
            return ResponseEntity.ok(List.of());
        }
    }

    private String exchangeGithubCode(String code) {
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        tokenHeaders.set("Accept", "application/json");

        MultiValueMap<String, String> tokenBody = new LinkedMultiValueMap<>();
        tokenBody.add("client_id", githubClientId);
        tokenBody.add("client_secret", githubClientSecret);
        tokenBody.add("code", code);
        tokenBody.add("redirect_uri", githubRedirectUri);

        ResponseEntity<Map<String, Object>> tokenResponse = restTemplate.exchange(
                "https://github.com/login/oauth/access_token",
                HttpMethod.POST,
                new HttpEntity<>(tokenBody, tokenHeaders),
                new ParameterizedTypeReference<>() {
                });
        Map<String, Object> tokenData = tokenResponse.getBody();
        if (tokenData == null || !tokenData.containsKey("access_token")) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "OAuth failed");
        }
        return String.valueOf(tokenData.get("access_token"));
    }

    private Map<String, Object> fetchGithubUser(String accessToken) {
        HttpHeaders userHeaders = new HttpHeaders();
        userHeaders.setBearerAuth(accessToken);
        userHeaders.set("Accept", "application/vnd.github+json");
        ResponseEntity<Map<String, Object>> userResponse = restTemplate.exchange(
                "https://api.github.com/user",
                HttpMethod.GET,
                new HttpEntity<>(userHeaders),
                new ParameterizedTypeReference<>() {
                });
        return userResponse.getBody() != null ? userResponse.getBody() : Map.of();
    }

    private List<GitRepoDto> fetchGithubRepos(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.set("Accept", "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        ResponseEntity<List<Map<String, Object>>> reposResponse = restTemplate.exchange(
                "https://api.github.com/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {
                });
        List<Map<String, Object>> repos = reposResponse.getBody();
        if (repos == null) {
            return List.of();
        }
        return repos.stream().map(r -> GitRepoDto.builder()
                .name(String.valueOf(r.getOrDefault("name", "")))
                .fullName(String.valueOf(r.getOrDefault("full_name", "")))
                .description(r.get("description") != null ? String.valueOf(r.get("description")) : "")
                .language(r.get("language") != null ? String.valueOf(r.get("language")) : "")
                .isPrivate(Boolean.TRUE.equals(r.get("private")))
                .stars(r.get("stargazers_count") instanceof Number n ? n.intValue() : 0)
                .htmlUrl(String.valueOf(r.getOrDefault("html_url", "")))
                .updatedAt(String.valueOf(r.getOrDefault("pushed_at", "")))
                .provider("GITHUB")
                .build()).toList();
    }

    private UserDto toUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .login(user.getLogin())
                .name(user.getName())
                .avatarUrl(user.getAvatarUrl())
                .email(user.getEmail())
                .role(accessRoleService.getDisplayRoleName(user))
                .systemRole(user.getRole() != null ? user.getRole().name() : null)
                .accessRoleId(user.getAccessRole() != null ? user.getAccessRole().getId() : null)
                .accessRoleKey(accessRoleService.getRoleKey(user))
                .primaryProvider(user.getPrimaryProvider() != null ? user.getPrimaryProvider().name() : null)
                .hasGithubLinked(user.hasGithubLinked())
                .hasGitlabLinked(user.hasGitlabLinked())
                .hasLocalPassword(user.hasLocalPassword())
                .suspended(Boolean.TRUE.equals(user.getSuspended()))
                .permissions(accessRoleService.getEffectivePermissionNames(user))
                .createdAt(user.getCreatedAt())
                .gitlabUrl(user.getGitlabUrl())
                .build();
    }

    private String buildGithubAuthorizationUrl(String state) {
        String githubUrl = "https://github.com/login/oauth/authorize"
                + "?client_id=" + githubClientId
                + "&redirect_uri=" + githubRedirectUri
                + "&scope=repo,user:email"
                + "&allow_signup=false";
        if (state != null && !state.isBlank()) {
            githubUrl += "&state=" + state;
        }
        return githubUrl;
    }

    public record LinkTokenRequest(String provider, String token, String gitlabUrl) {
    }

    public record LocalLoginRequest(String email, String password) {
    }
}
