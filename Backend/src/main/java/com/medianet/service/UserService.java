package com.medianet.service;

import com.medianet.entity.AccessRole;
import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.UserRepo;
import com.medianet.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@Service
@Transactional
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepo userRepo;
    private final AccessRoleService accessRoleService;
    private final TokenEncryptionService tokenEncryptionService;
    private final JwtUtil jwtUtil;
    private final JdbcTemplate jdbcTemplate;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Value("${app.first-user-is-admin:true}")
    private boolean firstUserIsAdmin;

    @Value("${app.bootstrap.admin.enabled:true}")
    private boolean bootstrapAdminEnabled;

    @Value("${app.bootstrap.admin.email:Admin@Medianet.com}")
    private String bootstrapAdminEmail;

    @Value("${app.bootstrap.admin.password:Admin@123456}")
    private String bootstrapAdminPassword;

    @Value("${app.bootstrap.admin.login:Admin@Medianet.com}")
    private String bootstrapAdminLogin;

    @Value("${app.bootstrap.admin.name:Admin Medianet}")
    private String bootstrapAdminName;

    public UserService(UserRepo userRepo, AccessRoleService accessRoleService,
            TokenEncryptionService tokenEncryptionService, JwtUtil jwtUtil, JdbcTemplate jdbcTemplate) {
        this.userRepo = userRepo;
        this.accessRoleService = accessRoleService;
        this.tokenEncryptionService = tokenEncryptionService;
        this.jwtUtil = jwtUtil;
        this.jdbcTemplate = jdbcTemplate;
    }

    public void ensureRoleCatalog() {
        accessRoleService.ensureSystemRoles();
    }

    public void normalizeLegacyClientAccessModel() {
        int migratedAssignments = jdbcTemplate.update("""
                insert into employee_clients (employee_id, client_id, assigned_at)
                select c.user_id, c.id, current_timestamp
                from clients c
                where c.user_id is not null
                    and not exists (
                        select 1 from employee_clients ec
                        where ec.employee_id = c.user_id and ec.client_id = c.id
                    )
                """);
        int clearedLegacyLinks = jdbcTemplate.update("update clients set user_id = null where user_id is not null");
        int updatedRoles = jdbcTemplate.update(
                "update users set role = ? where upper(role) = ?",
                UserRole.EMPLOYEE.name(),
                "CLIENT");

        if (migratedAssignments > 0 || clearedLegacyLinks > 0 || updatedRoles > 0) {
            log.info(
                    "[STARTUP] Legacy client access normalized: {} project assignments created, {} client-account links removed, {} users converted to EMPLOYEE",
                    migratedAssignments,
                    clearedLegacyLinks,
                    updatedRoles);
        }
    }

    public User upsertGithubUser(Map<String, Object> githubUser, String accessToken) {
        String login = (String) githubUser.getOrDefault("login", "unknown");
        String name = (String) githubUser.getOrDefault("name", login);
        String avatar = (String) githubUser.getOrDefault("avatar_url", "");
        String email = (String) githubUser.getOrDefault("email", null);
        String profileUrl = (String) githubUser.getOrDefault("html_url", "");

        User user = userRepo.findByLogin(login)
                .or(() -> email != null && !email.isBlank() ? userRepo.findByEmailIgnoreCase(email)
                        : java.util.Optional.empty())
                .orElseGet(() -> {
                    UserRole baseRole = firstUserIsAdmin && userRepo.count() == 0 ? UserRole.ADMIN : UserRole.EMPLOYEE;
                    AccessRole accessRole = accessRoleService.resolveRoleAssignment(null, baseRole);
                    return User.builder()
                            .login(login)
                            .role(baseRole)
                            .accessRole(accessRole)
                            .primaryProvider(AuthProvider.GITHUB)
                            .build();
                });

        user.setLogin(login);
        user.setName(name != null ? name : login);
        user.setAvatarUrl(avatar);
        user.setEmail(email);
        user.setProfileUrl(profileUrl);
        if (user.getPrimaryProvider() == null || user.getPrimaryProvider() == AuthProvider.LOCAL) {
            user.setPrimaryProvider(AuthProvider.GITHUB);
        }
        if (user.getAccessRole() == null) {
            user.setAccessRole(accessRoleService.resolveRoleAssignment(null, user.getRole()));
        }
        user.setGhToken(tokenEncryptionService.encrypt(accessToken));
        return userRepo.save(user);
    }

    public User linkGithubAccount(User user, Map<String, Object> githubUser, String accessToken) {
        user.setGhToken(tokenEncryptionService.encrypt(accessToken));
        if ((user.getAvatarUrl() == null || user.getAvatarUrl().isBlank()) && githubUser.get("avatar_url") != null) {
            user.setAvatarUrl(String.valueOf(githubUser.get("avatar_url")));
        }
        if ((user.getEmail() == null || user.getEmail().isBlank()) && githubUser.get("email") != null) {
            user.setEmail(String.valueOf(githubUser.get("email")));
        }
        if ((user.getProfileUrl() == null || user.getProfileUrl().isBlank()) && githubUser.get("html_url") != null) {
            user.setProfileUrl(String.valueOf(githubUser.get("html_url")));
        }
        return userRepo.save(user);
    }

    public User linkGitlabAccount(User user, Map<String, Object> gitlabUser, String accessToken) {
        user.setGlToken(tokenEncryptionService.encrypt(accessToken));
        if ((user.getAvatarUrl() == null || user.getAvatarUrl().isBlank()) && gitlabUser.get("avatar_url") != null) {
            user.setAvatarUrl(String.valueOf(gitlabUser.get("avatar_url")));
        }
        if ((user.getEmail() == null || user.getEmail().isBlank()) && gitlabUser.get("email") != null) {
            user.setEmail(String.valueOf(gitlabUser.get("email")));
        }
        if ((user.getName() == null || user.getName().isBlank()) && gitlabUser.get("name") != null) {
            user.setName(String.valueOf(gitlabUser.get("name")));
        }
        return userRepo.save(user);
    }

    public User linkGitlabAccount(User user, Map<String, Object> gitlabUser, String accessToken, String gitlabUrl) {
        user.setGitlabUrl(gitlabUrl);
        return linkGitlabAccount(user, gitlabUser, accessToken);
    }

    public User createLocalUser(String requestedLogin, String name, String email, String rawPassword, Long accessRoleId,
            UserRole fallbackRole) {
        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
        }
        if (userRepo.findByEmailIgnoreCase(email).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        }

        String resolvedLogin = requestedLogin != null && !requestedLogin.isBlank() ? requestedLogin.trim()
                : email.trim();
        if (userRepo.findByLogin(resolvedLogin).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Login already exists");
        }

        AccessRole accessRole = accessRoleService.resolveRoleAssignment(accessRoleId,
                fallbackRole != null ? fallbackRole : UserRole.EMPLOYEE);

        User user = User.builder()
                .login(resolvedLogin)
                .name(name != null && !name.isBlank() ? name.trim() : resolvedLogin)
                .email(email.trim())
                .role(accessRole.getBaseRole())
                .accessRole(accessRole)
                .primaryProvider(AuthProvider.LOCAL)
                .passwordHash(passwordEncoder.encode(rawPassword))
                .suspended(false)
                .build();
        return userRepo.save(user);
    }

    public User updateLocalUser(Long id, String requestedLogin, String name, String email, String rawPassword,
            Long accessRoleId, UserRole fallbackRole) {
        User user = userRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (email == null || email.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }

        String resolvedEmail = email.trim();
        userRepo.findByEmailIgnoreCase(resolvedEmail)
                .filter(existing -> !existing.getId().equals(user.getId()))
                .ifPresent(existing -> {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
                });

        String resolvedLogin = requestedLogin != null && !requestedLogin.isBlank() ? requestedLogin.trim()
                : user.getLogin();
        if (resolvedLogin == null || resolvedLogin.isBlank()) {
            resolvedLogin = resolvedEmail;
        }
        userRepo.findByLogin(resolvedLogin)
                .filter(existing -> !existing.getId().equals(user.getId()))
                .ifPresent(existing -> {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "Login already exists");
                });

        AccessRole accessRole = accessRoleService.resolveRoleAssignment(accessRoleId,
                fallbackRole != null ? fallbackRole : user.getRole());

        user.setLogin(resolvedLogin);
        user.setName(name != null && !name.isBlank() ? name.trim() : resolvedLogin);
        user.setEmail(resolvedEmail);
        user.setRole(accessRole.getBaseRole());
        user.setAccessRole(accessRole);
        if (rawPassword != null && !rawPassword.isBlank()) {
            user.setPasswordHash(passwordEncoder.encode(rawPassword));
        }
        return userRepo.save(user);
    }

    public User updateUserAccessRole(Long id, Long accessRoleId, UserRole fallbackRole) {
        User user = userRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        AccessRole accessRole = accessRoleService.resolveRoleAssignment(accessRoleId,
                fallbackRole != null ? fallbackRole : user.getRole());
        user.setRole(accessRole.getBaseRole());
        user.setAccessRole(accessRole);
        return userRepo.save(user);
    }

    public User updateSuspension(Long id, boolean suspended) {
        User user = userRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setSuspended(suspended);
        return userRepo.save(user);
    }

    public void deleteUser(Long id) {
        if (!userRepo.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        }
        // Clear nullable FK references before deleting the user
        jdbcTemplate.update("DELETE FROM employee_clients WHERE employee_id = ?", id);
        jdbcTemplate.update("UPDATE clients SET created_by = NULL WHERE created_by = ?", id);
        jdbcTemplate.update("UPDATE pipeline_definitions SET created_by_id = NULL WHERE created_by_id = ?", id);
        jdbcTemplate.update("UPDATE pipeline_runs SET triggered_by_id = NULL WHERE triggered_by_id = ?", id);
        jdbcTemplate.update("UPDATE pipeline_runs SET approved_by_id = NULL WHERE approved_by_id = ?", id);
        jdbcTemplate.update("UPDATE repositories SET owner_user_id = NULL WHERE owner_user_id = ?", id);
        userRepo.deleteById(id);
    }

    public User authenticateLocalUser(String email, String rawPassword) {
        if (email == null || email.isBlank() || rawPassword == null || rawPassword.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email and password are required");
        }

        User user = userRepo.findByEmailIgnoreCase(email.trim())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password"));

        if (!user.hasLocalPassword() || !passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }
        if (Boolean.TRUE.equals(user.getSuspended())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is suspended");
        }
        return user;
    }

    public User ensureBootstrapAdminAccount() {
        if (!bootstrapAdminEnabled) {
            return null;
        }

        String email = bootstrapAdminEmail != null && !bootstrapAdminEmail.isBlank()
                ? bootstrapAdminEmail.trim()
                : "Admin@Medianet.com";
        String login = bootstrapAdminLogin != null && !bootstrapAdminLogin.isBlank()
                ? bootstrapAdminLogin.trim()
                : email;
        String name = bootstrapAdminName != null && !bootstrapAdminName.isBlank()
                ? bootstrapAdminName.trim()
                : "Admin Medianet";
        String password = bootstrapAdminPassword != null && !bootstrapAdminPassword.isBlank()
                ? bootstrapAdminPassword
                : "Admin@123456";

        User user = userRepo.findByEmailIgnoreCase(email)
                .or(() -> userRepo.findByLogin(login))
                .orElseGet(() -> User.builder().build());

        boolean existingUser = user.getId() != null;
        user.setLogin(login);
        user.setName(name);
        user.setEmail(email);
        user.setRole(UserRole.ADMIN);
        user.setAccessRole(accessRoleService.resolveRoleAssignment(null, UserRole.ADMIN));
        user.setPrimaryProvider(AuthProvider.LOCAL);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setSuspended(false);

        User savedUser = userRepo.save(user);
        if (existingUser) {
            log.info("[STARTUP] Default admin account refreshed for {}", email);
        } else {
            log.info("[STARTUP] Default admin account created for {}", email);
        }
        return savedUser;
    }

    public User getRequiredUser(String authHeader) {
        Long userId = jwtUtil.extractUserId(authHeader);
        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }
        return userRepo.findById(userId)
                .map(user -> {
                    if (Boolean.TRUE.equals(user.getSuspended())) {
                        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is suspended");
                    }
                    return user;
                })
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
    }

    public User requireRole(String authHeader, UserRole... allowedRoles) {
        User user = getRequiredUser(authHeader);
        for (UserRole role : allowedRoles) {
            if (user.getRole() == role) {
                return user;
            }
        }
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Insufficient permissions");
    }

    public String getAccessToken(User user, AuthProvider provider) {
        return switch (provider) {
            case GITHUB -> tokenEncryptionService.decrypt(user.getGhToken());
            case GITLAB -> tokenEncryptionService.decrypt(user.getGlToken());
            default -> null;
        };
    }

    public User saveDockerHubCredential(User user, String username, String token) {
        String resolvedUsername = username != null ? username.trim() : null;
        if (resolvedUsername == null || resolvedUsername.isBlank()) {
            user.setDockerHubUsername(null);
            user.setDockerHubToken(null);
            return userRepo.save(user);
        }

        user.setDockerHubUsername(resolvedUsername);
        if (token != null && !token.isBlank()) {
            user.setDockerHubToken(tokenEncryptionService.encrypt(token.trim()));
        }
        return userRepo.save(user);
    }

    public String getDockerHubUsername(User user) {
        return user != null ? user.getDockerHubUsername() : null;
    }

    public String getDockerHubToken(User user) {
        return user != null ? tokenEncryptionService.decrypt(user.getDockerHubToken()) : null;
    }

    public boolean hasDockerHubCredential(User user) {
        return getDockerHubUsername(user) != null && !getDockerHubUsername(user).isBlank()
                && getDockerHubToken(user) != null && !getDockerHubToken(user).isBlank();
    }

    /**
     * Returns true if the user has a GitHub access token that can be used to push
     * images to GitHub Container Registry (ghcr.io).
     */
    public boolean hasGhcrCredential(User user) {
        if (user == null) return false;
        String token = getAccessToken(user, AuthProvider.GITHUB);
        return token != null && !token.isBlank();
    }

    /** Returns the GitHub token to use as GHCR password, or null. */
    public String getGhcrToken(User user) {
        return hasGhcrCredential(user) ? getAccessToken(user, AuthProvider.GITHUB) : null;
    }

    public User save(User user) {
        return userRepo.save(user);
    }

    /** Update AI settings for the current user. */
    public User updateAiSettings(Long userId, String aiProvider, String aiModel, String aiApiKey) {
        User user = userRepo.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        if (aiProvider != null) user.setAiProvider(aiProvider.toUpperCase().trim());
        if (aiModel != null)    user.setAiModel(aiModel.trim());
        if (aiApiKey != null && !aiApiKey.isBlank()) user.setAiApiKey(aiApiKey.trim());
        return userRepo.save(user);
    }

    /** Clear AI settings (revert to system default). */
    public User clearAiSettings(Long userId) {
        User user = userRepo.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setAiProvider(null);
        user.setAiModel(null);
        user.setAiApiKey(null);
        return userRepo.save(user);
    }
}
