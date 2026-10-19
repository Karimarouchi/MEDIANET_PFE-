package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.medianet.dto.CiTokenCreatedDto;
import com.medianet.entity.CiPipelineLink;
import com.medianet.entity.ClientRepository;
import com.medianet.entity.ClientRepositoryId;
import com.medianet.entity.Repository;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.CiPipelineLinkRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.RepositoryRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CI of a project's repositories, run by Woodpecker and driven only from Vulnix: enabling a repository activates it
 * in Woodpecker, points its pipeline source at Vulnix, and stores a CI token (scan + verdict on this repository only)
 * as a Woodpecker secret. Users never open Woodpecker.
 */
@Service
public class CiPipelineService {

    private static final Logger log = LoggerFactory.getLogger(CiPipelineService.class);
    static final String SECRET_NAME = "vulnix_token";
    private static final List<String> SECRET_EVENTS = List.of("push", "manual", "tag");
    private static final Pattern GITHUB = Pattern.compile("^https://github\\.com/([\\w.-]+)/([\\w.-]+?)(?:\\.git)?/?$");

    private final WoodpeckerClient woodpecker;
    private final CiPipelineLinkRepo linkRepo;
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final RepositoryRepo repositoryRepo;
    private final ClientService clientService;
    private final CiTokenService ciTokenService;
    private final GitHubRepoFiles github;
    private final UserService userService;
    private final String callbackUrl;

    public CiPipelineService(WoodpeckerClient woodpecker, CiPipelineLinkRepo linkRepo,
            ClientRepositoryRepo clientRepositoryRepo, RepositoryRepo repositoryRepo, ClientService clientService,
            CiTokenService ciTokenService, GitHubRepoFiles github, UserService userService,
            @Value("${vulnix.ci.woodpecker.callback-url:http://host.docker.internal:8080}") String callbackUrl) {
        this.woodpecker = woodpecker;
        this.linkRepo = linkRepo;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.repositoryRepo = repositoryRepo;
        this.clientService = clientService;
        this.ciTokenService = ciTokenService;
        this.github = github;
        this.userService = userService;
        this.callbackUrl = callbackUrl.replaceAll("/+$", "");
    }

    public record RepoCi(Long repositoryId, String repoUrl, String forgeFullName, boolean supported,
            String unsupportedReason, boolean enabled, Instant enabledAt, String branch) {
    }

    public record ProjectCi(boolean configured, List<RepoCi> repositories) {
    }

    public record PipelineSummary(long number, String status, String event, String branch, String commit,
            String message, String author, Long created, Long started, Long finished) {
    }

    public record Step(long id, String name, String state, Integer exitCode, String error, Long started, Long finished) {
    }

    public record PipelineDetail(PipelineSummary pipeline, List<Step> steps, List<String> errors) {
    }

    public record LogLine(int line, String text) {
    }

    /** owner/name of a GitHub URL, or null. Package-private for tests. */
    static String githubFullName(String repoUrl) {
        if (repoUrl == null) return null;
        Matcher m = GITHUB.matcher(repoUrl.trim());
        return m.matches() ? m.group(1) + "/" + m.group(2) : null;
    }

    public ProjectCi projectStatus(User user, Long clientId) {
        clientService.requireManageable(user, clientId);
        List<RepoCi> out = new ArrayList<>();
        List<ClientRepository> links = clientRepositoryRepo.findByClient_Id(clientId);
        Map<Long, CiPipelineLink> byRepo = new LinkedHashMap<>();
        linkRepo.findByRepositoryIdIn(links.stream().map(l -> l.getRepository().getId()).toList())
                .forEach(l -> byRepo.put(l.getRepositoryId(), l));
        for (ClientRepository l : links) {
            Repository repo = l.getRepository();
            String full = githubFullName(repo.getRepoUrl());
            CiPipelineLink ci = byRepo.get(repo.getId());
            out.add(new RepoCi(repo.getId(), repo.getRepoUrl(), full, full != null,
                    full == null ? "La CI ne prend en charge que les dépôts GitHub pour l'instant." : null,
                    ci != null, ci != null ? ci.getEnabledAt() : null, branchOf(repo)));
        }
        return new ProjectCi(woodpecker.isConfigured(), out);
    }

    /**
     * What the CI runs on this repository (before or after enabling it), the missing tests, and the prompt that asks
     * an AI assistant to write them. Reads the branch on GitHub with the user's GitHub token when there is one.
     */
    public CiRepoAnalyzer.Analysis analysis(User user, Long clientId, Long repositoryId, java.util.Set<String> steps, String focus) {
        clientService.requireManageable(user, clientId);
        if (!clientRepositoryRepo.existsById(new ClientRepositoryId(clientId, repositoryId))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ce dépôt n'est pas lié à ce projet.");
        }
        Repository repo = repositoryRepo.findById(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found"));
        String full = githubFullName(repo.getRepoUrl());
        if (full == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La CI ne prend en charge que les dépôts GitHub pour l'instant.");
        }
        String token = null;
        try {
            token = userService.getAccessToken(user, com.medianet.entity.AuthProvider.GITHUB);
        } catch (RuntimeException ignored) {
            // no GitHub account linked: public repositories still work
        }
        try {
            List<String> files = github.list(full, branchOf(repo), token);
            Map<String, String> manifests = github.read(full, branchOf(repo), token, CiPipelineGenerator.manifestsToRead(files));
            return CiRepoAnalyzer.analyze(full, branchOf(repo), files, manifests, steps, focus);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Impossible de lire " + full + " sur GitHub : " + e.getMessage());
        }
    }

    public RepoCi enable(User user, Long clientId, Long repositoryId) {
        clientService.requireManageable(user, clientId);
        if (!clientRepositoryRepo.existsById(new ClientRepositoryId(clientId, repositoryId))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ce dépôt n'est pas lié à ce projet.");
        }
        Repository repo = repositoryRepo.findById(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found"));
        String full = githubFullName(repo.getRepoUrl());
        if (full == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La CI ne prend en charge que les dépôts GitHub pour l'instant.");
        }
        CiPipelineLink existing = linkRepo.findByRepositoryId(repositoryId).orElse(null);
        if (existing != null) return toRepoCi(repo, full, existing);

        JsonNode forge = woodpecker.findForgeRepo(full);
        if (forge == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Woodpecker ne voit pas " + full + " : le compte GitHub relié à la CI n'a pas accès à ce dépôt.");
        }
        // Already active in Woodpecker (enabled before, or by hand): take it over, activating again answers 409.
        long wpRepoId = forge.path("active").asBoolean(false) && forge.path("id").asLong(0) > 0
                ? forge.path("id").asLong()
                : woodpecker.activate(forge.path("forge_remote_id").asText()).path("id").asLong();
        Map<String, Object> patch = new LinkedHashMap<>();
        patch.put("config_extension_endpoint", callbackUrl + "/api/woodpecker/config");
        patch.put("config_extension_exclusive", true);
        patch.put("config_extension_netrc", true); // lets Vulnix list the files of a private repository
        patch.put("allow_pr", false);
        woodpecker.patchRepo(wpRepoId, patch);

        CiTokenCreatedDto token = ciTokenService.createToken(user, "Woodpecker · " + full, clientId,
                List.of(repositoryId), 0);
        try {
            woodpecker.putSecret(wpRepoId, SECRET_NAME, token.token(), SECRET_EVENTS);
        } catch (RuntimeException e) {
            ciTokenService.revoke(token.id());
            throw e;
        }
        CiPipelineLink link = linkRepo.save(CiPipelineLink.builder()
                .repositoryId(repositoryId).clientId(clientId).woodpeckerRepoId(wpRepoId).forgeFullName(full)
                .ciTokenId(token.id()).enabledByUserId(user.getId()).enabledAt(Instant.now()).build());
        log.info("CI enabled repo={} woodpeckerRepo={} by={}", repositoryId, wpRepoId, user.getId());
        return toRepoCi(repo, full, link);
    }

    public void disable(User user, Long clientId, Long repositoryId) {
        clientService.requireManageable(user, clientId);
        CiPipelineLink link = linkRepo.findByRepositoryId(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "La CI n'est pas activée sur ce dépôt."));
        removeLink(link);
        log.info("CI disabled repo={} by={}", repositoryId, user.getId());
    }

    /**
     * Turns the CI of one repository off: token revoked, repository deactivated in Woodpecker (best effort: an
     * unreachable Woodpecker must not keep a deleted project alive), link removed. No permission check.
     */
    public void removeLink(CiPipelineLink link) {
        if (link.getCiTokenId() != null) ciTokenService.revoke(link.getCiTokenId());
        forgetLink(link);
    }

    /** Same as {@link #removeLink} without touching the token: the caller deletes the project's tokens itself. */
    public void forgetLink(CiPipelineLink link) {
        if (woodpecker.isConfigured()) {
            try {
                woodpecker.deactivate(link.getWoodpeckerRepoId());
            } catch (RuntimeException e) {
                log.warn("CI disable: Woodpecker deactivate failed repo={} ({})", link.getRepositoryId(), e.getMessage());
            }
        }
        linkRepo.delete(link);
    }

    public PipelineSummary trigger(User user, Long repositoryId) {
        CiPipelineLink link = requireLink(user, repositoryId);
        Repository repo = repositoryRepo.findById(repositoryId).orElseThrow();
        return summary(woodpecker.createPipeline(link.getWoodpeckerRepoId(), branchOf(repo)));
    }

    public List<PipelineSummary> history(User user, Long repositoryId) {
        CiPipelineLink link = requireLink(user, repositoryId);
        List<PipelineSummary> out = new ArrayList<>();
        for (JsonNode p : woodpecker.pipelines(link.getWoodpeckerRepoId(), 20)) out.add(summary(p));
        return out;
    }

    public PipelineDetail detail(User user, Long repositoryId, long number) {
        CiPipelineLink link = requireLink(user, repositoryId);
        return detail(woodpecker.pipeline(link.getWoodpeckerRepoId(), number));
    }

    public PipelineSummary cancel(User user, Long repositoryId, long number) {
        CiPipelineLink link = requireLink(user, repositoryId);
        woodpecker.cancel(link.getWoodpeckerRepoId(), number);
        return summary(woodpecker.pipeline(link.getWoodpeckerRepoId(), number));
    }

    public List<LogLine> logs(User user, Long repositoryId, long number, long stepId) {
        CiPipelineLink link = requireLink(user, repositoryId);
        PipelineDetail d = detail(woodpecker.pipeline(link.getWoodpeckerRepoId(), number));
        if (d.steps().stream().noneMatch(s -> s.id() == stepId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Étape introuvable dans ce pipeline.");
        }
        return decodeLogs(woodpecker.stepLogs(link.getWoodpeckerRepoId(), number, stepId));
    }

    // ── mapping (package-private for tests) ─────────────────────────────────────

    static PipelineSummary summary(JsonNode p) {
        return new PipelineSummary(p.path("number").asLong(), p.path("status").asText(), p.path("event").asText(),
                p.path("branch").asText(), p.path("commit").asText(), p.path("message").asText(),
                p.path("author").asText(), time(p, "created"), time(p, "started"), time(p, "finished"));
    }

    static PipelineDetail detail(JsonNode p) {
        List<Step> steps = new ArrayList<>();
        for (JsonNode w : p.path("workflows")) {
            for (JsonNode c : w.path("children")) {
                steps.add(new Step(c.path("id").asLong(), c.path("name").asText(), c.path("state").asText(),
                        c.hasNonNull("exit_code") ? c.path("exit_code").asInt() : null,
                        c.path("error").asText(null), time(c, "started"), time(c, "finished")));
            }
        }
        List<String> errors = new ArrayList<>();
        for (JsonNode e : p.path("errors")) {
            if (!e.path("is_warning").asBoolean(false)) errors.add(e.path("message").asText());
        }
        return new PipelineDetail(summary(p), steps, errors);
    }

    static List<LogLine> decodeLogs(JsonNode entries) {
        List<LogLine> out = new ArrayList<>();
        for (JsonNode e : entries) {
            String text = new String(Base64.getDecoder().decode(e.path("data").asText("")), StandardCharsets.UTF_8);
            out.add(new LogLine(e.path("line").asInt(), text.replaceAll("\\r?\\n$", "")));
        }
        return out;
    }

    private static Long time(JsonNode n, String field) {
        long v = n.path(field).asLong(0);
        return v > 0 ? v : null;
    }

    private CiPipelineLink requireLink(User user, Long repositoryId) {
        if (user == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        boolean allowed = user.getRole() == UserRole.ADMIN
                ? repositoryRepo.existsById(repositoryId)
                : repositoryRepo.canEmployeeAccess(repositoryId, user.getId());
        if (!allowed) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Repository not accessible");
        return linkRepo.findByRepositoryId(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "La CI n'est pas activée sur ce dépôt."));
    }

    private static String branchOf(Repository repo) {
        return repo.getBranch() == null || repo.getBranch().isBlank() ? "main" : repo.getBranch().trim();
    }

    private RepoCi toRepoCi(Repository repo, String full, CiPipelineLink link) {
        return new RepoCi(repo.getId(), repo.getRepoUrl(), full, true, null, true, link.getEnabledAt(), branchOf(repo));
    }
}
