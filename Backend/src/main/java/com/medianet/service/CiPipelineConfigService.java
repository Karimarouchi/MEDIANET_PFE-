package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CiPipelineLink;
import com.medianet.repository.CiPipelineLinkRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Answers Woodpecker's config-extension call: checks the signature, finds the repository enabled from Vulnix, lists
 * its files at the pipeline's commit (GitHub API, with the netrc token Woodpecker sends) and returns the generated
 * pipeline. Any problem after the signature check becomes a pipeline that fails with the reason, visible in Vulnix.
 */
@Service
public class CiPipelineConfigService {

    private static final Logger log = LoggerFactory.getLogger(CiPipelineConfigService.class);
    private static final Pattern SHA = Pattern.compile("[0-9a-f]{40}");

    private final WoodpeckerClient woodpecker;
    private final CiPipelineLinkRepo linkRepo;
    private final ObjectMapper json;
    private final GitHubRepoFiles github;
    private final String callbackUrl;
    Clock clock = Clock.systemUTC();

    public CiPipelineConfigService(WoodpeckerClient woodpecker, CiPipelineLinkRepo linkRepo, ObjectMapper json,
            GitHubRepoFiles github,
            @Value("${vulnix.ci.woodpecker.callback-url:http://host.docker.internal:8080}") String callbackUrl) {
        this.woodpecker = woodpecker;
        this.linkRepo = linkRepo;
        this.json = json;
        this.github = github;
        this.callbackUrl = callbackUrl.replaceAll("/+$", "");
    }

    /** Signed request → JSON body for Woodpecker ({"configs": [...]}). Unsigned or forged → 401. */
    public Map<String, Object> configFor(String requestTarget, byte[] body, String contentDigest,
            String signatureInput, String signature) {
        String refused = WoodpeckerSignatureVerifier.verify(woodpecker.publicKey(false), requestTarget, body,
                contentDigest, signatureInput, signature, clock.instant());
        if ("signature invalide".equals(refused)) {
            // Woodpecker's database was reset: its key changed.
            refused = WoodpeckerSignatureVerifier.verify(woodpecker.publicKey(true), requestTarget, body,
                    contentDigest, signatureInput, signature, clock.instant());
        }
        if (refused != null) {
            log.warn("Woodpecker config request refused: {}", refused);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Signature Woodpecker refusée : " + refused);
        }
        return response(pipelineYaml(body));
    }

    String pipelineYaml(byte[] body) {
        JsonNode req;
        try {
            req = json.readTree(body);
        } catch (Exception e) {
            return CiPipelineGenerator.failing("demande Woodpecker illisible.");
        }
        long wpRepoId = req.path("repo").path("id").asLong();
        String fullName = req.path("repo").path("full_name").asText();
        String commit = req.path("pipeline").path("commit").asText();
        CiPipelineLink link = linkRepo.findByWoodpeckerRepoId(wpRepoId).orElse(null);
        if (link == null || !link.getForgeFullName().equalsIgnoreCase(fullName)) {
            return CiPipelineGenerator.failing("la CI de " + fullName + " n'est pas activée dans Vulnix.");
        }
        if (!SHA.matcher(commit).matches()) {
            return CiPipelineGenerator.failing("commit inconnu pour ce pipeline.");
        }
        String token = netrcToken(req.path("netrc"));
        try {
            List<String> files = github.list(link.getForgeFullName(), commit, token);
            Map<String, String> manifests = github.read(link.getForgeFullName(), commit, token,
                    CiPipelineGenerator.manifestsToRead(files));
            log.info("CI pipeline generated repo={} commit={} files={}", link.getRepositoryId(), commit.substring(0, 12), files.size());
            return CiPipelineGenerator.generate(files, manifests,
                    new CiPipelineGenerator.VulnixTarget(callbackUrl, link.getRepositoryId()));
        } catch (Exception e) {
            log.warn("CI pipeline generation failed repo={}: {}", link.getRepositoryId(), e.getMessage());
            return CiPipelineGenerator.failing("impossible de lire les fichiers du dépôt sur GitHub (" + e.getMessage() + ").");
        }
    }

    /** GitHub netrc from Woodpecker: login = the OAuth token, password = "x-oauth-basic". Other forges: the password. */
    static String netrcToken(JsonNode netrc) {
        String login = netrc.path("login").asText("");
        String password = netrc.path("password").asText("");
        return password.isBlank() || "x-oauth-basic".equals(password) ? login : password;
    }

    static Map<String, Object> response(String yaml) {
        return Map.of("configs", List.of(Map.of("name", "vulnix", "data", yaml)));
    }
}
