package com.medianet.controller;

import com.medianet.dto.DeployRunDto;
import com.medianet.entity.User;
import com.medianet.service.CdStatusService;
import com.medianet.service.DeployService;
import com.medianet.service.ServerDiskService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Continuous deployment as seen from a project: status, approval of a waiting deploy, server disk and cleanup. */
@RestController
@RequestMapping("/api")
public class CdStatusController {

    private final CdStatusService cd;
    private final DeployService deployService;
    private final ServerDiskService disk;
    private final UserService userService;
    private final com.medianet.service.UptimeService uptime;
    private final com.medianet.service.MailService mail;

    public CdStatusController(CdStatusService cd, DeployService deployService, ServerDiskService disk, UserService userService,
            com.medianet.service.UptimeService uptime, com.medianet.service.MailService mail) {
        this.uptime = uptime;
        this.mail = mail;
        this.cd = cd;
        this.deployService = deployService;
        this.disk = disk;
        this.userService = userService;
    }

    @GetMapping("/pipelines/repositories/{repoId}/deployments")
    public List<CdStatusService.Target> deployments(@PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return cd.forRepository(userService.getRequiredUser(auth), repoId);
    }

    @PostMapping("/deploy-runs/{runId}/approve")
    public DeployRunDto approve(@PathVariable Long runId, @RequestHeader(value = "Authorization", required = false) String auth) {
        User user = userService.getRequiredUser(auth);
        cd.requireDeploymentAccess(user, deployService.deploymentOfRun(runId));
        return deployService.approve(runId, user.getLogin());
    }

    @PostMapping("/deploy-runs/{runId}/refuse")
    public DeployRunDto refuse(@PathVariable Long runId, @RequestHeader(value = "Authorization", required = false) String auth) {
        User user = userService.getRequiredUser(auth);
        cd.requireDeploymentAccess(user, deployService.deploymentOfRun(runId));
        return deployService.refuse(runId, user.getLogin());
    }

    /** Read-only check of a deployment on its server (nothing is changed). */
    @PostMapping("/deployments/{deploymentId}/check")
    public DeployService.CheckResult check(@PathVariable Long deploymentId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        cd.requireDeploymentAccess(userService.getRequiredUser(auth), deploymentId);
        return deployService.check(deploymentId);
    }

    @GetMapping("/deployments/{deploymentId}/disk")
    public ResponseEntity<ServerDiskService.Report> disk(@PathVariable Long deploymentId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        cd.requireDeploymentAccess(userService.getRequiredUser(auth), deploymentId);
        ServerDiskService.Report r = disk.latest(deploymentId);
        return r == null ? ResponseEntity.noContent().build() : ResponseEntity.ok(r);
    }

    @PostMapping("/deployments/{deploymentId}/disk/measure")
    public ServerDiskService.Report measure(@PathVariable Long deploymentId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        cd.requireDeploymentAccess(userService.getRequiredUser(auth), deploymentId);
        return disk.measure(deploymentId);
    }

    @PostMapping("/deployments/{deploymentId}/disk/clean")
    public ServerDiskService.Report clean(@PathVariable Long deploymentId, @RequestBody(required = false) Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        cd.requireDeploymentAccess(userService.getRequiredUser(auth), deploymentId);
        return disk.clean(deploymentId, body != null && Boolean.TRUE.equals(body.get("confirm")));
    }

    /** Availability of the project's sites from Uptime Kuma (read-only). */
    @GetMapping("/projects/{clientId}/uptime")
    public com.medianet.service.UptimeService.ProjectUptime projectUptime(@PathVariable Long clientId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return uptime.forProject(userService.getRequiredUser(auth), clientId);
    }

    /**
     * Sends a test e-mail. To one's own address; an admin may give another address ("to"), e.g. when the admin account
     * has no real mailbox.
     */
    @PostMapping("/users/me/test-email")
    public Map<String, Object> testEmail(@RequestBody(required = false) Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        User user = userService.getRequiredUser(auth);
        String to = user.getEmail();
        Object asked = body == null ? null : body.get("to");
        if (asked instanceof String s && !s.isBlank()) {
            if (user.getRole() != com.medianet.entity.UserRole.ADMIN && !s.trim().equalsIgnoreCase(user.getEmail())) {
                throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN,
                        "Seul un administrateur peut envoyer le test à une autre adresse.");
            }
            to = s.trim();
        }
        String error = mail.trySend(to, "[Vulnix] E-mail de test",
                "Ceci est un e-mail de test envoyé depuis Vulnix par " + user.getLogin() + ".\n"
                        + "Si vous le recevez, les notifications de déploiement (réussi, version précédente remise, échec, "
                        + "sauvegarde impossible, accord demandé, disque presque plein) vous parviendront aussi par e-mail.",
                "/profile");
        return error == null ? Map.of("sent", true, "to", to) : Map.of("sent", false, "to", to == null ? "" : to, "reason", error);
    }

    /** Deployment / server alerts by e-mail on or off for the current user (the bell always gets them). */
    @PutMapping("/users/me/email-notifications")
    public Map<String, Object> emailNotifications(@RequestBody Map<String, Object> body,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        User user = userService.getRequiredUser(auth);
        boolean on = !Boolean.FALSE.equals(body.get("enabled"));
        userService.setEmailNotifications(user.getId(), on);
        return Map.of("enabled", on);
    }
}
