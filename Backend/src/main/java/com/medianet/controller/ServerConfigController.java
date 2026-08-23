package com.medianet.controller;

import com.medianet.dto.AutoDeployRequest;
import com.medianet.dto.DeployRequest;
import com.medianet.dto.DeployRunDto;
import com.medianet.dto.DeploySettingsRequest;
import com.medianet.dto.HardeningFindingDto;
import com.medianet.dto.PortExposureDto;
import com.medianet.dto.PortRecommendationDto;
import com.medianet.dto.ServerDeploymentDto;
import com.medianet.dto.ServerNodeDetailDto;
import com.medianet.dto.ServerNodeDto;
import com.medianet.dto.ServerNodeRequest;
import com.medianet.entity.AccessPermission;
import com.medianet.entity.DeployRun;
import com.medianet.entity.User;
import com.medianet.service.AccessRoleService;
import com.medianet.service.DeployService;
import com.medianet.service.PortRecommendationService;
import com.medianet.service.ServerConfigService;
import com.medianet.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/servers")
public class ServerConfigController {

    private final ServerConfigService serverConfigService;
    private final UserService userService;
    private final PortRecommendationService portRecommendationService;
    private final DeployService deployService;
    private final AccessRoleService accessRoleService;

    public ServerConfigController(ServerConfigService serverConfigService, UserService userService,
            PortRecommendationService portRecommendationService, DeployService deployService,
            AccessRoleService accessRoleService) {
        this.serverConfigService = serverConfigService;
        this.userService = userService;
        this.portRecommendationService = portRecommendationService;
        this.deployService = deployService;
        this.accessRoleService = accessRoleService;
    }

    @GetMapping
    public ResponseEntity<List<ServerNodeDto>> getServers(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(serverConfigService.getServers());
    }

    @PostMapping
    public ResponseEntity<ServerNodeDto> createServer(
            @Valid @RequestBody ServerNodeRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(serverConfigService.createServer(request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ServerNodeDto> updateServer(
            @PathVariable Long id,
            @Valid @RequestBody ServerNodeRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(serverConfigService.updateServer(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        serverConfigService.deleteServer(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<ServerNodeDetailDto> getServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(serverConfigService.getServer(id));
    }

    @PostMapping("/{id}/live")
    public ResponseEntity<ServerNodeDetailDto> getLiveServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(serverConfigService.getLiveServer(id));
    }

    @PostMapping("/{id}/scan")
    public ResponseEntity<ServerNodeDetailDto> scanServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(serverConfigService.scanServer(id));
    }

    @GetMapping("/{id}/findings")
    public ResponseEntity<List<HardeningFindingDto>> getFindings(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(serverConfigService.getFindings(id));
    }

    /**
     * POST /api/servers/{id}/port-recommendations
     *
     * Génère des recommandations IA de sécurité pour les ports exposés du dernier scan.
     * Utilise la clé AI personnelle de l'utilisateur si configurée dans son profil,
     * sinon utilise la clé Gemini système par défaut.
     */
    @PostMapping("/{id}/port-recommendations")
    public ResponseEntity<List<PortRecommendationDto>> getPortRecommendations(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        User currentUser = requireServerConfig(authHeader);

        // Récupérer le contexte du serveur (nodeType, osName)
        Map<String, String> ctx = serverConfigService.getServerContext(id);
        String nodeType = ctx.get("nodeType");
        String osName = ctx.get("osName");

        // Récupérer les ports du dernier scan
        List<PortExposureDto> ports = serverConfigService.getPortsForServer(id);

        // Générer les recommandations IA
        List<PortRecommendationDto> recommendations =
                portRecommendationService.generateRecommendations(ports, nodeType, osName, currentUser);

        return ResponseEntity.ok(recommendations);
    }

    @GetMapping("/{id}/deployments")
    public ResponseEntity<List<ServerDeploymentDto>> listDeployments(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(deployService.listDeployments(id));
    }

    @PostMapping("/{id}/deployments")
    public ResponseEntity<ServerDeploymentDto> createDeployment(
            @PathVariable Long id,
            @RequestBody DeploySettingsRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.status(HttpStatus.CREATED).body(deployService.createDeployment(id, request));
    }

    @PatchMapping("/{id}/deployments/{deploymentId}")
    public ResponseEntity<ServerDeploymentDto> updateDeployment(
            @PathVariable Long id,
            @PathVariable Long deploymentId,
            @RequestBody DeploySettingsRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(deployService.updateDeployment(id, deploymentId, request));
    }

    @DeleteMapping("/{id}/deployments/{deploymentId}")
    public ResponseEntity<Void> deleteDeployment(
            @PathVariable Long id,
            @PathVariable Long deploymentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        deployService.deleteDeployment(id, deploymentId);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/deployments/{deploymentId}/auto-deploy")
    public ResponseEntity<ServerDeploymentDto> setDeploymentAutoDeploy(
            @PathVariable Long id,
            @PathVariable Long deploymentId,
            @RequestBody AutoDeployRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(deployService.setAutoDeploy(id, deploymentId, Boolean.TRUE.equals(request.enabled())));
    }

    @PostMapping("/{id}/deployments/{deploymentId}/deploy")
    public ResponseEntity<DeployRunDto> deployDeployment(
            @PathVariable Long id,
            @PathVariable Long deploymentId,
            @RequestBody(required = false) DeployRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        boolean force = request != null && Boolean.TRUE.equals(request.force());
        DeployRunDto dto = deployService.deploy(id, deploymentId, force, DeployRun.TriggerType.MANUAL);
        if (dto.blocked()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(dto);
        }
        return ResponseEntity.ok(dto);
    }

    @GetMapping("/{id}/deployments/{deploymentId}/runs")
    public ResponseEntity<List<DeployRunDto>> listDeploymentRuns(
            @PathVariable Long id,
            @PathVariable Long deploymentId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(deployService.listRuns(id, deploymentId));
    }

    @PatchMapping("/{id}/deploy-settings")
    public ResponseEntity<ServerNodeDetailDto> updateDeploySettings(
            @PathVariable Long id,
            @RequestBody DeploySettingsRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        deployService.updateDeploySettings(id, request);
        return ResponseEntity.ok(serverConfigService.getServer(id));
    }

    @PatchMapping("/{id}/auto-deploy")
    public ResponseEntity<ServerNodeDetailDto> setAutoDeploy(
            @PathVariable Long id,
            @RequestBody AutoDeployRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        deployService.setAutoDeploy(id, Boolean.TRUE.equals(request.enabled()));
        return ResponseEntity.ok(serverConfigService.getServer(id));
    }

    @PostMapping("/{id}/deploy")
    public ResponseEntity<DeployRunDto> deploy(
            @PathVariable Long id,
            @RequestBody(required = false) DeployRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        boolean force = request != null && Boolean.TRUE.equals(request.force());
        DeployRunDto dto = deployService.deploy(id, force, DeployRun.TriggerType.MANUAL);
        if (dto.blocked()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(dto);
        }
        return ResponseEntity.ok(dto);
    }

    @GetMapping("/{id}/deploys")
    public ResponseEntity<List<DeployRunDto>> listDeploys(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return ResponseEntity.ok(deployService.listDeploys(id));
    }

    private User requireServerConfig(String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        if (!accessRoleService.getEffectivePermissions(user).contains(AccessPermission.SERVER_CONFIG)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Permission SERVER_CONFIG requise.");
        }
        return user;
    }
}
