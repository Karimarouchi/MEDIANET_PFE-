package com.medianet.controller;

import com.medianet.dto.HardeningFindingDto;
import com.medianet.dto.PortExposureDto;
import com.medianet.dto.PortRecommendationDto;
import com.medianet.dto.ServerNodeDetailDto;
import com.medianet.dto.ServerNodeDto;
import com.medianet.dto.ServerNodeRequest;
import com.medianet.entity.User;
import com.medianet.service.PortRecommendationService;
import com.medianet.service.ServerConfigService;
import com.medianet.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/servers")
public class ServerConfigController {

    private final ServerConfigService serverConfigService;
    private final UserService userService;
    private final PortRecommendationService portRecommendationService;

    public ServerConfigController(ServerConfigService serverConfigService, UserService userService,
            PortRecommendationService portRecommendationService) {
        this.serverConfigService = serverConfigService;
        this.userService = userService;
        this.portRecommendationService = portRecommendationService;
    }

    @GetMapping
    public ResponseEntity<List<ServerNodeDto>> getServers(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.getServers());
    }

    @PostMapping
    public ResponseEntity<ServerNodeDto> createServer(
            @Valid @RequestBody ServerNodeRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.createServer(request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ServerNodeDto> updateServer(
            @PathVariable Long id,
            @Valid @RequestBody ServerNodeRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.updateServer(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        serverConfigService.deleteServer(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<ServerNodeDetailDto> getServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.getServer(id));
    }

    @PostMapping("/{id}/live")
    public ResponseEntity<ServerNodeDetailDto> getLiveServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.getLiveServer(id));
    }

    @PostMapping("/{id}/scan")
    public ResponseEntity<ServerNodeDetailDto> scanServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.scanServer(id));
    }

    @GetMapping("/{id}/findings")
    public ResponseEntity<List<HardeningFindingDto>> getFindings(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
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

        User currentUser = userService.getRequiredUser(authHeader);

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
}