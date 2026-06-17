package com.medianet.controller;

import com.medianet.dto.DockerHubCredentialDto;
import com.medianet.dto.DockerHubCredentialRequest;
import com.medianet.dto.PipelineDefinitionDto;
import com.medianet.dto.PipelineDefinitionRequest;
import com.medianet.dto.PipelineLogEventDto;
import com.medianet.dto.PipelinePresetDto;
import com.medianet.dto.PipelineRunDto;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.service.PipelineEventStreamService;
import com.medianet.service.PipelineService;
import com.medianet.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/pipelines")
public class PipelineController {

    private final PipelineService pipelineService;
    private final PipelineEventStreamService pipelineEventStreamService;
    private final UserService userService;

    public PipelineController(
            PipelineService pipelineService,
            PipelineEventStreamService pipelineEventStreamService,
            UserService userService) {
        this.pipelineService = pipelineService;
        this.pipelineEventStreamService = pipelineEventStreamService;
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<List<PipelineDefinitionDto>> listPipelines(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.listPipelines(currentUser));
    }

    @GetMapping("/{id}")
    public ResponseEntity<PipelineDefinitionDto> getPipeline(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.getPipeline(currentUser, id));
    }

    @GetMapping("/presets/monolith-ecommerce")
    public ResponseEntity<PipelinePresetDto> getMonolithPreset(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam Long repositoryId) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.getMonolithPreset(currentUser, repositoryId));
    }

    @GetMapping("/docker-hub-credential")
    public ResponseEntity<DockerHubCredentialDto> getDockerHubCredential(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.getDockerHubCredential(currentUser));
    }

    @PutMapping("/docker-hub-credential")
    public ResponseEntity<DockerHubCredentialDto> saveDockerHubCredential(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody DockerHubCredentialRequest request) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.saveDockerHubCredential(currentUser, request.username(), request.token()));
    }

    @PostMapping
    public ResponseEntity<PipelineDefinitionDto> createPipeline(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody PipelineDefinitionRequest request) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.createPipeline(currentUser, request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<PipelineDefinitionDto> updatePipeline(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody PipelineDefinitionRequest request) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.updatePipeline(currentUser, id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deletePipeline(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        pipelineService.deletePipeline(currentUser, id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/run")
    public ResponseEntity<PipelineRunDto> triggerRun(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.triggerRun(currentUser, id));
    }

    @GetMapping("/{id}/runs")
    public ResponseEntity<List<PipelineRunDto>> listRuns(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.listRuns(currentUser, id));
    }

    @GetMapping("/runs/{runId}")
    public ResponseEntity<PipelineRunDto> getRun(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long runId) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.getRun(currentUser, runId));
    }

    @GetMapping(value = "/runs/{runId}/logs", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamRunLogs(
            @PathVariable Long runId,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(value = "token", required = false) String token,
            HttpServletResponse response) {
        String effectiveAuth = authHeader != null && !authHeader.isBlank()
                ? authHeader
                : (token != null && !token.isBlank() ? "Bearer " + token : null);
        User currentUser = userService.requireRole(effectiveAuth, UserRole.ADMIN, UserRole.EMPLOYEE);
        PipelineRunDto snapshot = pipelineService.getRun(currentUser, runId);
        response.setHeader("X-Accel-Buffering", "no");
        response.setHeader("Cache-Control", "no-cache");
        return pipelineEventStreamService.createEmitter(
                runId,
                new PipelineLogEventDto("snapshot", runId, null, snapshot.currentStage(), "Connected to pipeline log stream.", snapshot, LocalDateTime.now()),
                Set.of("SUCCESS", "FAILED", "BLOCKED").contains(snapshot.status()));
    }

    @PostMapping("/runs/{runId}/approve")
    public ResponseEntity<PipelineRunDto> approveRun(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long runId) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(pipelineService.approveRun(currentUser, runId));
    }
}
