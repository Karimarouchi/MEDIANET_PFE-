package com.medianet.controller;

import com.medianet.dto.ScheduledScanRequest;
import com.medianet.dto.ScheduledScanResponse;
import com.medianet.entity.User;
import com.medianet.service.ScheduledScanService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ScheduledScanController {

    private final ScheduledScanService scheduledScanService;
    private final UserService userService;

    public ScheduledScanController(ScheduledScanService scheduledScanService,
                                    UserService userService) {
        this.scheduledScanService = scheduledScanService;
        this.userService = userService;
    }

    // POST /api/scheduled-scans
    @PostMapping("/scheduled-scans")
    public ResponseEntity<ScheduledScanResponse> create(
            @RequestBody ScheduledScanRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader); // auth check
        return ResponseEntity.ok(scheduledScanService.createScheduledScan(request, currentUser));
    }

    // GET /api/scheduled-scans
    @GetMapping("/scheduled-scans")
    public ResponseEntity<List<ScheduledScanResponse>> listAll(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scheduledScanService.listAll());
    }

    // GET /api/repositories/{repositoryId}/scheduled-scans
    @GetMapping("/repositories/{repositoryId}/scheduled-scans")
    public ResponseEntity<List<ScheduledScanResponse>> listByRepository(
            @PathVariable Long repositoryId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scheduledScanService.listByRepository(repositoryId));
    }

    // GET /api/repositories/scheduled-summary  (map repositoryId -> next scan)
    @GetMapping("/repositories/scheduled-summary")
    public ResponseEntity<Map<Long, ScheduledScanResponse>> scheduledSummary(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scheduledScanService.getScheduledSummaryByRepository());
    }

    // PUT /api/scheduled-scans/{id}
    @PutMapping("/scheduled-scans/{id}")
    public ResponseEntity<ScheduledScanResponse> update(
            @PathVariable Long id,
            @RequestBody ScheduledScanRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scheduledScanService.updateScheduledScan(id, request));
    }

    // PATCH /api/scheduled-scans/{id}/pause
    @PatchMapping("/scheduled-scans/{id}/pause")
    public ResponseEntity<ScheduledScanResponse> pause(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scheduledScanService.pause(id));
    }

    // PATCH /api/scheduled-scans/{id}/resume
    @PatchMapping("/scheduled-scans/{id}/resume")
    public ResponseEntity<ScheduledScanResponse> resume(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scheduledScanService.resume(id));
    }

    // DELETE /api/scheduled-scans/{id}
    @DeleteMapping("/scheduled-scans/{id}")
    public ResponseEntity<Void> delete(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        scheduledScanService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
