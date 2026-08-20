package com.medianet.controller;

import com.medianet.entity.User;
import com.medianet.service.PolicyDeviationService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/policy-deviations")
public class PolicyDeviationController {

    private final PolicyDeviationService policyDeviationService;
    private final UserService userService;

    public PolicyDeviationController(
            PolicyDeviationService policyDeviationService,
            UserService userService) {
        this.policyDeviationService = policyDeviationService;
        this.userService = userService;
    }

    @GetMapping("/pending")
    public ResponseEntity<List<Map<String, Object>>> pending(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(policyDeviationService.listPending(user));
    }

    @PostMapping("/{id}/approve")
    public ResponseEntity<Map<String, Object>> approve(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody(required = false) ReviewBody body) {
        User user = userService.getRequiredUser(authHeader);
        String comment = body != null ? body.comment() : null;
        Map<String, Object> result = policyDeviationService.approve(user, id, comment);
        if ("COMMIT_FAILED".equals(String.valueOf(result.get("status")))) {
            return ResponseEntity.status(org.springframework.http.HttpStatus.BAD_GATEWAY).body(result);
        }
        return ResponseEntity.ok(result);
    }

    @PostMapping("/{id}/reject")
    public ResponseEntity<Map<String, Object>> reject(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody(required = false) ReviewBody body) {
        User user = userService.getRequiredUser(authHeader);
        String comment = body != null ? body.comment() : null;
        return ResponseEntity.ok(policyDeviationService.reject(user, id, comment));
    }

    public record ReviewBody(String comment) {}
}
