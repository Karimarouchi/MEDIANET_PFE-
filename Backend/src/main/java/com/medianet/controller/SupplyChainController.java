package com.medianet.controller;

import com.medianet.entity.ScanResult;
import com.medianet.entity.User;
import com.medianet.service.ScanService;
import com.medianet.service.SupplyChainService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Supply-chain screening of a scan's npm dependencies. An indicator for review, never a gate:
 * the CI decision stays in {@code CiScanService}.
 */
@RestController
@RequestMapping("/api")
public class SupplyChainController {

    private final SupplyChainService supplyChainService;
    private final ScanService scanService;
    private final UserService userService;

    public SupplyChainController(SupplyChainService supplyChainService, ScanService scanService,
            UserService userService) {
        this.supplyChainService = supplyChainService;
        this.scanService = scanService;
        this.userService = userService;
    }

    // GET /api/scans/{scanId}/supply-chain → cached results (fast, never starts an analysis)
    @GetMapping("/scans/{scanId}/supply-chain")
    public ResponseEntity<Map<String, Object>> get(
            @PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        ScanResult scan = scanService.getAuthorizedScan(user, scanId);
        return ResponseEntity.ok(supplyChainService.report(scan));
    }

    public record PackageRef(String ecosystem, String name, String version) {
    }

    public record CheckRequest(java.util.List<PackageRef> packages) {
    }

    // POST /api/supply-chain/check → score a few packages right now (nothing stored)
    @PostMapping("/supply-chain/check")
    public ResponseEntity<java.util.List<Map<String, Object>>> check(
            @RequestBody CheckRequest body,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        java.util.List<SupplyChainService.Component> requested = body == null || body.packages() == null
                ? java.util.List.of()
                : body.packages().stream()
                        .map(p -> new SupplyChainService.Component(p.ecosystem(), p.name(), p.version()))
                        .toList();
        return ResponseEntity.ok(supplyChainService.checkPackages(requested));
    }

    // POST /api/scans/{scanId}/supply-chain/analyze → score the dependencies not cached yet
    @PostMapping("/scans/{scanId}/supply-chain/analyze")
    public ResponseEntity<Map<String, Object>> analyze(
            @PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        ScanResult scan = scanService.getAuthorizedScan(user, scanId);
        return ResponseEntity.ok(supplyChainService.analyze(scan));
    }
}
