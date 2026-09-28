package com.medianet.controller;

import com.medianet.dto.AttackGraphResponseDto;
import com.medianet.dto.AttackPathDto;
import com.medianet.entity.User;
import com.medianet.service.AttackGraphService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/attack-graph")
public class AttackGraphController {

    private final AttackGraphService attackGraphService;
    private final UserService userService;

    public AttackGraphController(AttackGraphService attackGraphService, UserService userService) {
        this.attackGraphService = attackGraphService;
        this.userService = userService;
    }

    // GET /api/attack-graph → all nodes/edges visible to the current user
    @GetMapping
    public ResponseEntity<AttackGraphResponseDto> getGraph(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(attackGraphService.buildGraph(currentUser));
    }

    // GET /api/attack-graph/paths?targetServerId=X → top ranked attack paths
    @GetMapping("/paths")
    public ResponseEntity<List<AttackPathDto>> getPaths(
            @RequestParam(required = false) Long targetServerId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(attackGraphService.computeTopPaths(currentUser, targetServerId));
    }
}
