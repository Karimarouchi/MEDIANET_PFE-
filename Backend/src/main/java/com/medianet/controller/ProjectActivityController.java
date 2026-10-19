package com.medianet.controller;

import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.service.ProjectActivityService;
import com.medianet.service.RepoCommitService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Commits of a project's repositories: activity per member, commit list (scan / deploy pickers), commit detail. */
@RestController
@RequestMapping("/api/clients/{id}")
public class ProjectActivityController {

    private final ProjectActivityService activityService;
    private final UserService userService;

    public ProjectActivityController(ProjectActivityService activityService, UserService userService) {
        this.activityService = activityService;
        this.userService = userService;
    }

    /** days: 7, 30, 90… (0 = whole history, capped per repository). */
    @GetMapping("/activity")
    public ResponseEntity<ProjectActivityService.ProjectActivity> activity(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestParam(value = "days", defaultValue = "30") int days) {
        User user = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(activityService.activity(user, id, days));
    }

    @GetMapping("/repos/{repoId}/commits")
    public ResponseEntity<ProjectActivityService.RepoCommits> commits(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @PathVariable Long repoId,
            @RequestParam(value = "branch", required = false) String branch,
            @RequestParam(value = "limit", defaultValue = "30") int limit) {
        User user = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(activityService.repoCommits(user, id, repoId, branch, limit));
    }

    @GetMapping("/repos/{repoId}/commits/{sha}")
    public ResponseEntity<RepoCommitService.CommitDetail> commit(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @PathVariable Long repoId,
            @PathVariable String sha) {
        User user = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(activityService.commitDetail(user, id, repoId, sha));
    }
}
