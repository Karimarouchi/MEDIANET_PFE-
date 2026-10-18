package com.medianet.controller;

import com.medianet.entity.User;
import com.medianet.service.CiPipelineService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/** CI of the project's repositories, shown and driven from Vulnix (Woodpecker runs behind). */
@RestController
@RequestMapping("/api")
public class CiPipelineController {

    private final CiPipelineService ci;
    private final UserService userService;

    public CiPipelineController(CiPipelineService ci, UserService userService) {
        this.ci = ci;
        this.userService = userService;
    }

    @GetMapping("/projects/{clientId}/ci")
    public CiPipelineService.ProjectCi projectStatus(@PathVariable Long clientId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.projectStatus(user(auth), clientId);
    }

    @PostMapping("/projects/{clientId}/ci/repositories/{repoId}")
    public CiPipelineService.RepoCi enable(@PathVariable Long clientId, @PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.enable(user(auth), clientId, repoId);
    }

    @GetMapping("/projects/{clientId}/ci/repositories/{repoId}/analysis")
    public com.medianet.service.CiRepoAnalyzer.Analysis analysis(@PathVariable Long clientId, @PathVariable Long repoId,
            @RequestParam(required = false) java.util.Set<String> steps, @RequestParam(required = false) String focus,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.analysis(user(auth), clientId, repoId, steps, focus);
    }

    @DeleteMapping("/projects/{clientId}/ci/repositories/{repoId}")
    public ResponseEntity<Void> disable(@PathVariable Long clientId, @PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        ci.disable(user(auth), clientId, repoId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/pipelines/repositories/{repoId}")
    public List<CiPipelineService.PipelineSummary> history(@PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.history(user(auth), repoId);
    }

    @PostMapping("/pipelines/repositories/{repoId}")
    public CiPipelineService.PipelineSummary trigger(@PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.trigger(user(auth), repoId);
    }

    @GetMapping("/pipelines/repositories/{repoId}/{number}")
    public CiPipelineService.PipelineDetail detail(@PathVariable Long repoId, @PathVariable long number,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.detail(user(auth), repoId, number);
    }

    @PostMapping("/pipelines/repositories/{repoId}/{number}/cancel")
    public CiPipelineService.PipelineSummary cancel(@PathVariable Long repoId, @PathVariable long number,
            @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.cancel(user(auth), repoId, number);
    }

    @GetMapping("/pipelines/repositories/{repoId}/{number}/steps/{stepId}/output")
    public List<CiPipelineService.LogLine> logs(@PathVariable Long repoId, @PathVariable long number,
            @PathVariable long stepId, @RequestHeader(value = "Authorization", required = false) String auth) {
        return ci.logs(user(auth), repoId, number, stepId);
    }

    private User user(String auth) {
        return userService.getRequiredUser(auth);
    }
}
