package com.medianet.controller;

import com.medianet.dto.AssistantChatRequest;
import com.medianet.dto.AssistantChatResponse;
import com.medianet.entity.User;
import com.medianet.service.AssistantService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/assistant")
public class AssistantController {

    private final AssistantService assistantService;
    private final UserService userService;

    public AssistantController(AssistantService assistantService, UserService userService) {
        this.assistantService = assistantService;
        this.userService = userService;
    }

    @PostMapping("/chat")
    public ResponseEntity<AssistantChatResponse> chat(
            @RequestBody AssistantChatRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(assistantService.chat(user, request));
    }
}
