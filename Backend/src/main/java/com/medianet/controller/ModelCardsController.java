package com.medianet.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.medianet.entity.AccessPermission;
import com.medianet.entity.User;
import com.medianet.service.AccessRoleService;
import com.medianet.service.ModelCardsService;
import com.medianet.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** "Modèles ML" page: requires the MODEL_INFO permission, which the admin gives to roles. */
@RestController
@RequestMapping("/api/models")
public class ModelCardsController {

    private final ModelCardsService modelCardsService;
    private final UserService userService;
    private final AccessRoleService accessRoleService;

    public ModelCardsController(ModelCardsService modelCardsService, UserService userService,
            AccessRoleService accessRoleService) {
        this.modelCardsService = modelCardsService;
        this.userService = userService;
        this.accessRoleService = accessRoleService;
    }

    @GetMapping
    public ResponseEntity<JsonNode> cards(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        if (!accessRoleService.getEffectivePermissions(user).contains(AccessPermission.MODEL_INFO)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Permission MODEL_INFO requise.");
        }
        return ResponseEntity.ok(modelCardsService.cards());
    }
}
