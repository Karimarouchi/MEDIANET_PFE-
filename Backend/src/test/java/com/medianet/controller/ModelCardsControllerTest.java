package com.medianet.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.AccessPermission;
import com.medianet.entity.User;
import com.medianet.service.AccessRoleService;
import com.medianet.service.ModelCardsService;
import com.medianet.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ModelCardsControllerTest {

    private final ModelCardsService cards = mock(ModelCardsService.class);
    private final UserService users = mock(UserService.class);
    private final AccessRoleService roles = mock(AccessRoleService.class);
    private final ModelCardsController controller = new ModelCardsController(cards, users, roles);
    private final User user = new User();

    private void permissions(AccessPermission... p) {
        when(users.getRequiredUser("Bearer x")).thenReturn(user);
        when(roles.getEffectivePermissions(user)).thenReturn(new LinkedHashSet<>(Set.of(p)));
    }

    @Test
    void withoutTheModelInfoPermissionTheAnswerIs403() {
        permissions(AccessPermission.VULNERABILITIES, AccessPermission.DASHBOARD);
        assertThatThrownBy(() -> controller.cards("Bearer x"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("MODEL_INFO");
    }

    @Test
    void withThePermissionTheCardsAreReturned() throws Exception {
        permissions(AccessPermission.MODEL_INFO);
        when(cards.cards()).thenReturn(new ObjectMapper().readTree("{\"models\":[]}"));
        assertThat(controller.cards("Bearer x").getBody().has("models")).isTrue();
    }
}
