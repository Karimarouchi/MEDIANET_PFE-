package com.medianet.service;

import com.medianet.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("FixPropagationService — correctif chef en série")
class FixPropagationServiceTest {

    @Mock private CveExposureService exposureService;
    @Mock private CveJournalService cveJournalService;
    @Mock private AutoFixService autoFixService;
    @Mock private UserService userService;
    @InjectMocks private FixPropagationService propagationService;

    @Test
    @DisplayName("sans version chef : on refuse de propager")
    void propagate_requiresChefVersion() {
        User user = new User();
        user.setId(1L);
        when(cveJournalService.getPolicy("CVE-2021-44228", "log4j-core"))
                .thenReturn(Map.of("officialStableVersion", ""));

        assertThatThrownBy(() -> propagationService.propagate(
                user, "CVE-2021-44228", "log4j-core", null))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("version chef");
    }

    @Test
    @DisplayName("aucun dépôt ouvert : zéro commit, pas d’erreur")
    void propagate_emptyTargets() {
        User user = new User();
        user.setId(1L);
        when(cveJournalService.getPolicy("CVE-2021-44228", "log4j-core"))
                .thenReturn(Map.of("officialStableVersion", "2.17.1"));
        when(exposureService.openTargets(user, "CVE-2021-44228", "log4j-core"))
                .thenReturn(List.of());

        Map<String, Object> out = propagationService.propagate(
                user, "CVE-2021-44228", "log4j-core", null);

        assertThat(out.get("committed")).isEqualTo(0);
        assertThat(out.get("attempted")).isEqualTo(0);
        assertThat(out.get("officialStableVersion")).isEqualTo("2.17.1");
    }
}
