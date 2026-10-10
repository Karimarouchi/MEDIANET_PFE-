package com.medianet.service;

import com.medianet.entity.ClientServer;
import com.medianet.entity.ServerNode;
import com.medianet.repository.ClientServerRepo;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.ServerNodeRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("ClientServerService — serveurs d'un projet")
class ClientServerServiceTest {

    @Mock private ServerNodeRepo serverNodeRepo;
    @Mock private ClientServerRepo clientServerRepo;
    @Mock private ClientService clientService;

    private ClientServerService service;
    private final User admin = User.builder().id(1L).role(UserRole.ADMIN).build();

    @BeforeEach
    void setUp() {
        service = new ClientServerService(serverNodeRepo, clientServerRepo, clientService);
    }

    @Test
    @DisplayName("link() rattache un serveur déjà utilisé par un autre projet (plusieurs projets possibles)")
    void link_allowsServerSharedByProjects() {
        ServerNode server = ServerNode.builder().id(5L).name("vps").host("1.2.3.4").build();
        when(serverNodeRepo.findById(5L)).thenReturn(Optional.of(server));
        when(clientServerRepo.existsByClientIdAndServerNode_Id(10L, 5L)).thenReturn(false);
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(server));

        List<ClientServerService.ProjectServerDto> result = service.link(admin, 10L, 5L);

        ArgumentCaptor<ClientServer> saved = ArgumentCaptor.forClass(ClientServer.class);
        verify(clientServerRepo).save(saved.capture());
        assertThat(saved.getValue().getClientId()).isEqualTo(10L);
        assertThat(result).extracting(ClientServerService.ProjectServerDto::name).containsExactly("vps");
    }

    @Test
    @DisplayName("link() ne crée pas de doublon")
    void link_isIdempotent() {
        ServerNode server = ServerNode.builder().id(5L).name("vps").host("1.2.3.4").build();
        when(serverNodeRepo.findById(5L)).thenReturn(Optional.of(server));
        when(clientServerRepo.existsByClientIdAndServerNode_Id(10L, 5L)).thenReturn(true);
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of(server));

        service.link(admin, 10L, 5L);

        verify(clientServerRepo, never()).save(any());
    }

    @Test
    @DisplayName("createLightweight() crée un serveur sans SSH, TEST ou PROD, rattaché au projet")
    void createLightweight_buildsServerWithoutSsh() {
        when(serverNodeRepo.existsByNameIgnoreCase("vps-prod")).thenReturn(false);
        when(serverNodeRepo.save(any(ServerNode.class))).thenAnswer(inv -> inv.getArgument(0));
        when(clientServerRepo.findServersByClientId(10L)).thenReturn(List.of());

        service.createLightweight(admin, 10L, "vps-prod", "203.0.113.7", "PROD");

        ArgumentCaptor<ServerNode> saved = ArgumentCaptor.forClass(ServerNode.class);
        verify(serverNodeRepo).save(saved.capture());
        assertThat(saved.getValue().getEnvironment()).isEqualTo("PROD");
        assertThat(saved.getValue().getEncryptedPassword()).isNull();
        verify(clientServerRepo).save(any(ClientServer.class));
    }

    @Test
    @DisplayName("createLightweight() rejette une URL à la place d'un hôte")
    void createLightweight_rejectsUrlHost() {
        assertThatThrownBy(() -> service.createLightweight(admin, 10L, "x", "http://evil/x", "TEST"))
                .isInstanceOf(ResponseStatusException.class);
        verify(serverNodeRepo, never()).save(any());
    }

    @Test
    @DisplayName("unlink() ne retire que le lien avec ce projet")
    void unlink_removesOnlyThisProjectLink() {
        service.unlink(admin, 10L, 5L);

        verify(clientServerRepo).deleteByClientIdAndServerNode_Id(10L, 5L);
        verify(serverNodeRepo, never()).delete(any());
    }
}
