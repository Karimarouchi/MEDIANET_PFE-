package com.medianet.service;

import com.medianet.dto.ClientDto;
import com.medianet.entity.*;
import com.medianet.repository.ClientRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.EmployeeClientRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.UserRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires pour {@link ClientService}.
 * Chaque méthode est testée indépendamment avec des mocks Mockito.
 * Si un test échoue → le nom du test indique exactement quelle fonctionnalité est cassée.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ClientService — CRUD clients et permissions")
class ClientServiceTest {

    @Mock private ClientRepo clientRepo;
    @Mock private EmployeeClientRepo employeeClientRepo;
    @Mock private ClientRepositoryRepo clientRepositoryRepo;
    @Mock private UserRepo userRepo;
    @Mock private RepositoryRepo repositoryRepo;

    private ClientService clientService;

    @BeforeEach
    void setUp() {
        clientService = new ClientService(
                clientRepo, employeeClientRepo, clientRepositoryRepo, userRepo, repositoryRepo);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // listVisibleClients
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("listVisibleClients() → ADMIN reçoit tous les clients")
    void listVisibleClients_adminVoitTousLesClients() {
        User admin = buildUser(1L, UserRole.ADMIN);
        Client c1 = buildClient(10L, "Client A");
        Client c2 = buildClient(11L, "Client B");

        when(clientRepo.findAllByOrderByCreatedAtDesc()).thenReturn(List.of(c1, c2));
        when(employeeClientRepo.findByClient_Id(anyLong())).thenReturn(Collections.emptyList());
        when(clientRepositoryRepo.findByClient_Id(anyLong())).thenReturn(Collections.emptyList());

        List<ClientDto> result = clientService.listVisibleClients(admin);

        assertThat(result).hasSize(2)
            .extracting(ClientDto::getName)
            .containsExactlyInAnyOrder("Client A", "Client B");
        verify(clientRepo).findAllByOrderByCreatedAtDesc();
    }

    @Test
    @DisplayName("listVisibleClients() → EMPLOYEE ne voit que ses clients assignés")
    void listVisibleClients_employeeVoitSeulementSesClients() {
        User employee = buildUser(2L, UserRole.EMPLOYEE);
        Client c1 = buildClient(20L, "Mon Client");

        when(clientRepo.findAllAssignedToEmployee(2L)).thenReturn(List.of(c1));
        when(employeeClientRepo.findByClient_Id(anyLong())).thenReturn(Collections.emptyList());
        when(clientRepositoryRepo.findByClient_Id(anyLong())).thenReturn(Collections.emptyList());

        List<ClientDto> result = clientService.listVisibleClients(employee);

        assertThat(result).hasSize(1);
        assertEquals("Mon Client", result.get(0).getName());
        verify(clientRepo).findAllAssignedToEmployee(2L);
        verify(clientRepo, never()).findAllByOrderByCreatedAtDesc();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getVisibleClient
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getVisibleClient() → lève 404 si le client n'existe pas")
    void getVisibleClient_lanceExceptionSiNonTrouve() {
        User admin = buildUser(1L, UserRole.ADMIN);
        when(clientRepo.findDetailedById(999L)).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> clientService.getVisibleClient(admin, 999L),
            "getVisibleClient() devrait lancer 404 si le client est introuvable");

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
    }

    @Test
    @DisplayName("getVisibleClient() → ADMIN peut accéder à n'importe quel client")
    void getVisibleClient_adminPeutAccederANImporteQuelClient() {
        User admin = buildUser(1L, UserRole.ADMIN);
        Client client = buildClient(5L, "VIP Client");

        when(clientRepo.findDetailedById(5L)).thenReturn(Optional.of(client));
        when(employeeClientRepo.findByClient_Id(5L)).thenReturn(Collections.emptyList());
        when(clientRepositoryRepo.findByClient_Id(5L)).thenReturn(Collections.emptyList());

        ClientDto result = clientService.getVisibleClient(admin, 5L);

        assertNotNull(result);
        assertEquals("VIP Client", result.getName());
    }

    @Test
    @DisplayName("getVisibleClient() → EMPLOYEE non assigné → lève 403")
    void getVisibleClient_interdireEmployeeNonAssigne() {
        User employee = buildUser(2L, UserRole.EMPLOYEE);
        Client client = buildClient(5L, "VIP Client");

        when(clientRepo.findDetailedById(5L)).thenReturn(Optional.of(client));
        // L'employee n'est PAS dans la liste des assignés
        when(employeeClientRepo.existsById(new EmployeeClientId(2L, 5L))).thenReturn(false);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> clientService.getVisibleClient(employee, 5L),
            "getVisibleClient() devrait lancer 403 si l'employé n'est pas assigné");

        assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // createClient
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("createClient() → ADMIN peut créer un client")
    void createClient_successPourAdmin() {
        User admin = buildUser(1L, UserRole.ADMIN);
        Client saved = buildClient(100L, "Nouveau Client");
        saved.setCompany("Acme Corp");
        saved.setEmail("contact@acme.com");
        saved.setCreatedBy(admin);

        when(clientRepo.save(any(Client.class))).thenReturn(saved);
        when(employeeClientRepo.findByClient_Id(100L)).thenReturn(Collections.emptyList());
        when(clientRepositoryRepo.findByClient_Id(100L)).thenReturn(Collections.emptyList());

        ClientDto result = clientService.createClient(
                admin, "Nouveau Client", "Acme Corp", "acme.com", "contact@acme.com");

        assertNotNull(result);
        assertEquals("Nouveau Client", result.getName());
        assertEquals("Acme Corp", result.getCompany());
        verify(clientRepo).save(any(Client.class));
    }

    @Test
    @DisplayName("createClient() → EMPLOYEE peut créer un client")
    void createClient_successPourEmployee() {
        User employee = buildUser(2L, UserRole.EMPLOYEE);
        Client saved = buildClient(101L, "Client EMPLOYEE");
        saved.setCreatedBy(employee);

        when(clientRepo.save(any(Client.class))).thenReturn(saved);
        when(employeeClientRepo.findByClient_Id(101L)).thenReturn(Collections.emptyList());
        when(clientRepositoryRepo.findByClient_Id(101L)).thenReturn(Collections.emptyList());

        ClientDto result = clientService.createClient(
                employee, "Client EMPLOYEE", null, null, null);

        assertNotNull(result);
        assertEquals("Client EMPLOYEE", result.getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // updateClient
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("updateClient() → ADMIN peut modifier n'importe quel client")
    void updateClient_adminModifieLeClient() {
        User admin = buildUser(1L, UserRole.ADMIN);
        Client client = buildClient(10L, "Ancien Nom");
        Client updated = buildClient(10L, "Nouveau Nom");
        updated.setCompany("Nouvelle Société");

        when(clientRepo.findById(10L)).thenReturn(Optional.of(client));
        when(clientRepo.save(any(Client.class))).thenReturn(updated);
        when(employeeClientRepo.findByClient_Id(10L)).thenReturn(Collections.emptyList());
        when(clientRepositoryRepo.findByClient_Id(10L)).thenReturn(Collections.emptyList());

        ClientDto result = clientService.updateClient(
                admin, 10L, "Nouveau Nom", "Nouvelle Société", null, null);

        assertEquals("Nouveau Nom", result.getName());
        verify(clientRepo).save(any(Client.class));
    }

    @Test
    @DisplayName("updateClient() → lève 404 si le client n'existe pas")
    void updateClient_lanceExceptionSiClientNonTrouve() {
        User admin = buildUser(1L, UserRole.ADMIN);
        when(clientRepo.findById(999L)).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> clientService.updateClient(admin, 999L, "Nom", null, null, null));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // deleteClient
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("deleteClient() → ADMIN peut supprimer un client existant")
    void deleteClient_adminSupprimeLEClient() {
        User admin = buildUser(1L, UserRole.ADMIN);
        when(clientRepo.existsById(10L)).thenReturn(true);

        clientService.deleteClient(admin, 10L);

        verify(clientRepo).deleteById(10L);
    }

    @Test
    @DisplayName("deleteClient() → EMPLOYEE ne peut pas supprimer → lève 403")
    void deleteClient_echoueSiNonAdmin() {
        User employee = buildUser(2L, UserRole.EMPLOYEE);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> clientService.deleteClient(employee, 10L),
            "deleteClient() devrait lancer 403 si l'utilisateur n'est pas ADMIN");

        assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
        verify(clientRepo, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName("deleteClient() → si le client n'existe pas, aucune suppression n'est effectuée")
    void deleteClient_neRienFaireSiClientInexistant() {
        User admin = buildUser(1L, UserRole.ADMIN);
        when(clientRepo.existsById(999L)).thenReturn(false);

        clientService.deleteClient(admin, 999L);

        verify(clientRepo, never()).deleteById(anyLong());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // assignEmployee
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("assignEmployee() → EMPLOYEE non-admin → lève 403")
    void assignEmployee_echoueSiNonAdmin() {
        User employee = buildUser(2L, UserRole.EMPLOYEE);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> clientService.assignEmployee(employee, 10L, 3L),
            "assignEmployee() devrait lancer 403 si l'utilisateur n'est pas ADMIN");

        assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
    }

    @Test
    @DisplayName("assignEmployee() → cible non-EMPLOYEE → lève 400")
    void assignEmployee_echoueSiCibleNestPasEmployee() {
        User admin = buildUser(1L, UserRole.ADMIN);
        Client client = buildClient(10L, "Client A");
        User targetAdmin = buildUser(5L, UserRole.ADMIN); // cible est ADMIN, pas EMPLOYEE

        when(clientRepo.findById(10L)).thenReturn(Optional.of(client));
        when(userRepo.findById(5L)).thenReturn(Optional.of(targetAdmin));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> clientService.assignEmployee(admin, 10L, 5L),
            "assignEmployee() devrait lancer 400 si la cible n'est pas un EMPLOYEE");

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private User buildUser(Long id, UserRole role) {
        User user = User.builder()
                .login("user-" + id)
                .role(role)
                .suspended(false)
                .primaryProvider(AuthProvider.LOCAL)
                .build();
        // Injection de l'id (simulé, car @GeneratedValue ne fonctionne pas hors JPA)
        user.setId(id);
        return user;
    }

    private Client buildClient(Long id, String name) {
        Client client = Client.builder()
                .name(name)
                .build();
        client.setId(id);
        client.setCreatedAt(LocalDateTime.now());
        return client;
    }
}
