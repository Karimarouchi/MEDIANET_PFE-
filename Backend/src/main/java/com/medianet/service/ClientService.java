package com.medianet.service;

import com.medianet.dto.ClientDto;
import com.medianet.entity.*;
import com.medianet.repository.ClientRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.EmployeeClientRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.UserRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

@Service
public class ClientService {

    private final ClientRepo clientRepo;
    private final EmployeeClientRepo employeeClientRepo;
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final UserRepo userRepo;
    private final RepositoryRepo repositoryRepo;

    public ClientService(ClientRepo clientRepo, EmployeeClientRepo employeeClientRepo,
            ClientRepositoryRepo clientRepositoryRepo, UserRepo userRepo, RepositoryRepo repositoryRepo) {
        this.clientRepo = clientRepo;
        this.employeeClientRepo = employeeClientRepo;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.userRepo = userRepo;
        this.repositoryRepo = repositoryRepo;
    }

    public List<ClientDto> listVisibleClients(User currentUser) {
        List<Client> clients = switch (currentUser.getRole()) {
            case ADMIN -> clientRepo.findAllByOrderByCreatedAtDesc();
            case EMPLOYEE -> clientRepo.findAllAssignedToEmployee(currentUser.getId());
        };
        return clients.stream().map(this::toDto).toList();
    }

    public ClientDto getVisibleClient(User currentUser, Long clientId) {
        Client client = clientRepo.findDetailedById(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));
        if (!canAccess(currentUser, client)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Client not accessible");
        }
        return toDto(client);
    }

    @Transactional
    public ClientDto createClient(User currentUser, String name, String company, String email) {
        if (currentUser.getRole() != UserRole.ADMIN && currentUser.getRole() != UserRole.EMPLOYEE) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Insufficient permissions");
        }
        Client client = Client.builder()
                .name(name)
                .company(company)
                .email(email)
                .createdBy(currentUser)
                .build();
        return toDto(clientRepo.save(client));
    }

    @Transactional
    public ClientDto updateClient(User currentUser, Long clientId, String name, String company, String email) {
        Client client = clientRepo.findById(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));
        if (!canManage(currentUser, client)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Client not manageable");
        }
        if (name != null && !name.isBlank()) {
            client.setName(name);
        }
        client.setCompany(company);
        client.setEmail(email);
        return toDto(clientRepo.save(client));
    }

    @Transactional
    public void deleteClient(User currentUser, Long clientId) {
        if (currentUser.getRole() != UserRole.ADMIN) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin required");
        }
        if (!clientRepo.existsById(clientId)) {
            return;
        }
        clientRepo.deleteById(clientId);
    }

    @Transactional
    public ClientDto assignEmployee(User currentUser, Long clientId, Long employeeId) {
        if (currentUser.getRole() != UserRole.ADMIN) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin required");
        }
        Client client = clientRepo.findById(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));
        User employee = userRepo.findById(employeeId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Employee not found"));
        if (employee.getRole() != UserRole.EMPLOYEE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Target user must be an employee");
        }
        EmployeeClientId id = new EmployeeClientId(employee.getId(), client.getId());
        if (!employeeClientRepo.existsById(id)) {
            employeeClientRepo.save(EmployeeClient.builder()
                    .id(id)
                    .employee(employee)
                    .client(client)
                    .build());
        }
        return getVisibleClient(currentUser, clientId);
    }

    @Transactional
    public ClientDto assignRepository(User currentUser, Long clientId, Long repositoryId) {
        Client client = clientRepo.findById(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));
        if (!canManage(currentUser, client)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Client not manageable");
        }
        Repository repository = repositoryRepo.findById(repositoryId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found"));

        ClientRepositoryId id = new ClientRepositoryId(clientId, repositoryId);
        if (!clientRepositoryRepo.existsById(id)) {
            clientRepositoryRepo.save(ClientRepository.builder()
                    .id(id)
                    .client(client)
                    .repository(repository)
                    .build());
        }
        return getVisibleClient(currentUser, clientId);
    }

    @Transactional
    public void removeRepository(User currentUser, Long clientId, Long repositoryId) {
        Client client = clientRepo.findById(clientId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Client not found"));
        if (!canManage(currentUser, client)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Client not manageable");
        }
        clientRepositoryRepo.deleteById(new ClientRepositoryId(clientId, repositoryId));
    }

    private boolean canAccess(User currentUser, Client client) {
        if (currentUser.getRole() == UserRole.ADMIN) {
            return true;
        }
        return employeeClientRepo.existsById(new EmployeeClientId(currentUser.getId(), client.getId()));
    }

    private boolean canManage(User currentUser, Client client) {
        return currentUser.getRole() == UserRole.ADMIN || canAccess(currentUser, client);
    }

    private ClientDto toDto(Client client) {
        List<EmployeeClient> employeeLinks = employeeClientRepo.findByClient_Id(client.getId());
        List<ClientRepository> repoLinks = clientRepositoryRepo.findByClient_Id(client.getId());
        List<Long> employeeIds = new ArrayList<>();
        List<String> employeeLogins = new ArrayList<>();
        for (EmployeeClient link : employeeLinks) {
            if (link.getEmployee() != null) {
                employeeIds.add(link.getEmployee().getId());
                employeeLogins.add(link.getEmployee().getLogin());
            }
        }
        List<Long> repositoryIds = new ArrayList<>();
        List<String> repositoryUrls = new ArrayList<>();
        for (ClientRepository link : repoLinks) {
            if (link.getRepository() != null) {
                repositoryIds.add(link.getRepository().getId());
                repositoryUrls.add(link.getRepository().getRepoUrl());
            }
        }
        return ClientDto.builder()
                .id(client.getId())
                .name(client.getName())
                .company(client.getCompany())
                .email(client.getEmail())
                .createdById(client.getCreatedBy() != null ? client.getCreatedBy().getId() : null)
                .createdByLogin(client.getCreatedBy() != null ? client.getCreatedBy().getLogin() : null)
                .employeeIds(employeeIds)
                .employeeLogins(employeeLogins)
                .repositoryIds(repositoryIds)
                .repositoryUrls(repositoryUrls)
                .createdAt(client.getCreatedAt())
                .build();
    }
}