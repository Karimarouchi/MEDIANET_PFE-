package com.medianet.service;

import com.medianet.entity.ClientRepository;
import com.medianet.entity.EmployeeClient;
import com.medianet.entity.Repository;
import com.medianet.entity.User;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.EmployeeClientRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Who committed what on a project's repositories: one entry per member assigned to the project (commits counted
 * and listed), and the authors that match no member. A commit belongs to a member when its GitHub login, its e-mail
 * (also the GitHub "noreply" form) or its author name matches the member's account.
 */
@Service
public class ProjectActivityService {

    public static final int MAX_COMMITS_PER_REPO = 500;

    public record ActivityCommit(Long repositoryId, String repository, String sha, String shortSha, String title,
                                 String authorName, String authorEmail, String authorLogin, Instant date, String url) {
    }

    public record MemberActivity(Long userId, String name, String email, String login, int commits,
                                 Instant lastCommit, List<String> repositories, List<ActivityCommit> list) {
    }

    public record OtherAuthor(String name, String email, String login, int commits, Instant lastCommit,
                              List<ActivityCommit> list) {
    }

    public record RepoError(Long repositoryId, String repository, String message) {
    }

    public record ProjectActivity(int days, int totalCommits, List<MemberActivity> members, List<OtherAuthor> others,
                                  List<RepoError> errors) {
    }

    /** Commit list of one repository of the project (scan and deploy pickers). */
    public record RepoCommits(Long repositoryId, String repository, String branch, List<RepoCommitService.CommitInfo> commits) {
    }

    private final ClientService clientService;
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final EmployeeClientRepo employeeClientRepo;
    private final RepoCommitService commits;

    public ProjectActivityService(ClientService clientService, ClientRepositoryRepo clientRepositoryRepo,
            EmployeeClientRepo employeeClientRepo, RepoCommitService commits) {
        this.clientService = clientService;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.employeeClientRepo = employeeClientRepo;
        this.commits = commits;
    }

    @Transactional(readOnly = true)
    public ProjectActivity activity(User viewer, Long clientId, int days) {
        clientService.requireManageable(viewer, clientId);
        int period = days <= 0 ? 0 : Math.min(days, 365);
        Instant since = period == 0 ? null : Instant.now().minus(Duration.ofDays(period));

        List<User> members = employeeClientRepo.findByClient_Id(clientId).stream().map(EmployeeClient::getEmployee).toList();
        Map<Long, List<ActivityCommit>> byMember = new LinkedHashMap<>();
        for (User m : members) byMember.put(m.getId(), new ArrayList<>());
        Map<String, List<ActivityCommit>> byOther = new LinkedHashMap<>();
        List<RepoError> errors = new ArrayList<>();
        int total = 0;

        for (ClientRepository link : clientRepositoryRepo.findByClient_Id(clientId)) {
            Repository repo = link.getRepository();
            String label = ProjectDeletionService.label(repo);
            List<RepoCommitService.CommitInfo> list;
            try {
                list = commits.list(viewer, repo, repo.getBranch(), since, MAX_COMMITS_PER_REPO);
            } catch (ResponseStatusException e) {
                errors.add(new RepoError(repo.getId(), label, e.getReason()));
                continue;
            }
            for (RepoCommitService.CommitInfo c : list) {
                total++;
                ActivityCommit ac = new ActivityCommit(repo.getId(), label, c.sha(), c.shortSha(), c.title(),
                        c.authorName(), c.authorEmail(), c.authorLogin(), c.date(), c.url());
                User owner = members.stream().filter(m -> matches(m, c)).findFirst().orElse(null);
                if (owner != null) byMember.get(owner.getId()).add(ac);
                else byOther.computeIfAbsent(authorKey(c), k -> new ArrayList<>()).add(ac);
            }
        }

        Comparator<ActivityCommit> newestFirst = Comparator.comparing(ActivityCommit::date,
                Comparator.nullsLast(Comparator.reverseOrder()));
        List<MemberActivity> memberOut = new ArrayList<>();
        for (User m : members) {
            List<ActivityCommit> list = new ArrayList<>(byMember.get(m.getId()));
            list.sort(newestFirst);
            Set<String> repos = new LinkedHashSet<>();
            list.forEach(c -> repos.add(c.repository()));
            memberOut.add(new MemberActivity(m.getId(), m.getName(), m.getEmail(), m.getLogin(), list.size(),
                    list.isEmpty() ? null : list.get(0).date(), new ArrayList<>(repos), list));
        }
        memberOut.sort(Comparator.comparingInt(MemberActivity::commits).reversed());

        List<OtherAuthor> otherOut = new ArrayList<>();
        for (List<ActivityCommit> list : byOther.values()) {
            list.sort(newestFirst);
            ActivityCommit first = list.get(0);
            otherOut.add(new OtherAuthor(first.authorName(), first.authorEmail(), first.authorLogin(), list.size(),
                    first.date(), list));
        }
        otherOut.sort(Comparator.comparingInt(OtherAuthor::commits).reversed());
        return new ProjectActivity(period, total, memberOut, otherOut, errors);
    }

    @Transactional(readOnly = true)
    public RepoCommits repoCommits(User viewer, Long clientId, Long repositoryId, String branch, int limit) {
        Repository repo = projectRepository(viewer, clientId, repositoryId);
        String ref = branch == null || branch.isBlank() ? repo.getBranch() : branch.trim();
        return new RepoCommits(repo.getId(), ProjectDeletionService.label(repo), ref,
                commits.list(viewer, repo, ref, null, Math.max(1, Math.min(limit, 100))));
    }

    @Transactional(readOnly = true)
    public RepoCommitService.CommitDetail commitDetail(User viewer, Long clientId, Long repositoryId, String sha) {
        return commits.detail(viewer, projectRepository(viewer, clientId, repositoryId), sha);
    }

    private Repository projectRepository(User viewer, Long clientId, Long repositoryId) {
        clientService.requireManageable(viewer, clientId);
        return clientRepositoryRepo.findByClient_Id(clientId).stream()
                .map(ClientRepository::getRepository)
                .filter(r -> r.getId().equals(repositoryId))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ce dépôt n'est pas lié à ce projet."));
    }

    /** Is this commit the member's? GitHub login, e-mail (incl. id+login@users.noreply.github.com) or full name. */
    static boolean matches(User member, RepoCommitService.CommitInfo c) {
        String login = lower(member.getLogin());
        String email = lower(member.getEmail());
        String name = lower(member.getName());
        String cLogin = lower(c.authorLogin());
        String cEmail = lower(c.authorEmail());
        String cName = lower(c.authorName());
        if (!login.isEmpty() && (login.equals(cLogin) || login.equals(cEmail))) return true;
        if (!email.isEmpty() && (email.equals(cEmail) || email.equals(cLogin))) return true;
        if (!login.isEmpty() && cEmail.endsWith("@users.noreply.github.com")) {
            String local = cEmail.substring(0, cEmail.indexOf('@'));
            if (local.equals(login) || local.endsWith("+" + login)) return true;
        }
        return !name.isEmpty() && name.equals(cName);
    }

    private static String authorKey(RepoCommitService.CommitInfo c) {
        if (c.authorLogin() != null && !c.authorLogin().isBlank()) return "login:" + lower(c.authorLogin());
        if (c.authorEmail() != null && !c.authorEmail().isBlank()) return "email:" + lower(c.authorEmail());
        return "name:" + lower(c.authorName());
    }

    private static String lower(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.ROOT);
    }
}
