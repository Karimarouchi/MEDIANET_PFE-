package com.medianet.service;

import com.medianet.dto.*;
import com.medianet.entity.AccessPermission;
import com.medianet.entity.ScanResult;
import com.medianet.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class AssistantService {

    private static final Logger log = LoggerFactory.getLogger(AssistantService.class);

    private static final int MAX_QUESTION = 600;
    private static final int MAX_HISTORY_TURNS = 4;
    private static final int MAX_TURN_CHARS = 280;
    private static final int MAX_DOSSIER = 1800;
    private static final Pattern CVE_ID = Pattern.compile("CVE-\\d{4}-\\d{4,7}", Pattern.CASE_INSENSITIVE);
    private static final Pattern SECRET_TOKEN = Pattern.compile(
            "(?i)(glpat-[A-Za-z0-9_\\-]+|ghp_[A-Za-z0-9_]+|gho_[A-Za-z0-9_]+"
                    + "|sk-[A-Za-z0-9_\\-]+|AIza[0-9A-Za-z_\\-]+"
                    + "|(?:api[_-]?key|token|password|secret)\\s*[:=]\\s*\\S+)");

    private final AiGatewayService aiGatewayService;
    private final AccessRoleService accessRoleService;
    private final ScanService scanService;
    private final SslResultStoreService sslResultStoreService;
    private final ServerConfigService serverConfigService;
    private final CveJournalService cveJournalService;
    private final PolicyDeviationService policyDeviationService;
    private final ClientService clientService;
    private final TransactionTemplate readTx;

    public AssistantService(
            AiGatewayService aiGatewayService,
            AccessRoleService accessRoleService,
            ScanService scanService,
            SslResultStoreService sslResultStoreService,
            ServerConfigService serverConfigService,
            CveJournalService cveJournalService,
            PolicyDeviationService policyDeviationService,
            ClientService clientService,
            PlatformTransactionManager transactionManager) {
        this.aiGatewayService = aiGatewayService;
        this.accessRoleService = accessRoleService;
        this.scanService = scanService;
        this.sslResultStoreService = sslResultStoreService;
        this.serverConfigService = serverConfigService;
        this.cveJournalService = cveJournalService;
        this.policyDeviationService = policyDeviationService;
        this.clientService = clientService;
        if (transactionManager != null) {
            TransactionTemplate tx = new TransactionTemplate(transactionManager);
            tx.setReadOnly(true);
            this.readTx = tx;
        } else {
            this.readTx = null;
        }
    }

    public AssistantStatusDto status(User user) {
        return aiGatewayService.probeChatStatus(user);
    }

    public AssistantChatResponse chat(User user, AssistantChatRequest request) {
        if (request == null || request.getMessage() == null || request.getMessage().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La question est requise.");
        }
        String question = redactSecrets(request.getMessage().trim());
        if (question.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La question est requise.");
        }
        if (question.length() > MAX_QUESTION) {
            question = question.substring(0, MAX_QUESTION);
        }
        final String asked = question;
        final Long scanId = request.getScanId();
        final Long serverId = request.getServerId();
        final String pageKey = resolvePage(request.getPage());

        String faq = localFaq(asked);
        if (faq != null) {
            return AssistantChatResponse.builder()
                    .reply(faq)
                    .contextLabel(defaultLabel(pageKey))
                    .links(pageLinks(pageKey, scanId, serverId))
                    .usedAi(false)
                    .build();
        }

        ContextPack pack = readTx != null
                ? readTx.execute(status -> buildContext(user, pageKey, scanId, serverId, asked))
                : buildContext(user, pageKey, scanId, serverId, asked);
        if (pack == null) {
            throw new IllegalStateException("Contexte assistant indisponible");
        }

        String prompt = buildPrompt(user, asked, pack, request.getHistory());
        String aiReply = null;
        try {
            aiReply = aiGatewayService.generateChat(prompt, user);
        } catch (Exception e) {
            log.warn("[Assistant] IA failed: {}", e.getMessage());
        }
        if (aiReply == null || aiReply.isBlank()) {
            log.warn("[Assistant] Réponse IA vide user={} page={} promptChars={}",
                    user.getLogin(), pageKey, prompt.length());
        }

        String reply;
        boolean usedAi = false;
        if (aiReply != null && !aiReply.isBlank()) {
            reply = unwrapIfJson(aiReply).trim();
            usedAi = true;
        } else {
            reply = fallbackReply(asked, pack);
        }

        return AssistantChatResponse.builder()
                .reply(reply)
                .contextLabel(pack.label)
                .links(pack.links)
                .usedAi(usedAi)
                .build();
    }

    static String redactSecrets(String text) {
        if (text == null || text.isBlank()) {
            return text;
        }
        return SECRET_TOKEN.matcher(text).replaceAll("[REDACTED]");
    }

    static String resolvePage(String page) {
        if (page == null || page.isBlank()) {
            return "general";
        }
        String p = page.trim().toLowerCase(Locale.ROOT);
        int q = p.indexOf('?');
        if (q >= 0) {
            p = p.substring(0, q);
        }
        if (p.startsWith("/ssl-analysis")) {
            return "ssl";
        }
        if (p.startsWith("/server-config")) {
            return "servers";
        }
        if (p.startsWith("/cve-journal") || p.startsWith("/pipeline")) {
            return "cve-journal";
        }
        if (p.startsWith("/vulnerabilities")) {
            return "vulnerabilities";
        }
        if (p.startsWith("/scans")) {
            return "scans";
        }
        if (p.startsWith("/repositories")) {
            return "repositories";
        }
        if (p.startsWith("/projects")) {
            return "projects";
        }
        if (p.startsWith("/profile")) {
            return "profile";
        }
        if (p.startsWith("/admin")) {
            return "admin";
        }
        if (p.equals("/") || p.equals("") || p.startsWith("/dashboard")) {
            return "dashboard";
        }
        return "general";
    }

    static String localFaq(String question) {
        if (question == null) {
            return null;
        }
        String q = question.toLowerCase(Locale.ROOT);
        boolean how = q.contains("comment") || q.contains("où") || q.contains("comment faire")
                || q.startsWith("comment");
        boolean gitHow = q.contains("lier") || q.contains("connecter") || q.contains("oauth")
                || q.contains("pat") || q.contains("token") || how;
        if (gitHow && (q.contains("gitlab") || q.contains("glpat") || q.contains("git lab"))) {
            return """
                    Pour lier GitLab : Profil → Connecter avec GitLab (scopes api + read_user).
                    L’OAuth expire ~2 h. Pour l’auto-fix / commit chef, colle un PAT glpat- avec api + write_repository.
                    Ne colle jamais le token dans ce chat.""";
        }
        if ((q.contains("lancer") || q.contains("démarrer") || q.contains("demarrer")) && q.contains("scan")
                && !q.contains("cve") && !q.contains("priorit")) {
            return "Repositories ou Scans → colle l’URL du dépôt → Démarrer. Le rapport s’ouvre dans Vulnérabilités.";
        }
        if (how && (q.contains("ssl") || q.contains("certificat"))) {
            return "SSL Analysis → saisis le domaine → lance le scan. Le grade, l’expiration et les protocoles TLS sont sur la fiche du scan.";
        }
        if ((q.contains("chatbot") || q.contains("clé chat") || q.contains("cle chat"))
                && (q.contains("résumé") || q.contains("resume") || q.contains("tableau")
                || q.contains("système") || q.contains("systeme") || q.contains("personnelle")
                || q.contains("ssl") || q.contains("cve"))) {
            return "Oui. La clé chatbot ne sert qu’à l’assistant. Les résumés CVE du tableau, le journal chef et le SSL utilisent « Clé IA personnelle » ; si elle est vide, c’est la clé système GEMINI_API_KEY — pas la clé chatbot.";
        }
        if (q.contains("clé ia") || q.contains("cle ia") || q.contains("paramètres ia") || q.contains("parametres ia")
                || (how && q.contains("gemini") && !q.contains("cve"))) {
            return "Profil : « Clé IA personnelle » = résumés CVE/SSL. « Clé chatbot » = l’assistant (Gemini, ChatGPT, Claude ou Grok). Sans clé perso, chaque fonction utilise sa clé système.";
        }
        if ((q.contains("élevé") || q.contains("eleve") || q.contains("résumé ia") || q.contains("resume ia"))
                && (q.contains("high") || q.contains("tableau") || q.contains("30"))) {
            return "CRITICAL / HIGH / MEDIUM / LOW = gravité CVSS (impact). URGENT et le badge KEV n’apparaissent que si la CVE est dans le catalogue CISA KEV : déjà exploitée dans le monde réel. Un CVSS 8.1 est HIGH, même sans exploitation. L’EPSS est une probabilité, pas un second rating.";
        }
        if ((q.contains("expire") || q.contains("renouvel"))
                && (q.contains("jour") || q.contains("certificat") || q.contains("12"))) {
            return "Oui : sous 30 jours, renouvelle tout de suite (idéalement 15–30 j avant). À 12 jours c’est urgent. Vérifie aussi la chaîne complète sur la fiche SSL Analysis.";
        }
        if (q.contains("tls 1.0") || q.contains("tls1.0") || q.contains("tls 1.1") || q.contains("tls1.1")) {
            return "TLS 1.0 et 1.1 sont obsolètes : à désactiver, ne garder que TLS 1.2+. Ouvre la fiche d’un scan SSL (pas seulement la liste) pour voir si ce domaine les accepte encore.";
        }
        if (how && (q.contains("déviation") || q.contains("deviation") || q.contains("accepter"))) {
            return "Le chef (permission Journal CVE) ouvre la notification ou le Journal. Accepter committe avec le token Git du développeur, pas celui du chef.";
        }
        return null;
    }

    private static List<AssistantLinkDto> pageLinks(String pageKey, Long scanId, Long serverId) {
        List<AssistantLinkDto> links = new ArrayList<>();
        switch (pageKey) {
            case "ssl" -> links.add(new AssistantLinkDto("SSL Analysis",
                    scanId != null ? "/ssl-analysis/" + scanId : "/ssl-analysis"));
            case "servers" -> links.add(new AssistantLinkDto("Server Config",
                    serverId != null ? "/server-config/" + serverId : "/server-config"));
            case "cve-journal" -> links.add(new AssistantLinkDto("Journal CVE", "/cve-journal"));
            case "vulnerabilities" -> links.add(new AssistantLinkDto("Vulnérabilités",
                    scanId != null ? "/vulnerabilities?scanId=" + scanId : "/scans"));
            case "profile" -> links.add(new AssistantLinkDto("Profil", "/profile"));
            default -> links.add(new AssistantLinkDto("Dashboard", "/"));
        }
        return links;
    }

    private ContextPack buildContext(User user, String pageKey, Long scanId, Long serverId, String question) {
        ContextPack pack = new ContextPack();
        pack.pageKey = pageKey;
        StringBuilder dossier = new StringBuilder();
        Set<AccessPermission> perms = accessRoleService.getEffectivePermissions(user);

        dossier.append("User: ").append(nz(user.getLogin()))
                .append(" rôle=").append(user.getRole())
                .append(" GitLab=").append(yesNo(user.hasGitlabLinked()))
                .append(" page=").append(pageKey).append('\n');

        appendHelp(dossier, pageKey);
        appendScanContext(user, perms, scanId, question, dossier, pack);
        appendSslContext(user, perms, pageKey, scanId, dossier, pack);
        appendServerContext(perms, pageKey, serverId, dossier, pack);
        appendJournalContext(user, perms, pageKey, question, dossier, pack);
        appendOverview(user, perms, pageKey, question, dossier, pack);
        if (pack.repoHint == null && looksLikeRepoQuestion(question)
                && (perms.contains(AccessPermission.SCANS) || perms.contains(AccessPermission.REPOSITORIES))) {
            try {
                attachRepoHint(user, scanService.getAllScans(user), question, pack);
            } catch (Exception ignored) {
            }
        }

        pack.dossier = truncate(dossier.toString(), MAX_DOSSIER);
        if (pack.label == null || pack.label.isBlank()) {
            pack.label = defaultLabel(pageKey);
        }
        return pack;
    }

    private void appendHelp(StringBuilder dossier, String pageKey) {
        String focus = switch (pageKey) {
            case "ssl" -> "Focus: TLS/grade/expiration.";
            case "servers" -> "Focus: findings serveur (pas de secrets SSH).";
            case "cve-journal" -> "Focus: politique versions / déviations.";
            case "vulnerabilities" -> "Focus: prioriser CVE du scan.";
            case "profile" -> "Focus: liaisons Git.";
            default -> "Expliquer l’écran, sans action.";
        };
        dossier.append(focus).append(" Pas de commit/scan/approbation.\n");
    }

    private void appendScanContext(User user, Set<AccessPermission> perms, Long scanId,
            String question, StringBuilder dossier, ContextPack pack) {
        if (scanId == null) {
            return;
        }
        if (!perms.contains(AccessPermission.SCANS)
                && !perms.contains(AccessPermission.VULNERABILITIES)
                && !perms.contains(AccessPermission.SSL_ANALYSIS)) {
            return;
        }
        try {
            ScanResult scan = scanService.getAuthorizedScan(user, scanId);
            var repoEntity = scan.getRepository();
            String repo = repoEntity != null ? repoEntity.getRepoUrl() : "?";
            String mode = repoEntity != null && repoEntity.getScanMode() != null
                    ? repoEntity.getScanMode() : "auto";
            String branch = repoEntity != null ? repoEntity.getBranch() : null;
            dossier.append("\n--- Scan #").append(scanId).append(" ---\n");
            dossier.append("Dépôt: ").append(repo)
                    .append(" | branche: ").append(nz(branch))
                    .append(" | mode: ").append(mode)
                    .append(" | statut: ").append(scan.getStatus())
                    .append('\n');
            pack.label = "Scan #" + scanId;
            if ("ssl-only".equals(mode)) {
                pack.links.add(new AssistantLinkDto("Rapport SSL", "/ssl-analysis/" + scanId));
            } else {
                pack.links.add(new AssistantLinkDto("Vulnérabilités", "/vulnerabilities?scanId=" + scanId));
            }

            if (!"ssl-only".equals(mode) && perms.contains(AccessPermission.VULNERABILITIES)) {
                List<CveDto> cves = scanService.getCvesByScan(user, scanId);
                long crit = cves.stream().filter(c -> "CRITICAL".equalsIgnoreCase(c.getSeverity())).count();
                long high = cves.stream().filter(c -> "HIGH".equalsIgnoreCase(c.getSeverity())).count();
                dossier.append("CVE: ").append(cves.size())
                        .append(" (CRITICAL ").append(crit).append(", HIGH ").append(high).append(")\n");
                cves.stream()
                        .sorted(cvePriorityOrder())
                        .limit(5)
                        .forEach(c -> dossier.append("- ").append(summarizeCve(c)).append('\n'));
                pack.priorityHint = buildPriorityHint(cves, scanId);
                Matcher askedCve = CVE_ID.matcher(question != null ? question : "");
                if (askedCve.find()) {
                    pack.askedCveHint = answerAboutCve(askedCve.group(), cves, scanId);
                }

                try {
                    List<SecretDto> secrets = scanService.getSecretsByScan(user, scanId);
                    if (secrets != null && !secrets.isEmpty()) {
                        dossier.append("Secrets détectés (valeurs masquées, non listées): ")
                                .append(secrets.size()).append('\n');
                    }
                } catch (Exception ignored) {
                    // secrets optional
                }
            }
        } catch (ResponseStatusException e) {
            log.debug("[Assistant] scan {} inaccessible: {}", scanId, e.getReason());
        } catch (Exception e) {
            log.warn("[Assistant] scan context failed: {}", e.getMessage());
        }
    }

    private void appendSslContext(User user, Set<AccessPermission> perms, String pageKey, Long scanId,
            StringBuilder dossier, ContextPack pack) {
        if (!perms.contains(AccessPermission.SSL_ANALYSIS)) {
            return;
        }
        if (scanId != null) {
            try {
                scanService.getAuthorizedScan(user, scanId);
                var stored = sslResultStoreService.findStored(scanId);
                if (stored != null) stored.ifPresent(ssl -> {
                    dossier.append("\n--- SSL scan #").append(scanId).append(" ---\n");
                    dossier.append(summarizeSsl(ssl)).append('\n');
                    if (pack.label == null || pack.label.startsWith("Scan")) {
                        pack.label = "SSL " + nz(ssl.getDomain());
                    }
                    pack.links.add(new AssistantLinkDto("Analyse SSL", "/ssl-analysis/" + scanId));
                    pack.sslHint = buildSslHint(ssl, scanId);
                });
            } catch (Exception e) {
                log.debug("[Assistant] SSL snapshot skip: {}", e.getMessage());
            }
            return;
        }
        if (!"ssl".equals(pageKey)) {
            return;
        }
        try {
            List<ScanResultDto> sslScans = scanService.getAllScans(user).stream()
                    .filter(s -> "ssl-only".equals(s.getScanMode()))
                    .limit(8)
                    .toList();
            if (!sslScans.isEmpty()) {
                dossier.append("\n--- Derniers scans SSL ---\n");
                for (ScanResultDto s : sslScans) {
                    dossier.append("- #").append(s.getId())
                            .append(" ").append(nz(s.getTargetDomain()))
                            .append(" ").append(s.getStatus()).append('\n');
                }
                pack.links.add(new AssistantLinkDto("SSL Analysis", "/ssl-analysis"));
                for (ScanResultDto s : sslScans) {
                    if (s.getId() == null) {
                        continue;
                    }
                    var stored = sslResultStoreService.findStored(s.getId());
                    if (stored != null && stored.isPresent()) {
                        SslResultDto ssl = stored.get();
                        dossier.append(summarizeSsl(ssl)).append('\n');
                        pack.sslHint = buildSslHint(ssl, s.getId());
                        pack.links.add(new AssistantLinkDto("Fiche SSL", "/ssl-analysis/" + s.getId()));
                        break;
                    }
                }
            }
        } catch (Exception e) {
            log.debug("[Assistant] SSL list skip: {}", e.getMessage());
        }
    }

    private void appendServerContext(Set<AccessPermission> perms, String pageKey, Long serverId,
            StringBuilder dossier, ContextPack pack) {
        if (!perms.contains(AccessPermission.SERVER_CONFIG)) {
            return;
        }
        if (serverId != null) {
            try {
                ServerNodeDetailDto node = serverConfigService.getServer(serverId);
                dossier.append("\n--- Serveur #").append(serverId).append(" ---\n");
                dossier.append("Nom: ").append(nz(node.name()))
                        .append(" | hôte: ").append(nz(node.host()))
                        .append(" | OS: ").append(nz(node.osName()))
                        .append(" | statut: ").append(nz(node.latestStatus()))
                        .append('\n');
                dossier.append("Critique: ").append(n(node.criticalCount()))
                        .append(" | warning: ").append(n(node.warningCount()))
                        .append(" | SSH root: ").append(nz(node.sshRootLogin()))
                        .append(" | firewall: ").append(nz(node.firewallStatus()))
                        .append('\n');
                if (node.findings() != null) {
                    node.findings().stream().limit(5).forEach(f -> dossier.append("- [")
                            .append(nz(f.severity())).append("] ").append(nz(f.title()))
                            .append(" → ").append(truncate(nz(f.recommendation()), 160))
                            .append('\n'));
                }
                pack.label = "Serveur " + nz(node.name());
                pack.links.add(new AssistantLinkDto("Fiche serveur", "/server-config/" + serverId));
            } catch (Exception e) {
                log.debug("[Assistant] server skip: {}", e.getMessage());
            }
            return;
        }
        if (!"servers".equals(pageKey)) {
            return;
        }
        try {
            List<ServerNodeDto> servers = serverConfigService.getServers();
            dossier.append("\n--- Serveurs (").append(servers.size()).append(") ---\n");
            servers.stream().limit(5).forEach(s -> dossier.append("- #").append(s.id())
                    .append(" ").append(nz(s.name()))
                    .append(" ").append(nz(s.host()))
                    .append(" ").append(nz(s.latestStatus())).append('\n'));
            pack.links.add(new AssistantLinkDto("Server Config", "/server-config"));
        } catch (Exception e) {
            log.debug("[Assistant] servers list skip: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void appendJournalContext(User user, Set<AccessPermission> perms, String pageKey, String question,
            StringBuilder dossier, ContextPack pack) {
        if (!perms.contains(AccessPermission.CVE_JOURNAL)) {
            return;
        }
        Matcher m = CVE_ID.matcher(question);
        if (m.find()) {
            try {
                Map<String, Object> policy = cveJournalService.getPolicy(m.group(), null);
                dossier.append("\n--- Politique ").append(m.group()).append(" ---\n");
                dossier.append(policy.entrySet().stream()
                        .filter(e -> e.getValue() != null)
                        .map(e -> e.getKey() + "=" + e.getValue())
                        .collect(Collectors.joining(", "))).append('\n');
                Object official = policy.get("officialStableVersion");
                if (official == null || official.toString().isBlank()) {
                    pack.policyHint = m.group() + " : pas de version officielle chef enregistrée. "
                            + "Le développeur suit la version « Fixed In » du scan, ou le chef la saisit dans le Journal.";
                } else {
                    pack.policyHint = m.group() + " : oui, version chef = " + official
                            + (policy.get("officialComment") != null ? " (« " + policy.get("officialComment") + " »)" : "")
                            + ".";
                }
            } catch (Exception e) {
                log.debug("[Assistant] policy skip: {}", e.getMessage());
            }
        }
        if (!"cve-journal".equals(pageKey)) {
            return;
        }
        try {
            Map<String, Object> journal = cveJournalService.getJournal();
            Object stats = journal.get("stats");
            dossier.append("\n--- Journal CVE ---\n").append(String.valueOf(stats)).append('\n');
            Object catalogObj = journal.get("catalog");
            if (catalogObj instanceof List<?> catalog) {
                catalog.stream().limit(5).forEach(row -> {
                    if (row instanceof Map<?, ?> map) {
                        dossier.append("- ").append(map.get("cveId"))
                                .append(" ").append(map.get("packageName"))
                                .append(" ").append(map.get("severity"))
                                .append(" statut=").append(map.get("remediationStatus"))
                                .append(" fix=").append(map.get("preferredFixVersion"))
                                .append('\n');
                    }
                });
            }
            pack.links.add(new AssistantLinkDto("Journal CVE", "/cve-journal"));
            if ("cve-journal".equals(pageKey)) {
                pack.label = "Journal CVE";
            }
        } catch (Exception e) {
            log.debug("[Assistant] journal skip: {}", e.getMessage());
        }
        try {
            List<Map<String, Object>> pending = policyDeviationService.listPending(user);
            dossier.append("Déviations en attente: ").append(pending.size()).append('\n');
            pending.stream().limit(3).forEach(row -> dossier.append("- ")
                    .append(row.get("cveId")).append(" ").append(row.get("packageName"))
                    .append(" par ").append(row.get("requestedByLogin")).append('\n'));
        } catch (Exception e) {
            log.debug("[Assistant] pending deviations skip: {}", e.getMessage());
        }
    }

    private void appendOverview(User user, Set<AccessPermission> perms, String pageKey, String question,
            StringBuilder dossier, ContextPack pack) {
        if (!"dashboard".equals(pageKey) && !"scans".equals(pageKey)
                && !"repositories".equals(pageKey) && !"projects".equals(pageKey)
                && !"admin".equals(pageKey) && !"general".equals(pageKey)) {
            return;
        }
        if (perms.contains(AccessPermission.PROJECTS) || perms.contains(AccessPermission.DASHBOARD)) {
            try {
                List<ClientDto> clients = clientService.listVisibleClients(user);
                dossier.append("\n--- Projets visibles (").append(clients.size()).append(") ---\n");
                clients.stream().limit(4).forEach(c -> dossier.append("- ").append(c.getName())
                        .append('\n'));
            } catch (Exception ignored) {
            }
        }
        if (perms.contains(AccessPermission.SCANS) || perms.contains(AccessPermission.REPOSITORIES)) {
            try {
                List<ScanResultDto> scans = scanService.getAllScans(user);
                dossier.append("Derniers scans: ").append(scans.size()).append('\n');
                scans.stream().limit(4).forEach(s -> dossier.append("- #").append(s.getId())
                        .append(" ").append(nz(s.getRepoUrl()))
                        .append(" ").append(s.getStatus())
                        .append(" CVE=").append(s.getCveCount())
                        .append(" mode=").append(nz(s.getScanMode())).append('\n'));
                attachRepoHint(user, scans, question, pack);
            } catch (Exception ignored) {
            }
        }
    }

    private String buildPrompt(User user, String question, ContextPack pack, List<AssistantChatTurn> history) {
        StringBuilder hist = new StringBuilder();
        if (history != null) {
            history.stream()
                    .filter(t -> t != null && t.getContent() != null && !t.getContent().isBlank())
                    .limit(MAX_HISTORY_TURNS)
                    .forEach(t -> {
                        String role = "assistant".equalsIgnoreCase(t.getRole()) ? "Assistant" : "Utilisateur";
                        hist.append(role).append(": ")
                                .append(truncate(redactSecrets(t.getContent().trim()), MAX_TURN_CHARS))
                                .append("\n");
                    });
        }
        return """
                Assistant Vulnix. Français, 6 lignes max. Uniquement le dossier. Pas d'action. Pas de JSON.
                Dossier:
                """
                + pack.dossier
                + (hist.isEmpty() ? "" : "\nHisto:\n" + hist)
                + "\nQ: " + question;
    }

    private String fallbackReply(String question, ContextPack pack) {
        String q = question.toLowerCase(Locale.ROOT);
        if (pack.askedCveHint != null && !pack.askedCveHint.isBlank()
                && !q.contains("officielle") && !q.contains("chef") && !q.contains("journal")) {
            return pack.askedCveHint;
        }
        if (pack.policyHint != null && !pack.policyHint.isBlank()
                && (q.contains("officielle") || q.contains("chef") || q.contains("journal")
                || q.contains("version") || q.contains("politique"))) {
            return pack.policyHint;
        }
        if (pack.repoHint != null && !pack.repoHint.isBlank()
                && (q.contains("dernier") || q.contains("projet") || q.contains("dépôt")
                || q.contains("depot") || q.contains("coussin") || q.contains("high"))) {
            return pack.repoHint;
        }
        if (pack.sslHint != null && !pack.sslHint.isBlank()
                && (q.contains("ssl") || q.contains("tls") || q.contains("certificat") || q.contains("expire"))) {
            return pack.sslHint;
        }
        boolean asksPriority = q.contains("priorit") || q.contains("traiter") || q.contains("corriger")
                || (q.contains("cve") && (q.contains("quelle") || q.contains("quoi") || q.contains("top")));
        if (asksPriority && pack.priorityHint != null && !pack.priorityHint.isBlank()) {
            return pack.priorityHint;
        }
        if (asksPriority && (pack.priorityHint == null || pack.priorityHint.isBlank())) {
            return "Ouvre un rapport dans Vulnérabilités (choisis un scan) pour que je priorise les CVE. "
                    + "Là tu es sur « " + pack.label + " », sans scan ouvert.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Gemini chat n'a pas répondu ; synthèse à partir du scan / de l'écran.\n\n");
        if (pack.sslHint != null && !pack.sslHint.isBlank()) {
            sb.append(pack.sslHint).append('\n');
            return sb.toString().trim();
        }
        if (q.contains("ssl") || q.contains("certificat") || q.contains("tls")) {
            sb.append("Ouvre une fiche SSL (pas seulement la liste) pour le grade, TLS 1.0 et l'expiration.\n");
        } else if (q.contains("serveur") || q.contains("ssh") || q.contains("hardening")) {
            sb.append("Les findings sont dans Server Config.\n");
        }
        if (pack.priorityHint != null && !pack.priorityHint.isBlank()) {
            sb.append(pack.priorityHint);
            return sb.toString().trim();
        }
        String dossier = pack.dossier;
        int scanAt = dossier.indexOf("--- Scan #");
        int sslAt = dossier.indexOf("--- SSL");
        int srvAt = dossier.indexOf("--- Serveur #");
        int scansListAt = dossier.indexOf("Derniers scans:");
        if (scanAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(scanAt), 900));
        } else if (sslAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(sslAt), 700));
        } else if (srvAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(srvAt), 700));
        } else if (scansListAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(scansListAt), 700));
        } else {
            sb.append("Contexte : ").append(pack.label).append(". Pose une question liée à cet écran, ou ouvre un scan.");
        }
        return sb.toString().trim();
    }

    private static String answerAboutCve(String cveId, List<CveDto> cves, Long scanId) {
        long crit = cves.stream().filter(c -> "CRITICAL".equalsIgnoreCase(c.getSeverity())).count();
        long high = cves.stream().filter(c -> "HIGH".equalsIgnoreCase(c.getSeverity())).count();
        CveDto hit = cves.stream()
                .filter(c -> c.getCveId() != null && c.getCveId().equalsIgnoreCase(cveId))
                .findFirst()
                .orElse(null);
        if (hit == null) {
            return cveId + " n'est pas dans le scan #" + scanId
                    + " (parfois listée sous un GHSA). Ce scan a " + crit + " CRITICAL et " + high + " HIGH.";
        }
        int rank = severityRank(hit.getSeverity());
        boolean worseExists = cves.stream().anyMatch(c -> severityRank(c.getSeverity()) > rank);
        Double cvss = hit.getCvssScore();
        CveDto higherCvss = cves.stream()
                .filter(c -> c.getCvssScore() != null && cvss != null && c.getCvssScore() > cvss + 0.05)
                .max(Comparator.comparingDouble(CveDto::getCvssScore))
                .orElse(null);
        StringBuilder sb = new StringBuilder();
        sb.append(cveId).append(" : ").append(nz(hit.getSeverity()));
        if (cvss != null) {
            sb.append(" · CVSS ").append(cvss);
        }
        if (hit.getEpssScore() != null) {
            sb.append(" · EPSS ").append(Math.round(hit.getEpssScore() * 1000.0) / 10.0).append("%");
        }
        sb.append(" dans ").append(nz(hit.getPackageName()));
        if (hit.getPackageVersion() != null) {
            sb.append("@").append(hit.getPackageVersion());
        }
        if (hit.getFixedVersion() != null && !hit.getFixedVersion().isBlank()) {
            sb.append(" → viser ").append(hit.getFixedVersion());
        }
        sb.append(".\n");
        if (worseExists) {
            sb.append("Non : ce n'est pas la plus critique du scan #").append(scanId)
                    .append(" (").append(crit).append(" CRITICAL, ").append(high).append(" HIGH).");
        } else if (crit == 0 && "HIGH".equalsIgnoreCase(hit.getSeverity())) {
            sb.append("Pas de CRITICAL sur ce scan. ").append(cveId)
                    .append(" est HIGH, au palier le plus élevé, parmi ").append(high).append(" HIGH.");
            if (higherCvss != null) {
                sb.append(" D'autres HIGH ont un CVSS plus haut (ex. ")
                        .append(nz(higherCvss.getCveId())).append(" CVSS ")
                        .append(higherCvss.getCvssScore()).append(").");
            }
            if (hit.getEpssScore() != null && hit.getEpssScore() >= 0.3) {
                sb.append(" Son EPSS élevé la rend plus urgente à traiter que beaucoup d'autres HIGH.");
            }
        } else if (higherCvss != null) {
            sb.append("Au même palier de sévérité, mais ").append(nz(higherCvss.getCveId()))
                    .append(" a un CVSS plus haut (").append(higherCvss.getCvssScore()).append(").");
        } else {
            sb.append("Oui : parmi ce scan, elle est au palier le plus élevé");
            if (cvss != null) {
                sb.append(" et son CVSS n'est dépassé par aucune autre.");
            }
            sb.append(".");
        }
        return sb.toString();
    }

    private static String buildPriorityHint(List<CveDto> cves, Long scanId) {
        if (cves == null || cves.isEmpty()) {
            return "Scan #" + scanId + " : aucune vulnérabilité listée. Rien à prioriser.";
        }
        long crit = cves.stream().filter(c -> "CRITICAL".equalsIgnoreCase(c.getSeverity())).count();
        long high = cves.stream().filter(c -> "HIGH".equalsIgnoreCase(c.getSeverity())).count();
        long kev = cves.stream().filter(CveDto::isKevListed).count();
        List<CveDto> real = cves.stream().filter(AssistantService::isRealCve).sorted(cvePriorityOrder()).toList();
        long sast = cves.size() - real.size();
        StringBuilder sb = new StringBuilder();
        sb.append("Scan #").append(scanId).append(" : ").append(cves.size()).append(" findings");
        sb.append(" — CRITICAL ").append(crit).append(", HIGH ").append(high);
        if (kev > 0) {
            sb.append(", KEV ").append(kev);
        }
        sb.append(".\n");
        if (crit == 0 && high == 0) {
            sb.append("Aucune CVE CRITICAL/HIGH : rien d'urgent à patcher en premier.\n");
        } else {
            sb.append("À traiter en premier :\n");
            real.stream().filter(c -> severityRank(c.getSeverity()) >= 3).limit(5)
                    .forEach(c -> sb.append("- ").append(summarizeCve(c)).append('\n'));
        }
        if (!real.isEmpty() && crit + high == 0) {
            sb.append("CVE nominales (MEDIUM/LOW) :\n");
            real.stream().limit(3).forEach(c -> sb.append("- ").append(summarizeCve(c)).append('\n'));
        }
        if (sast > 0) {
            sb.append(sast).append(" findings SAST/CWE (ex. liens HTTP en clair) : moins urgent qu'une CVE exploitable.");
        }
        return sb.toString().trim();
    }

    private static boolean isRealCve(CveDto c) {
        return c.getCveId() != null && c.getCveId().toUpperCase(Locale.ROOT).startsWith("CVE-");
    }

    private static Comparator<CveDto> cvePriorityOrder() {
        return Comparator
                .comparing((CveDto c) -> !isRealCve(c))
                .thenComparing(c -> !c.isKevListed())
                .thenComparing(c -> !c.isExploitAvailable())
                .thenComparingInt((CveDto c) -> -severityRank(c.getSeverity()));
    }

    private static String summarizeCve(CveDto c) {
        return nz(c.getCveId()) + " " + nz(c.getSeverity())
                + " " + nz(c.getPackageName()) + "@" + nz(c.getPackageVersion())
                + "→" + nz(c.getFixedVersion())
                + (c.isKevListed() ? " KEV" : "")
                + (c.isExploitAvailable() ? " exploit" : "");
    }

    private void attachRepoHint(User user, List<ScanResultDto> scans, String question, ContextPack pack) {
        if (scans == null || question == null || question.isBlank()) {
            return;
        }
        String q = question.toLowerCase(Locale.ROOT);
        ScanResultDto match = scans.stream()
                .filter(s -> s.getRepoUrl() != null && !"ssl-only".equals(s.getScanMode()))
                .filter(s -> {
                    String url = s.getRepoUrl().toLowerCase(Locale.ROOT);
                    String slug = url.replace(".git", "");
                    int slash = slug.lastIndexOf('/');
                    String name = slash >= 0 ? slug.substring(slash + 1) : slug;
                    return q.contains(name) || q.contains("coussin") && url.contains("coussin");
                })
                .findFirst()
                .orElse(null);
        if (match == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Dernier scan de ").append(match.getRepoUrl())
                .append(" : #").append(match.getId())
                .append(" ").append(match.getStatus())
                .append(" (").append(match.getCveCount()).append(" findings).");
        try {
            List<CveDto> cves = scanService.getCvesByScan(user, match.getId());
            long crit = cves.stream().filter(c -> "CRITICAL".equalsIgnoreCase(c.getSeverity())).count();
            long high = cves.stream().filter(c -> "HIGH".equalsIgnoreCase(c.getSeverity())).count();
            sb.append(" CRITICAL ").append(crit).append(", HIGH ").append(high).append(".");
        } catch (Exception ignored) {
        }
        sb.append(" Ouvre Vulnérabilités ?scanId=").append(match.getId()).append(" pour le détail.");
        pack.repoHint = sb.toString();
        pack.links.add(new AssistantLinkDto("Rapport", "/vulnerabilities?scanId=" + match.getId()));
    }

    private static boolean looksLikeRepoQuestion(String question) {
        if (question == null) {
            return false;
        }
        String q = question.toLowerCase(Locale.ROOT);
        return q.contains("github.com") || q.contains("gitlab.com") || q.contains("coussin")
                || q.contains("dernier scan") || q.contains("projet");
    }

    private static String buildSslHint(SslResultDto ssl, Long scanId) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scan SSL #").append(scanId).append(" ").append(nz(ssl.getDomain()))
                .append(" · grade ").append(nz(ssl.getGrade()))
                .append(" · ").append(ssl.getCertDaysLeft()).append(" j. restants")
                .append(" · TLS1.0=").append(ssl.isTls10() ? "oui (à désactiver)" : "non")
                .append(" · TLS1.1=").append(ssl.isTls11() ? "oui (à désactiver)" : "non")
                .append(" · TLS1.2=").append(ssl.isTls12() ? "oui" : "non")
                .append(" · TLS1.3=").append(ssl.isTls13() ? "oui" : "non")
                .append(".");
        if (ssl.isCertExpired()) {
            sb.append(" Certificat EXPIRÉ : renouveler immédiatement.");
        } else if (ssl.getCertDaysLeft() <= 30) {
            sb.append(" Moins de 30 jours : renouvelle tout de suite.");
        }
        return sb.toString();
    }

    private static String summarizeSsl(SslResultDto ssl) {
        return "Domaine=" + nz(ssl.getDomain())
                + " grade=" + nz(ssl.getGrade())
                + " statut=" + nz(ssl.getScanStatus())
                + " TLS1.0=" + ssl.isTls10() + " TLS1.1=" + ssl.isTls11()
                + " TLS1.2=" + ssl.isTls12() + " TLS1.3=" + ssl.isTls13()
                + " expiré=" + ssl.isCertExpired()
                + " jours_restants=" + ssl.getCertDaysLeft()
                + " émetteur=" + nz(ssl.getCertIssuer())
                + " heartbleed=" + ssl.isHeartbleed()
                + " poodle=" + ssl.isPoodle()
                + " rc4=" + ssl.isRc4();
    }

    private static String unwrapIfJson(String text) {
        String t = text.trim();
        if (!t.startsWith("{") || !t.endsWith("}")) {
            return t;
        }
        try {
            com.fasterxml.jackson.databind.JsonNode n = new com.fasterxml.jackson.databind.ObjectMapper().readTree(t);
            for (String field : List.of("reply", "reponse", "réponse", "answer", "text", "message")) {
                if (n.hasNonNull(field) && n.get(field).isTextual()) {
                    return n.get(field).asText();
                }
            }
        } catch (Exception ignored) {
        }
        return t;
    }

    private static String defaultLabel(String pageKey) {
        return switch (pageKey) {
            case "ssl" -> "Analyse SSL";
            case "servers" -> "Serveurs";
            case "cve-journal" -> "Journal CVE";
            case "vulnerabilities" -> "Vulnérabilités";
            case "scans" -> "Scans";
            case "repositories" -> "Dépôts";
            case "projects" -> "Projets";
            case "profile" -> "Profil";
            case "admin" -> "Admin";
            case "dashboard" -> "Dashboard";
            default -> "Vulnix";
        };
    }

    private static int severityRank(String sev) {
        if (sev == null) {
            return 0;
        }
        return switch (sev.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    private static String nz(String v) {
        return v == null || v.isBlank() ? "—" : v;
    }

    private static String n(Integer v) {
        return v == null ? "0" : String.valueOf(v);
    }

    private static String yesNo(boolean v) {
        return v ? "oui" : "non";
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static final class ContextPack {
        String pageKey;
        String label;
        String dossier = "";
        String priorityHint;
        String askedCveHint;
        String policyHint;
        String repoHint;
        String sslHint;
        List<AssistantLinkDto> links = new ArrayList<>();
    }
}
