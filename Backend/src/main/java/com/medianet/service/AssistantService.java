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

    private static final int MAX_QUESTION = 2000;
    private static final int MAX_HISTORY_TURNS = 8;
    private static final int MAX_TURN_CHARS = 800;
    private static final int MAX_DOSSIER = 7500;
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
        ContextPack pack = readTx != null
                ? readTx.execute(status -> buildContext(user, pageKey, scanId, serverId, asked))
                : buildContext(user, pageKey, scanId, serverId, asked);
        if (pack == null) {
            throw new IllegalStateException("Contexte assistant indisponible");
        }

        String prompt = buildPrompt(user, asked, pack, request.getHistory());
        String aiReply = null;
        try {
            aiReply = aiGatewayService.generateText(prompt, user);
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

    private ContextPack buildContext(User user, String pageKey, Long scanId, Long serverId, String question) {
        ContextPack pack = new ContextPack();
        pack.pageKey = pageKey;
        StringBuilder dossier = new StringBuilder();
        Set<AccessPermission> perms = accessRoleService.getEffectivePermissions(user);

        dossier.append("Utilisateur: ").append(nz(user.getLogin()))
                .append(" | rôle système: ").append(user.getRole())
                .append(" | permissions: ").append(perms.stream().map(Enum::name).collect(Collectors.joining(", ")))
                .append('\n');
        dossier.append("GitHub lié: ").append(yesNo(user.hasGithubLinked()))
                .append(" | GitLab lié: ").append(yesNo(user.hasGitlabLinked()))
                .append(" | clé IA perso: ").append(yesNo(user.getAiApiKey() != null && !user.getAiApiKey().isBlank()))
                .append('\n');
        dossier.append("Page UI: ").append(pageKey).append('\n');

        appendHelp(dossier, pageKey);
        appendScanContext(user, perms, scanId, dossier, pack);
        appendSslContext(user, perms, pageKey, scanId, dossier, pack);
        appendServerContext(perms, pageKey, serverId, dossier, pack);
        appendJournalContext(user, perms, pageKey, question, dossier, pack);
        appendOverview(user, perms, pageKey, dossier, pack);

        pack.dossier = truncate(dossier.toString(), MAX_DOSSIER);
        if (pack.label == null || pack.label.isBlank()) {
            pack.label = defaultLabel(pageKey);
        }
        return pack;
    }

    private void appendHelp(StringBuilder dossier, String pageKey) {
        dossier.append("\n--- Aide produit ---\n");
        dossier.append("""
                Vulnix (Medianet) : scans CVE/SAST/secrets, SSL, durcissement serveurs, journal CVE chef.
                Lier GitLab : Profil → Connecter avec GitLab (scopes api + read_user). Les tokens OAuth expirent ~2 h ;
                pour l’auto-fix, coller un PAT glpat- avec api + write_repository.
                Lancer un scan : Repositories ou Scans → coller l’URL du dépôt → Démarrer.
                Scan SSL : SSL Analysis → domaine.
                Serveurs : Server Config → ajouter un nœud SSH (ne jamais coller le mot de passe dans le chat).
                Journal CVE : le chef (permission CVE_JOURNAL) définit la version officielle ; Accepter committe
                avec le token Git du développeur, pas celui du chef.
                IA perso : Profil → Paramètres IA (Gemini / Claude / OpenAI). Sinon Gemini système.
                L’assistant n’exécute jamais commit, scan, approbation ou suppression : il explique et oriente.
                """);
        switch (pageKey) {
            case "ssl" -> dossier.append("Focus page : certificats TLS, protocoles, grade, expiration.\n");
            case "servers" -> dossier.append("Focus page : findings SSH/OS, ports, durcissement. Jamais de secrets SSH.\n");
            case "cve-journal" -> dossier.append("Focus page : politique de versions, déviations, statut de remédiation.\n");
            case "vulnerabilities" -> dossier.append("Focus page : CVE du scan ouvert, priorisation, versions cibles.\n");
            case "profile" -> dossier.append("Focus page : liaisons Git et clé IA.\n");
            default -> {
            }
        }
    }

    private void appendScanContext(User user, Set<AccessPermission> perms, Long scanId,
            StringBuilder dossier, ContextPack pack) {
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
                        .sorted(Comparator.comparingInt((CveDto c) -> severityRank(c.getSeverity())).reversed())
                        .limit(12)
                        .forEach(c -> dossier.append("- ").append(summarizeCve(c)).append('\n'));

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
                });
            } catch (Exception e) {
                log.debug("[Assistant] SSL snapshot skip: {}", e.getMessage());
            }
            return;
        }
        if (!"ssl".equals(pageKey) && !"dashboard".equals(pageKey)) {
            return;
        }
        try {
            List<ScanResultDto> sslScans = scanService.getAllScans(user).stream()
                    .filter(s -> "ssl-only".equals(s.getScanMode()))
                    .limit(5)
                    .toList();
            if (!sslScans.isEmpty()) {
                dossier.append("\n--- Derniers scans SSL ---\n");
                for (ScanResultDto s : sslScans) {
                    dossier.append("- #").append(s.getId())
                            .append(" ").append(nz(s.getTargetDomain()))
                            .append(" ").append(s.getStatus()).append('\n');
                }
                pack.links.add(new AssistantLinkDto("SSL Analysis", "/ssl-analysis"));
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
                    node.findings().stream().limit(10).forEach(f -> dossier.append("- [")
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
        if (!"servers".equals(pageKey) && !"dashboard".equals(pageKey)) {
            return;
        }
        try {
            List<ServerNodeDto> servers = serverConfigService.getServers();
            dossier.append("\n--- Serveurs (").append(servers.size()).append(") ---\n");
            servers.stream().limit(8).forEach(s -> dossier.append("- #").append(s.id())
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
            } catch (Exception e) {
                log.debug("[Assistant] policy skip: {}", e.getMessage());
            }
        }
        if (!"cve-journal".equals(pageKey) && !"dashboard".equals(pageKey) && !CVE_ID.matcher(question).find()) {
            return;
        }
        try {
            Map<String, Object> journal = cveJournalService.getJournal();
            Object stats = journal.get("stats");
            dossier.append("\n--- Journal CVE ---\n").append(String.valueOf(stats)).append('\n');
            Object catalogObj = journal.get("catalog");
            if (catalogObj instanceof List<?> catalog) {
                catalog.stream().limit(8).forEach(row -> {
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
            pending.stream().limit(5).forEach(row -> dossier.append("- ")
                    .append(row.get("cveId")).append(" ").append(row.get("packageName"))
                    .append(" par ").append(row.get("requestedByLogin")).append('\n'));
        } catch (Exception e) {
            log.debug("[Assistant] pending deviations skip: {}", e.getMessage());
        }
    }

    private void appendOverview(User user, Set<AccessPermission> perms, String pageKey,
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
                clients.stream().limit(8).forEach(c -> dossier.append("- ").append(c.getName())
                        .append(" (").append(c.getCompany() != null ? c.getCompany() : "").append(")\n"));
            } catch (Exception ignored) {
            }
        }
        if (perms.contains(AccessPermission.SCANS) || perms.contains(AccessPermission.REPOSITORIES)) {
            try {
                List<ScanResultDto> scans = scanService.getAllScans(user);
                dossier.append("Derniers scans: ").append(scans.size()).append('\n');
                scans.stream().limit(6).forEach(s -> dossier.append("- #").append(s.getId())
                        .append(" ").append(nz(s.getRepoUrl()))
                        .append(" ").append(s.getStatus())
                        .append(" CVE=").append(s.getCveCount())
                        .append(" mode=").append(nz(s.getScanMode())).append('\n'));
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
                Tu es l'assistant Vulnix, copilote DevSecOps de la plateforme Medianet.
                Réponds UNIQUEMENT en français, de façon concrète et courte (8 à 16 lignes max).
                Appuie-toi STRICTEMENT sur le dossier ci-dessous et les faits de l'app. N'invente pas de CVE, notes SSL ou serveurs absents du dossier.
                Si une info n'est pas dans le dossier, dis-le et indique où cliquer dans l'UI.
                N'exécute aucune action (pas de commit, scan, approbation, suppression). Propose le bouton / l'écran à utiliser.
                Ne répète jamais de jetons, mots de passe, clés API. S'ils apparaissent, écris [REDACTED].
                Quand tu cites une CVE, donne sévérité, paquet, version actuelle et version cible si connue.
                Tu peux utiliser des listes à puces. Pas de JSON.

                Dossier (périmètre de cet utilisateur) :
                """
                + pack.dossier
                + "\n\nHistorique récent :\n" + (hist.isEmpty() ? "(aucun)\n" : hist)
                + "\nQuestion : " + question;
    }

    private String fallbackReply(String question, ContextPack pack) {
        String q = question.toLowerCase(Locale.ROOT);
        StringBuilder sb = new StringBuilder();
        sb.append("L'IA externe est indisponible pour le moment, voici ce que je peux confirmer à partir de tes données.\n\n");
        if (q.contains("gitlab") || q.contains("token") || q.contains("oauth") || q.contains("pat")
                || q.contains("lier") || q.contains("connecter")) {
            sb.append("Pour GitLab : Profil → Connecter avec GitLab. Si l'OAuth expire (~2 h), colle un PAT ")
                    .append("avec les scopes api et write_repository (auto-fix / commit chef).\n");
        } else if (q.contains("ssl") || q.contains("certificat") || q.contains("tls")) {
            sb.append("Ouvre SSL Analysis pour lancer un scan de domaine, puis la fiche du scan pour le grade et l'expiration.\n");
        } else if (q.contains("serveur") || q.contains("ssh") || q.contains("hardening")) {
            sb.append("Les findings serveurs sont dans Server Config. Je n'affiche jamais les mots de passe SSH.\n");
        } else if (q.contains("scan") && (q.contains("lancer") || q.contains("démarrer") || q.contains("comment"))) {
            sb.append("Repositories ou Scans → URL du dépôt → Démarrer. Le rapport s'ouvre dans Vulnérabilités.\n");
        } else if (q.contains("chef") || q.contains("déviation") || q.contains("journal")) {
            sb.append("Le chef (permission Journal CVE) valide les versions. Accepter déclenche le commit avec le token du développeur.\n");
        }
        String dossier = pack.dossier;
        int scanAt = dossier.indexOf("--- Scan #");
        int sslAt = dossier.indexOf("--- SSL");
        int srvAt = dossier.indexOf("--- Serveur #");
        int scansListAt = dossier.indexOf("Derniers scans:");
        if (scanAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(scanAt), 1200));
        } else if (sslAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(sslAt), 900));
        } else if (srvAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(srvAt), 900));
        } else if (scansListAt >= 0) {
            sb.append("\n").append(truncate(dossier.substring(scansListAt), 900));
        } else {
            sb.append("\nContexte : ").append(pack.label).append(". Reformule ta question ou réessaie dans un instant.");
        }
        return sb.toString().trim();
    }

    private static String summarizeCve(CveDto c) {
        return nz(c.getCveId()) + " " + nz(c.getSeverity())
                + " pkg=" + nz(c.getPackageName()) + "@" + nz(c.getPackageVersion())
                + " fix=" + nz(c.getFixedVersion())
                + (c.isKevListed() ? " KEV" : "")
                + (c.isExploitAvailable() ? " exploit" : "")
                + (c.getFilePath() != null ? " file=" + c.getFilePath() : "");
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
        List<AssistantLinkDto> links = new ArrayList<>();
    }
}
