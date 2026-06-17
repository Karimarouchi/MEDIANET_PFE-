package com.medianet.service;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.medianet.entity.FindingSeverity;
import com.medianet.entity.ServerNode;
import com.medianet.entity.ServerNodeType;
import com.medianet.entity.SshAuthMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SshServerScanner {

    private static final Logger log = LoggerFactory.getLogger(SshServerScanner.class);

    private static final Pattern PORT_PATTERN = Pattern
            .compile("^(\\S+)\\s+(\\S+)\\s+\\S+\\s+\\S+\\s+(\\S+)\\s+\\S+.*$");
    private final TokenEncryptionService tokenEncryptionService;

    public SshServerScanner(TokenEncryptionService tokenEncryptionService) {
        this.tokenEncryptionService = tokenEncryptionService;
    }

    public ScanReport scan(ServerNode serverNode) throws Exception {
        Session session = openSession(serverNode);
        try {
            session.connect(15_000);

            Map<String, String> raw = new LinkedHashMap<>();
            raw.put("hostname", run(session, "hostname"));
            raw.put("osRelease",
                    run(session, "grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"' || uname -s"));
            raw.put("uname", run(session, "uname -a"));
            raw.put("cpu", run(session,
                    "printf 'cores='; (nproc 2>/dev/null || getconf _NPROCESSORS_ONLN); printf '\nload='; uptime"));
            raw.put("memory", run(session, "free -m"));
            raw.put("disk", run(session, "df -h /"));
            raw.put("ports",
                    run(session,
                            "export PATH=\"$PATH:/usr/sbin:/sbin\"; "
                                    + "ss -tulpn 2>/dev/null "
                                    + "|| ss -tuln 2>/dev/null "
                                    + "|| netstat -tulpn 2>/dev/null "
                                    + "|| netstat -tuln 2>/dev/null "
                                    + "|| { awk 'NR>1&&$4==\"0A\"{n=split($2,a,\":\");h=a[n];p=0;for(i=1;i<=length(h);i++)p=p*16+(index(\"0123456789abcdef\",substr(tolower(h),i,1))-1);if(p>0)print \"tcp LISTEN 0 0 0.0.0.0:\"p\" 0.0.0.0:*\"}' /proc/net/tcp /proc/net/tcp6 2>/dev/null; "
                                    + "awk 'NR>1&&$4==\"07\"{n=split($2,a,\":\");h=a[n];p=0;for(i=1;i<=length(h);i++)p=p*16+(index(\"0123456789abcdef\",substr(tolower(h),i,1))-1);if(p>0)print \"udp UNCONN 0 0 0.0.0.0:\"p\" 0.0.0.0:*\"}' /proc/net/udp /proc/net/udp6 2>/dev/null; } "
                                    + "|| echo 'ports unavailable'"));
            raw.put("services", run(session,
                    "systemctl list-units --type=service --all --no-pager --plain --no-legend 2>/dev/null | head -n 40 || echo 'systemctl unavailable'"));
            raw.put("serviceUnitFiles", run(session,
                    "systemctl list-unit-files --type=service --no-pager --plain --no-legend 2>/dev/null | head -n 80 || echo 'systemctl unavailable'"));
            raw.put("firewall", run(session,
                    "ufw status verbose 2>/dev/null || firewall-cmd --state 2>/dev/null || echo 'firewall unavailable'"));
            raw.put("sshd", run(session,
                    "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin unknown'"));
            raw.put("nginx", run(session, "nginx -T 2>&1 | sed -n '1,120p' || echo 'nginx unavailable'"));
            raw.put("docker", run(session,
                    "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null || echo 'docker unavailable'"));
            raw.put("journal", run(session,
                    "journalctl -n 25 --no-pager 2>/dev/null || tail -n 25 /var/log/syslog 2>/dev/null || echo 'journal unavailable'"));

            List<PortExposureData> ports = parsePorts(raw.get("ports"));
            List<ServiceStatusData> services = parseServices(raw.get("services"), raw.get("serviceUnitFiles"));
            String osName = firstNonBlank(raw.get("osRelease"), raw.get("uname"));
            String kernelVersion = extractKernelVersion(raw.get("uname"));
            String cpuSummary = extractCpuSummary(raw.get("cpu"));
            String memorySummary = extractMemorySummary(raw.get("memory"));
            String diskSummary = extractDiskSummary(raw.get("disk"));
            String firewallStatus = extractFirewallStatus(raw.get("firewall"));
            String sshRootLogin = extractSshRootLogin(raw.get("sshd"));
            String certificateSummary = extractCertificateSummary(raw.get("nginx"), ports);
            String dockerSummary = extractDockerSummary(raw.get("docker"));
            String journalExcerpt = trimTo(raw.get("journal"), 1800);
            List<FindingData> findings = buildFindings(
                    serverNode.getNodeType(),
                    ports,
                    services,
                    firewallStatus,
                    sshRootLogin,
                    certificateSummary,
                    dockerSummary,
                    raw.get("disk"),
                    raw.get("memory"),
                    raw.get("journal"));

            return new ScanReport(
                    raw.get("hostname"),
                    osName,
                    kernelVersion,
                    cpuSummary,
                    memorySummary,
                    diskSummary,
                    firewallStatus,
                    sshRootLogin,
                    dockerSummary,
                    certificateSummary,
                    journalExcerpt,
                    raw,
                    ports,
                    services,
                    findings);
        } finally {
            if (session.isConnected()) {
                session.disconnect();
            }
        }
    }

    public void verifyConnectivity(ServerNode serverNode) throws Exception {
        Session session = openSession(serverNode);
        try {
            session.connect(15_000);
            run(session, "hostname");
        } finally {
            if (session.isConnected()) {
                session.disconnect();
            }
        }
    }

    private Session openSession(ServerNode serverNode) throws Exception {
        JSch jsch = new JSch();
        if (serverNode.getAuthMethod() == SshAuthMethod.PRIVATE_KEY) {
            byte[] privateKey = tokenEncryptionService.decrypt(serverNode.getEncryptedPrivateKey())
                    .getBytes(StandardCharsets.UTF_8);
            String passphrase = tokenEncryptionService.decrypt(serverNode.getEncryptedPrivateKeyPassphrase());
            jsch.addIdentity(
                    serverNode.getName(),
                    privateKey,
                    null,
                    passphrase != null ? passphrase.getBytes(StandardCharsets.UTF_8) : null);
        }

        Session session = jsch.getSession(serverNode.getUsername(), serverNode.getHost(), serverNode.getPort());
        if (serverNode.getAuthMethod() == SshAuthMethod.PASSWORD) {
            session.setPassword(tokenEncryptionService.decrypt(serverNode.getEncryptedPassword()));
        }
        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        config.put("PreferredAuthentications", "publickey,password,keyboard-interactive");
        session.setConfig(config);
        session.setTimeout(15_000);
        return session;
    }

    private String run(Session session, String command) throws Exception {
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        channel.setCommand("bash -lc " + shellQuote(command));
        channel.setInputStream(null);
        channel.setOutputStream(stdout);
        channel.setErrStream(stderr);
        channel.connect(10_000);
        long deadline = System.currentTimeMillis() + 20_000;
        while (!channel.isClosed() && System.currentTimeMillis() < deadline) {
            Thread.sleep(120);
        }
        if (!channel.isClosed()) {
            channel.disconnect();
            throw new IllegalStateException("Timeout while running remote command: " + command);
        }
        String output = stdout.toString(StandardCharsets.UTF_8);
        String error = stderr.toString(StandardCharsets.UTF_8);
        channel.disconnect();
        String combined = output + (error.isBlank() ? "" : System.lineSeparator() + error);
        return combined.trim();
    }

    private String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }

    private String extractKernelVersion(String uname) {
        if (uname == null || uname.isBlank()) {
            return null;
        }
        String[] tokens = uname.trim().split("\\s+");
        return tokens.length >= 3 ? tokens[2] : uname.trim();
    }

    private String extractCpuSummary(String cpuOutput) {
        if (cpuOutput == null || cpuOutput.isBlank()) {
            return null;
        }
        String cores = "?";
        String load = null;
        for (String line : cpuOutput.split("\\R")) {
            if (line.startsWith("cores=")) {
                cores = line.substring("cores=".length()).trim();
            }
            if (line.startsWith("load=")) {
                load = line.substring("load=".length()).trim();
            }
        }
        if (load != null && load.contains("load average:")) {
            load = load.substring(load.indexOf("load average:") + "load average:".length()).trim();
        }
        return load != null && !load.isBlank()
                ? cores + " cœurs · load average " + load
                : cores + " cœurs";
    }

    private String extractMemorySummary(String freeOutput) {
        if (freeOutput == null || freeOutput.isBlank()) {
            return null;
        }
        for (String line : freeOutput.split("\\R")) {
            if (line.trim().startsWith("Mem:")) {
                String[] tokens = line.trim().split("\\s+");
                if (tokens.length >= 3) {
                    return tokens[2] + " MB / " + tokens[1] + " MB";
                }
            }
        }
        return trimTo(freeOutput, 120);
    }

    private String extractDiskSummary(String dfOutput) {
        if (dfOutput == null || dfOutput.isBlank()) {
            return null;
        }
        String[] lines = dfOutput.split("\\R");
        if (lines.length >= 2) {
            String[] tokens = lines[1].trim().split("\\s+");
            if (tokens.length >= 5) {
                return tokens[2] + " / " + tokens[1] + " (" + tokens[4] + ")";
            }
        }
        return trimTo(dfOutput, 120);
    }

    private String extractFirewallStatus(String firewallOutput) {
        if (firewallOutput == null || firewallOutput.isBlank()) {
            return "Inconnu";
        }
        String lower = firewallOutput.toLowerCase(Locale.ROOT);
        if (lower.contains("inactive") || lower.contains("not running") || lower.contains("firewall unavailable")) {
            return "Inactive";
        }
        if (lower.contains("active") || lower.contains("running")) {
            return "Active";
        }
        return trimTo(firewallOutput, 120);
    }

    private String extractSshRootLogin(String sshdOutput) {
        if (sshdOutput == null || sshdOutput.isBlank()) {
            return "Inconnu";
        }
        String normalized = sshdOutput.toLowerCase(Locale.ROOT);
        if (normalized.contains("permitrootlogin yes")) {
            return "Activé";
        }
        if (normalized.contains("permitrootlogin no")) {
            return "Désactivé";
        }
        if (normalized.contains("prohibit-password")) {
            return "Prohibit-password";
        }
        return trimTo(sshdOutput, 120);
    }

    private String extractDockerSummary(String dockerOutput) {
        if (dockerOutput == null || dockerOutput.isBlank()) {
            return "Docker non détecté";
        }
        if (dockerOutput.toLowerCase(Locale.ROOT).contains("docker unavailable")) {
            return "Docker non détecté";
        }
        long count = dockerOutput.lines().filter(line -> !line.isBlank()).count();
        return count == 0 ? "Aucun conteneur actif" : count + " conteneur(s) actif(s)";
    }

    private String extractCertificateSummary(String nginxOutput, List<PortExposureData> ports) {
        long sslCertificateCount = nginxOutput == null ? 0
                : nginxOutput.lines()
                        .filter(line -> line.contains("ssl_certificate "))
                        .count();
        boolean httpsExposed = ports.stream().anyMatch(port -> port.portNumber() == 443);
        if (sslCertificateCount > 0) {
            return sslCertificateCount + " certificat(s) NGINX détecté(s)";
        }
        if (httpsExposed) {
            return "HTTPS exposé sans certificat détecté";
        }
        return "Aucun certificat détecté";
    }

    private List<PortExposureData> parsePorts(String portsOutput) {
        if (portsOutput == null || portsOutput.isBlank()
                || portsOutput.toLowerCase(Locale.ROOT).contains("unavailable")) {
            return List.of();
        }
        List<PortExposureData> result = new ArrayList<>();
        log.info("[PortScan] raw output ({} chars): {}", portsOutput.length(),
                portsOutput.length() > 500 ? portsOutput.substring(0, 500) + "..." : portsOutput);
        for (String line : portsOutput.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isBlank()
                    || trimmed.startsWith("Netid")
                    || trimmed.startsWith("Proto")
                    || trimmed.startsWith("Active")
                    || trimmed.startsWith("ss:")) {
                continue;
            }
            Matcher matcher = PORT_PATTERN.matcher(trimmed);
            if (!matcher.matches()) {
                continue;
            }
            String protocol = matcher.group(1);
            String state = matcher.group(2);
            String local = matcher.group(3);
            Integer portNumber = extractPortNumber(local);
            if (portNumber == null) {
                continue;
            }
            String bindAddress = extractBindAddress(local);
            String processName = extractProcessName(trimmed);
            String exposureLevel = classifyExposure(bindAddress);
            result.add(new PortExposureData(
                    portNumber,
                    protocol,
                    bindAddress,
                    processName,
                    processName,
                    exposureLevel,
                    state));
        }
        return result;
    }

    private List<ServiceStatusData> parseServices(String servicesOutput, String unitFilesOutput) {
        if (servicesOutput == null || servicesOutput.isBlank()
                || servicesOutput.toLowerCase(Locale.ROOT).contains("unavailable")) {
            return List.of();
        }
        Map<String, String> enabledStatus = new HashMap<>();
        if (unitFilesOutput != null && !unitFilesOutput.isBlank()
                && !unitFilesOutput.toLowerCase(Locale.ROOT).contains("unavailable")) {
            for (String line : unitFilesOutput.split("\\R")) {
                String trimmed = line.trim();
                if (trimmed.isBlank()) {
                    continue;
                }
                String[] tokens = trimmed.split("\\s+");
                if (tokens.length >= 2) {
                    enabledStatus.put(tokens[0], tokens[1]);
                }
            }
        }

        List<ServiceStatusData> result = new ArrayList<>();
        for (String line : servicesOutput.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isBlank()) {
                continue;
            }
            String[] tokens = trimmed.split("\\s+");
            if (tokens.length < 4 || !tokens[0].endsWith(".service")) {
                continue;
            }
            result.add(new ServiceStatusData(
                    tokens[0],
                    tokens[2],
                    tokens[3],
                    enabledStatus.getOrDefault(tokens[0], "unknown")));
        }
        return result;
    }

    private List<FindingData> buildFindings(
            ServerNodeType nodeType,
            List<PortExposureData> ports,
            List<ServiceStatusData> services,
            String firewallStatus,
            String sshRootLogin,
            String certificateSummary,
            String dockerSummary,
            String diskOutput,
            String memoryOutput,
            String journalOutput) {
        List<FindingData> findings = new ArrayList<>();

        if (firewallStatus != null && firewallStatus.equalsIgnoreCase("Inactive")) {
            findings.add(new FindingData(
                    "Network",
                    FindingSeverity.CRITICAL,
                    "Pare-feu inactif",
                    "Le pare-feu système n'est pas actif, ce qui expose directement les services réseau.",
                    "Activer UFW ou firewall-cmd et restreindre les flux entrants au strict nécessaire.",
                    firewallStatus));
        }

        if (sshRootLogin != null && sshRootLogin.equalsIgnoreCase("Activé")) {
            findings.add(new FindingData(
                    "SSH",
                    FindingSeverity.WARNING,
                    "Connexion root SSH autorisée",
                    "PermitRootLogin est activé dans sshd_config.",
                    "Basculer PermitRootLogin à no ou prohibit-password et utiliser sudo à la place.",
                    sshRootLogin));
        }

        ports.stream()
                .filter(port -> "PUBLIC".equals(port.exposureLevel()))
                .filter(port -> Set.of(3306, 5432, 6379, 9200, 5601).contains(port.portNumber()))
                .forEach(port -> findings.add(new FindingData(
                        "Network Exposure",
                        port.portNumber() == 3306 || port.portNumber() == 5432 ? FindingSeverity.CRITICAL
                                : FindingSeverity.WARNING,
                        "Port sensible exposé publiquement",
                        "Le port " + port.portNumber() + " est accessible depuis l'extérieur sur " + port.bindAddress()
                                + ".",
                        "Restreindre ce port au réseau interne ou le placer derrière un reverse proxy/VPN.",
                        port.portNumber() + "/" + port.protocol())));

        int diskUsage = extractPercentageFromDisk(diskOutput);
        if (diskUsage >= 95) {
            findings.add(new FindingData(
                    "Storage",
                    FindingSeverity.CRITICAL,
                    "Espace disque critique",
                    "La partition racine dépasse 95% d'utilisation.",
                    "Nettoyer les logs, purger les artefacts et augmenter la capacité disque.",
                    diskUsage + "%"));
        } else if (diskUsage >= 85) {
            findings.add(new FindingData(
                    "Storage",
                    FindingSeverity.WARNING,
                    "Espace disque élevé",
                    "La partition racine dépasse 85% d'utilisation.",
                    "Prévoir un nettoyage ou une extension de volume avant saturation.",
                    diskUsage + "%"));
        }

        int memoryUsage = extractMemoryUsagePercent(memoryOutput);
        if (memoryUsage >= 90) {
            findings.add(new FindingData(
                    "Memory",
                    FindingSeverity.WARNING,
                    "Pression mémoire importante",
                    "La mémoire vive consommée dépasse 90%.",
                    "Vérifier les processus consommateurs et ajuster les limites ou la capacité mémoire.",
                    memoryUsage + "%"));
        }

        if (certificateSummary != null && certificateSummary.toLowerCase(Locale.ROOT).contains("sans certificat")) {
            findings.add(new FindingData(
                    "TLS",
                    FindingSeverity.WARNING,
                    "HTTPS sans certificat détecté",
                    "Le port 443 est exposé mais la configuration NGINX ne révèle aucun ssl_certificate.",
                    "Vérifier la configuration TLS du reverse proxy et déployer un certificat valide.",
                    certificateSummary));
        }

        if (nodeType == ServerNodeType.SCANNER_NODE
                && (dockerSummary == null || dockerSummary.contains("non détecté"))) {
            findings.add(new FindingData(
                    "Container Runtime",
                    FindingSeverity.INFO,
                    "Runtime Docker absent",
                    "Le nœud scanner n'expose aucun runtime Docker utilisable.",
                    "Installer ou démarrer Docker si ce nœud doit exécuter les scans conteneurisés.",
                    dockerSummary));
        }

        if (journalOutput != null) {
            String lowerJournal = journalOutput.toLowerCase(Locale.ROOT);
            if (lowerJournal.contains("failed password") || lowerJournal.contains("authentication failure")) {
                findings.add(new FindingData(
                        "Authentication",
                        FindingSeverity.INFO,
                        "Échecs d'authentification récents",
                        "Le journal système contient des tentatives de connexion échouées.",
                        "Mettre en place fail2ban et surveiller les adresses IP répétitives.",
                        "journalctl"));
            }
        }

        boolean sshPublic = ports.stream()
                .anyMatch(port -> port.portNumber() == 22 && "PUBLIC".equals(port.exposureLevel()));
        if (sshPublic && "Activé".equalsIgnoreCase(sshRootLogin)) {
            findings.add(new FindingData(
                    "SSH",
                    FindingSeverity.CRITICAL,
                    "SSH root exposé publiquement",
                    "Le service SSH écoute publiquement et PermitRootLogin est activé.",
                    "Désactiver root via SSH, restreindre la source IP et imposer l'authentification par clé.",
                    "22/tcp public"));
        }

        return findings;
    }

    private int extractPercentageFromDisk(String dfOutput) {
        if (dfOutput == null || dfOutput.isBlank()) {
            return -1;
        }
        String[] lines = dfOutput.split("\\R");
        if (lines.length < 2) {
            return -1;
        }
        String[] tokens = lines[1].trim().split("\\s+");
        if (tokens.length < 5) {
            return -1;
        }
        return parsePercent(tokens[4]);
    }

    private int extractMemoryUsagePercent(String freeOutput) {
        if (freeOutput == null || freeOutput.isBlank()) {
            return -1;
        }
        for (String line : freeOutput.split("\\R")) {
            if (line.trim().startsWith("Mem:")) {
                String[] tokens = line.trim().split("\\s+");
                if (tokens.length >= 3) {
                    try {
                        double total = Double.parseDouble(tokens[1]);
                        double used = Double.parseDouble(tokens[2]);
                        if (total > 0) {
                            return (int) Math.round((used / total) * 100d);
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }
        return -1;
    }

    private int parsePercent(String raw) {
        try {
            return Integer.parseInt(raw.replace("%", "").trim());
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    private Integer extractPortNumber(String localAddress) {
        int colon = localAddress.lastIndexOf(':');
        if (colon < 0 || colon == localAddress.length() - 1) {
            return null;
        }
        String raw = localAddress.substring(colon + 1).replace("*", "").replace("]", "");
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private String extractBindAddress(String localAddress) {
        int colon = localAddress.lastIndexOf(':');
        if (colon < 0) {
            return localAddress;
        }
        return localAddress.substring(0, colon).replace("[", "");
    }

    private String extractProcessName(String rawLine) {
        int start = rawLine.indexOf("users:((\"");
        if (start >= 0) {
            int end = rawLine.indexOf('"', start + 9);
            if (end > start) {
                return rawLine.substring(start + 9, end);
            }
        }
        int quoteStart = rawLine.indexOf('"');
        if (quoteStart >= 0) {
            int quoteEnd = rawLine.indexOf('"', quoteStart + 1);
            if (quoteEnd > quoteStart) {
                return rawLine.substring(quoteStart + 1, quoteEnd);
            }
        }
        return "unknown";
    }

    private String classifyExposure(String bindAddress) {
        if (bindAddress == null || bindAddress.isBlank()) {
            return "UNKNOWN";
        }
        if (bindAddress.contains("0.0.0.0") || bindAddress.contains("*") || bindAddress.contains("::")) {
            return "PUBLIC";
        }
        if (bindAddress.startsWith("127.") || bindAddress.equals("::1") || bindAddress.equals("localhost")) {
            return "LOCAL";
        }
        return "INTERNAL";
    }

    private String trimTo(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.length() <= maxLength) {
            return trimmed;
        }
        return trimmed.substring(0, maxLength) + "...";
    }

    public record PortExposureData(
            Integer portNumber,
            String protocol,
            String bindAddress,
            String processName,
            String serviceName,
            String exposureLevel,
            String state) {
    }

    public record ServiceStatusData(
            String serviceName,
            String state,
            String subState,
            String enabledStatus) {
    }

    public record FindingData(
            String category,
            FindingSeverity severity,
            String title,
            String description,
            String recommendation,
            String detectedValue) {
    }

    public record ScanReport(
            String hostname,
            String osName,
            String kernelVersion,
            String cpuSummary,
            String memorySummary,
            String diskSummary,
            String firewallStatus,
            String sshRootLogin,
            String dockerSummary,
            String certificateSummary,
            String journalExcerpt,
            Map<String, String> rawOutputs,
            List<PortExposureData> ports,
            List<ServiceStatusData> services,
            List<FindingData> findings) {
    }
}