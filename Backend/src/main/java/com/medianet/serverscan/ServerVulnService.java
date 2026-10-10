package com.medianet.serverscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.ServerNode;
import com.medianet.entity.ServerVulnScan;
import com.medianet.repository.ServerNodeRepo;
import com.medianet.repository.ServerVulnScanRepo;
import com.medianet.serverscan.ServerVulnParsers.PkgRow;
import com.medianet.serverscan.ServerVulnReport.PackageFinding;
import com.medianet.serverscan.ServerVulnReport.PortFinding;
import com.medianet.serverscan.ServerVulnReport.Summary;
import com.medianet.serverscan.ServerVulnReport.VulnRef;
import com.medianet.service.CisaKevService;
import com.medianet.service.SshServerScanner;
import com.medianet.service.SshServerScanner.Inventory;
import com.medianet.service.SshServerScanner.PortExposureData;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Vulnerability analysis of a server itself, from two angles:
 * <ul>
 * <li><b>outside</b>: nmap (service/version detection + the vulners script) run from the scanner image: what an
 * attacker on the internet really sees;</li>
 * <li><b>inside</b> (SSH): installed system packages, matched against the Trivy database, and the ports that
 * listen locally.</li>
 * </ul>
 * Only servers registered in Medianet are ever scanned. Results are indicators: banner-based matches can include
 * false positives (distributions back-port security fixes without changing the visible version).
 */
@Service
public class ServerVulnService {

    private static final Logger log = LoggerFactory.getLogger(ServerVulnService.class);
    private static final Duration STALE_AFTER = Duration.ofMinutes(20);
    private static final String EXTRA_PORTS =
            "1433,1521,2375,2376,3000,3306,3389,5000,5432,5601,5900,6379,8000,8080,8081,8443,8888,9000,9090,9200,11211,27017";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ServerNodeRepo serverNodeRepo;
    private final ServerVulnScanRepo scanRepo;
    private final SshServerScanner sshScanner;
    private final CisaKevService kevService;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    @Value("${vulnix.docker.image}")
    private String scannerImage;

    public ServerVulnService(ServerNodeRepo serverNodeRepo, ServerVulnScanRepo scanRepo, SshServerScanner sshScanner,
            CisaKevService kevService) {
        this.serverNodeRepo = serverNodeRepo;
        this.scanRepo = scanRepo;
        this.sshScanner = sshScanner;
        this.kevService = kevService;
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }

    public record ScanView(Long id, String status, LocalDateTime startedAt, LocalDateTime finishedAt,
            String errorMessage, ServerVulnReport report) {
    }

    public record Options(boolean external, boolean internal) {
    }

    // ─────────────────────────── API ───────────────────────────

    /** Starts a scan in the background; refuses to start a second one while one is running. */
    public ScanView start(Long serverId, Options options) {
        ServerNode server = serverNodeRepo.findById(serverId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Serveur introuvable"));
        if (!options.external() && !options.internal()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Choisissez au moins une analyse.");
        }
        if (options.external() && !ServerVulnParsers.isSafeHost(server.getHost())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Hôte du serveur invalide pour un scan.");
        }
        Optional<ServerVulnScan> last = scanRepo.findFirstByServerNode_IdOrderByStartedAtDesc(serverId);
        if (last.isPresent() && "RUNNING".equals(last.get().getStatus()) && !isStale(last.get())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Une analyse est déjà en cours pour ce serveur.");
        }
        ServerVulnScan scan = scanRepo.save(ServerVulnScan.builder()
                .serverNode(server)
                .status("RUNNING")
                .startedAt(LocalDateTime.now())
                .build());
        Long scanId = scan.getId();
        executor.submit(() -> runScan(scanId, server, options));
        return toView(scan);
    }

    public Optional<ScanView> latest(Long serverId) {
        return scanRepo.findFirstByServerNode_IdOrderByStartedAtDesc(serverId).map(this::toView);
    }

    /** Latest finished report of a server, or empty (used by the attack map). */
    public Optional<ServerVulnReport> latestReport(Long serverId) {
        return latest(serverId).map(ScanView::report);
    }

    // ─────────────────────────── scan ───────────────────────────

    private void runScan(Long scanId, ServerNode server, Options options) {
        ServerVulnScan scan = scanRepo.findById(scanId).orElse(null);
        if (scan == null) return;
        List<String> warnings = new ArrayList<>();
        List<PortFinding> external = List.of();
        List<PackageFinding> packages = List.of();
        List<PortExposureData> listening = List.of();
        String os = null;
        boolean externalDone = false;
        boolean internalDone = false;
        int failures = 0;

        try {
            if (options.external()) {
                try {
                    external = scanExternal(server, warnings);
                    externalDone = true;
                } catch (Exception ex) {
                    failures++;
                    warnings.add("Analyse externe (nmap) impossible : " + shortMessage(ex));
                    log.warn("[ServerVuln] external scan failed for {}: {}", server.getName(), ex.toString());
                }
            }
            if (options.internal()) {
                if (!hasSshCredentials(server)) {
                    warnings.add("Analyse interne ignorée : ce serveur n'a pas d'accès SSH configuré "
                            + "(à compléter dans Server Config).");
                } else {
                    try {
                        Inventory inv = sshScanner.inventory(server);
                        os = inv.osPretty();
                        listening = inv.listeningPorts();
                        packages = scanPackages(inv, warnings);
                        internalDone = true;
                    } catch (Exception ex) {
                        failures++;
                        warnings.add("Analyse interne (SSH) impossible : " + shortMessage(ex));
                        log.warn("[ServerVuln] internal scan failed for {}: {}", server.getName(), ex.toString());
                    }
                }
            }

            ServerVulnReport report = assemble(server.getHost(), os, externalDone, internalDone, external, listening,
                    packages, warnings);
            boolean anySuccess = externalDone || internalDone;
            scan.setStatus(!anySuccess ? "FAILED" : failures > 0 ? "PARTIAL" : "COMPLETED");
            scan.setReportJson(MAPPER.writeValueAsString(report));
            if (!anySuccess) scan.setErrorMessage(trim(String.join(" ", warnings), 990));
        } catch (Exception ex) {
            log.error("[ServerVuln] scan {} crashed", scanId, ex);
            scan.setStatus("FAILED");
            scan.setErrorMessage(trim(shortMessage(ex), 990));
        } finally {
            scan.setFinishedAt(LocalDateTime.now());
            scanRepo.save(scan);
        }
    }

    private List<PortFinding> scanExternal(ServerNode server, List<String> warnings) throws Exception {
        String host = server.getHost().trim();
        if (ServerVulnParsers.isLoopback(host)) {
            warnings.add("L'hôte " + host + " est local : l'analyse externe n'a pas de sens depuis le scanner.");
            throw new IllegalStateException("hôte local");
        }
        String ports = "1-1024," + EXTRA_PORTS + (server.getPort() != null ? "," + server.getPort() : "");
        List<String> cmd = List.of("docker", "run", "--rm", "--entrypoint", "nmap", scannerImage,
                "-sV", "--script", "vulners", "-Pn", "-T4", "--max-retries", "2", "--host-timeout", "900s",
                "--open", "-p", ports, "-oX", "-", "--", host);
        Exec res = exec(cmd, null, 1200);
        if (res.exitCode() != 0 && res.stdout().isBlank()) {
            throw new IllegalStateException("nmap a échoué : " + trim(res.stderr(), 300));
        }
        return ServerVulnParsers.parseNmapXml(res.stdout(), kevService::isKev);
    }

    private List<PackageFinding> scanPackages(Inventory inv, List<String> warnings) throws Exception {
        if (inv.packageManager().isBlank()) {
            warnings.add("Paquets non analysés : système « " + inv.osPretty()
                    + " » non pris en charge (Debian, Ubuntu et familles RHEL uniquement).");
            return List.of();
        }
        List<PkgRow> rows = "deb".equals(inv.packageManager())
                ? ServerVulnParsers.parseDpkg(inv.packagesOutput())
                : ServerVulnParsers.parseRpm(inv.packagesOutput());
        if (rows.isEmpty()) {
            warnings.add("Aucun paquet système lu sur le serveur.");
            return List.of();
        }
        String sbom = ServerVulnParsers.buildCycloneDx(inv.osId(), inv.osVersion(), inv.packageManager(), rows);
        List<String> cmd = List.of("docker", "run", "--rm", "-i",
                "-v", "medianet-trivy-cache:/root/.cache/trivy",
                "--entrypoint", "sh", scannerImage, "-c",
                "cat > /tmp/sbom.json && trivy sbom --quiet --format json --scanners vuln /tmp/sbom.json");
        Exec res = exec(cmd, sbom, 900);
        if (res.exitCode() != 0) {
            throw new IllegalStateException("Trivy a échoué : " + trim(res.stderr(), 300));
        }
        return ServerVulnParsers.parseTrivy(res.stdout(), kevService::isKev);
    }

    /** Merges nmap (what is reachable) with the local listening ports (what runs), then totals everything. */
    static ServerVulnReport assemble(String host, String os, boolean externalDone, boolean internalDone,
            List<PortFinding> external, List<PortExposureData> listening, List<PackageFinding> packages,
            List<String> warnings) {
        Map<String, PortFinding> ports = new LinkedHashMap<>();
        for (PortFinding p : external) {
            ports.put(p.protocol() + "/" + p.port(), p);
        }
        for (PortExposureData l : listening) {
            if (l.portNumber() == null) continue;
            String proto = l.protocol() == null ? "tcp" : l.protocol().toLowerCase().startsWith("udp") ? "udp" : "tcp";
            String key = proto + "/" + l.portNumber();
            if (ports.containsKey(key)) continue;
            String bind = l.bindAddress() == null ? "" : l.bindAddress();
            boolean local = bind.startsWith("127.") || bind.equals("::1") || bind.equals("[::1]");
            String exposure = local ? "LOCAL_ONLY" : externalDone ? "FIREWALLED" : "UNKNOWN";
            String name = l.processName() != null && !l.processName().isBlank() ? l.processName() : l.serviceName();
            ports.put(key, new PortFinding(l.portNumber(), proto, name == null ? "" : name, "", "", exposure,
                    List.of()));
        }
        List<PortFinding> portList = new ArrayList<>(ports.values());
        portList.sort((a, b) -> {
            int c = Integer.compare(exposureRank(a.exposure()), exposureRank(b.exposure()));
            return c != 0 ? c : Integer.compare(a.port(), b.port());
        });

        Set<String> seen = new HashSet<>();
        int[] sev = new int[4];
        int kev = 0;
        List<VulnRef> all = new ArrayList<>();
        portList.forEach(p -> all.addAll(p.vulns()));
        packages.forEach(p -> all.addAll(p.vulns()));
        for (VulnRef v : all) {
            if (!seen.add(v.id())) continue;
            int rank = ServerVulnParsers.severityRank(v.severity());
            if (rank < 4) sev[rank]++;
            if (v.kev()) kev++;
        }
        int exposed = (int) portList.stream().filter(p -> "EXTERNAL".equals(p.exposure())).count();
        int vulnPorts = (int) portList.stream().filter(p -> !p.vulns().isEmpty()).count();
        Summary summary = new Summary(portList.size(), exposed, vulnPorts, packages.size(), sev[0], sev[1], sev[2],
                sev[3], kev);
        return new ServerVulnReport(host, os, externalDone, internalDone, portList, packages, summary, warnings);
    }

    private static int exposureRank(String e) {
        return switch (e) {
            case "EXTERNAL" -> 0;
            case "UNKNOWN" -> 1;
            case "FIREWALLED" -> 2;
            default -> 3;
        };
    }

    // ─────────────────────────── helpers ───────────────────────────

    private ScanView toView(ServerVulnScan scan) {
        String status = scan.getStatus();
        String error = scan.getErrorMessage();
        if ("RUNNING".equals(status) && isStale(scan)) {
            status = "FAILED";
            error = "L'analyse a été interrompue (redémarrage du serveur ou délai dépassé).";
        }
        ServerVulnReport report = null;
        if (scan.getReportJson() != null) {
            try {
                report = MAPPER.readValue(scan.getReportJson(), ServerVulnReport.class);
            } catch (Exception ex) {
                log.warn("[ServerVuln] unreadable report {}: {}", scan.getId(), ex.toString());
            }
        }
        return new ScanView(scan.getId(), status, scan.getStartedAt(), scan.getFinishedAt(), error, report);
    }

    private static boolean isStale(ServerVulnScan scan) {
        return scan.getStartedAt() != null && scan.getStartedAt().plus(STALE_AFTER).isBefore(LocalDateTime.now());
    }

    private static boolean hasSshCredentials(ServerNode s) {
        boolean password = s.getEncryptedPassword() != null && !s.getEncryptedPassword().isBlank();
        boolean key = s.getEncryptedPrivateKey() != null && !s.getEncryptedPrivateKey().isBlank();
        return password || key;
    }

    private static String shortMessage(Exception ex) {
        String m = ex.getMessage();
        return m == null || m.isBlank() ? ex.getClass().getSimpleName() : m;
    }

    private static String trim(String s, int max) {
        if (s == null) return "";
        String t = s.trim();
        return t.length() <= max ? t : t.substring(0, max) + "…";
    }

    record Exec(int exitCode, String stdout, String stderr) {
    }

    /** Runs a command, feeding {@code stdin}, with both output streams drained so it can never block. */
    static Exec exec(List<String> cmd, String stdin, int timeoutSeconds) throws Exception {
        Process p = new ProcessBuilder(cmd).start();
        CompletableFuture<byte[]> out = CompletableFuture.supplyAsync(() -> readAll(p.getInputStream()));
        CompletableFuture<byte[]> err = CompletableFuture.supplyAsync(() -> readAll(p.getErrorStream()));
        try (OutputStream os = p.getOutputStream()) {
            if (stdin != null) os.write(stdin.getBytes(StandardCharsets.UTF_8));
        }
        if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("délai dépassé (" + timeoutSeconds + " s)");
        }
        return new Exec(p.exitValue(), new String(out.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8),
                new String(err.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8));
    }

    private static byte[] readAll(InputStream in) {
        try (in; ByteArrayOutputStream buf = new ByteArrayOutputStream()) {
            in.transferTo(buf);
            return buf.toByteArray();
        } catch (Exception ex) {
            return new byte[0];
        }
    }
}
