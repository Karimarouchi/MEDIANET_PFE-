package com.medianet.service;

import com.medianet.entity.NotificationType;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.ServerDiskReport;
import com.medianet.entity.ServerNode;
import com.medianet.repository.ServerDeploymentRepo;
import com.medianet.repository.ServerDiskReportRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Disk of a deployment server. Measuring never deletes anything; cleaning runs only on an explicit request from the UI
 * (with confirmation) and removes only what Docker can safely drop: untagged images no container uses, and the build
 * cache beyond {@link #KEEP_BUILD_CACHE} (kept so the next build and a rollback rebuild stay fast). Images in use,
 * containers and volumes (the data) are never touched.
 */
@Service
public class ServerDiskService {

    private static final Logger log = LoggerFactory.getLogger(ServerDiskService.class);
    static final int ALERT_PERCENT = 85;
    static final String KEEP_BUILD_CACHE = "2GB";
    private static final Duration TIMEOUT = Duration.ofMinutes(5);

    /** Docker data lives in /var/lib/docker; df falls back to / when it cannot be read. */
    static final String MEASURE = String.join("\n",
            "P=/var/lib/docker; df -Pk \"$P\" >/dev/null 2>&1 || P=/",
            "df -Pk \"$P\" | awk 'NR==2{printf \"DISK %.0f %.0f %.0f\\n\", $2*1024, $3*1024, $4*1024}'",
            "docker images -f dangling=true --format 'IMG {{.ID}}|{{.Repository}}|{{.CreatedSince}}|{{.Size}}'",
            "docker system df --format 'DF {{.Type}}|{{.Reclaimable}}'");

    static final String CLEAN = String.join("\n",
            "docker image prune -f",
            "docker builder prune -f --keep-storage " + KEEP_BUILD_CACHE);

    private final ServerDeploymentRepo deploymentRepo;
    private final ServerDiskReportRepo reportRepo;
    private final SshCommandExecutor ssh;
    private final NotificationService notifications;
    private final TransactionTemplate tx;

    public ServerDiskService(ServerDeploymentRepo deploymentRepo, ServerDiskReportRepo reportRepo, SshCommandExecutor ssh,
            NotificationService notifications, PlatformTransactionManager txManager) {
        this.deploymentRepo = deploymentRepo;
        this.reportRepo = reportRepo;
        this.ssh = ssh;
        this.notifications = notifications;
        this.tx = new TransactionTemplate(txManager);
    }

    public record OldImage(String id, String repository, String age, long bytes) {
    }

    public record Report(Long serverId, LocalDateTime measuredAt, long diskTotal, long diskUsed, long diskFree, int usedPercent,
            int oldImages, long oldImagesBytes, long buildCacheBytes, long reclaimableBytes, List<OldImage> images,
            LocalDateTime lastCleanupAt, String lastCleanupFreed, boolean alert) {
    }

    /** Parsed measurement. Package-private for tests. */
    record Measure(long total, long used, long free, List<OldImage> images, long buildCache) {
    }

    // ── public API ───────────────────────────────────────────────────────────────

    public Report latest(Long deploymentId) {
        ServerNode node = node(deploymentId);
        return reportRepo.findByServerNodeId(node.getId()).map(ServerDiskService::toReport).orElse(null);
    }

    public Report measure(Long deploymentId) {
        ServerNode node = node(deploymentId);
        return save(node.getId(), run(node, MEASURE), null, null);
    }

    /** After a successful deploy: measure and alert the team once a day when the disk is nearly full. */
    public void measureAfterDeploy(Long deploymentId) {
        ServerDeployment d = tx.execute(s -> loaded(deploymentId));
        Report r = save(d.getServerNode().getId(), run(d.getServerNode(), MEASURE), null, null);
        if (r.usedPercent() >= ALERT_PERCENT && d.getLinkedRepositoryId() != null) {
            boolean due = tx.execute(s -> reportRepo.findByServerNodeId(r.serverId())
                    .map(x -> x.getAlertedAt() == null || x.getAlertedAt().isBefore(LocalDateTime.now().minusHours(24)))
                    .orElse(true));
            if (due) {
                notifications.notifyRepositoryTeam(d.getLinkedRepositoryId(), NotificationType.SERVER_DISK_FULL,
                        "Disque presque plein : " + d.getServerNode().getName() + " (" + r.usedPercent() + " %)",
                        "Le serveur " + d.getServerNode().getName() + " utilise " + r.usedPercent() + " % de son disque ("
                                + DeployService.human(r.diskFree()) + " libres). Un nettoyage peut récupérer "
                                + DeployService.human(r.reclaimableBytes()) + " (anciennes images et cache de build). "
                                + "Un disque plein bloque les déploiements. Le nettoyage se lance depuis l'onglet CI/CD du projet.",
                        null, deploymentId);
                tx.executeWithoutResult(s -> reportRepo.findByServerNodeId(r.serverId()).ifPresent(x -> {
                    x.setAlertedAt(LocalDateTime.now());
                    reportRepo.save(x);
                }));
            }
        }
    }

    /** Explicit, confirmed request from the UI. Returns the new measurement and how much Docker reported freed. */
    public Report clean(Long deploymentId, boolean confirmed) {
        if (!confirmed) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Confirmez le nettoyage.");
        }
        ServerNode node = node(deploymentId);
        String out = run(node, CLEAN);
        String freed = freed(out);
        log.info("[Disk] cleanup server={} freed={}", node.getId(), freed);
        return save(node.getId(), run(node, MEASURE), LocalDateTime.now(), freed);
    }

    // ── parsing (package-private for tests) ──────────────────────────────────────

    static Measure parse(String output) {
        long total = 0, used = 0, free = 0, cache = 0;
        List<OldImage> images = new ArrayList<>();
        for (String raw : output == null ? new String[0] : output.split("\\R")) {
            String line = raw.trim();
            if (line.startsWith("DISK ")) {
                String[] p = line.substring(5).trim().split("\\s+");
                if (p.length == 3) {
                    total = Long.parseLong(p[0]);
                    used = Long.parseLong(p[1]);
                    free = Long.parseLong(p[2]);
                }
            } else if (line.startsWith("IMG ")) {
                String[] p = line.substring(4).split("\\|", -1);
                if (p.length == 4) images.add(new OldImage(p[0], p[1], p[2], bytes(p[3])));
            } else if (line.startsWith("DF Build Cache|")) {
                cache = bytes(line.substring("DF Build Cache|".length()));
            }
        }
        return new Measure(total, used, free, images, cache);
    }

    /** Docker sizes: "512MB", "1.25GB", "23.5kB", "0B", "1.2GB (40%)". */
    static long bytes(String s) {
        Matcher m = Pattern.compile("([0-9.]+)\\s*([kKMGT]?i?B)").matcher(s == null ? "" : s);
        if (!m.find()) return 0;
        double v = Double.parseDouble(m.group(1));
        String u = m.group(2).toUpperCase(Locale.ROOT).replace("I", "");
        double mult = switch (u) {
            case "KB" -> 1e3;
            case "MB" -> 1e6;
            case "GB" -> 1e9;
            case "TB" -> 1e12;
            default -> 1;
        };
        return Math.round(v * mult);
    }

    static String freed(String output) {
        long total = 0;
        Matcher m = Pattern.compile("Total(?: reclaimed space)?:\\s*([0-9.]+\\s*[kKMGT]?i?B)").matcher(output == null ? "" : output);
        while (m.find()) total += bytes(m.group(1));
        return DeployService.human(total);
    }

    // ── internals ────────────────────────────────────────────────────────────────

    private String run(ServerNode node, String command) {
        try {
            SshCommandExecutor.CommandResult r = ssh.execute(node, command, TIMEOUT);
            if (r.exitCode() != 0 && !r.output().contains("DISK ")) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Commande refusée par le serveur (code " + r.exitCode() + ").");
            }
            return r.output();
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Serveur injoignable en SSH : " + e.getMessage());
        }
    }

    private Report save(Long serverId, String output, LocalDateTime cleanedAt, String freed) {
        Measure m = parse(output);
        long oldBytes = m.images().stream().mapToLong(OldImage::bytes).sum();
        StringBuilder details = new StringBuilder();
        m.images().forEach(i -> details.append(i.id()).append('|').append(i.repository()).append('|').append(i.age()).append('|').append(i.bytes()).append('\n'));
        return tx.execute(s -> {
            ServerDiskReport r = reportRepo.findByServerNodeId(serverId).orElse(ServerDiskReport.builder().serverNodeId(serverId).build());
            r.setMeasuredAt(LocalDateTime.now());
            r.setDiskTotal(m.total());
            r.setDiskUsed(m.used());
            r.setDiskFree(m.free());
            r.setOldImages(m.images().size());
            r.setOldImagesBytes(oldBytes);
            r.setBuildCacheBytes(Math.max(0, m.buildCache() - bytes(KEEP_BUILD_CACHE)));
            r.setDetails(details.toString());
            if (cleanedAt != null) {
                r.setLastCleanupAt(cleanedAt);
                r.setLastCleanupFreed(freed);
            }
            return toReport(reportRepo.save(r));
        });
    }

    static Report toReport(ServerDiskReport r) {
        long total = r.getDiskTotal() == null ? 0 : r.getDiskTotal();
        long used = r.getDiskUsed() == null ? 0 : r.getDiskUsed();
        int pct = total > 0 ? (int) Math.round(used * 100.0 / total) : 0;
        List<OldImage> images = new ArrayList<>();
        for (String line : (r.getDetails() == null ? "" : r.getDetails()).split("\n")) {
            String[] p = line.split("\\|", -1);
            if (p.length == 4) images.add(new OldImage(p[0], p[1], p[2], Long.parseLong(p[3])));
        }
        long oldBytes = r.getOldImagesBytes() == null ? 0 : r.getOldImagesBytes();
        long cache = r.getBuildCacheBytes() == null ? 0 : r.getBuildCacheBytes();
        return new Report(r.getServerNodeId(), r.getMeasuredAt(), total, used, r.getDiskFree() == null ? 0 : r.getDiskFree(), pct,
                r.getOldImages() == null ? 0 : r.getOldImages(), oldBytes, cache, oldBytes + cache, images,
                r.getLastCleanupAt(), r.getLastCleanupFreed(), pct >= ALERT_PERCENT);
    }

    private ServerNode node(Long deploymentId) {
        return tx.execute(s -> loaded(deploymentId).getServerNode());
    }

    private ServerDeployment loaded(Long deploymentId) {
        ServerDeployment d = deploymentRepo.findById(deploymentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Déploiement introuvable."));
        ServerNode n = d.getServerNode();
        n.getEncryptedPassword();
        n.getEncryptedPrivateKey();
        n.getEncryptedPrivateKeyPassphrase();
        return d;
    }
}
