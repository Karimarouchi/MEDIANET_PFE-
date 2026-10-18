package com.medianet.service;

import com.medianet.entity.DeployStrategy;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Backup before deploy, disk measurement / cleanup parsing, e-mail body. */
class CdSafetyTest {

    private static final String SHA = "c".repeat(40);

    @Test
    void backupRunsBeforeAnythingChangesAndStopsTheDeployWhenItFails() {
        String s = DeployService.buildDeployScript("/opt/antigone/app", "main", DeployStrategy.DOCKER_COMPOSE, SHA, null, "db");
        int backup = s.indexOf("pg_dump");
        int reset = s.indexOf("git reset --hard \"$TARGET\"");
        assertThat(backup).isPositive().isLessThan(reset);
        assertThat(s)
                .contains("docker compose exec -T 'db' sh -c 'U=\"${POSTGRES_USER:-postgres}\"; D=\"${POSTGRES_DB:-$U}\"; pg_dump -U \"$U\" -d \"$D\" -Fc'")
                .contains("pg_restore --list")
                .contains("exit " + DeployService.EXIT_BACKUP_FAILED)
                .contains("tail -n +" + (DeployService.KEEP_BACKUPS + 1));
        assertThat(DeployService.buildDeployScript("/opt/x", "main", DeployStrategy.DOCKER_COMPOSE, SHA, null, null))
                .doesNotContain("pg_dump");
    }

    @Test
    void backupLineIsRead() {
        DeployService.Backup b = DeployService.backupOf("[CD] Sauvegarde : /opt/a/.vulnix-backups/avant-cccc-20261018.dump (48213 octets) vérifiée\n");
        assertThat(b.file()).isEqualTo("/opt/a/.vulnix-backups/avant-cccc-20261018.dump");
        assertThat(b.bytes()).isEqualTo(48213L);
        assertThat(DeployService.backupOf("[CD] Sauvegarde impossible")).isNull();
        assertThat(DeployService.human(48213)).isEqualTo("47 Ko");
        assertThat(DeployService.human(2_500_000_000L)).isEqualTo("2,33 Go");
    }

    @Test
    void diskMeasureIsParsedWithoutDeletingAnything() {
        String out = String.join("\n",
                "DISK 52521566208 44643332096 7878234112",
                "IMG 1a2b3c|<none>|2 weeks ago|512MB",
                "IMG 4d5e6f|<none>|3 days ago|1.2GB",
                "DF Images|3.1GB (40%)",
                "DF Build Cache|2.5GB");
        ServerDiskService.Measure m = ServerDiskService.parse(out);
        assertThat(m.total()).isEqualTo(52521566208L);
        assertThat(m.free()).isEqualTo(7878234112L);
        assertThat(m.images()).hasSize(2);
        assertThat(m.images().get(1).bytes()).isEqualTo(1_200_000_000L);
        assertThat(m.buildCache()).isEqualTo(2_500_000_000L);
        assertThat(ServerDiskService.MEASURE).doesNotContain("prune").doesNotContain(" rm");
        assertThat(ServerDiskService.CLEAN).contains("docker image prune -f").doesNotContain("-a").doesNotContain("volume");
    }

    @Test
    void dockerSizesAndFreedSpace() {
        assertThat(ServerDiskService.bytes("23.5kB")).isEqualTo(23_500L);
        assertThat(ServerDiskService.bytes("0B")).isZero();
        assertThat(ServerDiskService.bytes("1.5GiB")).isEqualTo(1_500_000_000L);
        assertThat(ServerDiskService.freed("Deleted Images:\ndeleted: sha256:x\n\nTotal reclaimed space: 1.2GB\nTotal:\t300MB\n"))
                .isEqualTo("1,40 Go");
    }

    @Test
    void mailBodyLinksBackToVulnixAndMasksAddresses() {
        MailService mail = new MailService(null, "", "", "Vulnix", "https://vulnix.example.com/");
        assertThat(mail.isConfigured()).isFalse();
        assertThat(mail.body("Déployé.", "/projects/2"))
                .contains("Déployé.")
                .contains("Ouvrir dans Vulnix : https://vulnix.example.com/projects/2")
                .contains("Notifications par e-mail");
        assertThat(MailService.mask("karim@example.com")).isEqualTo("k***@example.com");
    }

    @Test
    void checkScriptIsReadOnlyAndCoversWhatTheDeployNeeds() {
        String s = DeployService.buildCheckScript("/opt/antigone/app", "main", DeployStrategy.DOCKER_COMPOSE,
                "http://localhost:18081/api/health", "db");
        assertThat(s)
                .contains("git fetch --dry-run origin 'main'")
                .contains("git ls-files --error-unmatch .env")
                .contains("docker compose config -q")
                .contains("pg_dump")
                .contains("curl -s -o /dev/null -w '%{http_code}' --max-time 5 'http://localhost:18081/api/health'");
        // Nothing that changes the server.
        assertThat(s).doesNotContain("reset --hard").doesNotContain("up -d").doesNotContain("prune")
                .doesNotContain(" rm ").doesNotContain("restart").doesNotContain("mkdir").doesNotContain("> \"$F\"");
        assertThat(DeployService.buildCheckScript("/opt/x", "main", DeployStrategy.DOCKER_COMPOSE, null, null)).doesNotContain("pg_dump");
        assertThat(DeployService.parseCheck("[OK] Dossier présent : /opt/x\n[!] Pas de fichier .env\n[KO] git fetch impossible\nbruit"))
                .extracting(DeployService.CheckItem::level).containsExactly("OK", "WARN", "KO");
    }
}
