package com.medianet.serverscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.service.SshServerScanner.PortExposureData;
import com.medianet.serverscan.ServerVulnReport.PackageFinding;
import com.medianet.serverscan.ServerVulnReport.PortFinding;
import com.medianet.serverscan.ServerVulnReport.VulnRef;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ServerVulnParsers — sorties réelles de nmap (vulners) et de Trivy")
class ServerVulnParsersTest {

    private static String resource(String name) throws Exception {
        return Files.readString(Path.of("src/test/resources/serverscan", name), StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("nmap : ports ouverts, service/version et CVE triées par score (sans les références exploit seules)")
    void parsesNmapVulnersOutput() throws Exception {
        List<PortFinding> ports = ServerVulnParsers.parseNmapXml(resource("nmap-vulners.xml"), id -> id.equals("CVE-2019-17567"));

        assertThat(ports).extracting(PortFinding::port).containsExactly(2222, 8081);
        PortFinding ssh = ports.get(0);
        assertThat(ssh.product()).isEqualTo("OpenSSH");
        assertThat(ssh.version()).startsWith("8.2p1");
        assertThat(ssh.exposure()).isEqualTo("EXTERNAL");
        assertThat(ssh.vulns()).isNotEmpty();
        assertThat(ssh.vulns()).allMatch(v -> v.id().startsWith("CVE-"));
        // sorted by score, highest first
        for (int i = 1; i < ssh.vulns().size(); i++) {
            double prev = ssh.vulns().get(i - 1).cvss() == null ? -1 : ssh.vulns().get(i - 1).cvss();
            double cur = ssh.vulns().get(i).cvss() == null ? -1 : ssh.vulns().get(i).cvss();
            assertThat(prev).isGreaterThanOrEqualTo(cur);
        }
        PortFinding http = ports.get(1);
        assertThat(http.product()).isEqualTo("Apache httpd");
        assertThat(http.vulns()).extracting(VulnRef::id).contains("CVE-2019-17567");
        assertThat(http.vulns().stream().filter(v -> v.id().equals("CVE-2019-17567")).findFirst().get().kev()).isTrue();
    }

    @Test
    @DisplayName("nmap : un XML piégé avec une entité externe ne fuit rien")
    void refusesExternalEntities() throws Exception {
        String evil = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>"
                + "<nmaprun><host><ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/>"
                + "<service name=\"&e;\"/></port></ports></host></nmaprun>";
        try {
            List<PortFinding> ports = ServerVulnParsers.parseNmapXml(evil, null);
            assertThat(ports).allMatch(p -> !p.service().contains("root:"));
        } catch (Exception expected) {
            // refusing the document is also fine
        }
    }

    @Test
    @DisplayName("Trivy : paquets vulnérables regroupés, avec version corrigée et sévérité la plus haute")
    void parsesTrivyOutput() throws Exception {
        List<PackageFinding> pkgs = ServerVulnParsers.parseTrivy(resource("trivy-sbom.json"), null);

        assertThat(pkgs).isNotEmpty();
        PackageFinding first = pkgs.get(0);
        assertThat(first.vulns()).isNotEmpty();
        assertThat(first.severity()).isEqualTo(first.vulns().get(0).severity());
        assertThat(pkgs).anyMatch(p -> p.name().equals("libc6") && p.fixedVersion() != null);
    }

    @Test
    @DisplayName("dpkg : nom, version, architecture et paquet source")
    void parsesDpkg() {
        List<ServerVulnParsers.PkgRow> rows = ServerVulnParsers.parseDpkg(
                "apache2\t2.4.41-4ubuntu3.23\tamd64\tapache2\nlibssl1.1\t1.1.1f-1ubuntu2.20\tamd64\topenssl\n\nbad-line\n");
        assertThat(rows).hasSize(2);
        assertThat(rows.get(1).sourceName()).isEqualTo("openssl");
    }

    @Test
    @DisplayName("rpm : retire l'époque 0 et le paquet gpg-pubkey, déduit la source du .src.rpm")
    void parsesRpm() {
        List<ServerVulnParsers.PkgRow> rows = ServerVulnParsers.parseRpm(
                "openssl-libs\t1:3.0.7-24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\n"
                        + "gpg-pubkey\t0:abc-123\t(none)\t(none)\n"
                        + "bash\t0:5.1.8-6.el9\tx86_64\tbash-5.1.8-6.el9.src.rpm\n");
        assertThat(rows).extracting(ServerVulnParsers.PkgRow::name).containsExactly("openssl-libs", "bash");
        assertThat(rows.get(0).sourceName()).isEqualTo("openssl");
        assertThat(rows.get(1).version()).isEqualTo("5.1.8-6.el9");
    }

    @Test
    @DisplayName("SBOM CycloneDX : composant système + un composant par paquet avec purl distro")
    void buildsCycloneDx() throws Exception {
        String json = ServerVulnParsers.buildCycloneDx("ubuntu", "20.04", "deb",
                List.of(new ServerVulnParsers.PkgRow("libc6", "2.31-0ubuntu9.17", "amd64", "glibc")));
        JsonNode bom = new ObjectMapper().readTree(json);
        assertThat(bom.at("/components/0/type").asText()).isEqualTo("operating-system");
        assertThat(bom.at("/components/1/purl").asText())
                .isEqualTo("pkg:deb/ubuntu/libc6@2.31-0ubuntu9.17?distro=ubuntu-20.04&arch=amd64");
    }

    @Test
    @DisplayName("hôtes : seuls les noms et IP simples sont acceptés pour nmap")
    void validatesHosts() {
        assertThat(ServerVulnParsers.isSafeHost("203.0.113.7")).isTrue();
        assertThat(ServerVulnParsers.isSafeHost("vps.example.com")).isTrue();
        assertThat(ServerVulnParsers.isSafeHost("2001:db8::1")).isTrue();
        assertThat(ServerVulnParsers.isSafeHost("-oN /etc/passwd")).isFalse();
        assertThat(ServerVulnParsers.isSafeHost("-sV")).isFalse();
        assertThat(ServerVulnParsers.isSafeHost("a.com; rm -rf /")).isFalse();
        assertThat(ServerVulnParsers.isSafeHost("http://x.com")).isFalse();
        assertThat(ServerVulnParsers.isSafeHost("")).isFalse();
    }

    @Test
    @DisplayName("score CVSS → sévérité")
    void mapsSeverity() {
        assertThat(ServerVulnParsers.severityFromCvss(9.8)).isEqualTo("CRITICAL");
        assertThat(ServerVulnParsers.severityFromCvss(7.5)).isEqualTo("HIGH");
        assertThat(ServerVulnParsers.severityFromCvss(5.0)).isEqualTo("MEDIUM");
        assertThat(ServerVulnParsers.severityFromCvss(2.0)).isEqualTo("LOW");
        assertThat(ServerVulnParsers.severityFromCvss(null)).isEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("assemble : nmap = exposé, port local seul = LOCAL_ONLY / FIREWALLED, totaux sans doublon")
    void assemblesReport() {
        PortFinding http = new PortFinding(80, "tcp", "http", "Apache httpd", "2.4.41", "EXTERNAL",
                List.of(new VulnRef("CVE-1", 9.8, "CRITICAL", true, true, null)));
        List<PortExposureData> local = List.of(
                new PortExposureData(5432, "tcp", "127.0.0.1", "postgres", "postgres", "LOCAL", "LISTEN"),
                new PortExposureData(6379, "tcp", "0.0.0.0", "redis", "redis", "PUBLIC", "LISTEN"),
                new PortExposureData(80, "tcp", "0.0.0.0", "apache2", "apache2", "PUBLIC", "LISTEN"));
        PackageFinding pkg = new PackageFinding("openssl", "1.0", "1.1", "CRITICAL",
                List.of(new VulnRef("CVE-1", null, "CRITICAL", false, true, "1.1")));

        ServerVulnReport r = ServerVulnService.assemble("h", "Ubuntu", true, true, List.of(http), local, List.of(pkg),
                List.of());

        assertThat(r.ports()).extracting(PortFinding::port).containsExactly(80, 6379, 5432);
        assertThat(r.ports().get(1).exposure()).isEqualTo("FIREWALLED");
        assertThat(r.ports().get(2).exposure()).isEqualTo("LOCAL_ONLY");
        assertThat(r.summary().critical()).isEqualTo(1); // CVE-1 counted once across port + package
        assertThat(r.summary().kev()).isEqualTo(1);
        assertThat(r.summary().exposedPorts()).isEqualTo(1);
    }
}
