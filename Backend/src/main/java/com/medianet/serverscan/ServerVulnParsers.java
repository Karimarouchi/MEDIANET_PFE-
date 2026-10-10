package com.medianet.serverscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.medianet.serverscan.ServerVulnReport.PackageFinding;
import com.medianet.serverscan.ServerVulnReport.PortFinding;
import com.medianet.serverscan.ServerVulnReport.VulnRef;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/** Pure parsing / building helpers of the server vulnerability analysis (no I/O: easy to unit-test). */
public final class ServerVulnParsers {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern CVE_ID = Pattern.compile("^CVE-\\d{4}-\\d{4,}$");
    private static final Pattern HOST = Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^[0-9A-Fa-f:]{2,45}$");

    private ServerVulnParsers() {
    }

    /** A host is only passed to nmap if it is a plain hostname / IP: never an option, never a URL. */
    public static boolean isSafeHost(String host) {
        return host != null && HOST.matcher(host.trim()).matches() && !host.trim().startsWith("-");
    }

    public static boolean isLoopback(String host) {
        if (host == null) return false;
        String h = host.trim().toLowerCase(Locale.ROOT);
        return h.equals("localhost") || h.startsWith("127.") || h.equals("::1") || h.equals("0.0.0.0");
    }

    public static String severityFromCvss(Double cvss) {
        if (cvss == null) return "UNKNOWN";
        if (cvss >= 9.0) return "CRITICAL";
        if (cvss >= 7.0) return "HIGH";
        if (cvss >= 4.0) return "MEDIUM";
        return "LOW";
    }

    public static int severityRank(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            case "LOW" -> 3;
            default -> 4;
        };
    }

    // ───────────────────────── nmap (-sV --script vulners -oX -) ─────────────────────────

    public static List<PortFinding> parseNmapXml(String xml, Predicate<String> isKev) throws Exception {
        List<PortFinding> out = new ArrayList<>();
        if (xml == null || xml.isBlank()) return out;
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // nmap output carries a plain <!DOCTYPE nmaprun>: allow it, but never resolve external entities / DTDs
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        Document doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        NodeList ports = doc.getElementsByTagName("port");
        for (int i = 0; i < ports.getLength(); i++) {
            Element port = (Element) ports.item(i);
            Element state = firstChild(port, "state");
            if (state == null || !"open".equals(state.getAttribute("state"))) continue;
            Element service = firstChild(port, "service");
            String name = service != null ? service.getAttribute("name") : "";
            String product = service != null ? service.getAttribute("product") : "";
            String version = service != null ? service.getAttribute("version") : "";

            Map<String, VulnRef> vulns = new LinkedHashMap<>();
            NodeList scripts = port.getElementsByTagName("script");
            for (int s = 0; s < scripts.getLength(); s++) {
                Element script = (Element) scripts.item(s);
                if (!"vulners".equals(script.getAttribute("id"))) continue;
                collectVulners(script, vulns, isKev);
            }
            List<VulnRef> sorted = new ArrayList<>(vulns.values());
            sorted.sort((a, b) -> Double.compare(b.cvss() == null ? -1 : b.cvss(), a.cvss() == null ? -1 : a.cvss()));
            out.add(new PortFinding(
                    Integer.parseInt(port.getAttribute("portid")),
                    port.getAttribute("protocol"),
                    name, product, version, "EXTERNAL", sorted));
        }
        out.sort((a, b) -> Integer.compare(a.port(), b.port()));
        return out;
    }

    /** Every {@code <table>} that directly holds an {@code id} elem is one vulners entry. */
    private static void collectVulners(Element script, Map<String, VulnRef> vulns, Predicate<String> isKev) {
        NodeList tables = script.getElementsByTagName("table");
        for (int t = 0; t < tables.getLength(); t++) {
            Element table = (Element) tables.item(t);
            Map<String, String> elems = new LinkedHashMap<>();
            for (Node n = table.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n instanceof Element e && "elem".equals(e.getTagName())) {
                    elems.put(e.getAttribute("key"), e.getTextContent().trim());
                }
            }
            String id = elems.get("id");
            if (id == null || !CVE_ID.matcher(id).matches()) continue; // exploit-only references are not CVEs
            Double cvss = null;
            try {
                if (elems.get("cvss") != null) cvss = Double.parseDouble(elems.get("cvss"));
            } catch (NumberFormatException ignored) {
                // no score
            }
            boolean exploit = "true".equalsIgnoreCase(elems.get("is_exploit"));
            VulnRef previous = vulns.get(id);
            if (previous != null) exploit = exploit || previous.exploit();
            vulns.put(id, new VulnRef(id, cvss, severityFromCvss(cvss), exploit, isKev != null && isKev.test(id), null));
        }
    }

    private static Element firstChild(Element parent, String tag) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && tag.equals(e.getTagName())) return e;
        }
        return null;
    }

    // ───────────────────────── system packages (SSH inventory) ─────────────────────────

    public record PkgRow(String name, String version, String arch, String sourceName) {
    }

    /** Lines of {@code dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\n'}. */
    public static List<PkgRow> parseDpkg(String output) {
        List<PkgRow> rows = new ArrayList<>();
        if (output == null) return rows;
        for (String line : output.split("\\R")) {
            String[] p = line.split("\t", -1);
            if (p.length < 2 || p[0].isBlank() || p[1].isBlank()) continue;
            String src = p.length > 3 && !p[3].isBlank() ? p[3].trim() : p[0].trim();
            rows.add(new PkgRow(p[0].trim(), p[1].trim(), p.length > 2 ? p[2].trim() : "", src));
        }
        return rows;
    }

    /** Lines of {@code rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'}. */
    public static List<PkgRow> parseRpm(String output) {
        List<PkgRow> rows = new ArrayList<>();
        if (output == null) return rows;
        for (String line : output.split("\\R")) {
            String[] p = line.split("\t", -1);
            if (p.length < 2 || p[0].isBlank() || p[1].isBlank() || p[0].equals("gpg-pubkey")) continue;
            String version = p[1].trim().startsWith("0:") ? p[1].trim().substring(2) : p[1].trim();
            String src = p.length > 3 ? srpmName(p[3]) : "";
            rows.add(new PkgRow(p[0].trim(), version, p.length > 2 ? p[2].trim() : "", src.isBlank() ? p[0].trim() : src));
        }
        return rows;
    }

    private static String srpmName(String srpm) {
        // "openssl-3.0.7-24.el9.src.rpm" -> "openssl"
        String s = srpm == null ? "" : srpm.trim().replaceAll("\\.src\\.rpm$", "");
        int release = s.lastIndexOf('-');
        if (release <= 0) return s;
        int version = s.lastIndexOf('-', release - 1);
        return version > 0 ? s.substring(0, version) : s;
    }

    /** "ubuntu" / "debian" => deb, "rhel|centos|rocky|almalinux|fedora|ol|amzn" => rpm. */
    public static String packageManagerFor(String osId) {
        String id = osId == null ? "" : osId.toLowerCase(Locale.ROOT);
        if (id.equals("ubuntu") || id.equals("debian")) return "deb";
        if (List.of("rhel", "centos", "rocky", "almalinux", "fedora", "ol", "amzn").contains(id)) return "rpm";
        return "";
    }

    /** Minimal CycloneDX SBOM Trivy understands: an operating-system component + one library per package. */
    public static String buildCycloneDx(String osId, String osVersion, String manager, List<PkgRow> packages)
            throws Exception {
        ObjectNode bom = MAPPER.createObjectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", "1.5");
        bom.put("version", 1);
        ArrayNode components = bom.putArray("components");

        ObjectNode os = components.addObject();
        os.put("bom-ref", "os");
        os.put("type", "operating-system");
        os.put("name", osId);
        os.put("version", osVersion);

        String distro = osId + "-" + osVersion;
        int n = 0;
        for (PkgRow p : packages) {
            ObjectNode c = components.addObject();
            String ref = "pkg-" + (n++);
            c.put("bom-ref", ref);
            c.put("type", "library");
            c.put("name", p.name());
            c.put("version", p.version());
            String purl = "pkg:" + manager + "/" + osId + "/" + p.name() + "@" + p.version()
                    + "?distro=" + distro + (p.arch() == null || p.arch().isBlank() ? "" : "&arch=" + p.arch());
            c.put("purl", purl);
            ArrayNode props = c.putArray("properties");
            if (p.sourceName() != null && !p.sourceName().isBlank()) {
                props.addObject().put("name", "aquasecurity:trivy:SrcName").put("value", p.sourceName());
                props.addObject().put("name", "aquasecurity:trivy:SrcVersion").put("value", p.version());
            }
        }
        return MAPPER.writeValueAsString(bom);
    }

    // ───────────────────────── Trivy (sbom --format json) ─────────────────────────

    public static List<PackageFinding> parseTrivy(String json, Predicate<String> isKev) throws Exception {
        List<PackageFinding> out = new ArrayList<>();
        if (json == null || json.isBlank()) return out;
        JsonNode root = MAPPER.readTree(json);
        Map<String, List<VulnRef>> byPkg = new LinkedHashMap<>();
        Map<String, String[]> pkgInfo = new LinkedHashMap<>(); // key -> {name, version}

        for (JsonNode result : root.path("Results")) {
            for (JsonNode v : result.path("Vulnerabilities")) {
                String name = v.path("PkgName").asText("");
                String version = v.path("InstalledVersion").asText("");
                String id = v.path("VulnerabilityID").asText("");
                if (name.isBlank() || id.isBlank()) continue;
                Double cvss = null;
                for (JsonNode src : v.path("CVSS")) {
                    double s = src.path("V3Score").asDouble(0);
                    if (s > 0 && (cvss == null || s > cvss)) cvss = s;
                }
                String severity = v.path("Severity").asText("UNKNOWN").toUpperCase(Locale.ROOT);
                String fixed = v.path("FixedVersion").asText("");
                String key = name + "@" + version;
                pkgInfo.putIfAbsent(key, new String[] { name, version });
                byPkg.computeIfAbsent(key, k -> new ArrayList<>()).add(new VulnRef(
                        id, cvss, severity, false, isKev != null && isKev.test(id),
                        fixed.isBlank() ? null : fixed));
            }
        }
        for (Map.Entry<String, List<VulnRef>> e : byPkg.entrySet()) {
            List<VulnRef> vulns = e.getValue();
            vulns.sort((a, b) -> Integer.compare(severityRank(a.severity()), severityRank(b.severity())));
            String worst = vulns.get(0).severity();
            String fix = vulns.stream().map(VulnRef::fixedVersion).filter(x -> x != null).findFirst().orElse(null);
            String[] info = pkgInfo.get(e.getKey());
            out.add(new PackageFinding(info[0], info[1], fix, worst, vulns));
        }
        out.sort((a, b) -> {
            int c = Integer.compare(severityRank(a.severity()), severityRank(b.severity()));
            return c != 0 ? c : Integer.compare(b.vulns().size(), a.vulns().size());
        });
        return out;
    }
}
