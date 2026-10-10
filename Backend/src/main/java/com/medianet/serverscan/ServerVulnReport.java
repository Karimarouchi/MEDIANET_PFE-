package com.medianet.serverscan;

import java.util.List;

/**
 * Result of a server vulnerability analysis: open ports (service, version, known CVEs) and vulnerable system
 * packages. Stored as JSON on {@code ServerVulnScan}.
 */
public record ServerVulnReport(
        String host,
        String os,
        boolean externalScan,
        boolean internalScan,
        List<PortFinding> ports,
        List<PackageFinding> packages,
        Summary summary,
        List<String> warnings) {

    /** One known vulnerability. {@code cvss} may be null when the source gives no score. */
    public record VulnRef(String id, Double cvss, String severity, boolean exploit, boolean kev,
            String fixedVersion) {
    }

    /**
     * exposure: EXTERNAL (reachable from outside), FIREWALLED (listens but not reachable from outside),
     * LOCAL_ONLY (loopback), UNKNOWN (no external scan to tell).
     */
    public record PortFinding(int port, String protocol, String service, String product, String version,
            String exposure, List<VulnRef> vulns) {
    }

    public record PackageFinding(String name, String version, String fixedVersion, String severity,
            List<VulnRef> vulns) {
    }

    public record Summary(int openPorts, int exposedPorts, int vulnerablePorts, int vulnerablePackages,
            int critical, int high, int medium, int low, int kev) {
    }
}
