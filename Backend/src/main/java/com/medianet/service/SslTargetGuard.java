package com.medianet.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Validates the target of an SSL scan before anything connects to it.
 *
 * Two jobs: turn whatever the user pasted ("https://Site.com:8443/page?x") into a clean host and port, and refuse
 * targets that resolve to an internal address (loopback, private ranges, link-local, cloud metadata 169.254.169.254…),
 * so the SSL page cannot be used to probe the server's own network (SSRF). The check runs again right before each
 * connection, and the Kali container is pinned to the address checked here, which closes the DNS-rebinding gap.
 */
@Component
public class SslTargetGuard {

    private static final Pattern LABEL = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){3}$");
    private static final Pattern SCHEME = Pattern.compile("^[a-z][a-z0-9+.-]*://");

    private final boolean allowPrivateTargets;

    public SslTargetGuard(@Value("${ssl.scan.allow-private-targets:false}") boolean allowPrivateTargets) {
        this.allowPrivateTargets = allowPrivateTargets;
    }

    /** A cleaned scan target. {@link #canonical()} is "host" on port 443, "host:port" otherwise. */
    public record Target(String host, int port) {
        public String canonical() {
            return port == 443 ? host : host + ":" + port;
        }
    }

    /**
     * Cleans and validates the format only (no DNS). Throws 400 with a message a user can act on.
     */
    public static Target normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            throw bad("Indiquez un domaine, par exemple exemple.com ou exemple.com:8443.");
        }
        String s = raw.trim().toLowerCase(Locale.ROOT);
        s = SCHEME.matcher(s).replaceFirst("");
        int cut = indexOfAny(s, '/', '?', '#');
        if (cut >= 0) {
            s = s.substring(0, cut);
        }
        if (s.contains("@")) {
            throw bad("Le domaine ne doit pas contenir d'identifiant (partie avant « @ »).");
        }
        if (s.startsWith("[") || s.chars().filter(c -> c == ':').count() > 1) {
            throw bad("Les adresses IPv6 ne sont pas prises en charge : indiquez un nom de domaine.");
        }
        int port = 443;
        int colon = s.lastIndexOf(':');
        if (colon >= 0) {
            String p = s.substring(colon + 1);
            s = s.substring(0, colon);
            if (!p.matches("\\d{1,5}")) {
                throw bad("Port invalide : « " + p + " ».");
            }
            port = Integer.parseInt(p);
            if (port < 1 || port > 65535) {
                throw bad("Le port doit être compris entre 1 et 65535.");
            }
        }
        while (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty()) {
            throw bad("Indiquez un domaine, par exemple exemple.com.");
        }
        if (IPV4.matcher(s).matches()) {
            for (String part : s.split("\\.")) {
                if (Integer.parseInt(part) > 255) {
                    throw bad("Adresse IP invalide : « " + s + " ».");
                }
            }
            return new Target(s, port);
        }
        String ascii;
        try {
            ascii = IDN.toASCII(s, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw bad("Nom de domaine invalide : « " + s + " ».");
        }
        if (ascii.length() > 253) {
            throw bad("Nom de domaine trop long.");
        }
        String[] labels = ascii.split("\\.", -1);
        if (labels.length < 2) {
            throw bad("« " + s + " » n'est pas un nom de domaine complet (exemple : site.com).");
        }
        for (String label : labels) {
            if (!LABEL.matcher(label).matches()) {
                throw bad("Nom de domaine invalide : « " + s + " ».");
            }
        }
        if (labels[labels.length - 1].matches("\\d+")) {
            throw bad("Nom de domaine invalide : « " + s + " ».");
        }
        return new Target(ascii, port);
    }

    /**
     * Resolves the host and refuses it when any of its addresses is internal. Returns the address to connect to
     * (IPv4 preferred, since the Kali tools are run on IPv4).
     */
    public InetAddress resolvePublic(String host) {
        InetAddress[] all;
        try {
            all = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw bad("Le domaine « " + host + " » est introuvable (aucune réponse DNS).");
        }
        InetAddress chosen = null;
        for (InetAddress a : all) {
            if (!allowPrivateTargets && isInternal(a)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "« " + host + " » pointe vers une adresse interne (" + a.getHostAddress()
                                + ") : seuls les sites publics peuvent être analysés.");
            }
            if (chosen == null || (a instanceof Inet4Address && !(chosen instanceof Inet4Address))) {
                chosen = a;
            }
        }
        if (chosen == null) {
            throw bad("Le domaine « " + host + " » est introuvable (aucune adresse).");
        }
        return chosen;
    }

    /** Normalizes then resolves: the one call the scan entry points need. */
    public Target check(String raw) {
        Target t = normalize(raw);
        resolvePublic(t.host());
        return t;
    }

    public boolean allowsPrivateTargets() {
        return allowPrivateTargets;
    }

    /** True for every address the server must never be made to reach on a user's behalf. */
    static boolean isInternal(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()) {
            return true;
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            return isInternalV4(b, 0);
        }
        if (a instanceof Inet6Address) {
            int first = b[0] & 0xff;
            if ((first & 0xfe) == 0xfc) {
                return true; // fc00::/7 unique local
            }
            boolean allZeroPrefix = true;
            for (int i = 0; i < 10; i++) {
                if (b[i] != 0) {
                    allZeroPrefix = false;
                    break;
                }
            }
            if (allZeroPrefix && (((b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff) || (b[10] == 0 && b[11] == 0))) {
                return isInternalV4(b, 12); // ::ffff:a.b.c.d and ::a.b.c.d
            }
            if ((b[0] & 0xff) == 0x00 && (b[1] & 0xff) == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b) {
                return isInternalV4(b, 12); // 64:ff9b::/96 NAT64
            }
            if ((b[0] & 0xff) == 0x20 && (b[1] & 0xff) == 0x02) {
                return isInternalV4(b, 2); // 2002::/16 6to4
            }
            return (b[0] & 0xff) == 0x20 && (b[1] & 0xff) == 0x01 && (b[2] & 0xff) == 0x0d && (b[3] & 0xff) == 0xb8;
        }
        return true;
    }

    private static boolean isInternalV4(byte[] b, int o) {
        int a0 = b[o] & 0xff, a1 = b[o + 1] & 0xff, a2 = b[o + 2] & 0xff;
        return a0 == 0                                   // 0.0.0.0/8
                || a0 == 10                              // 10/8
                || a0 == 127                             // loopback
                || (a0 == 100 && (a1 & 0xc0) == 64)      // 100.64/10 carrier-grade NAT
                || (a0 == 169 && a1 == 254)              // link-local, cloud metadata
                || (a0 == 172 && (a1 & 0xf0) == 16)      // 172.16/12
                || (a0 == 192 && a1 == 168)              // 192.168/16
                || (a0 == 192 && a1 == 0 && a2 == 0)     // 192.0.0/24
                || (a0 == 192 && a1 == 0 && a2 == 2)     // TEST-NET-1
                || (a0 == 198 && (a1 & 0xfe) == 18)      // 198.18/15 benchmarking
                || (a0 == 198 && a1 == 51 && a2 == 100)  // TEST-NET-2
                || (a0 == 203 && a1 == 0 && a2 == 113)   // TEST-NET-3
                || a0 >= 224;                            // multicast, reserved, broadcast
    }

    private static int indexOfAny(String s, char... chars) {
        int best = -1;
        for (char c : chars) {
            int i = s.indexOf(c);
            if (i >= 0 && (best < 0 || i < best)) {
                best = i;
            }
        }
        return best;
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
