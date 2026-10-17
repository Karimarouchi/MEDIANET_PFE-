package com.medianet.util;

import jakarta.servlet.http.HttpServletRequest;

import java.net.InetAddress;

/**
 * Client address for rate limiting. X-Forwarded-For is set by the client too: it is trusted only when the request
 * comes from a proxy on a loopback or private address (nginx in the Docker network), and then only its last entry,
 * the one that proxy appended. A client reaching port 8080 directly is identified by its socket address.
 */
public final class ClientIp {

    private ClientIp() {
    }

    public static String of(HttpServletRequest request) {
        String remote = request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown";
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank() || !isLocalProxy(remote)) {
            return remote;
        }
        String[] parts = forwarded.split(",");
        String last = parts[parts.length - 1].trim();
        return last.isEmpty() ? remote : last;
    }

    static boolean isLocalProxy(String addr) {
        try {
            if (addr == null || !addr.matches("[0-9a-fA-F:.]+")) {
                return false; // never resolve names here
            }
            InetAddress a = InetAddress.getByName(addr);
            return a.isLoopbackAddress() || a.isSiteLocalAddress();
        } catch (Exception e) {
            return false;
        }
    }
}
