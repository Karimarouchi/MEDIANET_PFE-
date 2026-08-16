package com.medianet.filter;

import com.medianet.security.CiPrincipal;
import com.medianet.service.AuthCookieService;
import com.medianet.service.CiTokenService;
import com.medianet.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Global auth filter: JWT (cookie / Bearer / SSE ?token=) for the UI, and
 * {@code vx_live_} / {@code vx_test_} CI tokens exclusively on {@code /api/ci/**}.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final AuthCookieService authCookieService;
    private final CiTokenService ciTokenService;

    public JwtAuthFilter(JwtUtil jwtUtil, AuthCookieService authCookieService, CiTokenService ciTokenService) {
        this.jwtUtil = jwtUtil;
        this.authCookieService = authCookieService;
        this.ciTokenService = ciTokenService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        return path == null || !path.startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        String bearer = readAuthorizationBearer(request);

        if (isCiApiPath(path)) {
            authenticateCi(request, response, filterChain, bearer);
            return;
        }

        if (CiTokenService.isCiTokenValue(bearer)) {
            writeJson(response, HttpServletResponse.SC_FORBIDDEN, "CI token cannot access this API");
            return;
        }

        String token = resolveUserToken(request, bearer);
        Claims claims = token != null ? jwtUtil.parseAccessClaims(token) : null;
        boolean authenticated = claims != null;

        HttpServletRequest effectiveRequest = request;
        if (authenticated && (request.getHeader("Authorization") == null
                || request.getHeader("Authorization").isBlank())) {
            effectiveRequest = new AuthorizationHeaderRequest(request, "Bearer " + token);
        }

        if (!authenticated && requiresAuthentication(path)) {
            writeJson(response, HttpServletResponse.SC_UNAUTHORIZED, "Authentication required");
            return;
        }

        filterChain.doFilter(effectiveRequest, response);
    }

    private void authenticateCi(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain,
            String bearer) throws ServletException, IOException {
        if (!CiTokenService.isCiTokenValue(bearer)) {
            writeJson(response, HttpServletResponse.SC_UNAUTHORIZED, "CI token required");
            return;
        }
        Optional<CiPrincipal> principal = ciTokenService.authenticate(bearer);
        if (principal.isEmpty()) {
            writeJson(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid or revoked CI token");
            return;
        }
        request.setAttribute(CiPrincipal.REQUEST_ATTR, principal.get());
        filterChain.doFilter(request, response);
    }

    private static boolean isCiApiPath(String path) {
        if (path == null) {
            return false;
        }
        String normalized = path.toLowerCase(Locale.ROOT);
        return "/api/ci".equals(normalized) || normalized.startsWith("/api/ci/");
    }

    /** Authorization header only — cookies and ?token= are never accepted as CI credentials. */
    private static String readAuthorizationBearer(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String value = authHeader.substring(7).trim();
            if (!value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    private String resolveUserToken(HttpServletRequest request, String bearer) {
        if (bearer != null && !CiTokenService.isCiTokenValue(bearer)) {
            return bearer;
        }

        String cookieToken = authCookieService.readCookie(request, AuthCookieService.ACCESS_COOKIE);
        if (cookieToken != null) {
            return cookieToken;
        }

        String queryToken = request.getParameter("token");
        if (queryToken != null && !queryToken.isBlank()) {
            return queryToken.trim();
        }
        return null;
    }

    private static boolean requiresAuthentication(String path) {
        if (path == null) {
            return true;
        }
        String normalized = path.toLowerCase(Locale.ROOT);
        return !(normalized.equals("/api/hello")
                || normalized.equals("/api/auth/login")
                || normalized.equals("/api/auth/refresh")
                || normalized.equals("/api/auth/logout")
                || normalized.equals("/api/auth/github")
                || normalized.equals("/api/auth/github/callback")
                || normalized.equals("/api/auth/gitlab/callback"));
    }

    private static void writeJson(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    private static final class AuthorizationHeaderRequest extends HttpServletRequestWrapper {
        private final String authorization;

        private AuthorizationHeaderRequest(HttpServletRequest request, String authorization) {
            super(request);
            this.authorization = authorization;
        }

        @Override
        public String getHeader(String name) {
            if ("Authorization".equalsIgnoreCase(name)) {
                return authorization;
            }
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if ("Authorization".equalsIgnoreCase(name)) {
                return Collections.enumeration(List.of(authorization));
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames());
            boolean present = names.stream().anyMatch(n -> "Authorization".equalsIgnoreCase(n));
            if (!present) {
                names.add("Authorization");
            }
            return Collections.enumeration(names);
        }
    }
}
