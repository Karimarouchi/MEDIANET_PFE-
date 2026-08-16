package com.medianet.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory rate limit for {@code /api/ci/**} (per client IP).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 15)
public class CiRateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Deque<Long>> attemptsByIp = new ConcurrentHashMap<>();

    @Value("${app.ci.rate-limit-per-minute:60}")
    private int maxAttemptsPerMinute;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        if (path == null) {
            return true;
        }
        String normalized = path.toLowerCase(Locale.ROOT);
        return !normalized.equals("/api/ci") && !normalized.startsWith("/api/ci/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String ip = clientIp(request);
        long now = Instant.now().toEpochMilli();
        long windowStart = now - 60_000L;

        Deque<Long> attempts = attemptsByIp.computeIfAbsent(ip, key -> new ArrayDeque<>());
        synchronized (attempts) {
            while (!attempts.isEmpty() && attempts.peekFirst() < windowStart) {
                attempts.pollFirst();
            }
            if (attempts.size() >= maxAttemptsPerMinute) {
                response.setStatus(429);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"error\":\"Too many CI requests. Try again in a minute.\"}");
                return;
            }
            attempts.addLast(now);
        }

        filterChain.doFilter(request, response);
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown";
    }
}
