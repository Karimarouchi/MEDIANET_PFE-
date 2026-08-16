package com.medianet.filter;

import com.medianet.security.CiPrincipal;
import com.medianet.service.AuthCookieService;
import com.medianet.service.CiTokenService;
import com.medianet.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthFilter — isolation jeton CI vs JWT utilisateur")
class JwtAuthFilterTest {

    @Mock private JwtUtil jwtUtil;
    @Mock private AuthCookieService authCookieService;
    @Mock private CiTokenService ciTokenService;
    @Mock private FilterChain filterChain;

    private JwtAuthFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthFilter(jwtUtil, authCookieService, ciTokenService);
    }

    @Test
    @DisplayName("/api/ci/whoami sans Bearer vx_live_ → 401 CI token required")
    void ciPath_withoutCiToken_isUnauthorized() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/ci/whoami");
        request.setRequestURI("/api/ci/whoami");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("CI token required");
        verify(filterChain, never()).doFilter(any(), any());
        verify(ciTokenService, never()).authenticate(any());
    }

    @Test
    @DisplayName("/api/ci/whoami avec JWT utilisateur → 401 (cookie ignoré)")
    void ciPath_userJwtRejectedEvenWithCookie() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/ci/whoami");
        request.setRequestURI("/api/ci/whoami");
        request.addHeader("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("CI token required");
        verify(jwtUtil, never()).parseAccessClaims(any());
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("/api/ci/whoami avec vx_live_ valide → principal attaché")
    void ciPath_validTokenAuthenticated() throws Exception {
        String raw = "vx_live_abcdefghijklmnopqrstuvwx";
        CiPrincipal principal = new CiPrincipal(1L, "CI", "vx_live_abcd", 12L, Set.of(7L), Set.of("ci:scan"));
        when(ciTokenService.authenticate(raw)).thenReturn(Optional.of(principal));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/ci/whoami");
        request.setRequestURI("/api/ci/whoami");
        request.addHeader("Authorization", "Bearer " + raw);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(request.getAttribute(CiPrincipal.REQUEST_ATTR)).isEqualTo(principal);
        verify(filterChain).doFilter(request, response);
        verify(jwtUtil, never()).parseAccessClaims(any());
    }

    @Test
    @DisplayName("/api/ci/whoami avec vx_live_ révoqué → 401")
    void ciPath_revokedTokenUnauthorized() throws Exception {
        String raw = "vx_live_abcdefghijklmnopqrstuvwx";
        when(ciTokenService.authenticate(raw)).thenReturn(Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/ci/whoami");
        request.setRequestURI("/api/ci/whoami");
        request.addHeader("Authorization", "Bearer " + raw);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("Invalid or revoked CI token");
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("/api/scans avec vx_live_ → 403 (le jeton CI ne sort pas de /api/ci)")
    void userApi_ciTokenForbidden() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/scans");
        request.setRequestURI("/api/scans");
        request.addHeader("Authorization", "Bearer vx_live_abcdefghijklmnopqrstuvwx");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("CI token cannot access this API");
        verify(filterChain, never()).doFilter(any(), any());
        verify(ciTokenService, never()).authenticate(any());
    }

    @Test
    @DisplayName("/api/scans avec JWT utilisateur valide → chaîne continue")
    void userApi_jwtStillWorks() throws Exception {
        Claims claims = org.mockito.Mockito.mock(Claims.class);
        when(jwtUtil.parseAccessClaims("user.jwt.token")).thenReturn(claims);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/scans");
        request.setRequestURI("/api/scans");
        request.addHeader("Authorization", "Bearer user.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(200);
    }
}
