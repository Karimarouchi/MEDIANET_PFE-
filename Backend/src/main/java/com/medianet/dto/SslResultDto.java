package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SslResultDto {

    private String domain;
    private String grade;
    private String scanStatus; // RUNNING | COMPLETED | FAILED
    private String source;

    // ── Protocols ─────────────────────────────────────────────────────
    private boolean tls10;
    private boolean tls11;
    private boolean tls12;
    private boolean tls13;

    // ── Vulnerabilities ───────────────────────────────────────────────
    private boolean heartbleed;
    private boolean sweet32;
    private boolean has3des;
    private boolean crime;
    private boolean poodle;
    private boolean beast;
    private boolean robot;
    private boolean freak;
    private boolean logjam;
    private boolean rc4;
    private boolean drown;

    // ── Certificate ───────────────────────────────────────────────────
    private boolean certExpired;
    private int certDaysLeft;
    private String certIssuer;
    private String certSubject;
    private boolean chainComplete;
    private String certSignatureAlg;
    private String certKeySize;
    private String certNotBefore;
    private String certNotAfterStr;
    private String certSerialNumber;
    private boolean certEv;
    private boolean certWildcard;
    private boolean certTransparency;
    private int certSansCount;

    // ── Security Headers ──────────────────────────────────────────────
    private boolean hsts;
    private boolean ocspStapling;
    private boolean xFrameOptions;
    private boolean xContentTypeOptions;
    private boolean contentSecurityPolicy;
    private boolean referrerPolicy;
    private boolean permissionsPolicy;

    // ── SSL Labs external scan ─────────────────────────────────────────
    private String ssllabsGrade;          // A+/A/B/C/D/F/?/PENDING
    private String ssllabsStatus;         // PENDING|READY|ERROR|TIMEOUT|DISABLED
    private String ssllabsIpAddress;
    private boolean ssllabsHasWarnings;
    private boolean ssllabsForwardSecrecy;
    private boolean ssllabsDrown;

    // ── Censys Platform API ───────────────────────────────────────────
    private String censysGrade;           // A+/A/B/C/D/F/?
    private String censysStatus;          // PENDING|READY|ERROR|DISABLED
    private String censysIpAddress;
    private int    censysDaysLeft;
    private boolean censysExpired;
    private boolean censysCertValid;
    private String censysIssuer;
    private String censysKeySize;
    private String censysValidationLevel; // DV|OV|EV
    private boolean censysCtPresent;
    private int    censysSansCount;
    private String censysOpenPorts;

    // ── SSLyze (local parse of sslyze.json from Kali scan) ────────────
    private String  sslyzeGrade;           // A+/A/B/C/D/F/?
    private String  sslyzeStatus;          // PENDING|READY|ERROR
    private String  sslyzeIpAddress;
    // Protocols supported
    private boolean sslyzeSupportsSSL20;
    private boolean sslyzeSupportsSSL30;
    private boolean sslyzeSupportsTLS10;
    private boolean sslyzeSupportsTLS11;
    private boolean sslyzeSupportsTLS12;
    private boolean sslyzeSupportsTLS13;
    // Vulnerabilities
    private boolean sslyzeHeartbleed;
    private boolean sslyzeRobot;
    private boolean sslyzeCcsInjection;
    private boolean sslyzeCompression;     // CRIME
    private boolean sslyzeInsecureRenegotiation;
    // Certificate
    private String  sslyzeCertSubject;
    private String  sslyzeCertIssuer;
    private int     sslyzeKeySize;
    private boolean sslyzeChainTrusted;
    private boolean sslyzeOcspStapling;
    private int     sslyzeDaysLeft;
    private int     sslyzeCipherCount;     // total accepted cipher suites

    // ── Combined (fusion of all sources) ─────────────────────────────
    private String combinedGrade;         // worst-case weighted result
    private int    sourcesReady;          // how many sources returned READY
    private int    sourcesTotal;          // 4 (Kali + SSL Labs + Censys + SSLyze)
}
