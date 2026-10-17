import type { SslResultDto } from '../services/api';

/**
 * A well configured site as every source sees it (TLS 1.2 + 1.3 only, trusted certificate valid 80 days, all main
 * headers), for the SSL tests. Each test changes only what it is about.
 */
export function goodSslResult(over: Partial<SslResultDto> = {}): SslResultDto {
  const base = {
    domain: 'good.example.com',
    grade: 'A+',
    scanStatus: 'COMPLETED',
    tls10: false, tls11: false, tls12: true, tls13: true,
    heartbleed: false, sweet32: false, has3des: false, crime: false, poodle: false, beast: false, robot: false,
    freak: false, logjam: false, rc4: false, drown: false,
    certExpired: false, certDaysLeft: 80, certIssuer: "C=US, O=Let's Encrypt, CN=R11", certSubject: 'CN=good.example.com',
    chainComplete: true, certSignatureAlg: 'sha256WithRSAEncryption', certKeySize: '2048', certNotBefore: '', certNotAfterStr: '2026-12-31',
    certSerialNumber: '01', certEv: false, certWildcard: false, certTransparency: true, certSansCount: 1,
    hsts: true, hstsValue: 'max-age=31536000; includeSubDomains', ocspStapling: true,
    xFrameOptions: true, xContentTypeOptions: true, contentSecurityPolicy: true, cspReportOnly: false,
    cspValue: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    xFrameOptionsValue: 'DENY', xContentTypeOptionsValue: 'nosniff',
    referrerPolicy: true, referrerPolicyValue: 'strict-origin-when-cross-origin',
    permissionsPolicy: true, permissionsPolicyValue: 'camera=(), microphone=(), geolocation=()',
    crossOriginOpenerPolicy: false, crossOriginResourcePolicy: false, crossOriginEmbedderPolicy: false,
    headersLiveChecked: true,
    ssllabsGrade: 'A+', ssllabsStatus: 'READY', ssllabsIpAddress: '1.2.3.4', ssllabsHasWarnings: false,
    ssllabsForwardSecrecy: true, ssllabsDrown: false,
    censysGrade: 'A', censysStatus: 'READY', censysIpAddress: '1.2.3.4', censysDaysLeft: 80, censysExpired: false,
    censysCertValid: true, censysIssuer: "Let's Encrypt", censysKeySize: '2048', censysValidationLevel: 'DV',
    censysCtPresent: true, censysSansCount: 1, censysOpenPorts: '80, 443',
    sslyzeGrade: 'A+', sslyzeStatus: 'READY', sslyzeIpAddress: '1.2.3.4',
    sslyzeSupportsSSL20: false, sslyzeSupportsSSL30: false, sslyzeSupportsTLS10: false, sslyzeSupportsTLS11: false,
    sslyzeSupportsTLS12: true, sslyzeSupportsTLS13: true,
    sslyzeHeartbleed: false, sslyzeRobot: false, sslyzeCcsInjection: false, sslyzeCompression: false,
    sslyzeInsecureRenegotiation: false, sslyzeCertSubject: 'CN=good.example.com',
    sslyzeCertIssuer: "CN=R11,O=Let's Encrypt,C=US", sslyzeKeySize: 2048, sslyzeChainTrusted: true,
    sslyzeOcspStapling: true, sslyzeDaysLeft: 80, sslyzeCipherCount: 8,
    tlsProtocols: [],
    certificateDetail: { hostnameMatch: 'MATCH', validityStatus: 'VALID', keyType: 'RSA', keySize: 2048, serialNumber: '01' },
    combinedGrade: 'A+', sourcesReady: 4, sourcesTotal: 4,
  };
  return { ...base, ...over } as unknown as SslResultDto;
}
