import { sslProgressFromLogs, SSL_STEPS } from './sslProgress';

describe('sslProgressFromLogs', () => {
  it('before the first tool', () => {
    const p = sslProgressFromLogs(['[SYSTEM] Connected to scan #4 log stream']);
    expect(p.index).toBe(-1);
    expect(p.percent).toBe(0);
    expect(p.done).toBe(false);
  });

  it('reads the step from the scanner markers', () => {
    const p = sslProgressFromLogs([
      'Running SSL/TLS scans on site.com:443',
      '  [1/6] sslyze...',
      '  [2/6] sslscan...',
      '  [3/6] testssl.sh (timeout 600s)...',
    ]);
    expect(p.step?.key).toBe('testssl');
    expect(p.index).toBe(2);
    expect(p.percent).toBeGreaterThan(0);
    expect(p.percent).toBeLessThan(50);
    // testssl + the steps after it
    expect(p.maxRemainingSeconds).toBe(SSL_STEPS.slice(2).reduce((s, x) => s + x.maxSeconds, 0));
  });

  it('done once the summary is logged', () => {
    const p = sslProgressFromLogs(['  [6/6] whatweb...', '    SSL summary: grade=A']);
    expect(p.done).toBe(true);
    expect(p.percent).toBe(100);
  });
});

describe('queued scans', () => {
  it('says the scan waits for a worker, until one takes it', () => {
    expect(sslProgressFromLogs(["[QUEUE] Scan en file d'attente : il démarre dès qu'un poste de scan est libre."]).queued).toBe(true);
    expect(sslProgressFromLogs(["[QUEUE] Scan en file d'attente : …", '[QUEUE] Scan pris en charge par le poste ssl-1.']).queued).toBe(false);
  });
});
