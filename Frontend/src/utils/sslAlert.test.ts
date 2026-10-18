import { daysUntil, dueSslAlerts, sslAlertSentence, sslAlertUrgent, popupSeenToday, markPopupSeen } from './sslAlert';

const today = new Date(2026, 9, 18); // 18 octobre 2026, local

describe('sslAlert', () => {
  it('is due from the chosen day on, never before', () => {
    const clients = [
      { id: 1, name: 'hostinger', domainName: 'courtlinker.com', sslAlertDate: '2026-10-18', sslCertExpiresOn: '2026-12-19' },
      { id: 2, name: 'pfe', domainName: 'pfe.example.com', sslAlertDate: '2026-10-01', sslCertExpiresOn: '2026-10-20' },
      { id: 3, name: 'later', domainName: 'x.com', sslAlertDate: '2026-11-04', sslCertExpiresOn: '2026-12-01' },
      { id: 4, name: 'none', domainName: 'y.com', sslAlertDate: null },
    ];
    const due = dueSslAlerts(clients, today);
    expect(due.map((a) => a.clientId)).toEqual([2, 1]); // closest expiry first
    expect(due[1]).toMatchObject({ domain: 'courtlinker.com', expiresOn: '2026-12-19', daysLeft: 62 });
  });

  it('says the real date and the days left', () => {
    expect(sslAlertSentence('courtlinker.com', '2026-12-19', 62)).toBe('Le certificat de courtlinker.com expire le 19 décembre 2026, dans 62 jours.');
    expect(sslAlertSentence('d', '2026-10-17', -1)).toContain('a expiré le');
    expect(sslAlertSentence('d', '2026-10-19', 1)).toContain('demain');
    expect(sslAlertSentence('d', null, null)).toContain('relancez un scan SSL');
    expect(daysUntil('2026-10-18', today)).toBe(0);
  });

  it('turns red at 7 days or less', () => {
    expect(sslAlertUrgent(7)).toBe(true);
    expect(sslAlertUrgent(8)).toBe(false);
    expect(sslAlertUrgent(null)).toBe(false);
  });

  it('opens the window once a day per project', () => {
    window.localStorage.clear();
    expect(popupSeenToday(5, today)).toBe(false);
    markPopupSeen(5, today);
    expect(popupSeenToday(5, today)).toBe(true);
    expect(popupSeenToday(5, new Date(2026, 9, 19))).toBe(false);
    expect(popupSeenToday(6, today)).toBe(false);
  });
});
