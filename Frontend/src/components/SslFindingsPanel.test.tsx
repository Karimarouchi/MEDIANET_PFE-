import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import SslFindingsPanel from './SslFindingsPanel';
import SslCertificateBrief, { issuerName } from './SslCertificateBrief';
import type { SslResultDto } from '../services/api';
import { goodSslResult } from '../utils/sslTestFixtures';

const fs = require('fs');
const path = require('path');
const rc4: SslResultDto = JSON.parse(fs.readFileSync(path.join(__dirname, '../utils/__fixtures__/badssl/rc4_badssl_com.json'), 'utf8'));

describe('SslFindingsPanel', () => {
  it('lists the problems of a real scan with the flaw and the fix to copy', () => {
    render(<SslFindingsPanel result={{ ...rc4, webServer: 'nginx' }} />);
    expect(screen.getByRole('heading', { name: /problèmes? à corriger/ })).toBeInTheDocument();
    expect(screen.getByText('Chiffrement RC4 accepté')).toBeInTheDocument();
    expect(screen.getAllByText(/Faille si non corrigé/).length).toBeGreaterThan(0);
    expect(screen.getByText('Corrections pour nginx (serveur détecté)')).toBeInTheDocument();
    // nginx detected: only nginx lines, no Apache lines.
    expect(screen.getAllByText('nginx').length).toBeGreaterThan(0);
    expect(screen.queryByText('apache')).toBeNull();
    expect(screen.getAllByRole('button', { name: 'Copier' }).length).toBeGreaterThan(0);
  });

  it('keeps what passed folded until asked', () => {
    render(<SslFindingsPanel result={goodSslResult()} />);
    const toggle = screen.getByRole('button', { name: /Ce qui est bon/ });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByText('Heartbleed')).toBeNull();
    fireEvent.click(toggle);
    expect(screen.getByText('Heartbleed')).toBeInTheDocument();
  });

  it('shows both servers when it is not detected', () => {
    render(<SslFindingsPanel result={{ ...rc4, webServer: null }} />);
    expect(screen.getByText('Corrections pour nginx et Apache')).toBeInTheDocument();
    expect(screen.getAllByText('apache').length).toBeGreaterThan(0);
  });
});

describe('SslCertificateBrief', () => {
  it('reads the issuer name', () => {
    expect(issuerName("C=US, O=Let's Encrypt, CN=R11")).toBe("Let's Encrypt (R11)");
    expect(issuerName('unknown')).toBe('Inconnu');
  });

  it('shows the days left', () => {
    render(<SslCertificateBrief result={goodSslResult({ sslyzeDaysLeft: 62, certDaysLeft: 62 } as Partial<SslResultDto>)} />);
    expect(screen.getByText('encore 62 j')).toBeInTheDocument();
  });
});
