import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SslCertificateChain, { chainVerdict } from './SslCertificateChain';
import type { SslResultDto } from '../services/api';

const fs = require('fs');
const path = require('path');
const load = (name: string): SslResultDto =>
  JSON.parse(fs.readFileSync(path.join(__dirname, `../utils/__fixtures__/badssl/${name}.json`), 'utf8'));

describe('SslCertificateChain on real scans', () => {
  it('a complete chain: site → intermediates → root, all valid', () => {
    const r = load('3des_badssl_com');
    expect(chainVerdict(r).ok).toBe(true);
    render(<SslCertificateChain result={r} />);
    expect(screen.getByText('Certificat du site')).toBeInTheDocument();
    expect(screen.getByText('*.badssl.com')).toBeInTheDocument();
    expect(screen.getByText('Autorité racine')).toBeInTheDocument();
    expect(screen.getByText('ISRG Root X1')).toBeInTheDocument();
  });

  it('an expired link is flagged with what to do', () => {
    const r = load('expired_badssl_com');
    const v = chainVerdict(r);
    expect(v.ok).toBe(false);
    expect(v.text).toMatch(/expiré/);
    render(<SslCertificateChain result={r} />);
    expect(screen.getAllByText('Expiré').length).toBeGreaterThan(0);
  });

  it('a self-signed certificate is said so', () => {
    expect(chainVerdict(load('self-signed_badssl_com')).ok).toBe(false);
  });
});
