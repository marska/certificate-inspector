import { describe, expect, it } from 'vitest';

import { analyzeInput } from '../src/lib/certificate';
import { bundle, fixtures, NOW } from './fixtures';

describe('analyzeInput — the completion criteria from the spec', () => {
  it('takes base64-wrapped PEM and produces every headline property', async () => {
    const { leaf } = await fixtures();
    const input = Buffer.from(leaf.pem, 'utf8').toString('base64');

    const { decode, chain, issues } = await analyzeInput(input, { now: NOW });

    // 1-5: format recognised, decoded, parsed.
    expect(decode.detectedFormat).toBe('base64-pem');
    expect(decode.detectedFormatLabel).toBe('Base64-encoded PEM');
    expect(issues).toEqual([]);
    expect(chain.certificates).toHaveLength(1);

    const certificate = chain.certificates[0];

    // 6-19: every property the spec asks to be visible.
    expect(certificate.commonName).toBe('api.example.com');
    expect(certificate.subject.oneLine).toContain('O=Example Company');
    expect(certificate.issuer.oneLine).toContain('CN=Example TLS Intermediate CA');
    expect(certificate.validity.notBefore).toBeInstanceOf(Date);
    expect(certificate.validity.notAfter).toBeInstanceOf(Date);
    expect(certificate.validity.daysRemaining).toBe(165);
    expect(certificate.subjectAlternativeNames).toHaveLength(4);
    expect(certificate.publicKey.size).toBe(2048);
    expect(certificate.signature.algorithm).toBe('sha256WithRSAEncryption');
    expect(certificate.keyUsageNames).toContain('Digital Signature');
    expect(certificate.extendedKeyUsage[0].name).toBe('TLS Web Server Authentication');
    expect(certificate.fingerprints.sha256).toBeTruthy();
    expect(certificate.extensions.length).toBeGreaterThan(4);
    expect(certificate.pem).toBe(leaf.pem);
  });

  it('runs the whole test scenario from spec §35 on a two-certificate bundle', async () => {
    const { leaf, intermediate } = await fixtures();
    const { chain, decode } = await analyzeInput(bundle(leaf, intermediate), {
      now: NOW,
    });

    // 1-2: both certificates detected and parsed.
    expect(decode.blocks).toHaveLength(2);
    expect(chain.certificates).toHaveLength(2);

    // 3-4: leaf identified, issuer → subject established.
    expect(chain.leaf?.commonName).toBe('api.example.com');
    expect(chain.intermediates[0].commonName).toBe('Example TLS Intermediate CA');

    // 5: leaf signature verified with the issuer's public key.
    expect(chain.links[0].checks.at(-1)).toMatchObject({
      label: 'Signature verification',
      status: 'ok',
    });

    // 6: validity of both checked.
    expect(chain.issues.filter((issue) => issue.code === 'CERT_VALID')).toHaveLength(2);

    // 7: basic constraints of the intermediate.
    expect(chain.intermediates[0].isCA).toBe(true);
    expect(chain.intermediates[0].basicConstraints.pathLength).toBe(0);

    // 8-10: chain built, root absence reported as information.
    expect(chain.status).toBe('valid');
    const rootIssue = chain.issues.find((issue) => issue.code === 'CHAIN_INCOMPLETE');
    expect(rootIssue?.severity).toBe('info');
  });

  it('handles a full three-certificate chain end to end', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const { chain } = await analyzeInput(bundle(leaf, intermediate, root), { now: NOW });

    expect(chain.certificates.map((c) => c.role)).toEqual([
      'leaf',
      'intermediate',
      'root',
    ]);
    expect(chain.status).toBe('valid');
    expect(chain.cryptographicStatus).toBe('valid');
  });

  it('surfaces a private key warning without parsing anything', async () => {
    const { decode, chain } = await analyzeInput(
      '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----',
      { now: NOW },
    );

    expect(decode.containsPrivateKey).toBe(true);
    expect(chain.certificates).toEqual([]);
  });

  it('reports a malformed PEM with a specific cause', async () => {
    const { leaf } = await fixtures();
    const { issues, chain } = await analyzeInput(
      leaf.pem.replace('-----END CERTIFICATE-----', ''),
      { now: NOW },
    );

    expect(chain.certificates).toEqual([]);
    expect(issues[0].code).toBe('PEM_MISSING_END');
    expect(issues[0].detail).toContain('closing footer');
  });

  it('never mutates or leaks the input', async () => {
    const { leaf } = await fixtures();
    const original = leaf.der.slice();
    await analyzeInput(leaf.der, { now: NOW });
    expect(leaf.der).toEqual(original);
  });
});
