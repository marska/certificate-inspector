import { describe, expect, it } from 'vitest';

import { buildChain } from '../src/lib/certificate/build-chain';
import { parseCertificate } from '../src/lib/certificate/parse-certificate';
import { validateChain } from '../src/lib/certificate/validate-chain';
import type { ParsedCertificate } from '../src/lib/certificate/types';
import type { GeneratedCertificate } from './fixtures/factory';
import { NOW, fixtures } from './fixtures';

async function parseAll(
  ...certificates: GeneratedCertificate[]
): Promise<ParsedCertificate[]> {
  return Promise.all(
    certificates.map((certificate) =>
      parseCertificate(certificate.der, { now: NOW }),
    ),
  );
}

const codes = (chain: Awaited<ReturnType<typeof validateChain>>) =>
  chain.issues.map((issue) => issue.code);

describe('buildChain', () => {
  it('orders leaf → intermediate → root', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const chain = buildChain(await parseAll(leaf, intermediate, root));

    expect(chain.ordered.map((c) => c.commonName)).toEqual([
      'api.example.com',
      'Example TLS Intermediate CA',
      'Example Root CA',
    ]);
    expect(chain.leaf?.commonName).toBe('api.example.com');
    expect(chain.intermediates.map((c) => c.commonName)).toEqual([
      'Example TLS Intermediate CA',
    ]);
    expect(chain.root?.commonName).toBe('Example Root CA');
    expect(chain.missingIssuerOf).toBeUndefined();
  });

  it('reorders a shuffled bundle and flags the wrong order', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const chain = buildChain(await parseAll(root, leaf, intermediate));

    expect(chain.ordered.map((c) => c.commonName)).toEqual([
      'api.example.com',
      'Example TLS Intermediate CA',
      'Example Root CA',
    ]);
    expect(chain.wrongOrder).toBe(true);
  });

  it('assigns roles to every certificate', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const chain = buildChain(await parseAll(leaf, intermediate, root));

    expect(chain.ordered.map((c) => c.role)).toEqual(['leaf', 'intermediate', 'root']);
  });

  it('drops duplicates but records them', async () => {
    const { leaf, intermediate } = await fixtures();
    const chain = buildChain(await parseAll(leaf, intermediate, leaf));

    expect(chain.ordered).toHaveLength(2);
    expect(chain.duplicates).toHaveLength(1);
    expect(chain.duplicates[0].commonName).toBe('api.example.com');
  });

  it('stops at the last certificate when the issuer is absent', async () => {
    const { leaf, intermediate } = await fixtures();
    const chain = buildChain(await parseAll(leaf, intermediate));

    expect(chain.ordered).toHaveLength(2);
    expect(chain.root).toBeUndefined();
    expect(chain.missingIssuerOf?.commonName).toBe('Example TLS Intermediate CA');
  });

  it('reports a missing intermediate', async () => {
    const { leaf, root } = await fixtures();
    const chain = buildChain(await parseAll(leaf, root));

    expect(chain.ordered).toHaveLength(1);
    expect(chain.missingIssuerOf?.commonName).toBe('api.example.com');
    expect(chain.unrelated.map((c) => c.commonName)).toEqual(['Example Root CA']);
  });

  it('treats a lone self-signed CA as a root, not a leaf', async () => {
    const { root } = await fixtures();
    const chain = buildChain(await parseAll(root));

    expect(chain.leaf).toBeUndefined();
    expect(chain.root?.commonName).toBe('Example Root CA');
    expect(chain.root?.role).toBe('root');
  });

  it('treats a single end-entity certificate as the leaf', async () => {
    const { leaf } = await fixtures();
    const chain = buildChain(await parseAll(leaf));

    expect(chain.leaf?.commonName).toBe('api.example.com');
    expect(chain.root).toBeUndefined();
  });

  it('separates certificates from an unrelated chain', async () => {
    const { leaf, intermediate, root, otherRoot } = await fixtures();
    const chain = buildChain(await parseAll(leaf, intermediate, root, otherRoot));

    expect(chain.ordered).toHaveLength(3);
    expect(chain.unrelated.map((c) => c.commonName)).toEqual(['Unrelated Root CA']);
  });
});

describe('validateChain', () => {
  it('verifies every signature in a complete chain', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const chain = await validateChain(await parseAll(leaf, intermediate, root), {
      now: NOW,
    });

    expect(chain.status).toBe('valid');
    expect(chain.cryptographicStatus).toBe('valid');
    expect(chain.systemTrust).toBe('unknown');

    for (const link of chain.links) {
      const signature = link.checks.find((c) => c.label === 'Signature verification');
      expect(signature?.status).toBe('ok');
    }

    expect(codes(chain)).toContain('CHAIN_COMPLETE');
    expect(codes(chain)).toContain('ROOT_INCLUDED');
  });

  it('checks issuer/subject and AKI/SKI for each link', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const chain = await validateChain(await parseAll(leaf, intermediate, root), {
      now: NOW,
    });

    const leafLink = chain.links[0];
    expect(leafLink.issuerLabel).toBe('Example TLS Intermediate CA');
    expect(leafLink.checks.map((c) => [c.label, c.status])).toEqual([
      ['Issuer matches Subject', 'ok'],
      ['Authority Key Identifier matches Subject Key Identifier', 'ok'],
      ['Signature verification', 'ok'],
    ]);

    const rootLink = chain.links[2];
    expect(rootLink.checks[0].label).toBe('Self-signed (issuer = subject)');
    expect(rootLink.checks[0].status).toBe('ok');
  });

  it('treats a missing root as information, not an error', async () => {
    const { leaf, intermediate } = await fixtures();
    const chain = await validateChain(await parseAll(leaf, intermediate), { now: NOW });

    const incomplete = chain.issues.find((issue) => issue.code === 'CHAIN_INCOMPLETE');
    expect(incomplete?.severity).toBe('info');
    expect(chain.status).toBe('valid');
    expect(chain.cryptographicStatus).toBe('valid');
    expect(chain.missingIssuer).toContain('CN=Example Root CA');
  });

  it('warns when the intermediate is missing', async () => {
    const { leaf, root } = await fixtures();
    const chain = await validateChain(await parseAll(leaf, root), { now: NOW });

    const missing = chain.issues.find((issue) => issue.code === 'ISSUER_NOT_FOUND');
    expect(missing?.severity).toBe('warning');
    expect(missing?.message).toContain('Missing issuer certificate');
    expect(chain.status).toBe('incomplete');
  });

  it('detects a forged signature', async () => {
    const { forgedLeaf, intermediate, root } = await fixtures();
    const chain = await validateChain(await parseAll(forgedLeaf, intermediate, root), {
      now: NOW,
    });

    expect(chain.cryptographicStatus).toBe('invalid');
    expect(chain.status).toBe('invalid');
    expect(codes(chain)).toContain('SIGNATURE_INVALID');
    expect(chain.links[0].checks.at(-1)?.status).toBe('fail');
  });

  it('reports an expired certificate in the chain', async () => {
    const { expiredLeaf, intermediate, root } = await fixtures();
    const chain = await validateChain(await parseAll(expiredLeaf, intermediate, root), {
      now: NOW,
    });

    const expired = chain.issues.find((issue) => issue.code === 'CERT_EXPIRED');
    expect(expired?.severity).toBe('error');
    expect(expired?.message).toContain('expired 35 day(s) ago');
    expect(chain.status).toBe('invalid');
  });

  it('reports a certificate that is not valid yet', async () => {
    const { futureLeaf, intermediate } = await fixtures();
    const chain = await validateChain(await parseAll(futureLeaf, intermediate), {
      now: NOW,
    });

    expect(codes(chain)).toContain('CERT_NOT_YET_VALID');
  });

  it('warns about a certificate expiring soon', async () => {
    const { expiringSoonLeaf, intermediate } = await fixtures();
    const chain = await validateChain(await parseAll(expiringSoonLeaf, intermediate), {
      now: NOW,
    });

    const soon = chain.issues.find((issue) => issue.code === 'CERT_EXPIRING_SOON');
    expect(soon?.severity).toBe('warning');
    expect(soon?.message).toContain('expires in 18 day(s)');
  });

  it('flags a self-signed end-entity certificate', async () => {
    const { selfSignedLeaf } = await fixtures();
    const chain = await validateChain(await parseAll(selfSignedLeaf), { now: NOW });

    expect(codes(chain)).toContain('SELF_SIGNED_LEAF');
    expect(chain.links[0].checks[0].label).toBe('Self-signed (issuer = subject)');
    expect(chain.cryptographicStatus).toBe('valid');
  });

  it('flags a CA that is not marked CA:TRUE', async () => {
    const { leafUnderBadCa, badCaIntermediate, root } = await fixtures();
    const chain = await validateChain(
      await parseAll(leafUnderBadCa, badCaIntermediate, root),
      { now: NOW },
    );

    const issue = chain.issues.find((i) => i.code === 'INVALID_CA_CONSTRAINT');
    expect(issue?.severity).toBe('error');
    expect(issue?.message).toContain('not marked CA:TRUE');
  });

  it('flags a weak signature algorithm', async () => {
    const { sha1Leaf } = await fixtures();
    const chain = await validateChain(await parseAll(sha1Leaf), { now: NOW });

    const weak = chain.issues.find((issue) => issue.code === 'WEAK_SIGNATURE');
    expect(weak?.severity).toBe('warning');
    expect(weak?.message).toContain('sha1WithRSAEncryption');
  });

  it('flags duplicate certificates', async () => {
    const { leaf, intermediate } = await fixtures();
    const chain = await validateChain(await parseAll(leaf, intermediate, leaf), {
      now: NOW,
    });

    expect(codes(chain)).toContain('DUPLICATE_CERTIFICATE');
    expect(chain.certificates).toHaveLength(2);
  });

  it('flags a bundle that is out of order', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const chain = await validateChain(await parseAll(intermediate, root, leaf), {
      now: NOW,
    });

    expect(codes(chain)).toContain('WRONG_ORDER');
    expect(chain.cryptographicStatus).toBe('valid');
  });

  it('flags unrelated certificates', async () => {
    const { leaf, intermediate, otherRoot } = await fixtures();
    const chain = await validateChain(await parseAll(leaf, intermediate, otherRoot), {
      now: NOW,
    });

    const stray = chain.issues.find((i) => i.code === 'UNRELATED_CERTIFICATE');
    expect(stray?.message).toContain('Unrelated Root CA');
  });

  it('never claims system trust', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const chain = await validateChain(await parseAll(leaf, intermediate, root), {
      now: NOW,
    });

    expect(chain.systemTrust).toBe('unknown');
    expect(JSON.stringify(chain.issues)).not.toMatch(/\btrusted\b/i);
  });

  it('returns an empty result for no certificates', async () => {
    const chain = await validateChain([], { now: NOW });
    expect(chain.status).toBe('unknown');
    expect(chain.certificates).toEqual([]);
  });
});
